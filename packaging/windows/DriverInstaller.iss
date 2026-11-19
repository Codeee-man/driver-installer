; Inno Setup 6 script for DriverInstaller-Setup.exe. Compiled by tools/build_windows.py:
;
;   iscc /DAppVersion=1.2.3 /DNumericVersion=1.2.3.0 /DSourceDir=<portable folder>
;        /DShimFile=<driver-installer.cmd> /DOutputDir=<dist> [/DIconFile=<.ico>]
;        [/DSign "/Sdisign=..."]  DriverInstaller.iss
;
; What it does on top of copying the portable folder:
;   - installs to C:\Program Files\Driver Installer, where the program looks for its own
;     protected copy before it elevates anything (core/installer.py)
;   - locks the folder down: Administrators and SYSTEM full control, Users read & execute,
;     nothing inherited; clears any "mark of the web" (Zone.Identifier)
;   - Start menu shortcut; optional task: driver-installer.cmd on the system PATH
;   - removes a 1.0.x install made by install_helper.ps1 (C:\Program Files\driver-installer)

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef NumericVersion
  #define NumericVersion "0.0.0.0"
#endif
#ifndef SourceDir
  #error SourceDir (the portable DriverInstaller folder) must be defined
#endif
#ifndef ShimFile
  #error ShimFile (driver-installer.cmd) must be defined
#endif
#ifndef OutputDir
  #define OutputDir "."
#endif

[Setup]
AppId={{8F3B6C2E-4A1D-4E7B-9C55-2D0E1A7F6B31}
AppName=Driver Installer
AppVersion={#AppVersion}
AppVerName=Driver Installer {#AppVersion}
AppPublisher=Driver Installer project
AppPublisherURL=https://github.com/Codeee-man/driver-installer
AppSupportURL=https://github.com/Codeee-man/driver-installer/issues
VersionInfoVersion={#NumericVersion}
VersionInfoProductName=Driver Installer
VersionInfoProductVersion={#NumericVersion}
VersionInfoProductTextVersion={#AppVersion}
VersionInfoDescription=Driver Installer Setup
DefaultDirName={autopf}\Driver Installer
; The program looks for itself in exactly this folder; there is nothing to choose.
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=DriverInstaller-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
CloseApplications=yes
UninstallDisplayName=Driver Installer
UninstallDisplayIcon={app}\DriverInstaller.exe
SetupLogging=yes
#ifdef IconFile
SetupIconFile={#IconFile}
#endif
#ifdef Sign
; "disign" is defined on the iscc command line (/Sdisign=...): tools/codesign_windows.py,
; which signs Setup.exe and the uninstaller with SHA-256 and an RFC 3161 timestamp.
SignTool=disign
SignedUninstaller=yes
SignToolRetryCount=2
#endif

[Tasks]
Name: "addtopath"; Description: "Add CLI command (driver-installer) to system PATH"; GroupDescription: "Command line:"; Flags: unchecked

[InstallDelete]
; Leftovers of an older version would otherwise mix with the new runtime.
Type: filesandordirs; Name: "{app}\_internal"
Type: files; Name: "{app}\driver-installer.cmd"
; 1.0.x was installed by install_helper.ps1 into "driver-installer" (three .exe files).
Type: filesandordirs; Name: "{autopf}\driver-installer"; Check: IsLegacyReleaseInstall

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ShimFile}"; DestDir: "{app}"; Tasks: addtopath; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Driver Installer"; Filename: "{app}\DriverInstaller.exe"; WorkingDir: "{app}"; Comment: "Scan, review and install driver updates"

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
; runasoriginaluser: the program must start with the user's rights, not the installer's.
Filename: "{app}\DriverInstaller.exe"; Description: "Start Driver Installer"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
const
  EnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function IsLegacyReleaseInstall: Boolean;
begin
  Result := FileExists(ExpandConstant('{autopf}\driver-installer\driver-installer-helper.exe'));
end;

function PathContains(Paths, Dir: string): Boolean;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') > 0;
end;

function NeedsAddPath(Dir: string): Boolean;
var
  Paths: string;
begin
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', Paths) then
    Paths := '';
  Result := not PathContains(Paths, Dir);
end;

procedure RemoveFromPath(Dir: string);
var
  Paths: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', Paths) then
    exit;
  Paths := ';' + Paths + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Paths));
  if P = 0 then
    exit;
  Delete(Paths, P, Length(Dir) + 1);
  Paths := Copy(Paths, 2, Length(Paths) - 2);
  if RegWriteExpandStringValue(HKLM, EnvKey, 'Path', Paths) then
    Log('Removed ' + Dir + ' from the system PATH');
end;

procedure RunChecked(Exe, Params, What: string);
var
  Code: Integer;
begin
  Log(What + ': ' + Exe + ' ' + Params);
  if not Exec(Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    RaiseException(What + ' failed (exit code ' + IntToStr(Code) + '). The installation is not protected; uninstall it and try again.');
end;

procedure ProtectInstallFolder;
var
  App, Icacls: string;
begin
  App := ExpandConstant('{app}');
  Icacls := ExpandConstant('{sys}\icacls.exe');
  // Files written by Setup carry no download mark, but clear it anyway: a marked runtime DLL
  // can make Windows refuse to start the program.
  RunChecked(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath ''' + App + ''' -Recurse -File -Force | Unblock-File"',
    'Clearing Zone.Identifier');
  // Administrators + SYSTEM: full control. Users: read & execute. Nothing inherited, so no
  // other account can change what the UAC prompt elevates.
  RunChecked(Icacls, '"' + App + '" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /Q',
    'Setting the folder ACL');
  RunChecked(Icacls, '"' + App + '\*" /reset /T /C /Q', 'Resetting the ACLs below the folder');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    ProtectInstallFolder;
    if not WizardIsTaskSelected('addtopath') then
      RemoveFromPath(ExpandConstant('{app}'));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
