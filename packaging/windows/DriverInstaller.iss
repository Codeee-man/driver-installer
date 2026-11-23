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
; Elevation: per machine, administrators only. Inno Setup's loader ships with an asInvoker
; manifest and restarts itself elevated, which antivirus interception can break on first launch;
; tools/build_windows.py switches the manifest to requireAdministrator, so Windows shows the UAC
; prompt before Setup runs. No "install for me only" choice: overrides stay off.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=DriverInstaller-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
; A running DriverInstaller.exe would lock its files and make the ACL reset fail: close it.
CloseApplications=force
RestartApplications=no
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
; The program must start with the user's rights, not the installer's.
; Setup itself runs elevated from the start (its manifest is switched to requireAdministrator by
; tools/build_windows.py), so there is no non-elevated "original user" to run as. Explorer starts
; the program with the desktop's normal, non-elevated rights instead.
Filename: "{win}\explorer.exe"; Parameters: """{app}\DriverInstaller.exe"""; Description: "Start Driver Installer"; Flags: nowait postinstall skipifsilent

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

function RunIcacls(Params: string): Integer;
var
  Attempt: Integer;
begin
  Result := -1;
  for Attempt := 1 to 3 do
  begin
    Log('icacls ' + Params + ' (attempt ' + IntToStr(Attempt) + ')');
    if Exec(ExpandConstant('{sys}\icacls.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Result) and (Result = 0) then
      exit;
    Sleep(1500);                         // a file still held open by a closing program
  end;
end;

procedure ClearDownloadMarks(Dir: string);
var
  Rec: TFindRec;
begin
  // Files Setup writes carry no Zone.Identifier stream; delete any anyway (a marked runtime DLL
  // can stop the program from starting). DeleteFile on "file:stream" removes only the stream.
  if FindFirst(Dir + '\*', Rec) then
  try
    repeat
      if (Rec.Name <> '.') and (Rec.Name <> '..') then
        if Rec.Attributes and FILE_ATTRIBUTE_DIRECTORY <> 0 then
          ClearDownloadMarks(Dir + '\' + Rec.Name)
        else
          DeleteFile(Dir + '\' + Rec.Name + ':Zone.Identifier');
    until not FindNext(Rec);
  finally
    FindClose(Rec);
  end;
end;

procedure ProtectInstallFolder;
var
  App: string;
  Code: Integer;
begin
  App := ExpandConstant('{app}');
  ClearDownloadMarks(App);
  // Administrators + SYSTEM: full control. Users: read & execute. Nothing inherited, so no
  // other account can change what the UAC prompt elevates. Setup runs elevated, so this only
  // fails if something outside Setup interferes; then the install must not look protected.
  Code := RunIcacls('"' + App + '" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /Q');
  if Code = 0 then
    Code := RunIcacls('"' + App + '\*" /reset /T /C /Q');
  if Code <> 0 then
    RaiseException('Driver Installer was copied, but its folder could not be locked down so that only '
      + 'administrators can change it (icacls exit code ' + IntToStr(Code) + '). Close Driver Installer '
      + 'if it is running and run Setup again.');
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
