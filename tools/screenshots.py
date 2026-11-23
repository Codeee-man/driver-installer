"""Render the README screenshots headlessly: the main window and the [ SETTINGS ] dialog.

    QT_QPA_PLATFORM=offscreen python tools/screenshots.py [--out docs/img] [--accent green] [--font vt323]

Sample data only (no scan, no network, nothing installed): a few verified updates, a 16-thread
CPU shown as one row (x16), up-to-date devices, and the "Update available" button.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def sample():
    from core.model import Device, Update, dedupe_devices

    def update(name, vendor, hwid, have, new, source, checks, kind="net"):
        dev = Device(name, vendor=vendor, kind=kind, hardware_ids=[hwid], driver_version=have, address=name)
        upd = Update(dev, f"{name} driver", have, new, source, "a" * 64, {"id": name.lower()}, "verified")
        for key, state, reason in checks:
            upd.set_check(key, state, reason)
        return upd

    ok = "passed"
    full = [("sha256", ok, "digest matches"), ("manifest", ok, "pinned key"),
            ("blocklist", ok, "no match"), ("publisher", ok, "Authenticode")]
    partial = [("sha256", ok, "digest matches"), ("manifest", "not_applicable", "Microsoft Update Catalog"),
               ("blocklist", "skipped", "LOLDrivers database offline"), ("publisher", ok, "Authenticode: Realtek")]
    ups = [update("Intel(R) Wi-Fi 6E AX211 160MHz", "Intel", "pci:8086:51f0", "23.20.0.4", "23.60.1.2",
                  "Windows Update", full),
           update("NVIDIA GeForce RTX 4050 Laptop GPU", "NVIDIA", "pci:10de:28a1", "31.0.15.5222", "32.0.15.6094",
                  "Microsoft Update Catalog", full, "display"),
           update("Realtek Audio", "Realtek", "pci:8086:51c8", "6.0.9549.1", "6.0.9733.1",
                  "Microsoft Update Catalog", partial, "media")]
    cpu = "12th Gen Intel(R) Core(TM) i5-12500H"
    cpus = [Device(cpu, vendor="Intel", kind="processor", inf="cpu.inf", driver_version="10.0.26100.9818",
                   address=f"ACPI\\GENUINEINTEL\\_{n}", hardware_ids=[f"raw:acpi\\genuineintel\\_{n}", "raw:acpi\\genuineintel"])
            for n in range(16)]
    others = [Device("Samsung SSD 980 PRO 1TB", kind="diskdrive", inf="disk.inf", driver_version="10.0.26100.1",
                     hardware_ids=["raw:scsi\\disk"], address="disk"),
              Device("HID-compliant mouse", kind="mouse", inf="msmouse.inf", driver_version="10.0.26100.1",
                     hardware_ids=["raw:hid\\mouse"], address="mouse")]
    devices = dedupe_devices([u.device for u in ups] + cpus + others)
    return devices, ups


def render(out: Path, accent: str, font: str) -> list[Path]:
    import gui
    from core import engine
    from ui import settings, theme

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["XDG_CONFIG_HOME"] = os.environ["APPDATA"] = tmp       # never touch the real ui.json
        settings.save(accent=accent, font=font)
        app, win = gui.create(engine.Context(manifest={"packages": []}), Path(tmp))
        devices, ups = sample()
        win.model.load(devices, ups)
        win.toggle_full()
        win.on_update_result(True)                                       # as if GitHub had a newer release
        win.say(win.idle_summary())
        win.resize(1000, 560)
        win.show()
        for _ in range(10):
            app.processEvents()
        out.mkdir(parents=True, exist_ok=True)
        main, dialog = out / "ui-main.png", out / "ui-settings.png"
        win.grab().save(str(main))
        win.open_settings()
        for _ in range(10):
            app.processEvents()
        win.settings_dialog.grab().save(str(dialog))
        win.settings_dialog.close()
        win.close()
        print(f"{main}\n{dialog}  ({theme.current().accent}, {theme.current().font_id})")
        return [main, dialog]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "img")
    ap.add_argument("--accent", default="green")
    ap.add_argument("--font", default="vt323")
    args = ap.parse_args(argv)
    render(args.out, args.accent, args.font)
    return 0


if __name__ == "__main__":
    sys.exit(main())
