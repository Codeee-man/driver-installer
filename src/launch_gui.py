"""Entry point of the windowed Windows build (driver-installer-gui.exe): opens the GUI.
Extra arguments are passed on, e.g. `driver-installer-gui.exe --theme clean`."""
import sys

from cli import main

if __name__ == "__main__":
    sys.exit(main(["gui", *sys.argv[1:]]))
