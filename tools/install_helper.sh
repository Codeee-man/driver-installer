#!/bin/sh
# Install SafeDriver's elevated helper and CLI into root-owned system paths.
#
#   sudo tools/install_helper.sh               install / upgrade
#   sudo tools/install_helper.sh --with-timer  also install the weekly check (systemd user units)
#   sudo tools/install_helper.sh --uninstall   remove everything this script installed
#
# Why: the helper is the only part that runs as root. Run from a checkout, it
# lives in files your user account can edit, so anything running as you could
# change what gets elevated. Installed here, only root can modify it:
#
#   /usr/local/lib/driver-installer/           application code (root:root, 0644)
#   /usr/local/bin/driver-installer-helper     elevated helper; accepts only --apply-plan <plan>
#   /usr/local/bin/driver-installer            unprivileged CLI launcher
#   /usr/share/polkit-1/actions/org.safedriver.driver-installer.policy
#
# The installed copy carries its own core/trust.py. Pin your manifest key
# (tools/pin_key.sh) BEFORE installing, and re-run this script after any change.
#
# DESTDIR=/some/root stages the files for packaging instead of installing live.
set -eu

DESTDIR=${DESTDIR:-}
PYTHON=${PYTHON:-/usr/bin/python3}
LIB=/usr/local/lib/driver-installer
BIN=/usr/local/bin
POLKIT=/usr/share/polkit-1/actions
UNITS=/usr/lib/systemd/user
SRC=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

die() { echo "install_helper: $*" >&2; exit 1; }

MODE=install
TIMER=no
for arg in "$@"; do
    case $arg in
        --uninstall) MODE=uninstall ;;
        --with-timer) TIMER=yes ;;
        -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $arg" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root: sudo $0 $*"

if [ "$MODE" = uninstall ]; then
    rm -rf -- "$DESTDIR$LIB"
    rm -f -- "$DESTDIR$BIN/driver-installer-helper" "$DESTDIR$BIN/driver-installer" \
             "$DESTDIR$POLKIT/org.safedriver.driver-installer.policy" \
             "$DESTDIR$UNITS/driver-installer.service" "$DESTDIR$UNITS/driver-installer.timer"
    echo "Removed. Audit log and state remain in /var/lib/safedriver; delete them by hand if wanted."
    exit 0
fi

# The interpreter runs as root, so it must be one that only root can replace.
[ -x "$PYTHON" ] || die "$PYTHON not found (set PYTHON=/path/to/system/python3)"
REAL_PY=$(readlink -f -- "$PYTHON")
[ "$(stat -c %u -- "$REAL_PY")" -eq 0 ] || die "$REAL_PY is not owned by root; use the system Python, not a venv"
case $(stat -c %A -- "$REAL_PY") in ?????w*|????????w*) die "$REAL_PY is writable by non-root users" ;; esac
"$PYTHON" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "Python 3.10 or newer is required"
"$PYTHON" -I -c 'import cryptography' 2>/dev/null \
    || die "the system Python lacks 'cryptography' (apt install python3-cryptography / dnf install python3-cryptography)"

[ -f "$SRC/src/helper_main.py" ] && [ -f "$SRC/src/core/trust.py" ] || die "run this from a driver-installer checkout"
if ! "$PYTHON" -I -c "import sys; sys.path.insert(0, sys.argv[1]); from core import trust; sys.exit(0 if trust.PINNED_MANIFEST_KEYS else 1)" "$SRC/src"; then
    echo "warning: no manifest signing key is pinned in src/core/trust.py." >&2
    echo "         The installed helper will refuse every manifest. Run tools/pin_key.sh, then re-run this script." >&2
fi

umask 022
rm -rf -- "$DESTDIR$LIB"
install -d -o root -g root -m 0755 "$DESTDIR$LIB" "$DESTDIR$BIN"
install -o root -g root -m 0644 "$SRC"/src/*.py "$DESTDIR$LIB/"
for pkg in core core/security core/discovery; do
    install -d -o root -g root -m 0755 "$DESTDIR$LIB/$pkg"
    install -o root -g root -m 0644 "$SRC/src/$pkg"/*.py "$DESTDIR$LIB/$pkg/"
done

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<EOF
#!/bin/sh
# SafeDriver elevated helper. Installed by tools/install_helper.sh; do not edit.
# helper_main.py accepts exactly: --apply-plan <plan.json>
exec $REAL_PY -I $LIB/helper_main.py "\$@"
EOF
install -o root -g root -m 0755 "$TMP" "$DESTDIR$BIN/driver-installer-helper"

cat > "$TMP" <<EOF
#!/bin/sh
# SafeDriver CLI (runs unprivileged). Installed by tools/install_helper.sh.
exec $REAL_PY $LIB/cli.py "\$@"
EOF
install -o root -g root -m 0755 "$TMP" "$DESTDIR$BIN/driver-installer"

if [ -d "$DESTDIR$POLKIT" ] || [ -n "$DESTDIR" ]; then
    install -d -o root -g root -m 0755 "$DESTDIR$POLKIT"
    install -o root -g root -m 0644 "$SRC/contrib/polkit/org.safedriver.driver-installer.policy" "$DESTDIR$POLKIT/"
else
    echo "note: $POLKIT not found; pkexec will use its generic prompt (or sudo is used instead)." >&2
fi

if [ "$TIMER" = yes ]; then
    install -d -o root -g root -m 0755 "$DESTDIR$UNITS"
    install -o root -g root -m 0644 "$SRC/contrib/systemd/driver-installer.service" \
                                    "$SRC/contrib/systemd/driver-installer.timer" "$DESTDIR$UNITS/"
fi

echo "Installed:"
echo "  $BIN/driver-installer-helper   (elevated helper)"
echo "  $BIN/driver-installer          (CLI)"
[ "$TIMER" = yes ] && echo "Enable the weekly check for your user (not root):  systemctl --user enable --now driver-installer.timer"
echo "Put the signed manifest at /etc/driver-installer/manifest.json (+ .sig), or pass --manifest."
exit 0
