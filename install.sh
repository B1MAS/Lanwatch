#!/usr/bin/env sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
USER_INSTALL_ROOT=${XDG_DATA_HOME:-"$HOME/.local/share"}/lanwatch-app
USER_INSTALL_STAGE=${USER_INSTALL_ROOT}.new
USER_BIN_DIR=${XDG_BIN_HOME:-"$HOME/.local/bin"}

if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3.11+ was not found. Install Python 3 and retry.' >&2
    exit 1
fi
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
    printf '%s\n' 'Python 3.11+ is required.' >&2
    exit 1
}

if [ -e "$USER_INSTALL_STAGE" ]; then
    rm -rf -- "$USER_INSTALL_STAGE"
fi
mkdir -p "$USER_INSTALL_STAGE/app" "$USER_BIN_DIR"
python3 -m venv "$USER_INSTALL_STAGE/venv"
cp -R "$PROJECT_ROOT/lanwatch" "$USER_INSTALL_STAGE/app/lanwatch"
PYTHONPATH="$USER_INSTALL_STAGE/app" "$USER_INSTALL_STAGE/venv/bin/python" -c \
    "import lanwatch; print('LANwatch ' + lanwatch.__version__)"
if [ -e "$USER_INSTALL_ROOT" ]; then
    rm -rf -- "$USER_INSTALL_ROOT"
fi
mv -- "$USER_INSTALL_STAGE" "$USER_INSTALL_ROOT"
cat > "$USER_BIN_DIR/lanwatch" <<EOF
#!/usr/bin/env sh
PYTHONPATH="$USER_INSTALL_ROOT/app" exec "$USER_INSTALL_ROOT/venv/bin/python" -m lanwatch "\$@"
EOF
chmod 700 "$USER_BIN_DIR/lanwatch"
printf '%s\n' 'LANwatch installed.' "Run: $USER_BIN_DIR/lanwatch enroll" 'The installer does not use pip, the Internet, root, or change router settings.'
