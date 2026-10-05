#!/usr/bin/env sh
set -eu
USER_INSTALL_ROOT=${XDG_DATA_HOME:-"$HOME/.local/share"}/lanwatch-app
USER_BIN_DIR=${XDG_BIN_HOME:-"$HOME/.local/bin"}
rm -rf "$USER_INSTALL_ROOT"
rm -f "$USER_BIN_DIR/lanwatch"
printf '%s\n' 'LANwatch program files removed. .lanwatch user data was left untouched.'
