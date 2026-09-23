#!/bin/sh
# stow's one-line installer: fetch the latest stow-cli release through its
# cargo-dist installer, then wire cargo so every build on this machine
# runs through stow.
set -eu

RELEASE_URL="https://github.com/water-rs/stow/releases/latest/download"
INSTALLER_URL="${RELEASE_URL}/stow-cli-installer.sh"
INSTALLER="${TMPDIR:-/tmp}/stow-cli-installer.$$.sh"
trap 'rm -f "$INSTALLER"' EXIT INT TERM

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$INSTALLER_URL" -o "$INSTALLER"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$INSTALLER" "$INSTALLER_URL"
else
    echo "stow install: need curl or wget to download ${INSTALLER_URL}" >&2
    exit 1
fi

sh "$INSTALLER"

BIN_DIR="${CARGO_HOME:-${HOME}/.cargo}/bin"
if [ ! -x "${BIN_DIR}/stow" ]; then
    echo "stow install: the installer did not leave ${BIN_DIR}/stow" >&2
    exit 1
fi

# Write stow's wrapper wiring into the global cargo config — every cargo
# invocation on this machine is accelerated from here on. CARGO_HOME is
# honoured through the environment: it resolves both BIN_DIR above and the
# config path inside `stow setup`.
"${BIN_DIR}/stow" setup

echo "stow is installed — plain 'cargo build' now runs through stow"
