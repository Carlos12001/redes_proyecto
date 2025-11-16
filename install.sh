#!/usr/bin/env bash
set -euo pipefail

# Simple installer for python3, tkinter and OpenConnect on Ubuntu/Debian
# Usage: sudo ./install.sh   (or run as a normal user; sudo will be used where needed)

PKGS=(
  python3
  python3-tk
  openconnect
  network-manager-openconnect
  network-manager-openconnect-gnome
)

log() { printf '%s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Ensure apt-get is available
if ! command -v apt-get >/dev/null 2>&1; then
  err "apt-get not found. This script targets Ubuntu/Debian systems."
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    err "This script requires root privileges. Install sudo or run as root."
  fi
fi

log "Updating package lists..."
$SUDO DEBIAN_FRONTEND=noninteractive apt-get update -y

log "Installing packages: ${PKGS[*]}..."
$SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y "${PKGS[@]}"

log "Verifying python3..."
if command -v python3 >/dev/null 2>&1; then
  log "python3 version: $(python3 --version 2>&1)"
else
  err "python3 not found after installation."
fi

log "Cleaning up..."
$SUDO apt-get autoremove -y
$SUDO apt-get clean

log "Installation complete."

cat <<EOF

Next steps / notes:
- python3 and tkinter (python3-tk) are now available for Python 3 GUI scripts.
  Test with: python3 -c "import tkinter; print(tkinter.Tk())"
- openconnect is installed. To connect from the command line:
  sudo openconnect --protocol=anyconnect vpn.example.com
  (replace vpn.example.com with your VPN server; check your org's docs for username/auth)
- You can also add an OpenConnect VPN via GNOME Settings -> Network -> VPN (requires network-manager-openconnect-gnome).

EOF