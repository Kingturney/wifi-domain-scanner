#!/data/data/com.termux/files/usr/bin/bash
# Installs the domain scanner into Termux

set -e

REPO_URL="https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/scan_domains.sh"
BIN_DIR="$PREFIX/bin"
SCRIPT_NAME="scan-domains"

echo "[*] Installing dependencies..."
pkg update -y && pkg install -y dnsutils nmap net-tools curl git

echo "[*] Downloading scanner script..."
curl -fsSL "$REPO_URL" -o "$BIN_DIR/$SCRIPT_NAME"
chmod +x "$BIN_DIR/$SCRIPT_NAME"

echo "[+] Installed. Run with: scan-domains"
