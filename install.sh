#!/data/data/com.termux/files/usr/bin/bash
set -e

REPO_RAW="https://raw.githubusercontent.com/Kingturney/domain-recon/main"
BIN="$PREFIX/bin"
CMD="domain-recon"

echo "[*] Installing dependencies..."
pkg update -y
pkg install -y dnsutils nmap net-tools curl openssl iputils

echo "[*] Downloading tool..."
curl -fsSL "$REPO_RAW/domain-recon.sh" -o "$BIN/$CMD"
chmod +x "$BIN/$CMD"

echo "[+] Installed. Run: $CMD <domain>"
