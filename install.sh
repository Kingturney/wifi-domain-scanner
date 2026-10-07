#!/data/data/com.termux/files/usr/bin/bash
set -e

REPO_RAW="https://raw.githubusercontent.com/Kingturney/wifi-domain-scanner/main"
BIN="$PREFIX/bin"
CMD="recon"

echo "[*] Installing dependencies (first time only)..."
pkg update -y
pkg install -y git dnsutils nmap curl openssl netcat-openbsd inetutils

echo "[*] Downloading scan.sh..."
curl -fsSL "$REPO_RAW/scan.sh" -o "$BIN/$CMD"
chmod +x "$BIN/$CMD"

echo "[+] Done. Run: recon"
