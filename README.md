# wifi-domain-scanner

Scan the WiFi/LAN network you're connected to and extract **main (root) domains** — runs entirely in Termux.

## 🚀 Install

```bash
pkg install git -y
git clone https://github.com/Kingturney/wifi-domain-scanner.git
cd wifi-domain-scanner
bash install.sh
```

## ▶️ Usage

```bash
wifi-domain-scanner
```

Or without installing:

```bash
bash scan_domains.sh
```

## 🔍 What it does

1. Detects local IP, gateway, subnet
2. Ping-sweeps the subnet (`nmap -sn`)
3. Reverse DNS lookups on live hosts (`dig -x`)
4. Extracts **main domain** — e.g. `mail.google.com` → `google.com`
5. Saves everything to `~/domain_scan_<timestamp>/`

## 📂 Output files

| File | Description |
|---|---|
| `live_hosts.txt` | Live IPs on your network |
| `reverse_dns.txt` | PTR records |
| `main_domains.txt` | ⭐ Main domains found |
| `hosts.gnmap` | Raw nmap output |

## ⚙️ Requirements

- Termux (**F-Droid** version — not Play Store)
- WiFi/LAN connection
- Packages: `dnsutils nmap net-tools curl`

## ⚠️ Notes

- Most home routers don't return PTR for LAN IPs, so results depend on your network.
- Only scan networks you own or have permission to test.

## 📜 License

MIT
