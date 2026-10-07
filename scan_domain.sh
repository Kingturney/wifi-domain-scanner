#!/data/data/com.termux/files/usr/bin/bash
# Network Domain Scanner for Termux
# Scans connected network and extracts main domains

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

OUTPUT_DIR="$HOME/domain_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

log() { echo -e "${BLUE}[*]${NC} $1"; }
ok()  { echo -e "${GREEN}[+]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[-]${NC} $1"; }

banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔══════════════════════════════════════════╗
║   Network Domain Scanner - Termux        ║
║   Scans network & extracts main domains  ║
╚══════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Check dependencies
check_deps() {
    log "Checking dependencies..."
    local missing=()
    for cmd in nmap dig host arp curl; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        warn "Missing: ${missing[*]}"
        warn "Run: pkg install dnsutils nmap net-tools curl"
        exit 1
    fi
    ok "All dependencies found"
}

# Get local network info
get_network_info() {
    log "Detecting network info..."
    LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    GATEWAY=$(ip route | awk '/default/ {print $3; exit}')
    
    if [ -z "$LOCAL_IP" ]; then
        err "Could not detect local IP. Is WiFi connected?"
        exit 1
    fi
    
    SUBNET=$(echo "$LOCAL_IP" | cut -d. -f1-3).0/24
    ok "Local IP : $LOCAL_IP"
    ok "Gateway  : $GATEWAY"
    ok "Subnet   : $SUBNET"
}

# Scan for live hosts
scan_hosts() {
    log "Scanning subnet for live hosts (this may take a minute)..."
    nmap -sn "$SUBNET" -oG "$OUTPUT_DIR/hosts.gnmap" >/dev/null 2>&1
    
    grep "Up" "$OUTPUT_DIR/hosts.gnmap" | awk '{print $2}' > "$OUTPUT_DIR/live_hosts.txt"
    HOST_COUNT=$(wc -l < "$OUTPUT_DIR/live_hosts.txt")
    ok "Found $HOST_COUNT live hosts"
}

# Reverse DNS lookup
reverse_dns() {
    log "Performing reverse DNS lookups..."
    : > "$OUTPUT_DIR/reverse_dns.txt"
    while read -r ip; do
        hostname=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//')
        if [ -n "$hostname" ]; then
            echo "$ip -> $hostname" | tee -a "$OUTPUT_DIR/reverse_dns.txt"
        fi
    done < "$OUTPUT_DIR/live_hosts.txt"
    ok "Reverse DNS results saved"
}

# Extract main (root) domain from a hostname
extract_main_domain() {
    local host="$1"
    # Strip trailing dot
    host="${host%.}"
    # Handle known multi-part TLDs (co.uk, com.br, etc.)
    echo "$host" | awk -F. '{
        n = NF
        if (n < 2) { print $0; next }
        # common second-level ccTLDs
        split("co|com|net|org|gov|edu|ac", parts, "|")
        for (i in parts) {
            if ($(n-1) == parts[i] && n >= 3) {
                print $(n-2)"."$(n-1)"."$n
                next
            }
        }
        print $(n-1)"."$n
    }'
}

# Collect domains from various sources
collect_domains() {
    log "Extracting domains..."
    : > "$OUTPUT_DIR/all_domains_raw.txt"
    : > "$OUTPUT_DIR/main_domains.txt"
    
    # 1. From reverse DNS
    if [ -f "$OUTPUT_DIR/reverse_dns.txt" ]; then
        awk '{print $3}' "$OUTPUT_DIR/reverse_dns.txt" >> "$OUTPUT_DIR/all_domains_raw.txt"
    fi
    
    # 2. From DNS server / gateway PTR
    if [ -n "$GATEWAY" ]; then
        gw_ptr=$(dig +short -x "$GATEWAY" 2>/dev/null | sed 's/\.$//')
        [ -n "$gw_ptr" ] && echo "$gw_ptr" >> "$OUTPUT_DIR/all_domains_raw.txt"
    fi
    
    # 3. Common domain endings in local network
    for suffix in ".local" ".lan" ".home" ".internal"; do
        echo "${HOSTNAME:-termux}$suffix" >> "$OUTPUT_DIR/all_domains_raw.txt"
    done
    
    # Extract main domains
    sort -u "$OUTPUT_DIR/all_domains_raw.txt" | while read -r d; do
        [ -z "$d" ] && continue
        extract_main_domain "$d"
    done | sort -u > "$OUTPUT_DIR/main_domains.txt"
    
    ok "Main domains extracted:"
    echo "----------------------------------------"
    cat "$OUTPUT_DIR/main_domains.txt"
    echo "----------------------------------------"
}

# Passive DNS sniffing (optional, requires root or tcpdump)
sniff_dns() {
    if ! command -v tcpdump &>/dev/null; then
        warn "tcpdump not installed, skipping DNS sniffing"
        return
    fi
    if [ "$(id -u)" -ne 0 ]; then
        warn "DNS sniffing requires root. Run 'sudo tcpdump' manually if needed."
        return
    fi
    
    log "Sniffing DNS for 30 seconds (Ctrl+C to stop early)..."
    timeout 30 tcpdump -i any -l -n port 53 2>/dev/null \
        | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
        | sort -u > "$OUTPUT_DIR/sniffed_domains.txt" || true
    
    if [ -s "$OUTPUT_DIR/sniffed_domains.txt" ]; then
        log "Sniffed domains:"
        cat "$OUTPUT_DIR/sniffed_domains.txt"
        # Merge into main
        while read -r d; do extract_main_domain "$d"; done \
            < "$OUTPUT_DIR/sniffed_domains.txt" | sort -u \
            >> "$OUTPUT_DIR/main_domains.txt"
        sort -u "$OUTPUT_DIR/main_domains.txt" -o "$OUTPUT_DIR/main_domains.txt"
    fi
}

# Final report
report() {
    echo
    ok "Scan complete!"
    echo -e "${CYAN}Results directory:${NC} $OUTPUT_DIR"
    echo
    echo -e "${CYAN}Final main domains list:${NC}"
    cat "$OUTPUT_DIR/main_domains.txt"
    echo
    echo -e "${CYAN}Files generated:${NC}"
    ls -la "$OUTPUT_DIR"
}

main() {
    banner
    check_deps
    get_network_info
    scan_hosts
    reverse_dns
    collect_domains
    sniff_dns
    report
}

main "$@"
