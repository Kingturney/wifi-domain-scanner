#!/data/data/com.termux/files/usr/bin/bash
# domain-recon v2.0 — interactive menu
# Auto-installs dependencies on first run.

set -u

# ============================================================
# COLORS
# ============================================================
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; C='\033[0;36m'; M='\033[0;35m'
W='\033[1;37m'; N='\033[0m'

# ============================================================
# AUTO-INSTALL DEPENDENCIES
# ============================================================
ensure_deps() {
    local need=()
    command -v dig    >/dev/null 2>&1 || need+=("dnsutils")
    command -v nmap   >/dev/null 2>&1 || need+=("nmap")
    command -v curl   >/dev/null 2>&1 || need+=("curl")
    command -v openssl>/dev/null 2>&1 || need+=("openssl")
    command -v nc     >/dev/null 2>&1 || need+=("netcat-openbsd")
    command -v ping   >/dev/null 2>&1 || need+=("inetutils")

    if [ ${#need[@]} -gt 0 ]; then
        echo -e "${Y}[!] First run — installing missing tools: ${need[*]}${N}"
        echo -e "${B}[*] This may take 1-2 minutes...${N}"
        pkg update -y >/dev/null 2>&1
        pkg install -y "${need[@]}" >/dev/null 2>&1
        hash -r
        echo -e "${G}[+] Dependencies installed.${N}\n"
    fi
}

# ============================================================
# HELPERS
# ============================================================
OUT=""
new_out() {
    OUT="$HOME/recon_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUT"
}

log()  { echo -e "${B}[*]${N} $*"; }
ok()   { echo -e "${G}[+]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
err()  { echo -e "${R}[-]${N} $*"; }
hdr()  { echo -e "\n${C}══ $* ══${N}"; }
ask()  { printf "${W}$*${N} "; }

clean_domain() {
    local d="$1"
    d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"
    echo "$d"
}

main_domain() {
    local h="${1%.}"
    echo "$h" | awk -F. '{
        n=NF
        if(n<2){print $0; next}
        split("co|com|net|org|gov|edu|ac",p,"|")
        for(i in p) if($(n-1)==p[i] && n>=3){print $(n-2)"."$(n-1)"."$n; next}
        print $(n-1)"."$n
    }'
}

get_domain() {
    ask "Enter domain (e.g. example.com):"
    read -r D
    D=$(clean_domain "$D")
    [ -z "$D" ] && { err "No domain given."; return 1; }
    return 0
}

# ============================================================
# 1) HOST SCAN
# ============================================================
do_host() {
    hdr "Host scan"
    get_domain || return

    new_out
    log "Resolving $D ..."
    ip=$(dig +short A "$D" 2>/dev/null | head -1)

    if [ -z "$ip" ]; then
        err "Domain does not resolve."
        return
    fi
    ok "Resolved: $ip"

    log "Pinging $D ..."
    if ping -c1 -W2 "$D" >/dev/null 2>&1; then
        ok "Host is UP (ping responded)"
    else
        warn "Ping blocked (host may still be up behind a firewall)"
    fi

    log "Checking HTTP/HTTPS ..."
    for scheme in https http; do
        code=$(curl -sk -o /dev/null -w "%{http_code}" -m 6 "$scheme://$D" 2>/dev/null)
        [ -n "$code" ] && [ "$code" != "000" ] && \
            ok "$scheme  status: $code"
    done

    log "DNS records:"
    for rec in A AAAA MX NS TXT CNAME; do
        r=$(dig +short "$rec" "$D" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
        [ -n "$r" ] && printf "    %-6s %s\n" "$rec" "$r"
    done

    echo "$D $ip" > "$OUT/host.txt"
    ok "Saved: $OUT/host.txt"
}

# ============================================================
# 2) PORT SCAN
# ============================================================
do_ports() {
    hdr "Port scan"
    get_domain || return

    new_out
    log "Top 100 TCP ports on $D ..."
    warn "This takes 30–90 seconds."

    nmap -Pn -T4 --top-ports 100 --open "$D" -oG "$OUT/ports.gnmap" >/dev/null 2>&1 || true

    ports=$(grep "Ports:" "$OUT/ports.gnmap" 2>/dev/null \
        | sed 's/.*Ports: //; s|/|:|g' | tr ',' '\n' \
        | awk -F: '/open/ {printf "  %-8s %s\n", $1, $3}')

    if [ -n "$ports" ]; then
        echo
        ok "Open ports:"
        echo "$ports"
        echo "$ports" > "$OUT/ports.txt"
    else
        warn "No open ports found in top 100."
    fi
    ok "Saved: $OUT/ports.txt"
}

# ============================================================
# 3) SUBDOMAIN ENUM
# ============================================================
do_subs() {
    hdr "Subdomain enumeration"
    get_domain || return

    new_out
    root=$(main_domain "$D")
    ok "Root domain: $root"

    log "Querying crt.sh (crtificate transparency) ..."
    raw=$(curl -s -m 20 "https://crt.sh/?q=%25.$root&output=json" 2>/dev/null)

    if [ -z "$raw" ] || [ "$raw" = "[]" ]; then
        warn "crt.sh returned nothing."
        return
    fi

    # Extract names via simple parsing (no jq needed)
    echo "$raw" \
        | tr ',' '\n' \
        | grep -oE '"name_value":"[^"]+"' \
        | sed 's/"name_value":"//; s/"$//' \
        | tr '\n' '\n' \
        | sed 's/\\n/\n/g' \
        | sort -u \
        | grep -v '^\*' \
        > "$OUT/subs_raw.txt"

    log "Testing which subdomains resolve ..."
    : > "$OUT/subs_live.txt"
    while read -r sub; do
        [ -z "$sub" ] && continue
        ip=$(dig +short A "$sub" 2>/dev/null | head -1)
        if [ -n "$ip" ]; then
            printf "  %-45s %s\n" "$sub" "$ip" | tee -a "$OUT/subs_live.txt"
        fi
    done < "$OUT/subs_raw.txt"

    n=$(wc -l < "$OUT/subs_live.txt")
    ok "Live subdomains: $n"
    ok "Saved: $OUT/subs_live.txt"
}

# ============================================================
# 4) SERVER / STACK FINGERPRINT
# ============================================================
do_server() {
    hdr "Server fingerprint"
    get_domain || return

    new_out
    log "Fetching headers from $D ..."

    h=$(curl -skIL -m 8 -A "Mozilla/5.0 (Termux; recon)" "https://$D" 2>/dev/null)
    [ -z "$h" ] && h=$(curl -skIL -m 8 -A "Mozilla/5.0 (Termux; recon)" "http://$D" 2>/dev/null)
    [ -z "$h" ] && { err "No HTTP response."; return; }

    body=$(curl -skL -m 8 -A "Mozilla/5.0 (Termux; recon)" "https://$D" 2>/dev/null | head -c 30000)
    [ -z "$body" ] && body=$(curl -skL -m 8 -A "Mozilla/5.0 (Termux; recon)" "http://$D" 2>/dev/null | head -c 30000)

    server=$(echo "$h" | awk -F': ' 'tolower($1)=="server"{print $2; exit}' | tr -d '\r')
    powered=$(echo "$h" | awk -F': ' 'tolower($1)=="x-powered-by"{print $2; exit}' | tr -d '\r')

    # Server software
    sw="unknown"
    case "$server" in
        *nginx*)         sw="nginx" ;;
        *openresty*)     sw="openresty" ;;
        *Apache*)        sw="apache" ;;
        *LiteSpeed*)     sw="litespeed" ;;
        *Caddy*)         sw="caddy" ;;
        *Microsoft-IIS*) sw="iis" ;;
        *cloudflare*)    sw="cloudflare-edge" ;;
        *AmazonS3*)      sw="aws-s3" ;;
        *gunicorn*)      sw="gunicorn" ;;
        *Werkzeug*)      sw="werkzeug" ;;
        *Jetty*)         sw="jetty" ;;
        *Tomcat*)        sw="tomcat" ;;
        *Envoy*)         sw="envoy" ;;
        *Traefik*)       sw="traefik" ;;
        *HAProxy*)       sw="haproxy" ;;
        *) 
            echo "$body" | grep -qi "nginx"     && sw="nginx"
            echo "$body" | grep -qi "apache"    && sw="apache"
            echo "$body" | grep -qi "litespeed" && sw="litespeed"
            ;;
    esac

    # CDN
    cdn=""
    echo "$h" | grep -qi "cf-ray"      && cdn+="cloudflare "
    echo "$h" | grep -qi "x-amz-cf-id" && cdn+="cloudfront "
    echo "$h" | grep -qi "x-akamai"    && cdn+="akamai "
    echo "$h" | grep -qi "x-fastly"    && cdn+="fastly "
    echo "$h" | grep -qi "x-served-by" && cdn+="fastly "
    echo "$h" | grep -qi "x-varnish"   && cdn+="varnish "
    echo "$h" | grep -qi "x-sucuri"    && cdn+="sucuri "

    # Stack
    stack=""
    [ -n "$powered" ] && stack+="$powered "
    echo "$h" | grep -qi "wp-content"  && stack+="wordpress "
    echo "$h" | grep -qi "drupal"      && stack+="drupal "
    echo "$h" | grep -qi "joomla"      && stack+="joomla "
    echo "$h" | grep -qi "x-shopify"   && stack+="shopify "
    echo "$h" | grep -qi "x-vercel"    && stack+="vercel "
    echo "$h" | grep -qi "x-netlify"   && stack+="netlify "
    echo "$h" | grep -qi "x-amz"       && stack+="aws "
    echo "$h" | grep -qi "x-goog"      && stack+="gcp "

    echo
    ok "Server software : $sw"
    [ -n "$server" ] && ok "Server header   : $server"
    [ -n "$cdn" ]    && ok "CDN detected    : ${cdn% }"
    [ -n "$stack" ]  && ok "Stack detected  : ${stack% }"

    {
        echo "domain=$D"
        echo "server_software=$sw"
        echo "server_header=$server"
        echo "cdn=${cdn% }"
        echo "stack=${stack% }"
    } > "$OUT/server.txt"

    ok "Saved: $OUT/server.txt"
}

# ============================================================
# BANNER + MENU
# ============================================================
banner() {
    clear
    cat << "EOF"
   ╔══════════════════════════════════════════╗
   ║        DOMAIN RECON  ·  v2.0             ║
   ║        Termux · interactive              ║
   ╚══════════════════════════════════════════╝

EOF
}

menu() {
    echo -e "  ${W}Choose an option:${N}"
    echo
    echo -e "   ${C}1${N})  Host scan       (resolve, ping, DNS)"
    echo -e "   ${C}2${N})  Port scan       (top 100 TCP)"
    echo -e "   ${C}3${N})  Subdomains      (from crt.sh)"
    echo -e "   ${C}4${N})  Server / stack  (nginx? apache? cdn?)"
    echo -e "   ${C}5${N})  Full scan       (all of the above)"
    echo -e "   ${C}0${N})  Exit"
    echo
    ask "  >"
    read -r choice
    echo
}

main() {
    ensure_deps
    while true; do
        banner
        menu
        case "$choice" in
            1) do_host ;;
            2) do_ports ;;
            3) do_subs ;;
            4) do_server ;;
            5) do_host; do_ports; do_subs; do_server ;;
            0) echo -e "${G}Bye.${N}"; exit 0 ;;
            *) err "Invalid choice." ;;
        esac
        echo
        ask "Press Enter to return to menu..."
        read -r
    done
}

main "$@"
