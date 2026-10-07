#!/data/data/com.termux/files/usr/bin/bash
# domain-recon v1.0 — general domain scanner for Termux
# DNS · liveness · port scan · server fingerprint

set -u
VERSION="1.0"

# ---------- Colors ----------
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; C='\033[0;36m'; M='\033[0;35m'; N='\033[0m'

OUT="$HOME/domain_recon_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

log()  { echo -e "${B}[*]${N} $*"; }
ok()   { echo -e "${G}[+]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
err()  { echo -e "${R}[-]${N} $*"; }
hdr()  { echo -e "\n${C}══ $* ══${N}"; }

# ---------- Banner ----------
banner() {
cat << "EOF"

  ┌┬┐┌─┐┌┬┐┌─┐┬┌┐┌   ┬─┐┌─┐┌─┐┌─┐┌┐┌
   │││ ││││├─┤││││───├┬┘├┤ │  │ ││││
  ─┴┘└─┘┴ ┴┴ ┴┴┘└┘   ┴└─└─┘└─┘└─┘┘└┘
                          v1.0 · Termux

  DNS · liveness · ports · server fingerprint

EOF
}

# ---------- Dependencies ----------
deps() {
    hdr "Dependencies"
    local miss=()
    for c in dig host curl nmap ping openssl; do
        command -v "$c" >/dev/null 2>&1 || miss+=("$c")
    done
    if [ ${#miss[@]} -gt 0 ]; then
        warn "Missing: ${miss[*]}"
        log "Installing..."
        pkg install -y dnsutils nmap net-tools curl openssl iputils 2>/dev/null || {
            err "Run manually: pkg install dnsutils nmap net-tools curl openssl iputils"
            exit 1
        }
    fi
    ok "All tools ready"
}

# ---------- Input targets ----------
TARGETS=()
read_targets() {
    hdr "Targets"

    if [ "$#" -gt 0 ]; then
        TARGETS=("$@")
    else
        echo "Enter domains (space-separated), or '-' to read from file:"
        printf "  > "
        read -r line
        if [ "$line" = "-" ]; then
            printf "  File path: "
            read -r f
            [ ! -f "$f" ] && { err "File not found: $f"; exit 1; }
            mapfile -t TARGETS < "$f"
        else
            read -ra TARGETS <<< "$line"
        fi
    fi

    # Clean, dedupe, strip http(s)://
    local clean=()
    for t in "${TARGETS[@]}"; do
        t="${t#http://}"; t="${t#https://}"; t="${t%%/*}"
        [ -n "$t" ] && clean+=("$t")
    done
    printf '%s\n' "${clean[@]}" | sort -u > "$OUT/targets.txt"
    mapfile -t TARGETS < "$OUT/targets.txt"

    ok "Loaded ${#TARGETS[@]} target(s):"
    sed 's/^/    /' "$OUT/targets.txt"
}

# ---------- DNS records ----------
dns_lookup() {
    hdr "DNS records"
    : > "$OUT/dns.txt"

    for d in "${TARGETS[@]}"; do
        echo -e "\n${M}$d${N}"
        echo "### $d" >> "$OUT/dns.txt"

        for rec in A AAAA MX NS TXT CNAME; do
            res=$(dig +short "$rec" "$d" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
            if [ -n "$res" ]; then
                printf "  %-6s %s\n" "$rec" "$res"
                echo "  $rec: $res" >> "$OUT/dns.txt"
            fi
        done
    done
}

# ---------- Liveness ----------
check_live() {
    hdr "Liveness"
    : > "$OUT/live.txt"

    for d in "${TARGETS[@]}"; do
        ip=$(dig +short A "$d" 2>/dev/null | head -1)
        if [ -z "$ip" ]; then
            printf "  %-30s ${R}NO-DNS${N}\n" "$d"
            echo "$d NO-DNS" >> "$OUT/live.txt"
            continue
        fi

        status=""
        ping -c1 -W2 "$d" >/dev/null 2>&1 && status="ping" || status="dns-only"

        http=$(curl -sk -o /dev/null -w "%{http_code}" -m 6 "https://$d" 2>/dev/null)
        [ -z "$http" ] || [ "$http" = "000" ] && \
            http=$(curl -sk -o /dev/null -w "%{http_code}" -m 6 "http://$d" 2>/dev/null)

        if [ -n "$http" ] && [ "$http" != "000" ]; then
            printf "  %-30s %-15s %bhttp=%s%s\n" "$d" "$ip" "${G}" "$http" "${N}"
            echo "$d $ip http=$http $status" >> "$OUT/live.txt"
        else
            printf "  %-30s %-15s %b%s%s\n" "$d" "$ip" "${Y}" "$status" "${N}"
            echo "$d $ip $status" >> "$OUT/live.txt"
        fi
    done
}

# ---------- Port scan ----------
PORT_TOPN=100
scan_ports() {
    hdr "Port scan (top $PORT_TOPN TCP)"
    : > "$OUT/ports.txt"

    for d in "${TARGETS[@]}"; do
        grep -q "^$d " "$OUT/live.txt" || continue
        grep -q "NO-DNS" "$OUT/live.txt" && grep -q "^$d NO-DNS" "$OUT/live.txt" && continue

        log "Scanning $d..."
        nmap -Pn -T4 --top-ports "$PORT_TOPN" --open "$d" \
            -oG "$OUT/nmap_$d.gnmap" >/dev/null 2>&1 || true

        ports=$(grep "Ports:" "$OUT/nmap_$d.gnmap" 2>/dev/null \
            | sed 's/.*Ports: //; s|/|:|g' | tr ',' '\n' \
            | awk -F: '/open/ {printf "%s/%s ", $1, $3}')

        if [ -n "$ports" ]; then
            printf "  %-30s %s\n" "$d" "$ports"
            echo "$d -> $ports" >> "$OUT/ports.txt"
        else
            printf "  %-30s ${Y}(no open ports in top $PORT_TOPN)${N}\n" "$d"
            echo "$d -> none" >> "$OUT/ports.txt"
        fi
    done
}

# ---------- Server fingerprint ----------
fingerprint() {
    hdr "Server fingerprint"
    : > "$OUT/fingerprint.txt"
    : > "$OUT/servers.txt"

    for d in "${TARGETS[@]}"; do
        grep -q "^$d " "$OUT/live.txt" || continue
        grep -q "^$d NO-DNS" "$OUT/live.txt" && continue

        url="https://$d"
        hdr_raw=$(curl -skIL -m 6 -A "Mozilla/5.0 (Termux; domain-recon)" "$url" 2>/dev/null)
        if [ -z "$hdr_raw" ]; then
            url="http://$d"
            hdr_raw=$(curl -skIL -m 6 -A "Mozilla/5.0 (Termux; domain-recon)" "$url" 2>/dev/null)
        fi
        body=$(curl -skL -m 6 -A "Mozilla/5.0 (Termux; domain-recon)" "$url" 2>/dev/null | head -c 30000)

        server=$(echo "$hdr_raw" | awk -F': ' 'tolower($1)=="server"{print $2; exit}' | tr -d '\r')
        powered=$(echo "$hdr_raw" | awk -F': ' 'tolower($1)=="x-powered-by"{print $2; exit}' | tr -d '\r')

        # CDN
        cdn=""
        echo "$hdr_raw" | grep -qi "cf-ray"      && cdn+="cloudflare "
        echo "$hdr_raw" | grep -qi "x-amz-cf-id" && cdn+="cloudfront "
        echo "$hdr_raw" | grep -qi "x-akamai"    && cdn+="akamai "
        echo "$hdr_raw" | grep -qi "x-fastly"    && cdn+="fastly "
        echo "$hdr_raw" | grep -qi "x-served-by" && cdn+="fastly "
        echo "$hdr_raw" | grep -qi "x-varnish"   && cdn+="varnish "
        echo "$hdr_raw" | grep -qi "x-sucuri"    && cdn+="sucuri "

        # Server software
        sw=""
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
            *Cowboy*)        sw="cowboy" ;;
            *Kestrel*)       sw="kestrel" ;;
            *Envoy*)         sw="envoy" ;;
            *Traefik*)       sw="traefik" ;;
            *HAProxy*)       sw="haproxy" ;;
            *GitHub.com*)    sw="github-pages" ;;
        esac
        [ -z "$sw" ] && echo "$body" | grep -qi "nginx"     && sw="nginx"
        [ -z "$sw" ] && echo "$body" | grep -qi "apache"    && sw="apache"
        [ -z "$sw" ] && echo "$body" | grep -qi "litespeed" && sw="litespeed"
        [ -z "$sw" ] && sw="unknown"

        # Stack
        stack=""
        [ -n "$powered" ] && stack+="$powered "
        echo "$hdr_raw" | grep -qi "x-powered-by: express" && stack+="express "
        echo "$hdr_raw" | grep -qi "x-aspnet"              && stack+="asp.net "
        echo "$hdr_raw" | grep -qi "wp-content"            && stack+="wordpress "
        echo "$hdr_raw" | grep -qi "drupal"                && stack+="drupal "
        echo "$hdr_raw" | grep -qi "joomla"                && stack+="joomla "
        echo "$hdr_raw" | grep -qi "x-shopify"             && stack+="shopify "
        echo "$hdr_raw" | grep -qi "x-vercel"              && stack+="vercel "
        echo "$hdr_raw" | grep -qi "x-netlify"             && stack+="netlify "
        echo "$hdr_raw" | grep -qi "x-amz"                 && stack+="aws "
        echo "$hdr_raw" | grep -qi "x-goog"                && stack+="gcp "

        printf "  %-25s %-18s %s\n" "$d" "$sw" \
            "${cdn:+cdn=${cdn% } }${stack:+${stack% }}"
        echo "$d|$sw|${cdn% }|${stack% }|${server:-?}" >> "$OUT/fingerprint.txt"
        echo "$d -> $sw" >> "$OUT/servers.txt"
    done
}

# ---------- Summary ----------
summary() {
    hdr "Summary"
    echo -e "${C}Results folder:${N} $OUT"
    echo
    echo -e "${C}Targets (${#TARGETS[@]}):${N}"
    sed 's/^/  /' "$OUT/targets.txt"
    echo
    echo -e "${C}Server fingerprint:${N}"
    cat "$OUT/fingerprint.txt" 2>/dev/null | awk -F'|' '{printf "  %-25s %-18s %s\n",$1,$2,$5}' 
    echo
    echo -e "${C}Open ports:${N}"
    cat "$OUT/ports.txt" 2>/dev/null | sed 's/^/  /'
    echo
    echo -e "${C}Files:${N}"
    ls -1 "$OUT" | sed 's/^/  /'
}

# ---------- Main ----------
main() {
    banner
    deps
    read_targets "$@"
    dns_lookup
    check_live
    scan_ports
    fingerprint
    summary
}

main "$@"
