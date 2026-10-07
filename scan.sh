#!/data/data/com.termux/files/usr/bin/bash
# domain-recon v4.0

set -u

R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
C='\033[0;36m'
M='\033[0;35m'
W='\033[1;37m'
N='\033[0m'

log()  { echo -e "${B}[*]${N} $1"; }
ok()   { echo -e "${G}[+]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
err()  { echo -e "${R}[-]${N} $1"; }
hdr()  { echo -e "\n${C}== $1 ==${N}"; }
ask()  { printf "${W}%s${N} " "$1"; }

OUT=""
new_out() {
    OUT="$HOME/recon_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUT"
}

clean_domain() {
    local d="$1"
    d="${d#http://}"
    d="${d#https://}"
    d="${d%%/*}"
    echo "$d"
}

main_domain() {
    local h="${1%.}"
    echo "$h" | awk -F. '{n=NF; if(n<2){print $0; next}
        split("co|com|net|org|gov|edu|ac",p,"|")
        for(i in p) if($(n-1)==p[i] && n>=3){print $(n-2)"."$(n-1)"."$n; next}
        print $(n-1)"."$n}'
}

get_domain() {
    ask "Enter domain:"
    read -r D
    D=$(clean_domain "$D")
    if [ -z "$D" ]; then
        err "No domain."
        return 1
    fi
    return 0
}

# ============ 1) HOST SCAN ============
do_host() {
    hdr "Host scan"
    get_domain || return
    new_out
    ip=$(dig +short A "$D" 2>/dev/null | head -1)
    if [ -z "$ip" ]; then
        err "No DNS."
        return
    fi
    ok "Resolved: $ip"
    if ping -c1 -W2 "$D" >/dev/null 2>&1; then
        ok "Host is UP"
    else
        warn "Ping blocked"
    fi
    for s in https http; do
        c=$(curl -sk -o /dev/null -w "%{http_code}" -m 6 "$s://$D" 2>/dev/null)
        if [ -n "$c" ] && [ "$c" != "000" ]; then
            ok "$s -> $c"
        fi
    done
    echo "$D $ip" > "$OUT/host.txt"
    ok "Saved: $OUT/host.txt"
}

# ============ 2) PORT SCAN ============
do_ports() {
    hdr "Port scan"
    get_domain || return
    new_out
    log "Top 100 TCP ports on $D - this takes 30 to 90 seconds"
    nmap -Pn -T4 --top-ports 100 --open "$D" -oG "$OUT/ports.gnmap" >/dev/null 2>&1 || true
    ports=$(grep "Ports:" "$OUT/ports.gnmap" 2>/dev/null | sed 's/.*Ports: //; s|/|:|g' | tr ',' '\n' | awk -F: '/open/ {printf "  %-8s %s\n", $1, $3}')
    if [ -n "$ports" ]; then
        ok "Open ports:"
        echo "$ports"
        echo "$ports" > "$OUT/ports.txt"
    else
        warn "None."
    fi
}

# ============ 3) SUBDOMAINS ============
do_subs() {
    hdr "Subdomain enum"
    get_domain || return
    new_out
    root=$(main_domain "$D")
    log "Querying crt.sh ..."
    raw=$(curl -s -m 20 "https://crt.sh/?q=%25.$root&output=json" 2>/dev/null)
    if [ -z "$raw" ]; then
        warn "No data."
        return
    fi
    echo "$raw" | tr ',' '\n' | grep -oE '"name_value":"[^"]+"' | sed 's/"name_value":"//; s/"$//' | sed 's/\\n/\n/g' | sort -u | grep -v '^\*' > "$OUT/subs_raw.txt"
    : > "$OUT/subs_live.txt"
    while read -r sub; do
        if [ -z "$sub" ]; then continue; fi
        ip=$(dig +short A "$sub" 2>/dev/null | head -1)
        if [ -n "$ip" ]; then
            printf "  %-45s %s\n" "$sub" "$ip" | tee -a "$OUT/subs_live.txt"
        fi
    done < "$OUT/subs_raw.txt"
    ok "Live subdomains: $(wc -l < "$OUT/subs_live.txt")"
}

# ============ HELPERS: SERVER DETECT ============
detect_server() {
    local d="$1"
    local h body server sw cdn
    h=$(curl -skIL -m 8 -A "Mozilla/5.0 (Termux)" "https://$d" 2>/dev/null)
    if [ -z "$h" ]; then
        h=$(curl -skIL -m 8 "http://$d" 2>/dev/null)
    fi
    body=$(curl -skL -m 8 "https://$d" 2>/dev/null | head -c 30000)

    server=$(echo "$h" | awk -F': ' 'tolower($1)=="server"{print $2; exit}' | tr -d '\r')
    sw="unknown"
    case "$server" in
        *nginx*)         sw="nginx" ;;
        *openresty*)     sw="openresty" ;;
        *Apache*)        sw="apache" ;;
        *LiteSpeed*)     sw="litespeed" ;;
        *Caddy*)         sw="caddy" ;;
        *Microsoft-IIS*) sw="iis" ;;
        *cloudflare*)    sw="cloudflare" ;;
        *gunicorn*)      sw="gunicorn" ;;
        *Werkzeug*)      sw="werkzeug" ;;
        *Tomcat*)        sw="tomcat" ;;
        *Envoy*)         sw="envoy" ;;
        *Traefik*)       sw="traefik" ;;
    esac
    if [ "$sw" = "unknown" ]; then
        echo "$body" | grep -qi "nginx" && sw="nginx"
    fi
    if [ "$sw" = "unknown" ]; then
        echo "$body" | grep -qi "apache" && sw="apache"
    fi

    cdn=""
    echo "$h" | grep -qi "cf-ray" && cdn="${cdn}cloudflare "
    echo "$h" | grep -qi "x-amz-cf-id" && cdn="${cdn}cloudfront "
    echo "$h" | grep -qi "x-fastly" && cdn="${cdn}fastly "
    echo "$h" | grep -qi "x-akamai" && cdn="${cdn}akamai "
    echo "$h" | grep -qi "x-vercel" && cdn="${cdn}vercel "

    echo "${sw}|${server}|${cdn% }"
}

# ============ 4) SERVER FINGERPRINT ============
do_server() {
    hdr "Server fingerprint"
    get_domain || return
    new_out
    IFS='|' read -r sw server cdn <<< "$(detect_server "$D")"
    ok "Server: $sw"
    if [ -n "$server" ]; then ok "Header: $server"; fi
    if [ -n "$cdn" ]; then ok "CDN: $cdn"; fi
    {
        echo "domain=$D"
        echo "server=$sw"
        echo "header=$server"
        echo "cdn=$cdn"
    } > "$OUT/server.txt"
    ok "Saved: $OUT/server.txt"
}

# ============ 5) FULL SCAN ============
do_full() {
    do_host
    do_ports
    do_subs
    do_server
}

# ============ 6) PAYLOAD GENERATOR ============
gen_payloads() {
    local d="$1"
    echo "-- 1) Standard WebSocket --"
    echo "GET / HTTP/1.1[crlf]Host: $d[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
    echo
    echo "-- 2) Keep-Alive --"
    echo "GET / HTTP/1.1[crlf]Host: $d[crlf]Connection: Keep-Alive[crlf][crlf]"
    echo
    echo "-- 3) Direct HTTP --"
    echo "GET / HTTP/1.1[crlf]Host: $d[crlf][crlf]"
    echo
    echo "-- 4) X-Online-Host --"
    echo "GET / HTTP/1.1[crlf]Host: $d[crlf]X-Online-Host: $d[crlf][crlf]"
    echo
    echo "-- 5) SSL or SNI Direct --"
    echo "(no payload - use SSL or SNI mode in HTTP Custom)"
    echo
    echo "-- 6) V2Ray WebSocket --"
    echo "GET /ws HTTP/1.1[crlf]Host: $d[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Protocol: binary[crlf][crlf]"
    echo
    echo "-- 7) V2Ray gRPC --"
    echo "POST /grpc HTTP/2[crlf]Host: $d[crlf]Content-Type: application/grpc[crlf]TE: trailers[crlf][crlf]"
    echo
    echo "-- 8) Trojan WebSocket --"
    echo "GET / HTTP/1.1[crlf]Host: $d[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]"
}

do_payload() {
    hdr "Payload Generator"
    get_domain || return
    new_out
    log "Generating payloads for $D ..."
    echo
    gen_payloads "$D" | tee "$OUT/payloads.txt"
    ok "Saved: $OUT/payloads.txt"
    echo
    ok "Copy any payload above into HTTP Custom - Payload field."
}

# ============ 7) BEST SERVER RECOMMENDATION ============
do_recommend() {
    hdr "Best Server Recommendation"
    get_domain || return
    new_out

    log "Fingerprinting $D ..."
    IFS='|' read -r sw server cdn <<< "$(detect_server "$D")"
    ok "Server: $sw"
    if [ -n "$cdn" ]; then ok "CDN: $cdn"; fi

    log "Checking port 443 ..."
    tls_ok=0
    if timeout 5 nc -z "$D" 443 2>/dev/null; then
        tls_ok=1
        ok "443 open"
    else
        warn "443 closed"
    fi

    log "Testing WebSocket upgrade ..."
    ws_ok=0
    if [ "$tls_ok" = "1" ]; then
        resp=$(printf "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" "$D" | timeout 6 openssl s_client -quiet -connect "$D:443" -servername "$D" 2>/dev/null | head -1 | tr -d '\r')
        if echo "$resp" | grep -qE "101|200"; then
            ws_ok=1
            ok "WS upgrade works: $resp"
        else
            warn "WS upgrade failed"
        fi
    fi

    log "Checking HTTP/2 ..."
    h2=0
    if curl -sk --http2 -o /dev/null -m 6 "https://$D" 2>/dev/null; then
        h2=1
        ok "HTTP/2 supported"
    else
        warn "HTTP/2 not detected"
    fi

    echo
    hdr "Recommendation"

    case "$sw" in
        nginx|openresty|apache|litespeed|caddy|iis|cloudflare)
            if [ "$ws_ok" = "1" ]; then
                echo -e "${G}RECOMMENDED: V2Ray with WebSocket + TLS${N}"
                echo "  Reason: $sw handles WebSocket upgrades"
                echo "  Port  : 443"
                echo "  Path  : /"
                echo
                echo -e "${G}ALSO WORKS: SSH over WebSocket${N}"
                echo "  Reason: $sw will proxy WS to SSH backend"
                echo
                echo -e "${R}WILL NOT WORK: SSH Direct, SSL Direct${N}"
                echo "  Reason: $sw rejects raw SSH or TLS - needs HTTP handshake"
            else
                echo -e "${Y}WS upgrade failed - trying alternatives${N}"
                echo -e "${G}TRY: V2Ray gRPC if you control server${N}"
                echo -e "${G}TRY: SSL or SNI Direct${N}"
            fi
            ;;
        unknown)
            if [ "$tls_ok" = "1" ]; then
                echo -e "${G}RECOMMENDED: SSH Direct or SSL Direct${N}"
                echo "  Reason: No HTTP server detected - raw tunnel possible"
                echo "  Port  : 443"
            else
                echo -e "${R}No usable protocol detected${N}"
            fi
            ;;
        *)
            echo -e "${Y}Server: $sw - try V2Ray WS first${N}"
            ;;
    esac

    if [ "$h2" = "1" ]; then
        echo
        echo -e "${C}Bonus: HTTP/2 detected - V2Ray gRPC may also work${N}"
    fi

    {
        echo "domain=$D"
        echo "server=$sw"
        echo "cdn=$cdn"
        echo "port_443=$tls_ok"
        echo "ws_upgrade=$ws_ok"
        echo "http2=$h2"
    } > "$OUT/recommend.txt"
    echo
    ok "Saved: $OUT/recommend.txt"
}

# ============ 8) CDN PRESETS ============
do_cdn() {
    hdr "CDN Payload Presets"
    get_domain || return
    new_out
    IFS='|' read -r sw server cdn <<< "$(detect_server "$D")"
    ok "Server: $sw   CDN: ${cdn:-none}"
    echo
    echo -e "${C}-- Cloudflare WebSocket Ports --${N}"
    echo "80, 8080, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 443, 8443"
    echo
    echo -e "${C}-- Cloudflare WS Payload --${N}"
    echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
    echo
    echo -e "${C}-- CloudFront WS Payload --${N}"
    echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
    echo
    echo -e "${C}-- Fastly WS Payload --${N}"
    echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Fastly-SSL: 1[crlf][crlf]"
    echo
    gen_payloads "$D" > "$OUT/cdn_presets.txt"
    ok "Saved: $OUT/cdn_presets.txt"
}

# ============ 9) HTTP/2 + gRPC CHECK ============
do_http2() {
    hdr "HTTP/2 and gRPC Check"
    get_domain || return
    new_out
    log "Testing HTTP/2 ..."
    h2=0
    if curl -sk --http2 -o /dev/null -m 8 "https://$D" 2>/dev/null; then
        ok "HTTP/2 supported"
        h2=1
    else
        warn "HTTP/2 not supported"
    fi
    log "Testing gRPC endpoint ..."
    code=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -H "Content-Type: application/grpc" -H "TE: trailers" --http2 -X POST "https://$D/grpc" 2>/dev/null)
    if [ "$code" = "200" ] || [ "$code" = "415" ] || [ "$code" = "400" ]; then
        ok "gRPC responds with $code - V2Ray gRPC may work"
    else
        warn "gRPC response: $code"
    fi
    {
        echo "http2=$h2"
        echo "grpc_code=$code"
    } > "$OUT/http2.txt"
    ok "Saved: $OUT/http2.txt"
}

# ============ 10) BATCH PAYLOAD GENERATION ============
do_batch() {
    hdr "Batch Payload Generation"
    ask "File with domains one per line:"
    read -r f
    if [ ! -f "$f" ]; then
        err "File not found."
        return
    fi
    new_out
    count=0
    while read -r d; do
        if [ -z "$d" ]; then continue; fi
        d=$(clean_domain "$d")
        {
            echo "### $d ###"
            gen_payloads "$d"
            echo
        } >> "$OUT/batch_payloads.txt"
        ok "Generated for $d"
        count=$((count+1))
    done < "$f"
    ok "Total: $count domains"
    ok "Saved: $OUT/batch_payloads.txt"
}

# ============ 11) SAFE VS AGGRESSIVE ============
do_modes() {
    hdr "Safe vs Aggressive Mode"
    get_domain || return
    new_out
    IFS='|' read -r sw server cdn <<< "$(detect_server "$D")"
    tls_ok=0
    if timeout 5 nc -z "$D" 443 2>/dev/null; then tls_ok=1; fi
    ws_ok=0
    if [ "$tls_ok" = "1" ]; then
        resp=$(printf "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" "$D" | timeout 6 openssl s_client -quiet -connect "$D:443" -servername "$D" 2>/dev/null | head -1 | tr -d '\r')
        if echo "$resp" | grep -qE "101|200"; then ws_ok=1; fi
    fi

    echo
    echo -e "${C}-- SAFE MODE --${N}"
    if [ "$ws_ok" = "1" ]; then
        ok "Only use these - verified working:"
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
    else
        warn "No payloads verified - skip this domain"
    fi
    echo
    echo -e "${C}-- AGGRESSIVE MODE --${N}"
    warn "Try all of these in HTTP Custom:"
    gen_payloads "$D"
}

# ============ 12) PAYLOAD LIBRARY ============
do_library() {
    hdr "Payload Library"
    new_out
    ask "Enter domain - or press Enter for generic:"
    read -r D
    D=$(clean_domain "$D")
    if [ -z "$D" ]; then D="TARGET"; fi

    {
        echo "==== SSH WS Cloudflare ===="
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
        echo
        echo "==== SSH SSL ===="
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Connection: Keep-Alive[crlf][crlf]"
        echo
        echo "==== V2Ray VMess WS ===="
        echo "GET /v2ray HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Protocol: vmess[crlf][crlf]"
        echo
        echo "==== V2Ray VLESS gRPC ===="
        echo "POST /vless HTTP/2[crlf]Host: $D[crlf]Content-Type: application/grpc[crlf]TE: trailers[crlf][crlf]"
        echo
        echo "==== Trojan WS ===="
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]"
        echo
        echo "==== Shadowsocks WS ===="
        echo "GET /ss HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
        echo
        echo "==== nginx specific ===="
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]X-Forwarded-For: 127.0.0.1[crlf][crlf]"
    } | tee "$OUT/library.txt"

    ok "Saved: $OUT/library.txt"
}

# ============ BANNER + MENU ============
banner() {
    clear
    cat << "EOF"
   ==============================================
      DOMAIN RECON  v4.0
      Payload generator + server recommender
   ==============================================

EOF
}

menu() {
    echo -e "  ${W}Choose:${N}"
    echo -e "   ${C}1${N})  Host scan"
    echo -e "   ${C}2${N})  Port scan"
    echo -e "   ${C}3${N})  Subdomains"
    echo -e "   ${C}4${N})  Server / stack"
    echo -e "   ${C}5${N})  Full scan"
    echo -e "   ${C}6${N})  ${M}Payload Generator${N}"
    echo -e "   ${C}7${N})  ${M}Best Server Recommendation${N}"
    echo -e "   ${C}8${N})  CDN Payload Presets"
    echo -e "   ${C}9${N})  HTTP/2 and gRPC Check"
    echo -e "   ${C}10${N}) Batch Payload Generation"
    echo -e "   ${C}11${N}) Safe vs Aggressive Mode"
    echo -e "   ${C}12${N}) Payload Library"
    echo -e "   ${C}0${N})  Exit"
    echo
    ask "  >"
    read -r c
    echo
}

main() {
    while true; do
        banner
        menu
        case "$c" in
            1)  do_host ;;
            2)  do_ports ;;
            3)  do_subs ;;
            4)  do_server ;;
            5)  do_full ;;
            6)  do_payload ;;
            7)  do_recommend ;;
            8)  do_cdn ;;
            9)  do_http2 ;;
            10) do_batch ;;
            11) do_modes ;;
            12) do_library ;;
            0)  exit 0 ;;
            *)  err "Invalid." ;;
        esac
        echo
        ask "Enter to return..."
        read -r
    done
}

main "$@" if curl -sk --http2 -o /dev/null -m 8 "https://$D" 2>/dev/null; then
        ok "HTTP/2 supported"
        h2=1
    else
        warn "HTTP/2 not supported"
        h2=0
    fi
    log "Testing gRPC endpoint (POST /grpc with TE: trailers) ..."
    code=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 \
        -H "Content-Type: application/grpc" \
        -H "TE: trailers" \
        --http2 -X POST "https://$D/grpc" 2>/dev/null)
    if [ "$code" = "200" ] || [ "$code" = "415" ] || [ "$code" = "400" ]; then
        ok "gRPC endpoint responds ($code) — V2Ray gRPC likely works"
    else
        warn "gRPC response: $code"
    fi
    { echo "http2=$h2"; echo "grpc_code=$code"; } > "$OUT/http2.txt"
    ok "Saved: $OUT/http2.txt"
}

# ============ 10) BATCH PAYLOAD GENERATION ============
do_batch() {
    hdr "Batch Payload Generation"
    ask "File with domains (one per line):"; read -r f
    [ ! -f "$f" ] && { err "File not found."; return; }
    new_out
    local count=0
    while read -r d; do
        [ -z "$d" ] && continue
        d=$(clean_domain "$d")
        {
            echo "### $d ###"
            gen_payloads "$d"
            echo
        } >> "$OUT/batch_payloads.txt"
        ok "Generated for $d"
        count=$((count+1))
    done < "$f"
    ok "Total: $count domains"
    ok "Saved: $OUT/batch_payloads.txt"
}

# ============ 11) SAFE / AGGRESSIVE MODES ============
do_modes() {
    hdr "Safe vs Aggressive Mode"; get_domain || return
    new_out
    IFS='|' read -r sw server cdn <<< "$(detect_server "$D")"
    tls_ok=0; timeout 5 nc -z "$D" 443 2>/dev/null && tls_ok=1
    ws_ok=0
    if [ "$tls_ok" = "1" ]; then
        resp=$(printf "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" "$D" \
            | timeout 6 openssl s_client -quiet -connect "$D:443" -servername "$D" 2>/dev/null | head -1 | tr -d '\r')
        echo "$resp" | grep -qE "101|200" && ws_ok=1
    fi

    echo
    echo -e "${C}── SAFE MODE ──${N}"
    if [ "$ws_ok" = "1" ]; then
        ok "Safe payloads available — only use these:"
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
    else
        warn "Safe mode: no payloads verified — skip this domain"
    fi
    echo
    echo -e "${C}── AGGRESSIVE MODE ──${N}"
    warn "Aggressive mode — try all of these in HTTP Custom:"
    gen_payloads "$D"
}

# ============ 12) PAYLOAD LIBRARY ============
do_library() {
    hdr "Payload Library"
    new_out
    ask "Enter domain (or press Enter for generic templates):"; read -r D
    D=$(clean_domain "$D")
    [ -z "$D" ] && D="TARGET"

    {
        echo "════════ SSH WS (Cloudflare) ════════"
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
        echo
        echo "════════ SSH SSL ════════"
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Connection: Keep-Alive[crlf][crlf]"
        echo
        echo "════════ V2Ray VMess WS ════════"
        echo "GET /v2ray HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Protocol: vmess[crlf][crlf]"
        echo
        echo "════════ V2Ray VLESS gRPC ════════"
        echo "POST /vless HTTP/2[crlf]Host: $D[crlf]Content-Type: application/grpc[crlf]TE: trailers[crlf][crlf]"
        echo
        echo "════════ Trojan WS ════════"
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]"
        echo
        echo "════════ Shadowsocks WS ════════"
        echo "GET /ss HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
        echo
        echo "════════ nginx-specific ════════"
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]X-Forwarded-For: 127.0.0.1[crlf][crlf]"
    } | tee "$OUT/library.txt"

    ok "Saved: $OUT/library.txt"
}

# ============ BANNER + MENU ============
banner() {
    clear
    cat << "EOF"
   ╔══════════════════════════════════════════════╗
   ║     DOMAIN RECON · v4.0                      ║
   ║     Payload generator + server recommender   ║
   ╚══════════════════════════════════════════════╝

EOF
}
menu() {
    echo -e "  ${W}Choose:${N}"
    echo -e "   ${C}1${N})  Host scan"
    echo -e "   ${C}2${N})  Port scan"
    echo -e "   ${C}3${N})  Subdomains"
    echo -e "   ${C}4${N})  Server / stack"
    echo -e "   ${C}5${N})  Full scan"
    echo -e "   ${C}6${N})  ${M}Payload Generator${N} ⭐"
    echo -e "   ${C}7${N})  ${M}Best Server Recommendation${N} ⭐"
    echo -e "   ${C}8${N})  CDN Payload Presets"
    echo -e "   ${C}9${N})  HTTP/2 + gRPC Check"
    echo -e "   ${C}10${N}) Batch Payload Generation"
    echo -e "   ${C}11${N}) Safe vs Aggressive Mode"
    echo -e "   ${C}12${N}) Payload Library"
    echo -e "   ${C}0${N})  Exit"
    echo
    ask "  >"; read -r c; echo
}

main() {
    while true; do
        banner; menu
        case "$c" in
            1) do_host ;; 2) do_ports ;; 3) do_subs ;; 4) do_server ;;
            5) do_full ;; 6) do_payload ;; 7) do_recommend ;;
            8) do_cdn ;; 9) do_http2 ;; 10) do_batch ;;
            11) do_modes ;; 12) do_library ;;
            0) exit 0 ;;
            *) err "Invalid." ;;
        esac
        echo; ask "Ente#!/data/data/com.termux/files/usr/bin/bash
# domain-recon v4.0 — recon + payload generator + server recommender
set -u

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; C='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; N='\033[0m'

log()  { echo -e "${B}[*]${N} $*"; }
ok()   { echo -e "${G}[+]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
err()  { echo -e "${R}[-]${N} $*"; }
hdr()  { echo -e "\n${C}══ $* ══${N}"; }
ask()  { printf "${W}$*${N} "; }

OUT=""
new_out() { OUT="$HOME/recon_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$OUT"; }

clean_domain() { local d="$1"; d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"; echo "$d"; }
main_domain() {
    local h="${1%.}"
    echo "$h" | awk -F. '{n=NF; if(n<2){print $0; next}
        split("co|com|net|org|gov|edu|ac",p,"|")
        for(i in p) if($(n-1)==p[i] && n>=3){print $(n-2)"."$(n-1)"."$n; next}
        print $(n-1)"."$n}'
}
get_domain() {
    ask "Enter domain:"; read -r D
    D=$(clean_domain "$D")
    [ -z "$D" ] && { err "No domain."; return 1; }
    return 0
}

# ============ 1) HOST SCAN ============
do_host() {
    hdr "Host scan"; get_domain || return
    new_out
    ip=$(dig +short A "$D" 2>/dev/null | head -1)
    [ -z "$ip" ] && { err "No DNS."; return; }
    ok "Resolved: $ip"
    ping -c1 -W2 "$D" >/dev/null 2>&1 && ok "Host is UP" || warn "Ping blocked"
    for s in https http; do
        c=$(curl -sk -o /dev/null -w "%{http_code}" -m 6 "$s://$D" 2>/dev/null)
        [ -n "$c" ] && [ "$c" != "000" ] && ok "$s -> $c"
    done
    echo "$D $ip" > "$OUT/host.txt"
    ok "Saved: $OUT/host.txt"
}

# ============ 2) PORT SCAN ============
do_ports() {
    hdr "Port scan"; get_domain || return
    new_out
    log "Top 100 TCP ports on $D (30-90s)..."
    nmap -Pn -T4 --top-ports 100 --open "$D" -oG "$OUT/ports.gnmap" >/dev/null 2>&1 || true
    ports=$(grep "Ports:" "$OUT/ports.gnmap" 2>/dev/null | sed 's/.*Ports: //; s|/|:|g' | tr ',' '\n' | awk -F: '/open/ {printf "  %-8s %s\n", $1, $3}')
    if [ -n "$ports" ]; then ok "Open ports:"; echo "$ports"; echo "$ports" > "$OUT/ports.txt"; else warn "None."; fi
}

# ============ 3) SUBDOMAINS ============
do_subs() {
    hdr "Subdomain enum"; get_domain || return
    new_out
    root=$(main_domain "$D")
    log "crt.sh ..."
    raw=$(curl -s -m 20 "https://crt.sh/?q=%25.$root&output=json" 2>/dev/null)
    [ -z "$raw" ] && { warn "No data."; return; }
    echo "$raw" | tr ',' '\n' | grep -oE '"name_value":"[^"]+"' | sed 's/"name_value":"//; s/"$//' | sed 's/\\n/\n/g' | sort -u | grep -v '^\*' > "$OUT/subs_raw.txt"
    : > "$OUT/subs_live.txt"
    while read -r sub; do
        [ -z "$sub" ] && continue
        ip=$(dig +short A "$sub" 2>/dev/null | head -1)
        [ -n "$ip" ] && printf "  %-45s %s\n" "$sub" "$ip" | tee -a "$OUT/subs_live.txt"
    done < "$OUT/subs_raw.txt"
    ok "Live subdomains: $(wc -l < "$OUT/subs_live.txt")"
}

# ============ 4) SERVER FINGERPRINT ============
detect_server() {
    local d="$1"
    local h body server sw cdn
    h=$(curl -skIL -m 8 -A "Mozilla/5.0 (Termux)" "https://$d" 2>/dev/null)
    [ -z "$h" ] && h=$(curl -skIL -m 8 "http://$d" 2>/dev/null)
    body=$(curl -skL -m 8 "https://$d" 2>/dev/null | head -c 30000)

    server=$(echo "$h" | awk -F': ' 'tolower($1)=="server"{print $2; exit}' | tr -d '\r')
    sw="unknown"
    case "$server" in
        *nginx*) sw="nginx" ;; *openresty*) sw="openresty" ;;
        *Apache*) sw="apache" ;; *LiteSpeed*) sw="litespeed" ;;
        *Caddy*) sw="caddy" ;; *Microsoft-IIS*) sw="iis" ;;
        *cloudflare*) sw="cloudflare" ;; *gunicorn*) sw="gunicorn" ;;
        *Werkzeug*) sw="werkzeug" ;; *Tomcat*) sw="tomcat" ;;
        *Envoy*) sw="envoy" ;; *Traefik*) sw="traefik" ;;
    esac
    [ "$sw" = "unknown" ] && echo "$body" | grep -qi "nginx" && sw="nginx"
    [ "$sw" = "unknown" ] && echo "$body" | grep -qi "apache" && sw="apache"

    cdn=""
    echo "$h" | grep -qi "cf-ray" && cdn+="cloudflare "
    echo "$h" | grep -qi "x-amz-cf-id" && cdn+="cloudfront "
    echo "$h" | grep -qi "x-fastly" && cdn+="fastly "
    echo "$h" | grep -qi "x-akamai" && cdn+="akamai "
    echo "$h" | grep -qi "x-vercel" && cdn+="vercel "

    echo "$sw|$server|${cdn% }"
}

do_server() {
    hdr "Server fingerprint"; get_domain || return
    new_out
    IFS='|' read -r sw server cdn <<< "$(detect_server "$D")"
    ok "Server: $sw"
    [ -n "$server" ] && ok "Header: $server"
    [ -n "$cdn" ] && ok "CDN: $cdn"
    { echo "domain=$D"; echo "server=$sw"; echo "header=$server"; echo "cdn=$cdn"; } > "$OUT/server.txt"
}

# ============ 5) FULL SCAN ============
do_full() {
    do_host; do_ports; do_subs; do_server
}

# ============ 6) PAYLOAD GENERATOR ============
gen_payloads() {
    local d="$1"
    cat << EOF
── 1) Standard WebSocket (nginx/apache/cloudflare) ──
GET / HTTP/1.1[crlf]Host: $d[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]

── 2) Keep-Alive (simple HTTP) ──
GET / HTTP/1.1[crlf]Host: $d[crlf]Connection: Keep-Alive[crlf][crlf]

── 3) Direct HTTP ──
GET / HTTP/1.1[crlf]Host: $d[crlf][crlf]

── 4) X-Online-Host (SSH tunneling) ──
GET / HTTP/1.1[crlf]Host: $d[crlf]X-Online-Host: $d[crlf][crlf]

── 5) SSL/SNI Direct (no HTTP) ──
(no payload — use SSL/SNI mode in HTTP Custom)

── 6) V2Ray WebSocket ──
GET /ws HTTP/1.1[crlf]Host: $d[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Protocol: binary[crlf][crlf]

── 7) V2Ray gRPC (needs HTTP/2) ──
POST /grpc HTTP/2[crlf]Host: $d[crlf]Content-Type: application/grpc[crlf]TE: trailers[crlf][crlf]

── 8) Trojan WebSocket ──
GET / HTTP/1.1[crlf]Host: $d[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]
EOF
}

do_payload() {
    hdr "Payload Generator"; get_domain || return
    new_out
    log "Generating payloads for $D ..."
    echo
    gen_payloads "$D" | tee "$OUT/payloads.txt"
    ok "Saved: $OUT/payloads.txt"
    echo
    ok "Copy any payload above into HTTP Custom → Payload field."
}

# ============ 7) BEST SERVER RECOMMENDATION ============
do_recommend() {
    hdr "Best Server Recommendation"; get_domain || return
    new_out

    log "Fingerprinting $D ..."
    IFS='|' read -r sw server cdn <<< "$(detect_server "$D")"
    ok "Server: $sw"
    [ -n "$cdn" ] && ok "CDN: $cdn"

    log "Checking port 443 ..."
    tls_ok=0
    timeout 5 nc -z "$D" 443 2>/dev/null && tls_ok=1 && ok "443 open" || warn "443 closed"

    log "Testing WebSocket upgrade ..."
    ws_ok=0
    if [ "$tls_ok" = "1" ]; then
        resp=$(printf "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" "$D" \
            | timeout 6 openssl s_client -quiet -connect "$D:443" -servername "$D" 2>/dev/null | head -1 | tr -d '\r')
        echo "$resp" | grep -qE "101|200" && ws_ok=1
        [ "$ws_ok" = "1" ] && ok "WS upgrade works ($resp)" || warn "WS upgrade failed"
    fi

    log "Checking HTTP/2 ..."
    h2=0
    if curl -sk --http2 -o /dev/null -m 6 "https://$D" 2>/dev/null; then
        h2=1; ok "HTTP/2 supported"
    else
        warn "HTTP/2 not detected"
    fi

    # --- Decision ---
    echo
    hdr "Recommendation"

    case "$sw" in
        nginx|openresty|apache|litespeed|caddy|iis|cloudflare)
            if [ "$ws_ok" = "1" ]; then
                echo -e "${G}✅ RECOMMENDED: V2Ray (WebSocket + TLS)${N}"
                echo "   Reason: $sw handles WebSocket upgrades"
                echo "   Port  : 443"
                echo "   Path  : /"
                echo
                echo -e "${G}✅ ALSO WORKS: SSH over WebSocket${N}"
                echo "   Reason: nginx/apache will proxy WS to SSH backend"
                echo
                echo -e "${R}❌ WON'T WORK: SSH Direct, SSL Direct${N}"
                echo "   Reason: $sw rejects raw SSH/TLS — needs HTTP handshake"
            else
                echo -e "${Y}⚠️  WS upgrade failed — trying alternatives${N}"
                echo -e "${G}✅ TRY: V2Ray gRPC (if you control server)${N}"
                echo -e "${G}✅ TRY: SSL/SNI Direct${N}"
            fi
            ;;
        unknown)
            if [ "$tls_ok" = "1" ]; then
                echo -e "${G}✅ RECOMMENDED: SSH Direct or SSL Direct${N}"
                echo "   Reason: No HTTP server detected — raw tunnel possible"
                echo "   Port  : 443"
            else
                echo -e "${R}❌ No usable protocol detected${N}"
            fi
            ;;
    esac

    if [ "$h2" = "1" ]; then
        echo
        echo -e "${C}Bonus: HTTP/2 detected — V2Ray gRPC may also work${N}"
    fi

    # Save
    {
        echo "domain=$D"
        echo "server=$sw"
        echo "cdn=$cdn"
        echo "port_443=$tls_ok"
        echo "ws_upgrade=$ws_ok"
        echo "http2=$h2"
    } > "$OUT/recommend.txt"
    echo
    ok "Saved: $OUT/recommend.txt"
}

# ============ 8) CDN PRESETS ============
do_cdn() {
    hdr "CDN Payload Presets"; get_domain || return
    new_out
    IFS='|' read -r sw server cdn <<< "$(detect_server "$D")"
    ok "Server: $sw   CDN: ${cdn:-none}"
    echo
    echo -e "${C}── Cloudflare WebSocket Ports ──${N}"
    echo "80, 8080, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 443, 8443"
    echo
    echo -e "${C}── Cloudflare WS Payload ──${N}"
    echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
    echo
    echo -e "${C}── CloudFront WS Payload ──${N}"
    echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]X-Amz-Cf-Id: [crlf][crlf]"
    echo
    echo -e "${C}── Fastly WS Payload ──${N}"
    echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Fastly-SSL: 1[crlf][crlf]"
    echo
    gen_payloads "$D" > "$OUT/cdn_presets.txt"
    ok "Saved: $OUT/cdn_presets.txt"
}

# ============ 9) HTTP/2 + gRPC CHECK ============
do_http2() {
    hdr "HTTP/2 / gRPC Check"; get_domain || return
    new_out
    log "Testing HTTP/2 ..."
    if curl -sk --http2 -o /dev/null -m 8 "https://$D" 2>/dev/null; then
        ok "HTTP/2 supported"
        h2=1
    else
        warn "HTTP/2 not supported"
        h2=0
    fi
    log "Testing gRPC endpoint (POST /grpc with TE: trailers) ..."
    code=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 \
        -H "Content-Type: application/grpc" \
        -H "TE: trailers" \
        --http2 -X POST "https://$D/grpc" 2>/dev/null)
    if [ "$code" = "200" ] || [ "$code" = "415" ] || [ "$code" = "400" ]; then
        ok "gRPC endpoint responds ($code) — V2Ray gRPC likely works"
    else
        warn "gRPC response: $code"
    fi
    { echo "http2=$h2"; echo "grpc_code=$code"; } > "$OUT/http2.txt"
    ok "Saved: $OUT/http2.txt"
}

# ============ 10) BATCH PAYLOAD GENERATION ============
do_batch() {
    hdr "Batch Payload Generation"
    ask "File with domains (one per line):"; read -r f
    [ ! -f "$f" ] && { err "File not found."; return; }
    new_out
    local count=0
    while read -r d; do
        [ -z "$d" ] && continue
        d=$(clean_domain "$d")
        {
            echo "### $d ###"
            gen_payloads "$d"
            echo
        } >> "$OUT/batch_payloads.txt"
        ok "Generated for $d"
        count=$((count+1))
    done < "$f"
    ok "Total: $count domains"
    ok "Saved: $OUT/batch_payloads.txt"
}

# ============ 11) SAFE / AGGRESSIVE MODES ============
do_modes() {
    hdr "Safe vs Aggressive Mode"; get_domain || return
    new_out
    IFS='|' read -r sw server cdn <<< "$(detect_server "$D")"
    tls_ok=0; timeout 5 nc -z "$D" 443 2>/dev/null && tls_ok=1
    ws_ok=0
    if [ "$tls_ok" = "1" ]; then
        resp=$(printf "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" "$D" \
            | timeout 6 openssl s_client -quiet -connect "$D:443" -servername "$D" 2>/dev/null | head -1 | tr -d '\r')
        echo "$resp" | grep -qE "101|200" && ws_ok=1
    fi

    echo
    echo -e "${C}── SAFE MODE ──${N}"
    if [ "$ws_ok" = "1" ]; then
        ok "Safe payloads available — only use these:"
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
    else
        warn "Safe mode: no payloads verified — skip this domain"
    fi
    echo
    echo -e "${C}── AGGRESSIVE MODE ──${N}"
    warn "Aggressive mode — try all of these in HTTP Custom:"
    gen_payloads "$D"
}

# ============ 12) PAYLOAD LIBRARY ============
do_library() {
    hdr "Payload Library"
    new_out
    ask "Enter domain (or press Enter for generic templates):"; read -r D
    D=$(clean_domain "$D")
    [ -z "$D" ] && D="TARGET"

    {
        echo "════════ SSH WS (Cloudflare) ════════"
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
        echo
        echo "════════ SSH SSL ════════"
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Connection: Keep-Alive[crlf][crlf]"
        echo
        echo "════════ V2Ray VMess WS ════════"
        echo "GET /v2ray HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Protocol: vmess[crlf][crlf]"
        echo
        echo "════════ V2Ray VLESS gRPC ════════"
        echo "POST /vless HTTP/2[crlf]Host: $D[crlf]Content-Type: application/grpc[crlf]TE: trailers[crlf][crlf]"
        echo
        echo "════════ Trojan WS ════════"
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]"
        echo
        echo "════════ Shadowsocks WS ════════"
        echo "GET /ss HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
        echo
        echo "════════ nginx-specific ════════"
        echo "GET / HTTP/1.1[crlf]Host: $D[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]X-Forwarded-For: 127.0.0.1[crlf][crlf]"
    } | tee "$OUT/library.txt"

    ok "Saved: $OUT/library.txt"
}

# ============ BANNER + MENU ============
banner() {
    clear
    cat << "EOF"
   ╔══════════════════════════════════════════════╗
   ║     DOMAIN RECON · v4.0                      ║
   ║     Payload generator + server recommender   ║
   ╚══════════════════════════════════════════════╝

EOF
}
menu() {
    echo -e "  ${W}Choose:${N}"
    echo -e "   ${C}1${N})  Host scan"
    echo -e "   ${C}2${N})  Port scan"
    echo -e "   ${C}3${N})  Subdomains"
    echo -e "   ${C}4${N})  Server / stack"
    echo -e "   ${C}5${N})  Full scan"
    echo -e "   ${C}6${N})  ${M}Payload Generator${N} ⭐"
    echo -e "   ${C}7${N})  ${M}Best Server Recommendation${N} ⭐"
    echo -e "   ${C}8${N})  CDN Payload Presets"
    echo -e "   ${C}9${N})  HTTP/2 + gRPC Check"
    echo -e "   ${C}10${N}) Batch Payload Generation"
    echo -e "   ${C}11${N}) Safe vs Aggressive Mode"
    echo -e "   ${C}12${N}) Payload Library"
    echo -e "   ${C}0${N})  Exit"
    echo
    ask "  >"; read -r c; echo
}

main() {
    while true; do
        banner; menu
        case "$c" in
            1) do_host ;; 2) do_ports ;; 3) do_subs ;; 4) do_server ;;
            5) do_full ;; 6) do_payload ;; 7) do_recommend ;;
            8) do_cdn ;; 9) do_http2 ;; 10) do_batch ;;
            11) do_modes ;; 12) do_library ;;
            0) exit 0 ;;
            *) err "Invalid." ;;
        esac
        echo; ask "Enter to return..."; read -r
    done
}
main "$@"read -r
    done
}

main "$@"
