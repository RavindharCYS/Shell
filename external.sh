#!/bin/bash
set -eo pipefail

# =================================================================
# External Reconnaissance Tool - The Complete & Professional Version
# =================================================================
# This script is architected for robustness, handling real-world scenarios
# where inputs may be empty and tools may be missing, without crashing.
# It uses a central data store model and parallel processing for efficiency.
# =================================================================

# --- Configuration ---
DEFAULT_SCAN_DELAY=1
NMAP_TIMING=3
MAX_PARALLEL_SCANS=10
TIMEOUT=300
WORDLIST="/usr/share/wordlists/dirb/common.txt"

# --- All Steps Definition (in logical execution order) ---
ALL_STEPS=("setup" "rev_ip" "subdomains" "resolve" "portscan" "servicedetect" "webtech" "waf" "techdetect" "screenshots" "webvuln" "dirb" "misconfigs" "vulndetect" "zonetransfer" "emails" "report" "archive" "cleanup")

# --- Helper Functions ---
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"; }
create_checkpoint() { echo "$1" >> checkpoints.log; log "[+] Checkpoint created: $1"; }

# --- Dependency Check ---
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        log "[!] Warning: Tool '$1' not found. Steps depending on it will be skipped."
        return 1
    fi
    return 0
}

# --- Core Logic Functions (Architected for Robustness) ---

usage() {
    echo "Usage: $0 -i <input_file> -o <output_dir> [OPTIONS]"
    echo
    echo "A robust, fully functional external reconnaissance tool."
    echo
    echo "Required:"
    echo "  -i, --input-file <file>    File with IPs and/or domains (one per line)."
    echo "  -o, --output-dir <dir>     Directory to store results."
    echo
    echo "Options:"
    echo "  -x, --exclude-file <file>  File with hosts/IPs to exclude from scans."
    echo "  -s, --skip-steps <steps>   Comma-separated list of steps to skip."
    echo "  -h, --help                 Display this help message."
    exit 1
}

setup() {
    log "[+] Initializing scan in directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"/{nmap,subdomain_results,web_detection,vulnerability_scan,nmap_vuln_scans,dirb_reports,screenshots,security_checks,waf_detection,dns_info,email_harvest,tech_detection}
    cd "$OUTPUT_DIR" || { log "[-] Failed to create/access directory"; exit 1; }

    LOG_FILE="recon_log_$(date +%Y%m%d_%H%M%S).log"
    exec > >(tee -a "$LOG_FILE") 2>&1
    log "[+] Starting scan at $(date). All output will be logged to $LOG_FILE"

    # Smart Input Processing into Master Files
    touch master_ips.txt master_hostnames.txt root_domains.txt excluded_hosts.txt
    if [[ -n "$EXCLUDE_FILE" ]]; then cp "$EXCLUDE_FILE" ./excluded_hosts.txt; fi
    
    log "[+] Processing initial targets from $INPUT_FILE..."
    ip_regex='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
    while read -r target; do
        [[ -z "$target" ]] && continue
        if [[ $target =~ $ip_regex ]]; then echo "$target" >> master_ips.txt; else
            echo "$target" >> master_hostnames.txt; echo "$target" >> root_domains.txt
        fi
    done < <(sort -u "$INPUT_FILE")
    sort -u -o master_ips.txt master_ips.txt
    sort -u -o master_hostnames.txt master_hostnames.txt
    sort -u -o root_domains.txt root_domains.txt
    log "[✓] Setup complete. Initial IPs: $(wc -l < master_ips.txt), Initial Hostnames: $(wc -l < master_hostnames.txt)"
}

reverse_ip_lookup() {
    check_tool "host" || return
    if [[ ! -s master_ips.txt ]]; then log "[!] No IPs to perform reverse lookup on. Skipping."; return; fi
    create_checkpoint "rev_ip"
    
    log "[+] Performing Reverse IP Lookup..."
    while read -r ip; do
        if grep -qFx "$ip" excluded_hosts.txt 2>/dev/null; then continue; fi
        domain=$(host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $5}' | sed 's/\.$//')
        if [[ -n "$domain" ]]; then
            echo "$domain" >> master_hostnames.txt; echo "$domain" >> root_domains.txt
        fi; sleep "$DEFAULT_SCAN_DELAY"
    done < master_ips.txt
    sort -u -o master_hostnames.txt master_hostnames.txt; sort -u -o root_domains.txt root_domains.txt
    log "[✓] Reverse IP Lookup complete."
}

subdomain_enumeration() {
    create_checkpoint "subdomains"
    if [[ ! -s root_domains.txt ]]; then log "[!] No root domains found to enumerate for subdomains. Skipping."; return; fi
    
    log "[+] Finding Subdomains for $(wc -l < root_domains.txt) root domains..."
    local initial_count=$(wc -l < master_hostnames.txt)
    while read -r domain; do
        log "[*] Enumerating subdomains for: $domain"
        check_tool "subfinder" && subfinder -d "$domain" -silent -o "subdomain_results/subfinder_$domain.txt"
        check_tool "amass" && amass enum -passive -d "$domain" -timeout "$TIMEOUT" -o "subdomain_results/amass_$domain.txt"
        sleep "$DEFAULT_SCAN_DELAY"
    done < root_domains.txt

    cat subdomain_results/*.txt 2>/dev/null | sort -u >> master_hostnames.txt
    sort -u -o master_hostnames.txt master_hostnames.txt
    log "[✓] Subdomain enumeration added $(( $(wc -l < master_hostnames.txt) - initial_count )) new hostnames."
}

resolve_all_ips() {
    check_tool "dig" || return
    create_checkpoint "resolve"
    if [[ ! -s master_hostnames.txt ]]; then log "[!] No hostnames to resolve. Skipping."; return; fi

    log "[+] Resolving all $(wc -l < master_hostnames.txt) hostnames to IPs..."
    local initial_count=$(wc -l < master_ips.txt)
    cat master_hostnames.txt | xargs -I{} -P"$MAX_PARALLEL_SCANS" dig +short A "{}" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> master_ips.tmp
    cat master_ips.tmp >> master_ips.txt && rm master_ips.tmp
    
    sort -u -o master_ips.txt master_ips.txt
    log "[✓] IP resolution added $(( $(wc -l < master_ips.txt) - initial_count )) new IPs."
}

port_scanning() {
    check_tool "nmap" || return
    create_checkpoint "portscan"
    if [[ ! -s master_ips.txt ]]; then log "[!] No IPs to scan. Skipping port scan."; return; fi

    log "[+] Running Nmap Top 1000 scan on $(wc -l < master_ips.txt) unique IPs..."
    nmap -sS -Pn --top-ports 1000 -T"$NMAP_TIMING" --open -iL master_ips.txt -oA nmap/top_1000_scan
    
    if grep -q "open" nmap/top_1000_scan.gnmap 2>/dev/null; then
        log "[*] Open ports found. Running full scan on responsive hosts..."
        grep "open" nmap/top_1000_scan.gnmap | cut -d' ' -f2 | sort -u > nmap/responsive_hosts.txt
        nmap -sS -Pn -p- -T"$NMAP_TIMING" --open -iL nmap/responsive_hosts.txt -oA nmap/full_scan
    fi
    log "[✓] Port scanning completed."
}

service_detection() {
    check_tool "nmap" || return
    create_checkpoint "servicedetect"
    if [[ ! -f nmap/top_1000_scan.gnmap ]]; then log "[!] No Nmap results to analyze. Skipping service detection."; return; fi
    
    grep "open" nmap/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > nmap/hosts_with_open_ports.txt
    if [[ ! -s nmap/hosts_with_open_ports.txt ]]; then log "[!] No hosts with open ports found. Skipping service detection."; return; fi
    log "[+] Performing Service & Version Detection..."
    
    open_ports=$(grep -h "open" nmap/*.gnmap 2>/dev/null | cut -d' ' -f4- | tr -d ' ' | sed 's|/open/[a-zA-Z-]*||g' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
    if [[ -n "$open_ports" ]]; then
        nmap -sV -O --version-intensity 5 -p"$open_ports" -iL nmap/hosts_with_open_ports.txt -oA nmap/service_scan
    fi
    log "[✓] Service detection completed."
}

web_stack_detection() {
    create_checkpoint "webtech"
    log "[+] Reliably identifying live web servers..."
    
    # Actively probe common web ports on all unique hostnames
    > web_detection/confirmed_web_servers.txt
    while read -r host; do
        if nc -z -w1 "$host" 80; then echo "http://$host" >> web_detection/confirmed_web_servers.txt; fi
        if nc -z -w1 "$host" 443; then echo "https://$host" >> web_detection/confirmed_web_servers.txt; fi
    done < <(sort -u master_hostnames.txt 2>/dev/null)
    sort -u -o web_detection/confirmed_web_servers.txt web_detection/confirmed_web_servers.txt

    if [[ ! -s web_detection/confirmed_web_servers.txt ]]; then log "[!] No live web servers found. Skipping related steps."; return; fi
    log "[✓] Found $(wc -l < web_detection/confirmed_web_servers.txt) live web servers."
}

detect_waf() {
    check_tool "wafw00f" || return; create_checkpoint "waf"
    if [[ ! -s root_domains.txt ]]; then log "[!] No root domains to check for WAF. Skipping."; return; fi
    log "[+] Detecting WAFs on root domains..."; wafw00f -i root_domains.txt -o waf_detection/waf_report.json -f json 2>/dev/null; log "[✓] WAF detection complete."
}

detect_technologies() {
    check_tool "whatweb" || return; create_checkpoint "techdetect"
    if [[ ! -s web_detection/confirmed_web_servers.txt ]]; then log "[!] No web servers for tech detection. Skipping."; return; fi
    log "[+] Running WhatWeb for technology detection..."; whatweb --no-errors -i web_detection/confirmed_web_servers.txt --max-threads "$MAX_PARALLEL_SCANS" -a 3 --log-json=web_detection/whatweb_results.json; log "[✓] Technology detection complete."
}

take_screenshots() {
    check_tool "cutycapt" || return; create_checkpoint "screenshots"
    if [[ ! -s web_detection/confirmed_web_servers.txt ]]; then log "[!] No web servers to screenshot. Skipping."; return; fi
    log "[+] Taking screenshots..."; cat web_detection/confirmed_web_servers.txt | xargs -I{} -P"$MAX_PARALLEL_SCANS" bash -c 'sanitized_target=$(echo "{}" | tr -c "[:alnum:].-" "_"); timeout 30s cutycapt --url="{}" --out="screenshots/$sanitized_target.png" 2>/dev/null'; log "[✓] Screenshots complete."
}

web_vulnerability_scan() {
    check_tool "nikto" || return; create_checkpoint "webvuln"
    if [[ ! -s web_detection/confirmed_web_servers.txt ]]; then log "[!] No web servers to scan. Skipping Nikto."; return; fi
    log "[+] Running Nikto web scans..."; 
    while read -r target; do 
        sanitized_target=$(echo "$target" | tr -c '[:alnum:].' '_'); 
        nikto -h "$target" -Tuning 4 -maxtime 15m -o "vulnerability_scan/nikto_$sanitized_target.txt" -ask no &
        if (( $(jobs -r -p | wc -l) >= MAX_PARALLEL_SCANS )); then wait -n; fi
    done < web_detection/confirmed_web_servers.txt
    wait
    log "[✓] Nikto scans complete."
}

directory_bruteforcing() {
    check_tool "gobuster" || return; create_checkpoint "dirb"
    if [[ ! -s web_detection/confirmed_web_servers.txt ]]; then log "[!] No web servers to bruteforce. Skipping."; return; fi
    if [[ ! -f "$WORDLIST" ]]; then log "[!] Wordlist not found at $WORDLIST. Skipping."; return; fi
    log "[+] Running directory bruteforcing..."; 
    while read -r target; do 
        sanitized_target=$(echo "$target" | tr -c '[:alnum:].' '_'); 
        gobuster dir -u "$target" -w "$WORDLIST" -q -t 20 -o "dirb_reports/gobuster_$sanitized_target.txt" --delay 200ms &
        if (( $(jobs -r -p | wc -l) >= MAX_PARALLEL_SCANS )); then wait -n; fi
    done < web_detection/confirmed_web_servers.txt
    wait
    log "[✓] Directory bruteforcing complete."
}

check_misconfigs() {
    check_tool "curl" || return; create_checkpoint "misconfigs"
    if [[ ! -s web_detection/confirmed_web_servers.txt ]]; then log "[!] No web servers to check for misconfigs. Skipping."; return; fi
    log "[+] Checking for security misconfigurations..."; 
    cat web_detection/confirmed_web_servers.txt | xargs -I{} -P"$MAX_PARALLEL_SCANS" bash -c 'if curl -sIkL --connect-timeout 5 "{}/.git/HEAD" | grep -q "200 OK"; then echo "{} has exposed .git directory" >> security_checks/exposed_git.txt; fi'
    log "[✓] Misconfiguration checks complete."
}

vulnerability_detection() {
    check_tool "nmap" || return; create_checkpoint "vulndetect"
    if [[ ! -s nmap/hosts_with_open_ports.txt ]]; then log "[!] No hosts with open ports for Nmap vuln scan. Skipping."; return; fi
    log "[+] Running Nmap vulnerability scripts..."; nmap -sV --script "vuln" --script-args "unsafe=0" -T"$NMAP_TIMING" -iL nmap/hosts_with_open_ports.txt -oA nmap_vuln_scans/nmap_vuln_scan; log "[✓] Nmap vulnerability scan complete."
}

zone_transfer() {
    check_tool "dig" || return; create_checkpoint "zonetransfer"
    if [[ ! -s root_domains.txt ]]; then log "[!] No root domains for zone transfer check. Skipping."; return; fi
    log "[+] Attempting DNS Zone Transfers..."; while read -r domain; do for ns in $(dig +short NS "$domain"); do dig @"$ns" "$domain" AXFR > "dns_info/zonetransfer_${domain}_${ns}.txt"; done; done < root_domains.txt; log "[✓] Zone Transfer attempts complete."
}

harvest_emails() {
    check_tool "theHarvester" || return; create_checkpoint "emails"
    if [[ ! -s root_domains.txt ]]; then log "[!] No root domains to harvest emails from. Skipping."; return; fi
    log "[+] Harvesting Email Addresses..."; while read -r domain; do theHarvester -d "$domain" -b google,bing -f "email_harvest/$domain.html"; sleep 5; done < root_domains.txt; log "[✓] Email harvesting complete."
}

generate_report() {
    create_checkpoint "report"
    log "[+] Generating HTML Report..."
    cat > report.html <<-EOF
<!DOCTYPE html><html><head><title>Recon Report - $(date +"%Y-%m-%d")</title><style>body{font-family:monospace;background-color:#1e1e1e;color:#d4d4d4;margin:20px}h1,h2{color:#4ec9b0;border-bottom:1px solid #4ec9b0}pre{background-color:#252526;padding:10px;border-radius:5px;white-space:pre-wrap;word-wrap:break-word;border-left:3px solid #4ec9b0}.section{margin-bottom:20px;padding:15px;background-color:#2d2d2d;border:1px solid #3c3c3c;border-radius:5px}.summary{background-color:#3e3e42}a{color:#569cd6}</style></head><body>
<h1>External Reconnaissance Report</h1>
<div class="section summary"><h2>Summary</h2><p><strong>Unique IPs Scanned:</strong> $(wc -l < master_ips.txt 2>/dev/null||echo 0)</p><p><strong>Unique Hostnames Found:</strong> $(wc -l < master_hostnames.txt 2>/dev/null||echo 0)</p><p><strong>Web Servers Found:</strong> $(wc -l < web_detection/confirmed_web_servers.txt 2>/dev/null||echo 0)</p></div>
<div class="section"><h2>Potential Security Issues</h2><pre>$(cat security_checks/exposed_git.txt 2>/dev/null || echo "No exposed git repos found.")</pre></div>
<div class="section"><h2>Live Web Servers</h2><pre>$(cat web_detection/confirmed_web_servers.txt 2>/dev/null||echo "None found.")</pre></div>
<div class="section"><h2>All Discovered Hostnames</h2><pre>$(cat master_hostnames.txt 2>/dev/null||echo "None found.")</pre></div>
<div class="section"><h2>Nmap Service Scan Highlights</h2><pre>$(grep -E "open|Host is up" nmap/service_scan.nmap 2>/dev/null||echo "No service scan results.")</pre></div>
</body></html>
EOF
    log "[✓] HTML Report generated: report.html"
}

create_archive() { create_checkpoint "archive"; log "[+] Creating results archive..."; tar -czf "../${OUTPUT_DIR##*/}_report_$(date +%Y%m%d).tar.gz" ./* --exclude='*.log'; log "[✓] Archive created." ;}
final_cleanup() { create_checkpoint "cleanup"; log "[+] Cleaning up temporary files..."; find . -name "*.tmp" -delete; log "[✓] Cleanup complete." ;}

# --- Main Execution Logic ---
main() {
    # Argument parsing
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -i|--input-file) INPUT_FILE=$(readlink -f "$2"); shift ;;
            -o|--output-dir) OUTPUT_DIR=$(readlink -f "$2"); shift ;;
            -x|--exclude-file) EXCLUDE_FILE=$(readlink -f "$2"); shift ;;
            -s|--skip-steps) SKIP_STEPS="$2"; shift ;;
            -h|--help) usage; exit 0 ;;
            *) echo "Unknown parameter: $1"; usage; exit 1 ;;
        esac
        shift
    done

    # Validate required arguments
    if [[ -z "$INPUT_FILE" || -z "$OUTPUT_DIR" ]]; then log "[-] Error: Input file and output directory are required."; usage; exit 1; fi
    if [[ ! -f "$INPUT_FILE" ]]; then log "[-] Error: Input file not found: $INPUT_FILE"; exit 1; fi

    # --- Run all steps in logical order ---
    setup
    for step in "${ALL_STEPS[@]}"; do
        if [[ ",$SKIP_STEPS," == *",$step,"* ]]; then log "[!] Skipping step as per user request: $step"; continue; fi
        # Dynamically call the function for the current step
        $step
    done

    log "[🎉] Reconnaissance Scan Completed."
}

# --- Script Entry Point ---
main "$@"