#!/bin/bash
set -eo pipefail

# === Configuration ===
# Default delays between operations to reduce production impact
DEFAULT_SCAN_DELAY=2  # seconds between host scans
NMAP_TIMING=3         # Reduced from T4 to T3 for production
MAX_PARALLEL_SCANS=5  # Limit concurrent operations
TIMEOUT=300           # Default timeout for operations
WORDLIST="/usr/share/wordlists/dirb/common.txt" # Default wordlist for gobuster

# === All Steps Definition ===
ALL_STEPS=("deps" "setup" "rev_ip" "subdomains" "resolve" "portscan" "servicedetect" "webtech" "webvuln" "vulndetect" "dirb" "screenshots" "misconfigs" "waf" "zonetransfer" "emails" "techdetect" "report" "archive" "cleanup")

# === Functions ===

usage() {
    echo "Usage: $0 -i <input_file> -o <output_dir> [OPTIONS]"
    echo
    echo "External Reconnaissance Tool for Production Environments."
    echo
    echo "Required:"
    echo "  -i, --input-file <file>    File with IPs or domains (one per line)."
    echo "  -o, --output-dir <dir>     Directory to store results."
    echo
    echo "Options:"
    echo "  -x, --exclude-file <file>  File with hosts to exclude from aggressive scans."
    echo "  -s, --skip-steps <steps>   Comma-separated list of steps to skip."
    echo "                             Available steps: ${ALL_STEPS[*]}"
    echo "  --resume                   Resume from the last completed checkpoint."
    echo "  --nmap-timing <0-5>        Set Nmap timing template (default: $NMAP_TIMING)."
    echo "  -t, --threads <num>        Set max parallel processes (default: $MAX_PARALLEL_SCANS)."
    echo "  --delay <secs>             Set default delay between scans (default: $DEFAULT_SCAN_DELAY)."
    echo "  -w, --wordlist <file>      Wordlist for directory bruteforcing (default: $WORDLIST)."
    echo "  -h, --help                 Display this help message."
    exit 1
}

# --- Utility Functions ---

# Function to log messages with a timestamp
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Resource Monitoring Function
monitor_resources() {
    log "[+] Current system load: $(uptime | awk -F'load average: ' '{print $2}')"
    log "[+] Memory usage: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
}

# Checkpoint Management
create_checkpoint() {
    echo "$1" >> checkpoints.log
    log "[+] Checkpoint created: $1"
}

# Dependency Check
### MODIFICATION ###: This function now only warns instead of exiting.
check_dependencies() {
    log "[+] Checking for required tools..."
    local missing_tools=0
    local tools=("nmap" "host" "subfinder" "amass" "jq" "dig" "whatweb" "nikto" "gobuster" "cutycapt" "wafw00f" "theHarvester" "wappalyzer" "sslscan" "whois" "tee" "tar")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log "[!] Warning: Required tool '$tool' is not installed. Steps depending on it will be skipped."
            missing_tools=1
        fi
    done
    if [[ $missing_tools -eq 0 ]]; then
        log "[✓] All dependencies appear to be satisfied."
    fi
}

# --- Core Logic Functions ---

# Step 1: Setup and Initialization
setup() {
    log "[+] Initializing scan in directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
    cd "$OUTPUT_DIR" || { log "[-] Failed to create/access directory"; exit 1; }

    LOG_FILE="recon_log_$(date +%Y%m%d_%H%M%S).log"
    exec > >(tee -a "$LOG_FILE") 2>&1

    log "[+] Starting External Recon and Scanning at $(date)"
    log "[+] This script includes delays to minimize impact on production systems"
    
    cp "$INPUT_FILE" ./ip.txt
    touch domains.txt subdomains.txt excluded_hosts.txt
    
    if [[ -n "$EXCLUDE_FILE" ]]; then
        log "[+] Using exclusion list from: $EXCLUDE_FILE"
        cp "$EXCLUDE_FILE" ./excluded_hosts.txt
    fi

    start_time=$(date +%s)
    echo "$start_time" > .start_time
}

# Step 2: Reverse IP Lookup
reverse_ip_lookup() {
    ### MODIFICATION ###
    if ! command -v host &>/dev/null; then log "[!] Warning: 'host' not found. Skipping reverse IP lookup."; return; fi
    create_checkpoint "rev_ip"
    log "[+] Performing Reverse IP Lookup..."
    # ... rest of the function is unchanged
    while read -r ip; do
        log "[*] Processing IP: $ip"
        if grep -qFx "$ip" excluded_hosts.txt 2>/dev/null; then
            log "[!] Skipping excluded IP: $ip"
            continue
        fi
        host "$ip" | awk '/domain name pointer/ {print $5}' | sed 's/\.$//' >> Reverse_IP_lookup.txt
        sleep "$DEFAULT_SCAN_DELAY"
    done < ip.txt

    sort -u Reverse_IP_lookup.txt -o Reverse_IP_lookup.txt
    cp Reverse_IP_lookup.txt domains.txt
    log "[✓] Reverse IP Lookup completed: $(wc -l < domains.txt) domains found"
}

# Step 3: Subdomain Enumeration
subdomain_enumeration() {
    create_checkpoint "subdomains"
    log "[+] Finding Subdomains..."
    mkdir -p subdomain_results
    while read -r domain; do
        log "[*] Enumerating subdomains for: $domain"
        ### MODIFICATION ###: Check for each tool individually.
        if command -v subfinder &>/dev/null; then
            subfinder -d "$domain" -silent -o "subdomain_results/subfinder_$domain.txt"
        else
            log "[!] Warning: 'subfinder' not found, skipping it."
        fi
        if command -v amass &>/dev/null; then
            amass enum -passive -d "$domain" -timeout "$TIMEOUT" -o "subdomain_results/amass_$domain.txt"
        else
            log "[!] Warning: 'amass' not found, skipping it."
        fi
        if command -v curl &>/dev/null && command -v jq &>/dev/null; then
            curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sort -u >> "subdomain_results/crtsh_$domain.txt"
        else
            log "[!] Warning: 'curl' or 'jq' not found, skipping crt.sh check."
        fi
        monitor_resources
        sleep $((DEFAULT_SCAN_DELAY * 2))
    done < domains.txt

    cat subdomain_results/*.txt 2>/dev/null | sort -u > Subdomains_tmp.txt
    log "[+] Filtering out potential wildcard domains..."
    grep -v "^\*\." Subdomains_tmp.txt > Subdomains.txt
    rm Subdomains_tmp.txt
    log "[✓] Subdomain enumeration completed: $(wc -l < Subdomains.txt) subdomains found"
}


# Step 4: Subdomain IP Resolution
resolve_subdomain_ips() {
    ### MODIFICATION ###
    if ! command -v dig &>/dev/null; then log "[!] Warning: 'dig' not found. Skipping subdomain IP resolution."; return; fi
    create_checkpoint "resolve"
    log "[+] Resolving Subdomain IPs (parallel processing)..."
    # ... rest of the function is unchanged
    log "[*] Resolving $(wc -l < Subdomains.txt) subdomains..."
    
    pids=()
    while read -r sub; do
        (
            ip=$(dig +short A "$sub" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
            if [[ -n "$ip" ]]; then
                echo "$ip"
                echo "$sub,$ip" >> subdomain_ip_mapping.tmp
            fi
        ) &
        pids+=($!)
        if (( ${#pids[@]} >= MAX_PARALLEL_SCANS )); then
            wait -n
        fi
    done < Subdomains.txt
    wait
    
    sort -u subdomain_ip_mapping.tmp -o subdomain_ip_mapping.txt 2>/dev/null || true
    if [[ -f subdomain_ip_mapping.txt ]]; then
      cut -d, -f2 subdomain_ip_mapping.txt | sort -u > Subdomain_IPs.txt
    fi
    rm subdomain_ip_mapping.tmp 2>/dev/null || true
    log "[✓] Subdomain IP resolution completed: $(wc -l < Subdomain_IPs.txt 2>/dev/null) IPs found"
}

# Step 5: Port Scanning
port_scanning() {
    ### MODIFICATION ###
    if ! command -v nmap &>/dev/null; then log "[!] Warning: 'nmap' not found. Skipping all port scanning."; return; fi
    create_checkpoint "portscan"
    log "[+] Running Nmap Port Scans (reduced intensity)..."
    # ... rest of the function is unchanged
    log "[*] Running top 1000 ports scan first..."
    nmap -sS -Pn --top-ports 1000 -T"$NMAP_TIMING" --max-retries 2 -iL ip.txt -oA nmap/main_ip_top_ports
    nmap -sS -Pn --top-ports 1000 -T"$NMAP_TIMING" --max-retries 2 -iL Subdomain_IPs.txt -oA nmap/subdomain_top_ports
    
    grep "open" nmap/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > hosts_with_open_ports.txt
    
    log "[*] Running full port scan ONLY on hosts with open ports..."
    if [[ -s hosts_with_open_ports.txt ]]; then
        nmap -sS -Pn -p- -T"$NMAP_TIMING" --max-retries 2 -iL hosts_with_open_ports.txt -oA nmap/all_hosts_fullscan
    fi
    log "[✓] Port scanning completed"
}

# Step 6: Service & Version Detection
service_detection() {
    ### MODIFICATION ###
    if ! command -v nmap &>/dev/null; then log "[!] Warning: 'nmap' not found. Skipping service detection."; return; fi
    create_checkpoint "servicedetect"
    log "[+] Performing Service & Version Detection..."
    # ... rest of the function is unchanged
    if [[ -f nmap/all_hosts_fullscan.gnmap ]]; then
        open_ports=$(grep -h "open" nmap/all_hosts_fullscan.gnmap | cut -d' ' -f4- | tr -d ' ' | sed 's|/open/[a-zA-Z-]*||g' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$open_ports" ]]; then
            log "[*] Scanning only identified open ports for services..."
            nmap -sV -O --version-intensity 4 -p"$open_ports" -T"$NMAP_TIMING" -iL hosts_with_open_ports.txt -oA nmap/services_os_scan
        fi
    fi
    log "[✓] Service detection completed"
}

# Step 7: Web Technology Detection (WhatWeb)
web_stack_detection() {
    ### MODIFICATION ###
    if ! command -v whatweb &>/dev/null; then log "[!] Warning: 'whatweb' not found. Skipping WhatWeb technology detection."; return; fi
    create_checkpoint "webtech"
    log "[+] Running Web Technology Detection..."
    # ... rest of the function is unchanged
    grep -h "open" nmap/*.gnmap 2>/dev/null | grep -E "http|web|ssl" | cut -d' ' -f2 | sort -u > potential_web_hosts.txt
    > web_servers.txt
    while read -r host; do
        echo "http://$host" >> web_servers.txt
        echo "https://$host" >> web_servers.txt
    done < potential_web_hosts.txt

    log "[*] Running WhatWeb on $(wc -l < web_servers.txt) potential URLs..."
    whatweb --no-errors --max-threads 5 --wait 5 -i web_servers.txt -a 3 --log-json=web_detection/whatweb_results.json
    if [[ -f web_detection/whatweb_results.json ]]; then
      jq -r '.[] | .target' web_detection/whatweb_results.json > confirmed_web_servers.txt
    fi
    log "[✓] Web technology detection completed"
}

# Step 8: Safe Web Vulnerability Scanning (Nikto)
web_vulnerability_scan() {
    ### MODIFICATION ###
    if ! command -v nikto &>/dev/null; then log "[!] Warning: 'nikto' not found. Skipping web vulnerability scan."; return; fi
    create_checkpoint "webvuln"
    log "[+] Running Lightweight Web Vulnerability Scan..."
    # ... rest of the function is unchanged
    if [[ ! -s confirmed_web_servers.txt ]]; then
        log "[!] No confirmed web servers found. Skipping Nikto scan."
        return
    fi
    log "[*] Performing light Nikto scan on $(wc -l < confirmed_web_servers.txt) web servers..."
    while read -r target; do
        log "[*] Scanning $target (with timeout and tuning)..."
        sanitized_target=$(echo "$target" | tr -c '[:alnum:].' '_')
        timeout "$TIMEOUT" nikto -h "$target" -Tuning 4 -maxtime 15m -o "vulnerability_scan/nikto_$sanitized_target.txt"
        sleep $((DEFAULT_SCAN_DELAY * 3))
        monitor_resources
    done < confirmed_web_servers.txt
    log "[✓] Web vulnerability scanning completed"
}

# Step 9: Selective Vulnerability Detection (Nmap Scripts)
vulnerability_detection() {
    ### MODIFICATION ###
    if ! command -v nmap &>/dev/null; then log "[!] Warning: 'nmap' not found. Skipping Nmap vulnerability detection."; return; fi
    create_checkpoint "vulndetect"
    log "[+] Running Targeted Vulnerability Scans with Nmap NSE..."
    # ... rest of the function is unchanged
    grep -h "open" nmap/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > nmap_targets.txt
    if [[ ! -s nmap_targets.txt ]]; then
        log "[!] No targets for Nmap scripting. Skipping."
        return
    fi
    log "[*] Checking for common vulnerabilities (non-intrusive scripts)..."
    nmap -sV --script "vuln" --script-args "unsafe=0" -T"$NMAP_TIMING" -iL nmap_targets.txt -oA vuln_scan/nmap_vuln_scan
    log "[✓] Vulnerability detection completed"
}

# Step 10: Directory Bruteforcing (gobuster)
directory_bruteforcing() {
    ### MODIFICATION ###
    if ! command -v gobuster &>/dev/null; then log "[!] Warning: 'gobuster' not found. Skipping directory bruteforcing."; return; fi
    create_checkpoint "dirb"
    log "[+] Performing Directory Bruteforcing..."
    # ... rest of the function is unchanged
    if [[ ! -s confirmed_web_servers.txt ]]; then
        log "[!] No confirmed web servers. Skipping dirb."
        return
    fi
    if [[ ! -f "$WORDLIST" ]]; then
        log "[-] Wordlist not found at $WORDLIST. Skipping directory bruteforcing."
        return
    fi
    while read -r target; do
        sanitized_target=$(echo "$target" | tr -c '[:alnum:].' '_')
        log "[*] Directory bruteforcing on $target"
        gobuster dir -u "$target" -w "$WORDLIST" -q -t 10 -o "dirb_reports/gobuster_$sanitized_target.txt" --delay 500ms
        sleep 5
    done < confirmed_web_servers.txt
    log "[✓] Directory bruteforcing completed."
}

# Step 11: Screenshot Web Pages
take_screenshots() {
    ### MODIFICATION ###
    if ! command -v cutycapt &>/dev/null; then log "[!] Warning: 'cutycapt' not found. Skipping screenshots."; return; fi
    create_checkpoint "screenshots"
    log "[+] Taking Screenshots of Web Pages..."
    # ... rest of the function is unchanged
    if [[ ! -s confirmed_web_servers.txt ]]; then
        log "[!] No confirmed web servers. Skipping screenshots."
        return
    fi
    while read -r target; do
        sanitized_target=$(echo "$target" | tr -c '[:alnum:].' '_')
        log "[*] Capturing screenshot of $target"
        timeout 30s cutycapt --url="$target" --out="screenshots/$sanitized_target.png" 2>/dev/null
        sleep 2
    done < confirmed_web_servers.txt
    log "[✓] Screenshots completed."
}

# Step 12: Check for Common Security Misconfigurations
check_misconfigs() {
    ### MODIFICATION ###
    if ! command -v curl &>/dev/null; then log "[!] Warning: 'curl' not found. Skipping misconfiguration checks."; return; fi
    create_checkpoint "misconfigs"
    log "[+] Checking for Common Security Misconfigurations..."
    # ... rest of the function is unchanged
    if [[ ! -s confirmed_web_servers.txt ]]; then
        log "[!] No confirmed web servers. Skipping misconfig checks."
        return
    fi
    log "[*] Checking for exposed .git directories and environment files..."
    while read -r target; do
        if curl -sIk --connect-timeout 5 "$target/.git/HEAD" | grep -q "200 OK"; then
            echo "$target has exposed .git directory" >> security_checks/exposed_git.txt
        fi
        for file in ".env" ".env.backup" "wp-config.php" "database.yml"; do
            if curl -sIk --connect-timeout 5 "$target/$file" | grep -q "200 OK"; then
                echo "$target has exposed $file" >> security_checks/exposed_config.txt
            fi
        done
        sleep 1
    done < confirmed_web_servers.txt
    log "[✓] Misconfiguration checks completed."
}

# Step 13: WAF Detection
detect_waf() {
    ### MODIFICATION ###
    if ! command -v wafw00f &>/dev/null; then log "[!] Warning: 'wafw00f' not found. Skipping WAF detection."; return; fi
    create_checkpoint "waf"
    log "[+] Detecting Web Application Firewalls..."
    # ... rest of the function is unchanged
    if [[ ! -s Subdomains.txt ]]; then log "[!] No subdomains to check for WAF."; return; fi
    wafw00f -i Subdomains.txt -o waf_detection/waf_report.txt 2>/dev/null
    log "[✓] WAF detection completed."
}

# Step 14: DNS Zone Transfer Attempt
zone_transfer() {
    ### MODIFICATION ###
    if ! command -v dig &>/dev/null; then log "[!] Warning: 'dig' not found. Skipping zone transfer attempts."; return; fi
    create_checkpoint "zonetransfer"
    log "[+] Attempting DNS Zone Transfers..."
    # ... rest of the function is unchanged
    while read -r domain; do
        log "[*] Checking zone transfer for $domain"
        for ns in $(dig +short NS "$domain"); do
            dig @"$ns" "$domain" AXFR > "dns_info/zonetransfer_${domain}_${ns}.txt"
        done
        sleep 1
    done < domains.txt
    log "[✓] DNS Zone Transfer attempts completed."
}

# Step 15: Email Harvesting
harvest_emails() {
    ### MODIFICATION ###
    if ! command -v theHarvester &>/dev/null; then log "[!] Warning: 'theHarvester' not found. Skipping email harvesting."; return; fi
    create_checkpoint "emails"
    log "[+] Harvesting Email Addresses..."
    # ... rest of the function is unchanged
    while read -r domain; do
        log "[*] Searching for emails related to $domain"
        theHarvester -d "$domain" -b google,bing -f "email_harvest/$domain.html"
        sleep 10
    done < domains.txt
    log "[✓] Email harvesting completed."
}

# Step 16: Technologies Identification (Wappalyzer)
detect_technologies() {
    ### MODIFICATION ###: This directly addresses your request.
    if ! command -v wappalyzer &>/dev/null; then
        log "[!] Warning: 'wappalyzer' not found. Skipping technology detection with Wappalyzer."
        return
    fi
    create_checkpoint "techdetect"
    log "[+] Identifying Technologies with Wappalyzer CLI..."
    if [[ ! -s confirmed_web_servers.txt ]]; then log "[!] No web servers for tech detection."; return; fi
    while read -r target; do
        sanitized_target=$(echo "$target" | tr -c '[:alnum:].' '_')
        log "[*] Detecting technologies on $target"
        wappalyzer "$target" > "tech_detection/wappalyzer_$sanitized_target.json" 2>/dev/null
        sleep 3
    done < confirmed_web_servers.txt
    log "[✓] Technology identification completed."
}

# Step 17: Generate HTML Report
generate_report() {
    create_checkpoint "report"
    log "[+] Generating HTML Report..."
    # This function is unchanged as it only uses built-in commands
    report_date=$(date +"%Y-%m-%d")
    cat > report.html <<-EOF
<!DOCTYPE html>
<html><head><title>Recon Report - $report_date</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; color: #333; }
h1, h2, h3 { color: #2c3e50; }
pre { background-color: #eee; padding: 10px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }
.section { margin-bottom: 20px; padding: 15px; background-color: #fff; border: 1px solid #ddd; border-radius: 5px; }
.summary { background-color: #eaf2f8; }
</style></head><body>
<h1>External Reconnaissance Report</h1>
<div class="section summary"><h2>Summary</h2>
<p><strong>Date:</strong> $report_date</p>
<p><strong>Domains:</strong> $(wc -l < domains.txt 2>/dev/null || echo 0)</p>
<p><strong>Subdomains:</strong> $(wc -l < Subdomains.txt 2>/dev/null || echo 0)</p>
<p><strong>Web Servers:</strong> $(wc -l < confirmed_web_servers.txt 2>/dev/null || echo 0)</p>
</div>
<div class="section"><h2>Domains</h2><pre>$(cat domains.txt 2>/dev/null || echo "No domains found.")</pre></div>
<div class="section"><h2>Subdomains</h2><pre>$(head -50 Subdomains.txt 2>/dev/null || echo "No subdomains found.")</pre></div>
<div class="section"><h2>Open Ports & Services (Sample)</h2><pre>$(head -50 nmap/services_os_scan.nmap 2>/dev/null || echo "No service scan results.")</pre></div>
<div class="section"><h2>Potential Security Issues</h2><pre>$(cat security_checks/exposed_git.txt 2>/dev/null || echo "None found.")
$(cat security_checks/exposed_config.txt 2>/dev/null || echo "None found.")</pre></div>
</body></html>
EOF
    log "[✓] HTML Report generated: report.html"
}

# Step 18: Create Results Archive
create_archive() {
    create_checkpoint "archive"
    log "[+] Creating Results Archive..."
    # This function is unchanged
    archive_name="../${OUTPUT_DIR##*/}_report_$(date +%Y%m%d).tar.gz"
    tar -czf "$archive_name" ./* --exclude='*.log'
    log "[✓] Archive created: $archive_name"
}

# Step 19: Final Cleanup
final_cleanup() {
    create_checkpoint "cleanup"
    log "[+] Cleaning up temporary files..."
    find . -name "*.tmp" -delete
}


# --- Main Execution Logic ---

main() {
    # Argument parsing
    SKIP_STEPS=""
    RESUME=0

    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -i|--input-file) INPUT_FILE="$2"; shift ;;
            -o|--output-dir) OUTPUT_DIR="$2"; shift ;;
            -x|--exclude-file) EXCLUDE_FILE="$2"; shift ;;
            -s|--skip-steps) SKIP_STEPS="$2"; shift ;;
            --resume) RESUME=1 ;;
            -t|--threads) MAX_PARALLEL_SCANS="$2"; shift ;;
            --nmap-timing) NMAP_TIMING="$2"; shift ;;
            --delay) DEFAULT_SCAN_DELAY="$2"; shift ;;
            -w|--wordlist) WORDLIST="$2"; shift ;;
            -h|--help) usage ;;
            *) echo "Unknown parameter passed: $1"; usage ;;
        esac
        shift
    done

    # Validate required arguments
    if [[ -z "$INPUT_FILE" || -z "$OUTPUT_DIR" ]]; then
        log "[-] Error: Input file and output directory are required."
        usage
    fi
    if [[ ! -f "$INPUT_FILE" ]]; then
        log "[-] Error: Input file not found: $INPUT_FILE"
        exit 1
    fi
    
    # Create an array of completed steps if resuming
    COMPLETED_STEPS=()
    if [[ "$RESUME" -eq 1 && -f "$OUTPUT_DIR/checkpoints.log" ]]; then
        mapfile -t COMPLETED_STEPS < "$OUTPUT_DIR/checkpoints.log"
        log "[+] Resuming scan. Found ${#COMPLETED_STEPS[@]} completed steps."
    fi

    # Execute all steps unless skipped
    for step in "${ALL_STEPS[@]}"; do
        # Check if step should be skipped via command line
        if [[ ",$SKIP_STEPS," == *",$step,"* ]]; then
            # We don't log during 'setup' because the log file isn't configured yet.
            if [[ "$step" != "setup" ]]; then
                log "[!] Skipping step as per user request: $step"
            fi
            continue
        fi

        # Check if step should be skipped due to resume
        if [[ "$RESUME" -eq 1 ]]; then
            for completed in "${COMPLETED_STEPS[@]}"; do
                if [[ "$step" == "$completed" ]]; then
                    log "[!] Skipping already completed step: $step"
                    # Use 'continue 2' to break out of the inner loop and continue the outer one
                    continue 2
                fi
            done
        fi
        
        # Create directories for results if they don't exist
        case "$step" in
            rev_ip|subdomains|resolve) : ;; # No specific dir needed for these
            *) mkdir -p "${step//detect/detection}" "${step//scan/scans}" "${step//_//}" &>/dev/null ;;
        esac

        # Call the corresponding function
        case "$step" in
            deps) check_dependencies ;;
            setup) setup ;;
            rev_ip) reverse_ip_lookup ;;
            subdomains) subdomain_enumeration ;;
            resolve) resolve_subdomain_ips ;;
            portscan) port_scanning ;;
            servicedetect) service_detection ;;
            webtech) web_stack_detection ;;
            webvuln) web_vulnerability_scan ;;
            vulndetect) vulnerability_detection ;;
            dirb) directory_bruteforcing ;;
            screenshots) take_screenshots ;;
            misconfigs) check_misconfigs ;;
            waf) detect_waf ;;
            zonetransfer) zone_transfer ;;
            emails) harvest_emails ;;
            techdetect) detect_technologies ;;
            report) generate_report ;;
            archive) create_archive ;;
            cleanup) final_cleanup ;;
        esac
    done

    # --- Completion ---
    log "[✓] External Recon and Scanning Completed."
    start_time=$(cat .start_time 2>/dev/null || date +%s)
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    hours=$((duration / 3600)); minutes=$(((duration % 3600) / 60)); seconds=$((duration % 60))
    log "[⏱️] Total execution time: ${hours}h ${minutes}m ${seconds}s"
}

# Run the main function
main "$@"