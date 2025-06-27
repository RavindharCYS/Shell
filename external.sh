#!/bin/bash

# === Configuration ===
# Default delays between operations to reduce production impact
DEFAULT_SCAN_DELAY=2  # seconds between host scans
NMAP_TIMING=3         # Reduced from T4 to T3 for production
MAX_PARALLEL_SCANS=5  # Limit concurrent operations
TIMEOUT=300           # Default timeout for operations

# === Setup and Initialization ===
echo "[+] External Reconnaissance Tool for Production Environments"
echo "[+] Enter directory name for storing results:"
read result_dir

# Create directory to store outputs
mkdir -p "$result_dir"
cd "$result_dir" || { echo "[-] Failed to create/access directory"; exit 1; }

# Initialize log file
LOG_FILE="recon_log_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[+] Starting External Recon and Scanning at $(date)"
echo "[+] This script includes delays to minimize impact on production systems"

# === Input Validation ===
if [[ ! -f ../ip.txt ]]; then
    echo "[-] Error: ip.txt file not found in parent directory"
    exit 1
fi

# Copy and initialize files
cp ../ip.txt .
touch subdomain_ip.txt domains.txt subdomains.txt excluded_hosts.txt

# === Exclusion Configuration ===
echo "[+] Do you want to exclude any critical hosts from aggressive scanning? (y/n)"
read exclude_response
if [[ "$exclude_response" == "y" ]]; then
    echo "[+] Enter hosts to exclude (one per line, empty line to finish):"
    while true; do
        read exclude_host
        [[ -z "$exclude_host" ]] && break
        echo "$exclude_host" >> excluded_hosts.txt
    done
fi

# === Resource Monitoring Function ===
monitor_resources() {
    echo "[+] Current system load: $(uptime | awk '{print $10 $11 $12}')"
    echo "[+] Memory usage: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
}

# === Checkpoint Management ===
create_checkpoint() {
    echo "CHECKPOINT: $1" >> checkpoints.txt
    echo "[+] Checkpoint created: $1"
}

resume_from_checkpoint() {
    if [[ -f checkpoints.txt ]]; then
        last_checkpoint=$(tail -n 1 checkpoints.txt | cut -d':' -f2- | xargs)
        echo "[+] Found checkpoint: $last_checkpoint"
        echo "[+] Resume from this checkpoint? (y/n)"
        read resume_response
        if [[ "$resume_response" == "y" ]]; then
            return 0
        fi
    fi
    return 1
}

# === Step 1: Reverse IP Lookup with delay ===
reverse_ip_lookup() {
    echo "[+] Performing Reverse IP Lookup..."
    create_checkpoint "reverse_ip_lookup"
    
    while read -r ip; do
        echo "[*] Processing IP: $ip"
        if grep -q "$ip" excluded_hosts.txt 2>/dev/null; then
            echo "[!] Skipping excluded IP: $ip"
            continue
        fi
        
        host "$ip" | grep "domain name pointer" | awk '{print $5}' >> Reverse_IP_lookup.txt
        sleep $DEFAULT_SCAN_DELAY
    done < ip.txt

    sort -u Reverse_IP_lookup.txt -o Reverse_IP_lookup.txt
    cp Reverse_IP_lookup.txt domains.txt
    echo "[✓] Reverse IP Lookup completed: $(wc -l < domains.txt) domains found"
}

# === Step 2: Subdomain Enumeration with advanced tools ===
subdomain_enumeration() {
    echo "[+] Finding Subdomains..."
    create_checkpoint "subdomain_enumeration"
    
    mkdir -p subdomain_results
    
    while read -r domain; do
        echo "[*] Enumerating subdomains for: $domain"
        
        # Run multiple tools with delay between domains
        echo "[*] Running Subfinder..."
        subfinder -d "$domain" -silent >> subdomain_results/subfinder_"$domain".txt
        
        echo "[*] Running Amass passive scan (limited for production)..."
        amass enum -passive -d "$domain" -timeout $TIMEOUT >> subdomain_results/amass_"$domain".txt
        
        echo "[*] Checking Certificate Transparency logs..."
        curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sort -u >> subdomain_results/crtsh_"$domain".txt
        
        # Combine and deduplicate results
        cat subdomain_results/*_"$domain".txt | sort -u >> Subdomains.txt
        
        # Monitor resource usage
        monitor_resources
        
        # Delay between domains
        sleep $(($DEFAULT_SCAN_DELAY * 2))
    done < domains.txt

    sort -u Subdomains.txt -o Subdomains.txt
    echo "[✓] Subdomain enumeration completed: $(wc -l < Subdomains.txt) subdomains found"
    
    # Filter out wildcard domains
    echo "[+] Filtering out potential wildcard domains..."
    grep -v "^\*\." Subdomains.txt > Subdomains_filtered.txt
    mv Subdomains_filtered.txt Subdomains.txt
}

# === Step 3: Subdomain IP Resolution with parallel processing ===
resolve_subdomain_ips() {
    echo "[+] Resolving Subdomain IPs (with parallel processing)..."
    create_checkpoint "resolve_subdomain_ips"
    
    total_subdomains=$(wc -l < Subdomains.txt)
    echo "[*] Resolving $total_subdomains subdomains..."
    
    > Subdomain_IPs.txt
    > subdomain_ip_mapping.txt
    
    # Split subdomains file for parallel processing
    split -l 100 Subdomains.txt subdomains_chunk_
    
    for chunk in subdomains_chunk_*; do
        (
            while read -r sub; do
                ip=$(dig +short "$sub" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
                if [[ ! -z "$ip" ]]; then
                    echo "$ip" >> Subdomain_IPs.txt.tmp
                    echo "$sub,$ip" >> subdomain_ip_mapping.txt.tmp
                fi
                sleep 0.5  # Small delay between DNS queries
            done < "$chunk"
        ) &
        
        # Limit number of parallel processes
        while [[ $(jobs -r | wc -l) -ge $MAX_PARALLEL_SCANS ]]; do
            sleep 1
        done
    done
    
    # Wait for all resolution jobs to complete
    wait
    
    # Combine temporary files
    cat Subdomain_IPs.txt.tmp 2>/dev/null >> Subdomain_IPs.txt
    cat subdomain_ip_mapping.txt.tmp 2>/dev/null >> subdomain_ip_mapping.txt
    rm -f Subdomain_IPs.txt.tmp subdomain_ip_mapping.txt.tmp subdomains_chunk_*
    
    sort -u Subdomain_IPs.txt -o Subdomain_IPs.txt
    sort -u subdomain_ip_mapping.txt -o subdomain_ip_mapping.txt
    
    echo "[✓] Subdomain IP resolution completed: $(wc -l < Subdomain_IPs.txt) IPs found"
}

# === Step 4: Port Scanning with decreased intensity ===
port_scanning() {
    echo "[+] Running Nmap Port Scans (with reduced intensity for production)..."
    create_checkpoint "port_scanning"
    
    # More careful approach for production
    echo "[*] Running top ports scan first..."
    nmap -sS -Pn --top-ports 1000 -T$NMAP_TIMING --max-retries 2 --host-timeout 30m -iL ip.txt -oA main_ip_top_ports
    nmap -sS -Pn --top-ports 1000 -T$NMAP_TIMING --max-retries 2 --host-timeout 30m -iL Subdomain_IPs.txt -oA subdomain_top_ports
    
    # Extract open ports for targeted full scan
    grep "open" main_ip_top_ports.gnmap | cut -d' ' -f2 > hosts_with_open_ports.txt
    grep "open" subdomain_top_ports.gnmap | cut -d' ' -f2 > subdomain_hosts_with_open_ports.txt
    
    echo "[*] Running full scan only on hosts with open ports..."
    if [[ -s hosts_with_open_ports.txt ]]; then
        nmap -sS -Pn -p- -T$NMAP_TIMING --max-retries 2 --host-timeout 60m -iL hosts_with_open_ports.txt -oA main_ip_fullscan
    fi
    
    if [[ -s subdomain_hosts_with_open_ports.txt ]]; then
        nmap -sS -Pn -p- -T$NMAP_TIMING --max-retries 2 --host-timeout 60m -iL subdomain_hosts_with_open_ports.txt -oA subdomain_fullscan
    fi
    
    echo "[✓] Port scanning completed"
}

# === Step 5: Service Detection with selective version scanning ===
service_detection() {
    echo "[+] Performing Service & OS Detection (carefully)..."
    create_checkpoint "service_detection"
    
    # Extract open ports for more efficient service scanning
    if [[ -f main_ip_fullscan.gnmap ]]; then
        open_ports_main=$(grep -h "open" main_ip_fullscan.gnmap | cut -d' ' -f4- | tr ',' '\n' | grep "open" | cut -d'/' -f1 | sort -u | tr '\n' ',')
        if [[ ! -z "$open_ports_main" ]]; then
            echo "[*] Scanning only open ports on main IPs..."
            nmap -sV -O --version-intensity 4 -p"${open_ports_main%,}" -T$NMAP_TIMING -iL hosts_with_open_ports.txt -oA main_ip_service_os
        fi
    fi
    
    if [[ -f subdomain_fullscan.gnmap ]]; then
        open_ports_sub=$(grep -h "open" subdomain_fullscan.gnmap | cut -d' ' -f4- | tr ',' '\n' | grep "open" | cut -d'/' -f1 | sort -u | tr '\n' ',')
        if [[ ! -z "$open_ports_sub" ]]; then
            echo "[*] Scanning only open ports on subdomain IPs..."
            nmap -sV -O --version-intensity 4 -p"${open_ports_sub%,}" -T$NMAP_TIMING -iL subdomain_hosts_with_open_ports.txt -oA subdomain_service_os
        fi
    fi
    
    echo "[✓] Service detection completed"
}

# === Step 6: Enhanced Web Stack Detection ===
web_stack_detection() {
    echo "[+] Running Web Technology Detection..."
    create_checkpoint "web_stack_detection"
    
    mkdir -p web_detection
    
    # Extract web servers from Nmap results
    echo "[*] Identifying web servers from Nmap results..."
    grep -h "open" *_service_os.gnmap | grep -E "http|web|ssl" > potential_web_servers.txt
    
    # Combine with all subdomains for thorough checks
    echo "[*] Checking all subdomains for web services..."
    
    > web_servers.txt
    while read -r sub; do
        echo "http://$sub" >> web_servers.txt
        echo "https://$sub" >> web_servers.txt
    done < Subdomains.txt
    
    # Run WhatWeb with rate limiting
    echo "[*] Running WhatWeb on $(wc -l < web_servers.txt) potential web servers..."
    whatweb --no-errors --max-threads 5 --wait 5 -i web_servers.txt -v -a 3 --log-json=web_detection/whatweb_results.json
    
    # Generate readable report
    cat web_detection/whatweb_results.json | jq -r '.[] | "[" + .target + "] " + (.plugins | to_entries | map(.key + ": " + (.value | tostring)) | join(", "))' > web_detection/whatweb_summary.txt
    
    echo "[✓] Web technology detection completed"
}

# === Step 7: Safe Web Vulnerability Scanning ===
web_vulnerability_scan() {
    echo "[+] Running Lightweight Web Vulnerability Scan..."
    create_checkpoint "web_vulnerability_scan"
    
    mkdir -p vulnerability_scan
    
    # Extract confirmed web servers from WhatWeb results
    jq -r '.[] | .target' web_detection/whatweb_results.json > confirmed_web_servers.txt
    
    echo "[*] Performing light Nikto scan on $(wc -l < confirmed_web_servers.txt) web servers..."
    cat confirmed_web_servers.txt | while read -r target; do
        echo "[*] Scanning $target (with timeout and tuning for production)..."
        # Use a more targeted scan with specific security checks
        timeout $TIMEOUT nikto -h "$target" -Tuning 4 -maxtime 15m -o vulnerability_scan/nikto_$(echo "$target" | sed 's/[:/]/_/g').txt
        
        # Respect the server by waiting between scans
        sleep $((DEFAULT_SCAN_DELAY * 3))
        monitor_resources
    done
    
    echo "[✓] Web vulnerability scanning completed"
}

# === Step 8: Selective Vulnerability Detection ===
vulnerability_detection() {
    echo "[+] Running Targeted Vulnerability Scans..."
    create_checkpoint "vulnerability_detection"
    
    mkdir -p vuln_scan
    
    # Run Nmap vulnerability scan only on specific services known to be vulnerable
    echo "[*] Extracting service information for targeted vulnerability scanning..."
    
    # Find SSH servers for specific checks
    grep -h "open" *_service_os.gnmap | grep "ssh" > ssh_servers.txt
    if [[ -s ssh_servers.txt ]]; then
        echo "[*] Checking SSH servers for vulnerabilities..."
        nmap -sV --script "ssh* and not brute and not dos" -p 22 -iL ssh_servers.txt -oA vuln_scan/ssh_vulns
    fi
    
    # Find web servers for specific checks
    grep -h "open" *_service_os.gnmap | grep -E "http|https" > http_servers.txt
    if [[ -s http_servers.txt ]]; then
        echo "[*] Checking web servers for vulnerabilities..."
        nmap -sV --script "http-vuln* and not dos and not brute" -p 80,443,8080,8443 -iL http_servers.txt -oA vuln_scan/http_vulns
    fi
    
    # Find database servers
    grep -h "open" *_service_os.gnmap | grep -E "mysql|mssql|oracle|postgresql" > db_servers.txt
    if [[ -s db_servers.txt ]]; then
        echo "[*] Checking database servers for security issues..."
        nmap -sV --script "mysql* or mssql* or oracle* or postgresql* and not brute and not dos" -iL db_servers.txt -oA vuln_scan/db_vulns
    fi
    
    echo "[✓] Vulnerability detection completed"
}

# === Step 9: Additional Recon ===
additional_recon() {
    echo "[+] Performing Additional Reconnaissance..."
    create_checkpoint "additional_recon"
    
    mkdir -p additional_info
    
    # DNS records for domains
    echo "[*] Gathering DNS records for domains..."
    while read -r domain; do
        echo "[*] DNS records for $domain" >> additional_info/dns_records.txt
        for record in A AAAA MX NS TXT SOA CNAME; do
            dig +short $record $domain >> additional_info/dns_records.txt
        done
        echo "---------------------" >> additional_info/dns_records.txt
        sleep $DEFAULT_SCAN_DELAY
    done < domains.txt
    
    # WHOIS information
    echo "[*] Gathering WHOIS information..."
    while read -r domain; do
        whois $domain > additional_info/whois_${domain}.txt
        sleep $DEFAULT_SCAN_DELAY
    done < domains.txt
    
    # SSL/TLS information for HTTPS sites
    echo "[*] Checking SSL/TLS configurations..."
    grep "https" confirmed_web_servers.txt | while read -r target; do
        host=$(echo $target | sed 's|https://||')
        echo "[*] Checking SSL for $host..."
        timeout $TIMEOUT sslscan --no-failed $host > additional_info/ssl_${host}.txt
        sleep $DEFAULT_SCAN_DELAY
    done
    # === Step 9: Directory Bruteforcing with rate limiting ===
echo "[+] Performing Directory Bruteforcing on Web Servers..."
mkdir -p dirb_reports
while read -r sub; do
    # Check if host is up and running HTTP/HTTPS before scanning
    if curl -s --head --connect-timeout 3 "http://$sub" >/dev/null || curl -s --head --connect-timeout 3 "https://$sub" >/dev/null; then
        echo "[*] Directory bruteforcing on $sub"
        # Use gobuster with rate limiting for production safety
        gobuster dir -u "http://$sub" -w /usr/share/wordlists/dirb/common.txt -q -t 5 -o "dirb_reports/gobuster_$sub.txt" --delay 500ms
        sleep 5  # Delay between hosts to reduce load
    fi
done < Subdomains.txt

# === Step 10: Screenshot Web Pages ===
echo "[+] Taking Screenshots of Web Pages..."
mkdir -p screenshots
while read -r sub; do
    echo "[*] Capturing screenshot of $sub"
    # Use cutycapt or aquatone for screenshots
    timeout 30s cutycapt --url="http://$sub" --out="screenshots/$sub.png" 2>/dev/null
    if [ ! -f "screenshots/$sub.png" ] || [ ! -s "screenshots/$sub.png" ]; then
        timeout 30s cutycapt --url="https://$sub" --out="screenshots/$sub.png" 2>/dev/null
    fi
    sleep 2  # Add delay between screenshots
done < Subdomains.txt

# === Step 11: Check for Common Security Misconfigurations ===
echo "[+] Checking for Common Security Misconfigurations..."
mkdir -p security_checks

# Check for exposed .git directories
echo "[*] Checking for exposed .git directories..."
while read -r sub; do
    if curl -s --head --connect-timeout 3 "http://$sub/.git/HEAD" | grep -q "200 OK"; then
        echo "$sub has exposed .git directory" >> security_checks/exposed_git.txt
    elif curl -s --head --connect-timeout 3 "https://$sub/.git/HEAD" | grep -q "200 OK"; then
        echo "$sub has exposed .git directory" >> security_checks/exposed_git.txt
    fi
    sleep 1
done < Subdomains.txt

# Check for exposed environment files
echo "[*] Checking for exposed environment files..."
while read -r sub; do
    for file in ".env" ".env.backup" ".env.dev" "wp-config.php" "config.php" "settings.php" "database.yml"; do
        if curl -s --head --connect-timeout 3 "http://$sub/$file" | grep -q "200 OK"; then
            echo "$sub has exposed $file" >> security_checks/exposed_config.txt
        elif curl -s --head --connect-timeout 3 "https://$sub/$file" | grep -q "200 OK"; then
            echo "$sub has exposed $file" >> security_checks/exposed_config.txt
        fi
        sleep 0.5
    done
done < Subdomains.txt

# === Step 12: WAF Detection ===
echo "[+] Detecting Web Application Firewalls..."
mkdir -p waf_detection
while read -r sub; do
    echo "[*] Checking for WAF on $sub"
    wafw00f "http://$sub" -o "waf_detection/waf_$sub.txt" 2>/dev/null
    sleep 2
done < Subdomains.txt

# === Step 13: DNS Zone Transfer Attempt ===
echo "[+] Attempting DNS Zone Transfers..."
mkdir -p dns_info
while read -r domain; do
    echo "[*] Checking zone transfer for $domain"
    # Get name servers
    ns_servers=$(dig +short NS $domain)
    for ns in $ns_servers; do
        dig @$ns $domain AXFR > "dns_info/zonetransfer_${domain}_${ns}.txt"
    done
    sleep 1
done < domains.txt

# === Step 14: Email Harvesting ===
echo "[+] Harvesting Email Addresses..."
mkdir -p email_harvest
while read -r domain; do
    echo "[*] Searching for emails related to $domain"
    theHarvester -d $domain -b google,bing,yahoo -f "email_harvest/$domain.html"
    sleep 5  # Significant delay to avoid API rate limits
done < domains.txt

# === Step 15: Technologies Identification ===
echo "[+] Identifying Technologies with Wappalyzer CLI..."
mkdir -p tech_detection
while read -r sub; do
    if curl -s --head --connect-timeout 3 "http://$sub" >/dev/null; then
        echo "[*] Detecting technologies on http://$sub"
        wappalyzer "http://$sub" > "tech_detection/wappalyzer_http_$sub.json" 2>/dev/null
    fi
    if curl -s --head --connect-timeout 3 "https://$sub" >/dev/null; then
        echo "[*] Detecting technologies on https://$sub"
        wappalyzer "https://$sub" > "tech_detection/wappalyzer_https_$sub.json" 2>/dev/null
    fi
    sleep 3
done < Subdomains.txt

# === Step 16: Generate HTML Report ===
echo "[+] Generating HTML Report..."
report_date=$(date +"%Y-%m-%d")
cat > report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Reconnaissance Report - $report_date</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #2c3e50; }
        .section { margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>External Reconnaissance Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Date:</strong> $report_date</p>
        <p><strong>Target IPs:</strong> $(wc -l < ip.txt)</p>
        <p><strong>Domains Discovered:</strong> $(wc -l < domains.txt)</p>
        <p><strong>Subdomains Discovered:</strong> $(wc -l < Subdomains.txt)</p>
        <p><strong>Subdomain IPs:</strong> $(wc -l < Subdomain_IPs.txt)</p>
    </div>
    
    <div class="section">
        <h2>Domains</h2>
        <table>
            <tr><th>Domain</th></tr>
EOF

# Add domains to the report
while read -r domain; do
    echo "<tr><td>$domain</td></tr>" >> report.html
done < domains.txt

cat >> report.html << EOF
        </table>
    </div>
    
    <div class="section">
        <h2>Top Subdomains</h2>
        <table>
            <tr><th>Subdomain</th></tr>
EOF

# Add top 20 subdomains to the report
head -20 Subdomains.txt | while read -r sub; do
    echo "<tr><td>$sub</td></tr>" >> report.html
done

cat >> report.html << EOF
        </table>
    </div>
    
    <div class="section">
        <h2>Open Ports Summary</h2>
        <p>See detailed Nmap reports for complete information.</p>
    </div>
    
    <div class="section">
        <h2>Web Servers</h2>
        <p>Screenshots of web pages are available in the screenshots directory.</p>
    </div>
    
    <div class="section">
        <h2>Potential Security Issues</h2>
        <ul>
EOF

# Add security issues if found
if [ -f security_checks/exposed_git.txt ]; then
    cat security_checks/exposed_git.txt | while read -r line; do
        echo "<li>$line</li>" >> report.html
    done
fi

if [ -f security_checks/exposed_config.txt ]; then
    cat security_checks/exposed_config.txt | while read -r line; do
        echo "<li>$line</li>" >> report.html
    done
fi

cat >> report.html << EOF
        </ul>
    </div>
    
    <div class="section">
        <h2>Next Steps</h2>
        <ul>
            <li>Review all open ports and consider implementing firewall rules</li>
            <li>Investigate potential security issues flagged in this report</li>
            <li>Consider more in-depth testing for critical applications</li>
            <li>Review DNS configurations and domain exposure</li>
        </ul>
    </div>
</body>
</html>
EOF

# === Step 17: Create Results Archive ===
echo "[+] Creating Results Archive..."
tar -czf "../${result_dir}_report_${report_date}.tar.gz" *

# === Step 18: Final Cleanup ===
echo "[+] Cleaning Temporary Files..."
find . -name "*.tmp" -delete

# === Completion ===
echo "[✓] External Recon and Scanning Completed."
echo "[📁] Results saved in directory: $result_dir"
echo "[📊] HTML Report: $result_dir/report.html"
echo "[📦] Archive: ${result_dir}_report_${report_date}.tar.gz"

# Calculate and display total execution time
end_time=$(date +%s)
start_time=$(stat -c %Y "$result_dir" 2>/dev/null || echo $end_time)
duration=$((end_time - start_time))
hours=$((duration / 3600))
minutes=$(((duration % 3600) / 60))
seconds=$((duration % 60))

echo "[⏱️] Total execution time: ${hours}h ${minutes}m ${seconds}s"