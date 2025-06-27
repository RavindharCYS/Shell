#!/bin/bash

# =================================================================
# Installation Script for 'external.sh' dependencies on Kali Linux
# =================================================================

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root. Please use 'sudo'." 
   exit 1
fi

echo "[+] Starting dependency installation..."

# --- Update package lists ---
echo "[*] Updating package lists..."
apt-get update

# --- Install APT Packages ---
echo "[*] Installing core tools from APT repository..."
apt-get install -y \
    dnsutils \
    jq \
    nmap \
    whois \
    curl \
    whatweb \
    nikto \
    gobuster \
    wafw00f \
    sslscan \
    cutycapt \
    theharvester \
    seclists \
    golang-go \
    nodejs \
    npm

if [ $? -ne 0 ]; then
    echo "[-] Failed to install one or more APT packages. Please check the errors above."
    exit 1
fi
echo "[✓] Core APT packages installed successfully."

# --- Install Go-based tools ---
echo "[*] Installing Go-based tools (Subfinder, Amass)..."
# Note: This installs the tools for the user running the sudo command.
# If you run `sudo -i` first, they install for root. If you run `sudo ./script.sh`, 
# they install for your standard user ($SUDO_USER).
RUN_USER=${SUDO_USER:-$(whoami)}
GO_PATH=$(su -l $RUN_USER -c 'go env GOPATH')
if [ -z "$GO_PATH" ]; then
    echo "[-] Could not determine Go path. Please ensure Go is installed correctly."
    exit 1
fi

echo "[*] Go path is: $GO_PATH"
export PATH=$PATH:$GO_PATH/bin

su -l $RUN_USER -c 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
su -l $RUN_USER -c 'go install -v github.com/owasp-amass/amass/v4/...@master'

# --- Ensure Go binaries are in the PATH ---
# Check if the Go bin path is already in the user's bashrc/zshrc
BASH_PROFILE="/home/$RUN_USER/.bashrc"
ZSH_PROFILE="/home/$RUN_USER/.zshrc"
GO_BIN_PATH_LINE="export PATH=\$PATH:\$HOME/go/bin"

if [ -f "$BASH_PROFILE" ] && ! grep -q "$GO_BIN_PATH_LINE" "$BASH_PROFILE"; then
    echo "[*] Adding Go bin path to $BASH_PROFILE"
    echo -e "\n# Go binaries path\n$GO_BIN_PATH_LINE" >> "$BASH_PROFILE"
fi
if [ -f "$ZSH_PROFILE" ] && ! grep -q "$GO_BIN_PATH_LINE" "$ZSH_PROFILE"; then
    echo "[*] Adding Go bin path to $ZSH_PROFILE"
    echo -e "\n# Go binaries path\n$GO_BIN_PATH_LINE" >> "$ZSH_PROFILE"
fi

echo "[✓] Go-based tools installed. You may need to source your .bashrc/.zshrc or restart your terminal for the PATH to update."

# --- Install Node.js-based tools ---
echo "[*] Installing Node.js-based tools (Wappalyzer CLI)..."
npm install -g wappalyzer-cli

if [ $? -ne 0 ]; then
    echo "[-] Failed to install Wappalyzer CLI via npm."
    exit 1
fi
echo "[✓] Node.js tools installed successfully."


# --- Final Verification ---
echo "[+] Verifying installations..."
source "$BASH_PROFILE" 2>/dev/null || source "$ZSH_PROFILE" 2>/dev/null

command -v subfinder >/dev/null 2>&1 || { echo >&2 "[-] Subfinder not found in PATH."; }
command -v amass >/dev/null 2>&1 || { echo >&2 "[-] Amass not found in PATH."; }
command -v nmap >/dev/null 2>&1 || { echo >&2 "[-] Nmap not found."; }
command -v wappalyzer >/dev/null 2>&1 || { echo >&2 "[-] Wappalyzer not found."; }
command -v gobuster >/dev/null 2>&1 || { echo >&2 "[-] Gobuster not found."; }

echo ""
echo "[🎉] All dependencies have been installed successfully!"
echo "[!] IMPORTANT: Please open a new terminal or run 'source ~/.bashrc' (or ~/.zshrc) for all changes to take effect."