#!/bin/bash

# =================================================================
# Installation Script for 'external-cli.sh' dependencies
# Designed for Debian-based systems like Kali Linux or Ubuntu.
# =================================================================

# --- Color Codes ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Helper Functions ---
print_status() {
    echo -e "[*] $1"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}" >&2
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

# --- Installation Functions ---

install_apt_packages() {
    print_status "Installing core tools from APT repository..."
    
    # List of packages to install via apt
    local apt_packages=(
        dnsutils      # for dig, host
        jq
        nmap
        whois
        curl
        whatweb
        nikto
        gobuster
        wafw00f
        sslscan
        cutycapt
        theharvester
        seclists      # for wordlists
        golang-go
        nodejs
        npm
    )

    apt-get update
    apt-get install -y "${apt_packages[@]}"
    
    if [ $? -ne 0 ]; then
        print_error "Failed to install one or more APT packages. Please check the errors above."
        exit 1
    fi
    print_success "Core APT packages installed successfully."
}

install_go_tools() {
    print_status "Installing Go-based tools (Subfinder, Amass)..."
    
    # This ensures tools are installed for the user who ran `sudo`, not for root.
    local run_user=${SUDO_USER:-$(whoami)}
    local go_path
    go_path=$(su -l "$run_user" -c 'go env GOPATH')

    if [ -z "$go_path" ]; then
        print_error "Could not determine Go path. Please ensure Go is installed correctly."
        exit 1
    fi

    print_status "Go path is: $go_path"
    local go_bin_path="$go_path/bin"

    # List of Go-based tools
    local go_tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
        "github.com/owasp-amass/amass/v4/cmd/amass"
    )

    for tool in "${go_tools[@]}"; do
        print_status "Installing $tool..."
        su -l "$run_user" -c "go install -v $tool@latest"
    done

    # --- Ensure Go binaries are in the PATH ---
    # This is a more robust way to add the path to the user's profile.
    local bash_profile="/home/$run_user/.bashrc"
    local zsh_profile="/home/$run_user/.zshrc"
    local path_export_line="export PATH=\$PATH:$go_bin_path"

    for profile in "$bash_profile" "$zsh_profile"; do
        if [ -f "$profile" ] && ! grep -q "PATH.*$go_bin_path" "$profile"; then
            print_status "Adding Go bin path to $profile"
            echo -e "\n# Go binaries path\n$path_export_line" >> "$profile"
        fi
    done
    
    print_success "Go-based tools installed."
}

install_node_tools() {
    print_status "Installing Node.js-based tools (Wappalyzer CLI)..."
    
    # List of global npm packages
    local npm_packages=(
        "wappalyzer-cli"
    )

    npm install -g "${npm_packages[@]}"
    
    if [ $? -ne 0 ]; then
        print_error "Failed to install one or more Node.js packages via npm."
        exit 1
    fi
    print_success "Node.js tools installed successfully."
}

verify_installation() {
    print_status "Verifying installations..."
    
    local all_tools=(
        # APT
        "dig" "host" "jq" "nmap" "whois" "curl" "whatweb" "nikto" "gobuster" "wafw00f" "sslscan" "cutycapt" "theHarvester"
        # Go (needs to be checked as the user)
        "subfinder" "amass"
        # Node
        "wappalyzer"
    )
    
    local missing_count=0
    local run_user=${SUDO_USER:-$(whoami)}

    for tool in "${all_tools[@]}"; do
        if ! su -l "$run_user" -c "command -v $tool" &>/dev/null; then
            print_error "$tool not found in PATH."
            missing_count=$((missing_count + 1))
        fi
    done

    if [ "$missing_count" -gt 0 ]; then
        print_error "$missing_count tools seem to be missing or not in the PATH."
        print_warning "Try running 'source ~/.bashrc' (or ~/.zshrc) in a new terminal."
        return 1
    fi

    print_success "All required tools are installed and available in the PATH."
    return 0
}

# --- Main Execution ---

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root. Please use 'sudo ./install_reqs.sh'." 
   exit 1
fi

echo "====================================================="
echo " Starting Dependency Installation for external-cli.sh"
echo "====================================================="

install_apt_packages
install_go_tools
install_node_tools

echo
verify_installation
echo

print_warning "IMPORTANT: For all changes to take effect, please open a NEW terminal session or run:"
print_warning "source ~/.bashrc  (or 'source ~/.zshrc' if you use Zsh)"
echo

print_success "Installation script finished!"