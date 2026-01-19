#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Backup original DNS
if [ -f /etc/resolv.conf ]; then
    cp /etc/resolv.conf /tmp/resolv.conf.backup
fi

cleanup() {
    echo -e "\n${YELLOW}[!] Cleaning up...${NC}"
    
    # Restore IPTABLES
    sudo iptables -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0 2>/dev/null
    
    # Restore DNS (Best effort)
    # Restore DNS (Best effort)
    echo -e "${YELLOW}[*] Restoring system DNS...${NC}"
    if [ -f /tmp/resolv.conf.backup ]; then
        sudo cp /tmp/resolv.conf.backup /etc/resolv.conf
        rm /tmp/resolv.conf.backup
    fi
     sudo systemctl restart systemd-resolved 2>/dev/null
    
    echo -e "${GREEN}[+] System restored to normal.${NC}"
    exit 0
}

trap cleanup EXIT SIGINT SIGTERM

# Clear previous rules
sudo iptables -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0 2>/dev/null

echo -e "${CYAN}"
cat << "EOF"
 ________  ___  ___          _____ ______       ___    ___      ________  ________   ___     
|\   __  \|\  \|\  \        |\   _ \  _   \    |\  \  /  /|    |\   ____\|\   ___  \|\  \    
\ \  \|\  \ \  \\\  \       \ \  \\\__\ \  \   \ \  \/  / /    \ \  \___|\ \  \\ \  \ \  \   
 \ \  \\\  \ \   __  \       \ \  \\|__| \  \   \ \    / /      \ \_____  \ \  \\ \  \ \  \  
  \ \  \\\  \ \  \ \  \       \ \  \    \ \  \   \/  /  /        \|____|\  \ \  \\ \  \ \  \ 
   \ \_______\ \__\ \__\       \ \__\    \ \__\__/  / /            ____\_\  \ \__\\ \__\ \__\
    \|_______|\|__|\|__|        \|__|     \|__|\___/ /            |\_________\|__| \|__|\|__|
                                              \|___|/             \|_________|               
EOF
echo -e "${NC}"

echo -e "${YELLOW}[*] OhMySNI DPI Bypass & DNS Tool${NC}"
echo -e "${YELLOW}[*] Target: Bypass SNI filtering and DNS poisoning${NC}"
echo ""

# 1. Update DNS to bypass DNS Poisoning
# 1. Update DNS to bypass DNS Poisoning
echo -e "${GREEN}[*] Setting DNS to Cloudflare (1.1.1.1)...${NC}"

# Check if resolv.conf is a symlink (systemd-resolved)
if [ -L /etc/resolv.conf ]; then
    echo -e "${YELLOW}[!] Warning: /etc/resolv.conf is a symlink. Modifying it might break local DNS resolution.${NC}"
fi

# Unlock resolv.conf if it's immutable
if lsattr /etc/resolv.conf 2>/dev/null | grep -q "i"; then
    sudo chattr -i /etc/resolv.conf 2>/dev/null
fi

echo -e "nameserver 1.1.1.1\nnameserver 1.0.0.1" | sudo tee /etc/resolv.conf > /dev/null

echo -e "${GREEN}[*] Verifying internet connection...${NC}"
if ! ping -c 1 -W 2 google.com > /dev/null 2>&1; then
    echo -e "${RED}[!] No internet connection detected after DNS change!${NC}"
    echo -e "${YELLOW}[*] Attempting to restore DNS...${NC}"
    cleanup
fi

# 2. Compile C++ Code
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "linuxmrh.cpp" ]; then
    echo -e "${RED}[!] Error: linuxmrh.cpp not found!${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Compiling bypass engine...${NC}"
g++ -O3 linuxmrh.cpp -o mrh -lnetfilter_queue

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Compilation failed!${NC}"
    exit 1
fi

# 3. Set IPTABLES rule
echo -e "${GREEN}[*] Intercepting traffic...${NC}"
sudo iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0

# Run the bypass engine
sudo ./mrh

# Cleanup is handled by the trap function on exit