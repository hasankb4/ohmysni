#!/bin/bash




cleanup() {
    echo -e "\n${RED}[!] Emergency cleanup...${NC}"
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -F
    sudo iptables -X
    sudo iptables -t nat -F
    sudo iptables -t mangle -F
    echo -e "${GREEN}[+] Internet traffic is back to normal.${NC}"
    exit
}

trap cleanup EXIT SIGINT SIGTERM

sudo iptables -F
echo "[*] Compiling..."
g++ -O3 linuxmrh.cpp -o mrh -lnetfilter_queue

echo "[*] Traffic is being redirected (Port 443)..."
sudo iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0

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
                                                                                             
 _________  ___  ___  ________   ________   _______   ___                                    
|\___   ___\\  \|\  \|\   ___  \|\   ___  \|\  ___ \ |\  \                                   
\|___ \  \_\ \  \\\  \ \  \\ \  \ \  \\ \  \ \   __/|\ \  \                                  
     \ \  \ \ \  \\\  \ \  \\ \  \ \  \\ \  \ \  \_|/_\ \  \                                 
      \ \  \ \ \  \\\  \ \  \\ \  \ \  \\ \  \ \  \_|\ \ \  \____                            
       \ \__\ \ \_______\ \__\\ \__\ \__\\ \__\ \_______\ \_______\                          
        \|__|  \|_______|\|__| \|__|\|__| \|__|\|_______|\|_______|                          

EOF
echo "[*] Program is running..."
sudo ./mrh 
