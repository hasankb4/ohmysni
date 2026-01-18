#!/bin/bash

# Renkler
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

CSV_FILE="sites.csv"

echo -e "${CYAN}--- Domain Ekleme Paneli ---${NC}"
echo -e "${YELLOW}İpucu: Birden fazla domaini boşluk bırakarak yazabilirsin.${NC}"
echo -e "${YELLOW}Örnek: discord.com roblox.com google.com${NC}"
echo -ne "${GREEN}Eklenecek domain(ler)i girin: ${NC}"
read -a new_domains

if [ ! -f "$CSV_FILE" ]; then
    touch "$CSV_FILE"
fi

current_content=$(cat "$CSV_FILE" 2>/dev/null)

for domain in "${new_domains[@]}"; do
    if [[ -z "$domain" ]]; then continue; fi

    if [[ $current_content =~ (^|,)"$domain"(,|$) ]]; then
        echo -e "${YELLOW}[!] $domain zaten listede var, atlanıyor.${NC}"
    else
        if [ -s "$CSV_FILE" ]; then
            sed -i "s/$/, $domain/" "$CSV_FILE"
        else
            echo -n "$domain" > "$CSV_FILE"
        fi
        echo -e "${GREEN}[+] $domain başarıyla eklendi.${NC}"
    fi
done

echo -e "${CYAN}Güncel Liste: $(cat $CSV_FILE)${NC}"