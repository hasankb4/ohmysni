
#ifdef __linux__


#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <regex>
#include <cstring>

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

std::vector<std::string> domains;
void setDomains() {
    domains.clear();
    std::ifstream file("sites.csv");
    if (!file.is_open()) {
        std::cout << "[!] sites.csv not found.\n";
        return;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (line.length() > 3) domains.push_back(line);
    }
}
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) sum += *(unsigned char*)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum = (sum >> 16) + (sum & 0xffff);
    return (unsigned short)~sum;
}

void compute_tcp_checksum(struct iphdr *iph, unsigned char *payload) {
    if (!iph || !payload) return;
    int ip_header_len = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(payload + ip_header_len);
    int tcp_len = ntohs(iph->tot_len) - ip_header_len;

    if (tcp_len < (int)sizeof(struct tcphdr)) return;

    pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(tcp_len);

    std::vector<unsigned char> pgram(sizeof(pseudo_header) + tcp_len);
    std::memcpy(pgram.data(), &psh, sizeof(pseudo_header));
    std::memcpy(pgram.data() + sizeof(pseudo_header), tcph, tcp_len);

    tcph->check = 0;
    tcph->check = calculate_checksum((unsigned short*)pgram.data(), pgram.size());
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data) {
    
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return nfq_set_verdict(qh, 0, 1, 0, NULL);
    
    uint32_t id = ntohl(ph->packet_id);
    unsigned char *payload = nullptr;
    int len = nfq_get_payload(nfa, &payload);

    if (len <= 0 || !payload) {
        return nfq_set_verdict(qh, id, 1, 0, NULL);
    }

    if (len < 40) {
        return nfq_set_verdict(qh, id, 1, len, payload);
    }

    struct iphdr *iph = (struct iphdr *)payload;
    if (iph->protocol != IPPROTO_TCP) {
        return nfq_set_verdict(qh, id, 1, len, payload);
    }

    int ip_header_len = iph->ihl * 4;
    int tcp_payload_offset = ip_header_len + sizeof(struct tcphdr);

    for (const std::string& site : domains) {
        if (site.length() < 3) continue;
        
        int siteLen = (int)site.length();
        for (int i = tcp_payload_offset; i <= (len - siteLen); i++) {
            if (std::memcmp(&payload[i], site.c_str(), siteLen) == 0) {
                std::cout << "[!] Catched: " << site << " (ID: " << id << ")" << std::endl;
                
                int split_at = i + 1; 

                if (split_at < len) {
                    iph->tot_len = htons(split_at);
                    iph->check = 0;
                    iph->check = calculate_checksum((unsigned short *)payload, ip_header_len);
                    compute_tcp_checksum(iph, payload);
                    
                    return nfq_set_verdict(qh, id, 1, split_at, payload);
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, 1, len, payload);
}

int main() {
    setDomains();
    struct nfq_handle *h = nfq_open();
    if (!h) { std::cerr << "NFQ Open hatası\n"; return 1; }
    
    if (nfq_unbind_pf(h, AF_INET) < 0) { std::cerr << "Unbind hatası\n"; }
    if (nfq_bind_pf(h, AF_INET) < 0) { std::cerr << "Bind hatası\n"; return 1; }

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &callback, NULL);
    if (!qh) { std::cerr << "Queue oluşturma hatası\n"; return 1; }
    
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) { std::cerr << "Mode hatası\n"; return 1; }
    
    int fd = nfq_fd(h);
    char buf[8192] __attribute__ ((aligned)); 
    int rv;

    std::cout << "[*] MRH Listening... \n";

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
#endif
