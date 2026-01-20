#ifdef __linux__

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// Global counter for IP Header ID
static uint16_t global_ip_id = 10000;

struct pseudo_header {
  uint32_t source_address;
  uint32_t dest_address;
  uint8_t placeholder;
  uint8_t protocol;
  uint16_t tcp_length;
};

unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
  long sum = 0;
  while (nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }
  if (nbytes == 1)
    sum += *(unsigned char *)ptr;
  sum = (sum >> 16) + (sum & 0xffff);
  sum = (sum >> 16) + (sum & 0xffff);
  return (unsigned short)~sum;
}

bool isTLSClientHello(unsigned char *data, int len) {
  if (len < 6)
    return false;
  // TLS Record: Handshake (0x16) and Client Hello (0x01)
  return (data[0] == 0x16 && data[5] == 0x01);
}

void sendTCPSegment(int sock, struct sockaddr_in *dest, unsigned char *ip_data,
                    int ip_header_len, int tcp_header_len,
                    unsigned char *payload_data, size_t payload_len,
                    uint32_t seq_offset, bool is_first_segment) {

  if (payload_len == 0)
    return;

  size_t tcp_len = tcp_header_len + payload_len;
  if (tcp_len > 65535)
    return;

  size_t total_len = ip_header_len + tcp_len;
  std::vector<unsigned char> pkt(total_len);

  std::memcpy(pkt.data(), ip_data, ip_header_len);
  struct iphdr *iph = (struct iphdr *)pkt.data();
  iph->tot_len = htons(total_len);
  iph->id = htons(global_ip_id++);

  std::memcpy(pkt.data() + ip_header_len, ip_data + ip_header_len,
              tcp_header_len);
  struct tcphdr *tcph = (struct tcphdr *)(pkt.data() + ip_header_len);

  tcph->seq = htonl(ntohl(tcph->seq) + seq_offset);
  std::memcpy(pkt.data() + ip_header_len + tcp_header_len, payload_data,
              payload_len);

  iph->check = 0;
  iph->check = calculate_checksum((unsigned short *)pkt.data(), ip_header_len);

  pseudo_header psh = {iph->saddr, iph->daddr, 0, IPPROTO_TCP,
                       htons((uint16_t)tcp_len)};
  std::vector<unsigned char> pgram(sizeof(pseudo_header) + tcp_len);

  std::memcpy(pgram.data(), &psh, sizeof(pseudo_header));
  std::memcpy(pgram.data() + sizeof(pseudo_header), tcph, tcp_len);

  tcph->check = 0;
  tcph->check =
      calculate_checksum((unsigned short *)pgram.data(), pgram.size());

  sendto(sock, pkt.data(), total_len, 0, (struct sockaddr *)dest,
         sizeof(*dest));
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data) {

  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  if (!ph)
    return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, NULL);

  uint32_t id = ntohl(ph->packet_id);
  unsigned char *payload = nullptr;
  int len = nfq_get_payload(nfa, &payload);

  // DEBUG LOGGING
  std::cout << "[DEBUG] Packet received. ID: " << id << " Len: " << len
            << std::endl;

  if (len < 40)
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  struct iphdr *iph = (struct iphdr *)payload;
  if (iph->protocol != IPPROTO_TCP)
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  int ip_header_len = iph->ihl * 4;
  struct tcphdr *tcph = (struct tcphdr *)(payload + ip_header_len);
  int tcp_header_len = tcph->doff * 4;
  int tcp_payload_len = len - (ip_header_len + tcp_header_len);
  unsigned char *tcp_data = payload + ip_header_len + tcp_header_len;

  // More detailed logging
  if (tcp_payload_len > 0) {
    std::cout << "[DEBUG] TCP payload len: " << tcp_payload_len
              << " First bytes: ";
    fflush(stdout);
    for (int i = 0; i < std::min(6, tcp_payload_len); i++) {
      printf("%02x ", tcp_data[i]);
    }
    fflush(stdout);
    std::cout << std::endl;

    // Explicit TLS check logging
    if (tcp_data[0] == 0x16) {
      std::cout << "[DEBUG] TLS Record detected (0x16). Byte[5]=" << std::hex
                << (int)tcp_data[5] << std::dec << std::endl;
    }
  }

  if (tcp_payload_len > 0 && isTLSClientHello(tcp_data, tcp_payload_len)) {

    int split_pos = 1; // Split after the first byte to confuse DPI
    if (tcp_payload_len <= split_pos) {
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    std::cout << "[!] TLS Client Hello Captured: Applying Bypass..."
              << std::endl;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
      std::cerr << "[ERROR] Failed to create raw socket!" << std::endl;
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph->daddr;

    size_t remainder = tcp_payload_len - split_pos;

    std::cout << "[DEBUG] Sending split packets. First: " << split_pos
              << " bytes, Second: " << remainder << " bytes" << std::endl;

    // Send segments in reverse order to bypass Deep Packet Inspection
    sendTCPSegment(sock, &dest, payload, ip_header_len, tcp_header_len,
                   tcp_data + split_pos, remainder, split_pos, false);

    sendTCPSegment(sock, &dest, payload, ip_header_len, tcp_header_len,
                   tcp_data, split_pos, 0, true);

    close(sock);
    std::cout << "[DEBUG] Original packet DROPPED, fragments sent."
              << std::endl;
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
  }

  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main() {
  std::ios_base::sync_with_stdio(false);
  std::cout.setf(std::ios::unitbuf);

  std::cout << "--- OhMySNI: Linux DPI Bypass Tool ---" << std::endl;
  std::cout << "Make sure to set the IPTABLES rule before running!"
            << std::endl;

  struct nfq_handle *h = nfq_open();
  if (!h) {
    perror("nfq_open");
    return 1;
  }

  nfq_unbind_pf(h, AF_INET);
  nfq_bind_pf(h, AF_INET);

  struct nfq_q_handle *qh = nfq_create_queue(h, 0, &callback, NULL);
  if (!qh) {
    perror("nfq_create_queue");
    return 1;
  }

  nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

  int fd = nfq_fd(h);
  char buf[4096] __attribute__((aligned));
  int rv;

  while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
    nfq_handle_packet(h, buf, rv);
  }

  nfq_destroy_queue(qh);
  nfq_close(h);
  return 0;
}
#endif
