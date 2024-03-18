#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_ethernet_header(const struct ether_header* ethernet) {
    printf("====Ethernet Header====\n");
    printf("src mac : ");
    for(int i=0; i<ETHER_ADDR_LEN; i++) {
        printf("%02x", ethernet->ether_shost[i]);
        if(i < ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\n");

    printf("dst mac : ");
    for(int i=0; i<ETHER_ADDR_LEN; i++) {
        printf("%02x", ethernet->ether_dhost[i]);
        if(i < ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\n");
}

void print_ip_header(const struct ip* ip_hdr) {
    printf("====IP Header====\n");
    printf("src ip : %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("dst ip : %s\n", inet_ntoa(ip_hdr->ip_dst));
}

void print_tcp_header(const struct tcphdr* tcp_hdr) {
    printf("====TCP Header====\n");
    printf("src port : %d\n", ntohs(tcp_hdr->source));
    printf("dst port : %d\n", ntohs(tcp_hdr->dest));
}

void print_data(const u_char* data, int size) {
    printf("====Data====\n");
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0 && i != 0)
            printf("\n");
        printf("%02x ", data[i]);
    }
    printf("\n\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;
	printf("yes");
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        // error확인
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
		
        const struct ether_header* ethernet = (struct ether_header*)packet;
        if(ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
            const struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
            if(ip_hdr->ip_p == IPPROTO_TCP) {
				const struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl * 4);
				int ip_header_length = ip_hdr->ip_hl * 4;
				int tcp_header_length = tcp_hdr->doff * 4;
				int total_header_size = sizeof(struct ether_header) + ip_header_length + tcp_header_length;
				int data_size = ntohs(ip_hdr->ip_len) - (ip_header_length + tcp_header_length);

				print_ethernet_header(ethernet);
				print_ip_header(ip_hdr);
				print_tcp_header(tcp_hdr);
				
				if (data_size > 0) {
					const u_char* data = packet + total_header_size;
					print_data(data, data_size);
				}
				else printf("\n\n");
			}
        }
    }
    pcap_close(pcap);
}
