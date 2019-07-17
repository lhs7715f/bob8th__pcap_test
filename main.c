#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ETHTYPE_IP 0x0800
#define IP_PROTO_TCP 0x06



void mac_print(uint8_t *ptr){
    for(int i=0; i<6; i++)
        printf("%02x ", ptr[i]);
    printf("\n");
}

void ip_print(uint8_t *ptr){
    for(int i=0; i<4; i++){
        printf("%d", ptr[i]);
        if(i != 3)
            printf(".");
    }
    printf("\n");
}

void data_print(uint8_t *ptr, uint8_t n){
    for(int i=0; i<n; i++)
            printf("%02x ", ptr[i]);
        printf("\n");
}

void dump(const uint8_t* p, uint32_t len){
    for(uint8_t i=0; i<len; i++){
        printf("%02x ", p[i]);

        if((i & 0x0f) == 0x0f)
            printf("\n");
    }

    printf("\n");

    struct ethernet_hdr{
        uint8_t ether_dhost[MAC_ADDR_LEN];
        uint8_t ether_shost[MAC_ADDR_LEN];
        uint16_t ethertype;
    };

    struct ipv4_hdr{
        uint8_t ip_version;
        uint8_t TOS;
        uint16_t ip_len;
        uint16_t ip_id;
        uint16_t ip_flag;
        uint8_t TTL;
        uint8_t ip_protocol;
        uint16_t ip_hdr_checksum;
        uint8_t src_ip_addr[IP_ADDR_LEN];
        uint8_t dst_ip_addr[IP_ADDR_LEN];
    };

    struct tcp_hdr{
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t tcp_info[16];
        uint8_t tcp_payload[10];

    };

    struct ethernet_hdr *eth = (struct ethernet_hdr*)p;

    printf("Source Mac: ");
    mac_print(eth->ether_shost);
    printf("Destination Mac: ");
    mac_print(eth->ether_dhost);

    if(htons(eth->ethertype) == ETHTYPE_IP){
        struct ipv4_hdr *ip = (struct ipv4_hdr*)(p+14);

        printf("Source IP: ");
        ip_print(ip->src_ip_addr);
        printf("Destination IP: ");
        ip_print(ip->dst_ip_addr);

        if(ip->ip_protocol == IP_PROTO_TCP){
            struct tcp_hdr *tcp = (struct tcp_hdr*)(p+14+20);

            printf("Source PORT: %d\n", htons(tcp->src_port));
            printf("Destination PORT: %d\n", htons(tcp->dst_port));

            if(sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr) <= ip->ip_len)
                data_print(tcp->tcp_payload, (uint8_t)10);
            else
                data_print(tcp->tcp_payload, (uint8_t)(10-(sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr)-sizeof(ip->ip_len))));
        }
    }

}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char *argv[])
{
    if(argc != 2){
        usage();
        return -1;
    }

    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL){
        fprintf(stderr, "couldn't open device %s : %s", dev, errbuf);
        return -1;
    }

    for(int i=0; i<10; i++)
    {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        printf("%u bytes captured\n", header->caplen); //caplen: 캡쳐된 패킷의 길이가 저장되어 있는 멤버

        dump(packet,header->caplen);
    }

    pcap_close(handle);

    return 0;
}
