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
/*

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

unsigned char *alldata;
uint32_t len_alldata;

void parse(unsigned char *buf, int len){
	switch(buf[0]){
		case 20: printf("Content Type: Handshake (%d)\n", buf[0]); break;
		case 21: printf("Content Type: alert (%d)\n", buf[0]); break;
		case 22: printf("Content Type: handshake (%d)\n", buf[0]); break;
		case 23: printf("Content Type: application_data (%d)\n", buf[0]); break;
		default: break;
	}

	if(buf[1] == 3){
		switch(buf[2]){
			case 1: printf("Version: TLS 1.%d (0x03%02x)\n", buf[2]-1, buf[2]); break;
			case 2: printf("Version: TLS 1.%d (0x03%02x)\n", buf[2]-1, buf[2]); break;
			case 3: printf("Version: TLS 1.%d (0x03%02x)\n", buf[2]-1, buf[2]); break;
			case 4: printf("Version: TLS 1.%d (0x03%02x)\n", buf[2]-1, buf[2]); break;
			default: break;
		}
	}

	int record_layer_len = buf[3] * 256 + buf[4];
    printf("Length: %d\n", record_layer_len);

	switch(buf[5]){
		case 0: printf("Handshake Type: Hello Request (%d)\n", buf[5]); break;
		case 1: printf("Handshake Type: Client Hello (%d)\n", buf[5]); break;
		case 2: printf("Handshake Type: Server Hello (%d)\n", buf[5]); break;
		case 11: printf("Handshake Type: Certificate (%d)\n", buf[5]); break;
		case 12: printf("Handshake Type: Server Key Exchange (%d)\n", buf[5]); break;
		case 13: printf("Handshake TYpe: Certificate Request (%d)\n", buf[5]); break;
		case 14: printf("Handshake Type: Server Hello Done (%d)\n", buf[5]); break;
		case 15: printf("Handshake Type: Certificate Verify (%d)\n", buf[5]); break;
		case 16: printf("Handshake Type: Client Key Exchange (%d)\n", buf[5]); break;
		case 20: printf("Handshake Type: Finished (%d)\n", buf[5]); break;
		default: break;
	}

	int handshake_protocol_len = buf[6] * 256 * 256 + buf[7] * 256 + buf[8]; 
    printf("Length: %d\n", handshake_protocol_len);

	if(buf[9] == 3){
		switch(buf[10]){
			case 1: printf("Version: TLS 1.%d (0x03%02x)\n", buf[10]-1, buf[10]); break;
			case 2: printf("Version: TLS 1.%d (0x03%02x)\n", buf[10]-1, buf[10]); break;
			case 3: printf("Version: TLS 1.%d (0x03%02x)\n", buf[10]-1, buf[10]); break;
			case 4: printf("Version: TLS 1.%d (0x03%02x)\n", buf[10]-1, buf[10]); break;
			default: break;
		}
	}

    printf("Random: ");
    for(int i=0; i<32; i++) printf("%02x ", buf[11+i]);

	int session_id_len = buf[43];
    printf("\nSession ID length: %d\n", session_id_len);

    printf("Session ID: ");
    for(int i=0; i<session_id_len; i++) printf("%02x", buf[44+i]);

    int a = 44 + session_id_len;
	int cipher_suites_length = buf[a] * 256 + buf[a+1];
    printf("\nCipher Suites Length: %d\n", cipher_suites_length);
    printf("Cipher Suites (%d suites)\n", cipher_suites_length/2);

	for(int i=0; i<cipher_suites_length/2; i++){ 
		
		if(buf[a+2+2*i] == 0x00){
			switch(buf[a+2+2*i+1]){
				case 13: printf("	 Cipher Suite: TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 16: printf("    Cipher Suite: TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 19: printf("    Cipher Suite: TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 22: printf("    Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 48: printf("    Cipher Suite: TLS_DH_DSS_WITH_AES_128_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 49: printf("    Cipher Suite: TLS_DH_RSA_WITH_AES_128_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 50: printf("    Cipher Suite: TLS_DHE_DSS_WITH_AES_128_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 51: printf("    Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 54: printf("    Cipher Suite: TLS_DH_DSS_WITH_AES_256_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 55: printf("    Cipher Suite: TLS_DH_RSA_WITH_AES_256_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 56: printf("    Cipher Suite: TLS_DHE_DSS_WITH_AES_256_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 57: printf("    Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 62: printf("    Cipher Suite: TLS_DH_DSS_WITH_AES_128_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 63: printf("    Cipher Suite: TLS_DH_RSA_WITH_AES_128_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 64: printf("    Cipher Suite: TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 103: printf("    Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 104: printf("    Cipher Suite: TLS_DH_DSS_WITH_AES_256_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 105: printf("    Cipher Suite: TLS_DH_RSA_WITH_AES_256_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 106: printf("    Cipher Suite: TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				case 107: printf("    Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+3+2*i]); break;
				default: break;			
			}
		}
		else if(buf[a+2+2*i] == 0x13){
			switch(buf[a+2+2*i+1]){
				case 1: printf("	Cipher Suite: TLS_AES_128_GCM_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 2: printf("	Cipher Suite: TLS_AES_256_GCM_SHA384 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 3: printf("	Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 4: printf("	Cipher Suite: TLS_AES_128_CCM_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 5: printf("	Cipher Suite: TLS_AES_128_CCM_8_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				default: break;
			}
		}
		else if(buf[a+2+2*i] == 0xcc){
			switch(buf[a+2+2*i+1]){
				case 168: printf("    Cipher SUite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 169: printf("	  Cipher SUite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 170: printf("	  Cipher SUite: TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 171: printf("	  Cipher SUite: TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 172: printf("	  Cipher SUite: TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 173: printf("	  Cipher SUite: TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 174: printf("	  Cipher SUite: TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				default: break;
			}
		}
		else if(buf[a+2+2*i] == 0xc0){
			switch(buf[a+2+2*i+1]){
				case 35: printf("	 Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 36: printf("	 Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 37: printf(" 	 Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 38: printf("	 Cipher Suite: TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 39: printf("	 Cipher Suite: TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 40: printf("	 Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 41: printf("	 Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 42: printf("	 Cipher Suite: TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 43: printf("	 Cipher Suite: TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 44: printf("	 Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 45: printf("	 Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 46: printf("	 Cipher Suite: TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 47: printf("	 Cipher Suite: TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 48: printf("	 Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 49: printf("	 Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 50: printf("	 Cipher Suite: TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				case 51: printf("	 Cipher Suite: TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 (0x%02x%02x)\n", buf[a+2+2*i], buf[a+2+2*i+1]); break;
				default: break;
			}
		}
		else
			return;
	}

	int b = a+2+cipher_suites_length;

    printf("Compression Methods Length: %d\n", buf[b]);
    printf("Compression Methods (%d method)\n	Compression Method: null (0)\n", buf[b]);

    int c = b + buf[b] + 1;
	int extension_len = buf[c] * 256 + buf[c+1];
	int n = 0;
	while(n < extension_len){
		unsigned int type = buf[c+2+n] * 256 + buf[c+3+n];
		unsigned int len = buf[c+4+n] * 256 + buf[c+5+n];

		switch(type){
			case 0: printf("Extension: server_name (len=%d)\n", len);
				printf("	Type: server_name (%d)\n", type);
				printf("	Length: %d\n", len);
				printf("	Server Name Indication extension\n");
				printf("		Server Name list length: %d\n", buf[c+6+n]);
				printf("		Server Name type: (%d)\n", buf[c+7+n] * 256 + buf[c+8+n]);
				printf("		Server Name length: %d\n", buf[c+6+n]-3);
				printf("		Server Name: ");
				for(int i=0; i<buf[c+6+n]-3; i++)
					printf("%c", buf[c+9+n+i]);
				printf("\n");
				break;
			case 23: printf("Extension: extended_master_secret (len=%d)\n", len); break;
			case 65281: printf("Extension: renegotiation_info (len=%d)\n", len); break;
			case 10: printf("Extension: supported_groups (len=%d)\n", len); break;
			case 11: printf("Extension: ex_point_formats (len=%d)\n", len); break;
			case 16: printf("Extension: application_layer_protocol_negotiation (len=%d)\n", len); break;
			case 5: printf("Extension: status_request (len=%d)\n", len); break;
			case 51: printf("Extension: key_share (len=%d)\n", len); break;
			case 43: 
				printf("Extension: supported_versions (len=%d)\n", len);
				printf("	Type: supported_versions (%d)\n", type);
				printf("	Length: %d\n", len);
				printf("	Supported Versions length: %d\n", buf[c+6+n]);
				for(int i=0; i<buf[c+6+n]/2; i++)
					printf("Supported Version: TLS 1.%d (0x%02x%02x)\n", buf[c+8+n+2*i]-1, buf[c+7+n], buf[c+8+n+2*i]);
				break;
			case 13: printf("Extension: signature_algorithms (len=%d)\n", len); break;
			case 65486: printf("Extension: encrypted_server_name (len=%d)\n", len); break;
			case 28: printf("Extension: record_size_limit (len=%d)\n", len); break;
			default: break;
		}
		n = n + len + 4;
	}
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    uint8_t ip_hl, th_off;
    int ret;
    unsigned char *data, *http;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) id = ntohl(ph->packet_id);
    hwph = nfq_get_packet_hw(tb);
    ret = nfq_get_payload(tb, &data);
    alldata = data;
    len_alldata = ret;
    //dump(alldata, len_alldata);
    printf("\n\n");

    ip_hl = ((data[0] << 4) & 0xff) >> 4;
    th_off = data[ip_hl*4+12] >> 4;
    http = data+(ip_hl*4+th_off*4);

    if(http[0] == 0x16 && http[5] == 0x01){
         dump(http, len_alldata-ip_hl*4+th_off*4);
         parse(http, len_alldata-ip_hl*4+th_off*4);
    }

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    return nfq_set_verdict(qh, id, NF_ACCEPT, len_alldata, alldata);
}

int main()
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

*/

