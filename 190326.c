#include <stdio.h>
#include <pcap.h> // PCAP 라이브러리 가져오기
#include <arpa/inet.h> // inet_ntoa 등 함수 포함
#include <netinet/in.h> // in_addr 등 구조체 포함
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

pcap_t *handle; // 핸들러
char *dev = "ens33"; // 자신의 네트워크 장비
char errbuf[PCAP_ERRBUF_SIZE]; // 오류 메시지를 저장하는 버퍼
// struct bpf_program fp; // 필터 구조체
// char *filter_exp = "port 9190"; // 필터 표현식
// bpf_u_int32 mask; // 서브넷 마스크
// bpf_u_int32 net; // 아이피 주소
// struct pcap_pkthdr *header; // 패킷 관련 정보
// const u_char *packet; // 실제 패킷
// struct in_addr addr; // 주소 정보
u_int32_t target_ip;

#define ETHER_ADDR_LEN 6
#define PROTOCOL_LEN 4

struct e_i_t_packet {
        u_char ether_dhost[ETHER_ADDR_LEN]; // 목적지 MAC 주소
        u_char ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC 주소
        u_short ether_type;
        
        
        u_char ip_vhl;
        u_char ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char ip_ttl;
        u_char ip_p; // IP 프로토콜 유형
        u_short ip_sum;
       
	    uint8_t src_ip[PROTOCOL_LEN]; // 출발지 IP 주소
        uint8_t dst_ip[PROTOCOL_LEN]; // 목적지 IP 주소
        u_short th_sport; // 출발지 TCP 주소
        u_short th_dport; // 목적지 TCP 주소
        tcp_seq th_seq;
        tcp_seq th_ack;
        u_char th_offx2;
        #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)
#define SIZE_ETHERNET 14
void send_packet(const u_char *d_packet, pcap_t* handle)
{
	if(pcap_sendpacket(handle, d_packet, 200) != 0)
		fprintf(stderr, "\nError sending the packet! : %s\n", pcap_geterr(handle));
}


typedef u_int tcp_seq;

struct *e_i_t_packet;
u_int size_ip;
u_int size_tcp;
int first=1;
tcp_seq dummy_seq;

void * get_mac_address(uint8_t * my_MAC)
{
	unsigned int my_MAC_fetch[6];
	FILE *fp;
	fp = fopen("/sys/class/net/ens33/address","r");
	fscanf(fp, "%x:%x:%x:%x:%x:%x",&my_MAC_fetch[0],&my_MAC_fetch[1],&my_MAC_fetch[2],&my_MAC_fetch[3],&my_MAC_fetch[4],&my_MAC_fetch[5]);
	for(int i = 0; i<6 ; i++)
	{
		my_MAC[i] = (uint8_t)my_MAC_fetch[i];
	}
	fclose(fp);

}

void * get_ip_address(uint8_t * my_ipaddr, char * interface)
{
	struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	uint8_t num = 0;
	int cnt = 0;
	int i=0;
	if(ioctl(s, SIOCGIFADDR, &ifr) < 0)
	{
		printf("Error");
	} else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
		//sizeof(struct sockaddr)
		do{
			if(ipstr[i] == '.' || ipstr[i] == '\0')
			{
				my_ipaddr[cnt++] = num;
				num = 0;
			}else
			{	
				num = num * 10 + (ipstr[i] - '0');
			}
			i++;
		}while(cnt != 4);
	}
}

struct e_i_t_packet request_packet(struct e_i_t_packet packet, uint8_t * my_MAC,uint8_t * my_ipaddr, char * argv)
{
    int i;
        u_char ether_dhost[ETHER_ADDR_LEN]; // 목적지 MAC 주소
        u_char ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC 주소
        u_short ether_type;
        u_char ip_vhl;
        u_char ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        
        u_char ip_ttl;
        packet.ip_p=1; // IP 프로토콜 유형
        u_short ip_sum;
       
       
       for(i=0;i<4;i++)
            packet.src_ip[i]=my_ipaddr[i]; // 출발지 IP 주소
        
        uint32_t num = inet_addr(argv);

        packet.dst_ip[0] = num; // 목적지 IP 주소
        packet.dst_ip[0] = num >> 8; // 목적지 IP 주소
        packet.dst_ip[0] = num >> 16; // 목적지 IP 주소
        packet.dst_ip[0] = num >> 24; // 목적지 IP 주소




        u_short th_sport; // 출발지 TCP 주소
        u_short th_dport; // 목적지 TCP 주소
        tcp_seq th_seq;
        tcp_seq th_ack;
        u_char th_offx2;
        
        u_char th_flags;
        
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
    printf("------------------------------------------------------\n");
        ethernet = (struct sniff_ethernet*)(packet);
        printf("MAC 출발지 주소 :");
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_shost[i]);
        }
        printf("\nMAC 목적지 주소 :");
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_dhost[i]);
        }
        printf("\nMAC 목적지 주소 :");
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_dhost[i]);
        }
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        memcpy(&(ip->ip_dst.s_addr),&target_ip,sizeof(target_ip));
	    size_ip = IP_HL(ip)*4;
        printf("\nIP 출발지 주소: %s\n", inet_ntoa(ip->ip_src));
        printf("IP 목적지 주소: %s\n", inet_ntoa(ip->ip_dst));
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

        if(first==1)
                dummy_seq=tcp->th_seq;
	    
        
        memcpy(&(tcp->th_seq),&dummy_seq,sizeof(dummy_seq));
        size_tcp = TH_OFF(tcp)*4;
        printf("출발지 포트: %d\n", ntohs(tcp->th_sport));
        printf("목적지 포트: %d\n", ntohs(tcp->th_dport));
        printf("seq: %d\n", ntohs(tcp->th_seq));
	    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
        
        printf("\n------------------------------------------------------\n");
    	first++;

        return packet;
}

int main(void) {

    uint8_t my_MAC[6];
    uint8_t my_ipaddr[4];
    strutc e_i_t_packet packet;	
    

	dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                printf("네트워크 장치를 찾을 수 없습니다.\n");
                return 0;
        }
        printf("나의 네트워크 장치: %s\n", dev);
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                printf("장치의 주소를 찾을 수 없습니다.\n");
                return 0;
        }
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
                printf("장치를 열 수 없습니다.\n");
                printf("error message: %s", errbuf);
		return 0;
        }

    get_mac_address(my_MAC);
	get_ip_address(my_ipaddr, dev);	
        
        while(1)
{       
        packet=request_packet(packet);
        request_packet(packet, my_MAC, my_ipaddr, argv[1]);
}

        while(pcap_next_ex(handle, &header, &packet) == 1) 
        {

		printf("sending packet to target....\n");
		send_packet(packet,handle);
        }




	return 0;
}
