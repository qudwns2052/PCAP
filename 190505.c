#include <stdio.h>
#include <pcap.h> // PCAP 라이브러리 가져오기
#include <arpa/inet.h> // inet_ntoa 등 함수 포함
#include <netinet/in.h> // in_addr 등 구조체 포함
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define BUF_SIZE 100
void showpayload();
void pack();
void unpack();
char myip[40];
char toip[40];
char fromip[40];
struct in_addr to_struct_ip;
struct in_addr from_struct_ip;
struct in_addr my_struct_ip;
pcap_t *handle; // 핸들러
char *dev = "ens33"; // 자신의 네트워크 장비
char errbuf[PCAP_ERRBUF_SIZE]; // 오류 메시지를 저장하는 버퍼
struct bpf_program fp; // 필터 구조체
char *filter_exp = "port 80"; // 필터 표현식
bpf_u_int32 mask; // 서브넷 마스크
bpf_u_int32 net; // 아이피 주소
struct pcap_pkthdr *header; // 패킷 관련 정보
const u_char *packet; // 실제 패킷
u_char *dummy_packet;
u_char *dummy_packet2;
struct in_addr addr; // 주소 정보
u_int32_t target_ip;
u_int32_t m_ip;
u_short to_header_size;
u_short from_header_size;

#define ETHER_ADDR_LEN 6
struct sniff_ip;
struct sniff_tcp;
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; // 목적지 MAC 주소
        u_char ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC 주소
        u_short ether_type;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)
int payload_len;
void to_send_packet(const u_char *d_packet, pcap_t* handle);
void from_send_packet(const u_char *d_packet, pcap_t* handle);
struct sniff_ip {
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
        struct in_addr ip_src; // 출발지 IP 주소
        struct in_addr ip_dst; // 목적지 IP 주소
};

typedef u_int tcp_seq;

struct sniff_tcp {
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

#define SIZE_ETHERNET 14

struct sniff_ethernet *ethernet; // 이더넷 헤더
struct sniff_ip *ip;// IP 헤더
struct sniff_tcp *tcp; // TCP 혜더
char *payload; // 페이로드
u_int size_ip;
u_int size_tcp;
int to_first=1;// 이 패킷이 첫번째인지 아닌지 판단하는 용도의 변수
int from_first=1;
tcp_seq to_dummy_seq;
tcp_seq from_dummy_seq;

void parsing();
int isfiltered();

int main(int argc, char* argv[]){
	if(argc!=5){
		printf("Usage : %s <from ip> <my ip> <to ip> <port>\n",argv[0]);
		exit(1);
	}
	strcpy(toip,argv[3]);
	inet_aton(toip,&to_struct_ip);
	strcpy(fromip,argv[1]);
	inet_aton(fromip,&from_struct_ip);
    strcpy(myip,argv[2]);
    inet_aton(myip,&my_struct_ip);

	//패킷 스니핑 과정
	dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                printf("네트워크 장치를 찾을 수 없습니다.\n");
                return 0;
        }
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                printf("장치의 주소를 찾을 수 없습니다.\n");
                return 0;
        }
        addr.s_addr = net;
        addr.s_addr = mask;
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
                printf("장치를 열 수 없습니다.\n");
                printf("error message: %s", errbuf);
                return 0;
        }
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                printf("필터를 적용할 수 없습니다.\n");
                return 0;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                printf("필터를 세팅할 수 없습니다.\n");
                return 0;
        }
        printf("패킷을 감지합니다.\n");

	while(pcap_next_ex(handle, &header, &packet) == 1) 
        {
                printf("start\n");
            parsing();

           


                printf("start2\n");
           if(strcmp(inet_ntoa(ip->ip_src),myip)==0 || isfiltered()!=1)
            {
            
                printf("packing....\n");
                pack();
                printf("sending packet to target....\n");
                to_send_packet(dummy_packet,handle);
                printf("process completed!\n");
                free(dummy_packet);
            
            }
	else if(strcmp(inet_ntoa(ip->ip_dst),myip)==0 || isfiltered()!=1)
        {
            printf("unpacking....\n");
            unpack();
            printf("sending packet to target....\n");
            from_send_packet(dummy_packet2,handle);
            printf("process completed!\n");
            free(dummy_packet2);
        }

        }
        
	//패킷 스니핑 과정 end
	return 0;
}
void parsing(){
	int i;
	ethernet=(struct sniff_ethernet*)(packet);
	ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);
	size_ip= IP_HL(ip)*4;
	tcp=(struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
	size_tcp=TH_OFF(tcp)*4;
	payload=(u_char*)(packet+SIZE_ETHERNET+size_ip+size_tcp);
        payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);

}

void showpayload(){
	int i;
        if(payload_len == 0);
        else {
                printf("< 페이로드 데이터 >\n");
                for(int i = 1; i < payload_len; i++) {
                        printf("%c", payload[i - 1]);
                }
		printf("\n------------------------------------------------------\n");
        }
}

int isfiltered()
{

	if(tcp->th_flags!=0x18)
    {
		return 1;
	}
	else
	    return 0;

}

void pack(){
	if(to_first==1)
    {
		to_dummy_seq=ntohl(tcp->th_seq);//이 패킷이 첫번째일때(first==1)만 dummy_seq변수에 첫 패킷의 seq을 저장
		to_first++;
	}
	u_short hh;
	
    memcpy(&packet[38],&to_dummy_seq,sizeof(to_dummy_seq));
	memcpy(&(ip->ip_dst),&to_struct_ip,sizeof(to_struct_ip)); //update ip_dst as target ip
	memcpy(&(ip->ip_src),&my_struct_ip,sizeof(my_struct_ip));
	
    to_header_size=htons(132+payload_len);
    hh=htons(132+payload_len-14);
	printf("%d %d\n", ntohs(to_header_size), payload_len);
	if(payload_len==0)
		return;
	memcpy(&(ip->ip_len),&to_header_size,sizeof(to_header_size));  //update ip_total_len as pckt size+fake header size
	dummy_packet=(u_char*)malloc(sizeof(u_char)*htons(to_header_size));
	memset(dummy_packet,0,sizeof(const u_char)*htons(to_header_size));
	memcpy(dummy_packet,packet,sizeof(packet)*66);
	memcpy(dummy_packet+66,packet,sizeof(packet)*(66+payload_len+1));
}
void unpack(){
	if(from_first==1)
    {
                from_dummy_seq=ntohl(tcp->th_seq);//이 패킷이 첫번째일때(first==1)만 dummy_seq변수에 첫 패킷의 seq을 저장
                from_first++;
    }
	from_header_size=htons(payload_len-13);
	memcpy(&packet[38]+66,&from_dummy_seq,sizeof(from_dummy_seq));
    memcpy(&(ip->ip_dst)+66,&from_struct_ip,sizeof(from_struct_ip)); //update ip_dst as target ip 
	memcpy(&(ip->ip_src)+66,&my_struct_ip,sizeof(my_struct_ip));

	dummy_packet2=(u_char*)malloc(sizeof(u_char)*htons(from_header_size));
	//memcpy(dummy_packet2,packet+66,sizeof(packet)*(66+payload_len));
	for(int i=0; i<66+payload_len+1; i++)
    {
		dummy_packet2[i]=packet[i+66];
	}
	u_short hh=htons(66);
	memcpy(&dummy_packet2[16],&hh,sizeof(from_header_size));	
}
void to_send_packet(const u_char *d_packet, pcap_t* handle){
        if(pcap_sendpacket(handle, d_packet, htons(to_header_size)) != 0)
                fprintf(stderr, "\nError sending the packet! : %s\n", pcap_geterr(handle));
}
void from_send_packet(const u_char *d_packet, pcap_t* handle){
        if(pcap_sendpacket(handle, d_packet,htons(from_header_size)-1) != 0)
                fprintf(stderr, "\nError sending the packet! : %s\n", pcap_geterr(handle));
}
