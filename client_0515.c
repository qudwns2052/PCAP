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
#include "protocol_structure.h"

struct pcap_pkthdr *header; // 패킷 관련 정보
const u_char *packet; // 실제 패킷
u_char *dummy_packet;
u_char *dummy_packet2;
int res;

int to_header_size;

struct sniff_ethernet *ethernet; // 이더넷 헤더
struct sniff_ip *ip;// IP 헤더
struct sniff_tcp *tcp; // TCP 혜더
char *payload; // 페이로드


int payload_len;

int to_first=1;// 이 패킷이 첫번째인지 아닌지 판단하는 용도의 변수


tcp_seq to_dummy_seq;


int main(int argc, char* argv[])
{
	if(argc!=3)
        {
		printf("Usage : %s <interface> <target ip>\n",argv[0]);
		exit(1);
	}
        char *dev = argv[1]; // 자신의 네트워크 장비
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

        if(handle == NULL)
        {
                fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
                return -1;
        }

        char * target_ip_str = argv[2];
       
        char my_ip[4];
        char target_ip[4];
        

        inet_pton(AF_INET, target_ip_str, target_ip);


        /*        Get my IP Address      */
        int fd;
        struct ifreq ifr;

        fd = socket(AF_INET, SOCK_DGRAM, 0);

        ifr.ifr_addr.sa_family = AF_INET;

        strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

        ioctl(fd, SIOCGIFADDR, &ifr); // ???????

        close(fd);
        memcpy(my_ip, &((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr), 4);
/*************************************************************************************************/
	

	while(1) 
{

        res = pcap_next_ex(handle, &header, &packet);
        /*        Parsing      */
        ethernet=(struct sniff_ethernet*)(packet);
	ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);
	tcp=(struct sniff_tcp*)(packet+SIZE_ETHERNET+SIZE_IP);
	payload=(u_char*)(packet+SIZE_HEADER);
        payload_len = ntohs(ip->ip_len) - (SIZE_IP + SIZE_TCP);
        /**********************************************************/
        


        /*        packing           */
        if(!memcmp(ip->ip_src, my_ip, 4))
        {
                printf("packing....\n");
                to_header_size=(SIZE_HEADER*2)+payload_len; // fake header + real header + real payload
      
                if(to_first==1)
        {
	        to_dummy_seq=ntohl(tcp->th_seq);//이 패킷이 첫번째일때(first==1)만 dummy_seq변수에 첫 패킷의 seq을 저장
	        to_first++;
        }
        
        
        dummy_packet=(u_char*)malloc(sizeof(u_char)*to_header_size);
      
        memset(dummy_packet, 0, to_header_size);
	memcpy(dummy_packet, packet, SIZE_HEADER);
	memcpy(dummy_packet+SIZE_HEADER, packet, to_header_size - SIZE_HEADER);

        ethernet=(struct sniff_ethernet*)(dummy_packet);
	ip=(struct sniff_ip*)(dummy_packet+SIZE_ETHERNET);
	tcp=(struct sniff_tcp*)(dummy_packet+SIZE_ETHERNET+SIZE_IP);
        
        u_short update_ip_len = htons(to_header_size);
        memcpy(&(tcp->th_seq), &to_dummy_seq, sizeof(to_dummy_seq));
        memcpy(ip->ip_dst, target_ip, 4); //update ip_dst as target ip
        memcpy(&(ip->ip_len), &update_ip_len, sizeof(update_ip_len));  //update ip_total_len as pckt size+fake header size
        pcap_sendpacket(handle, dummy_packet, to_header_size);
        }
        /**********************************************************/

        /*       unpacking          */
        if(!memcmp(ip->ip_src, target_ip, 4)
            &&!memcmp(ip->ip_dst, my_ip, 4))
        {

        printf("unpacking....\n");

        dummy_packet2=(u_char*)malloc(sizeof(u_char)*payload_len);
      
        memset(dummy_packet2, 0, payload_len);
	memcpy(dummy_packet2, packet+SIZE_HEADER, payload_len);

        ethernet=(struct sniff_ethernet*)(dummy_packet2);
	ip=(struct sniff_ip*)(dummy_packet2+SIZE_ETHERNET);
	
        memcpy(ip->ip_dst, my_ip, 4); //update ip_dst as target ip
        pcap_sendpacket(handle, dummy_packet2, payload_len);
        }
        /**********************************************************/


}
        free(dummy_packet);
        free(dummy_packet2);
       
	return 0;
}