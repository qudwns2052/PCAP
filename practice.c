#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h> 
#include <sys/ioctl.h> 
#include <net/if.h>  
#include <unistd.h> 
#include <time.h>
// #include "protocol_structure.h"
// #include "printarr.h"
// #include "protocol_check.h"
// #include "swap_endian.h"
#define ETHER_LEN 14
#define ETHERTYPE_ARP 0X0806
#define ARP_HTYPE 0X0001
#define ARP_PTYPE 0X0800
#define ARP_HLEN 0X06
#define ARP_PLEN 0X04
#define ARP_OPER_REQ 0X0001
#define ARP_OPER_REP 0X0002

void usage() {
  printf("syntax: arp_spoof <interface> <sender ip> <target ip>\n");
  printf("sample: arp_spoof wlan0 192.168.10.34 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  //Default variables
  struct pcap_pkthdr* header;
  const u_char* packet;
  int res;

  // My variables , structures 
  struct sniff_ethernet *ethernet_request;
  struct sniff_arp *arp_request;
  struct sniff_ethernet *ethernet_sender_reply;
  struct sniff_arp *arp_sender_reply;
  struct sniff_ethernet *ethernet_target_reply;
  struct sniff_arp *arp_target_reply;
  struct sniff_ethernet *ethernet;
  struct sniff_arp *arp;
  struct sniff_ip *ip;

  char arp_request_sender_packet[42];    
  char arp_request_target_packet[42]; 
  char arp_reply_sender_packet[42];
  char arp_reply_target_packet[42];

  char* ip_sender_str = argv[2];      // readable ip 
  char* ip_target_str = argv[3];      // readable ip
  char ip_sender[4];                     // Victim ip
  char ip_target[4];                    // Gateway ip usaully
  char ip_attacker[4]; 		           	// My IP Address

  char mac_broadcast[6] = {0xFF , 0xFF , 0xFF , 0xFF , 0xFF , 0xFF};
  char mac_sender[6] = {0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00};
  char mac_target[6] = {0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00};
  char mac_attacker[6];               // My Mac Address

  inet_pton(AF_INET , ip_sender_str , ip_sender);
  inet_pton(AF_INET , ip_target_str , ip_target);


  /*        Get my IP Address      */
  int fd;   //file descriptor 선언
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);  //클라이언트 소켓 생성 (IPv4, UDP 통신 프로토콜, 0)

  ifr.ifr_addr.sa_family = AF_INET;		 //I want to get an IPv4 IP address

  strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);	 //I want IP address attached to "ens33"

  ioctl(fd, SIOCGIFADDR, &ifr);     //???

  close(fd);
  memcpy(ip_attacker,&((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr),4);
  /*************************************************************************************************/


  /*        Get my Mac Address      */
  struct ifconf ifc; 
  char buf[1024]; 
  int success = 0; 

  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP); 
  if (sock == -1) { /* handle error*/ }; 

  ifc.ifc_len = sizeof(buf); 
  ifc.ifc_buf = buf; 
  if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ } 

  struct ifreq* it = ifc.ifc_req; 
  const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq)); 

  for (; it != end; ++it) { 
      strcpy(ifr.ifr_name, it->ifr_name); 
      if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) { 
              if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback 
                      if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) { 
                              success = 1; 
                              break; 
                      } 
              } 
      } 
      else { /* handle error */ } 
  } 
  if (success) memcpy(mac_attacker, ifr.ifr_hwaddr.sa_data, 6);


    for(int i=0; i<4; i++)
    {
        printf("%x ", ip_attacker[i]);
    }
    printf("\n");
    for(int i=0; i<6; i++)
    {
        printf("%x ", mac_attacker[i]);
    }
    printf("\n");

}