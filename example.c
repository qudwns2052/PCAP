#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>

pcap_t *handle;
char *dev = "ens33";
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char *filter_exp = "port 80";
bpf_u_int32 mask;
bpf_u_int32 net;
struct pcap_pkthdr *header;
const u_char *packet;
struct in_addr addr;

int main(void)
{
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        printf("network device don't found\n");
        return 0;
    }
    printf("my network device: %s\n", dev);
    if (pcap_lookupnet(dev, &net, &mask, errbuf)==-1)
    {
        printf("address of device don't found\n");
        return 0;
    }
    addr.s_addr=net;
    printf("my IP address: %s\n", inet_ntoa(addr));
    addr.s_addr=mask;
    printf("my subnet mask: %s\n", inet_ntoa(addr));
    return 0;
}