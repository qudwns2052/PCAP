#include <stdio.h>
#include <pcap.h>

int main(void)
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        printf("Don't find device.\n");
    }
    printf("device name: %s\n", dev);
    return 0;
}