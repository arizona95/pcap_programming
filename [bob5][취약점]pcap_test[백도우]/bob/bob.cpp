#include <stdio.h>
#include <winsock2.h>
#pragma comment (lib, "ws2_32")
#include<windows.h>
#include <pcap.h>
#include "pcap_header.h"

#define PCAP_CNT_MAX 0
#define PCAP_SNAPSHOT 1024
#define PCAP_TIMEOUT 100


void packet_view(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
        
int main(int argc, char *argv[]) {
        char *dev=NULL;
        char errbuf[PCAP_ERRBUF_SIZE];
        bpf_u_int32 net;
        bpf_u_int32 netmask;	
        pcap_t *pd;
		pcap_if_t *alldevs;

		 if(pcap_findalldevs(&alldevs, errbuf) == -1)
        {
                fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
                exit(1);
        }
        
		 dev = alldevs->name;
		printf("Device      : %s\n", dev);
        pcap_lookupnet( dev , &net, &netmask, errbuf);
        pd = pcap_open_live( dev , PCAP_SNAPSHOT, 1, PCAP_TIMEOUT, errbuf);
        pcap_loop(pd, PCAP_CNT_MAX, packet_view, 0);
        pcap_close(pd);

        return 1;
}
void packet_view(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p)
{
    int len;
    const unsigned char *q=p;
    len = 0;
        
	/*
    while(len < h->len) {
            printf("%02x ", *(p++));
            if(!(++len % 16))
                    printf("\n");
    }*/
    printf("\n");
	if(*(q+23)==6)
	{
		int ip_header = 0;
		ip_header = ((*(q + 14)) % 16) <<2;
		printf("DATA : %d\n", ip_header);
		printf("PACKET\n");
        printf("EType: %02x%02x             Protocol : %02x\n",  *(q+12), *(q+13),*(q+23));
		printf("SMac :%02x:%02x:%02x:%02x:%02x:%02x DMac :%02x:%02x:%02x:%02x:%02x:%02x\n", *(q+6),*(q+7),*(q+8),*(q+9),*(q+10),*(q+11),*(q),*(q+1),*(q+2),*(q+3),*(q+4),*(q+5));
		q=q+14;
		printf("Sip  :%d.%d.%d.%d	Dip  :%d.%d.%d.%d\n",*(q+12),*(q+13),*(q+14),*(q+15),*(q+16),*(q+17),*(q+18),*(q+19));
		q=q+ip_header;
		printf("Src  :%4d              Dst  :%d\n",((*q)<<4)+(*(q+1)),((*(q+2))<<4)+(*(q+3)));
	}
    return ;
}





