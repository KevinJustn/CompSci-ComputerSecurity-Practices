#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
// #include "myheader.h"

void got_packet (u_char *args, const struct pcap_pthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *) packet;
    
    if (ntohs (eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader * ip = (struct ipheader *) (packet + sizeof (struct ethheader)) ;
        printf ("Source: %s   ", inet_ntoa(ip->iph_sourceip));
        printf ("Destination: %s\n", inet_ntoa(ip->iph_destip));
    }   
    printf("Got a packet\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    handle = pap_open_live("br-57a9ddc781c7", BUFSIZ, 1, 1000, errbuf);

    pcap_compile (handle, &fp, filter_exp, 0, net);
    if (pap_setfilter (handle, &p) !=0) {
        pap_perror (handle, "Error:");
        exit (EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pap_close(handle);         
    return 0;
}