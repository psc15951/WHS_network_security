#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    //struct tcpheader * tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
    struct tcpheader * tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
    unsigned short int data_len = ntohs(ip->iph_len) - sizeof(struct ipheader) - (tcp->tcp_offx2 >> 4) * 4; 

    // Mac Addr
    printf("Destination Mac Addr: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
    printf("Source Mac Addr: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);

    // IP Addr
    printf("Destination IP Addr: %s\n", inet_ntoa(ip->iph_sourceip)); 
    printf("Source IP Addr: %s\n", inet_ntoa(ip->iph_destip)); 
    
    // Port
    printf("Destination port: %d\n",ntohs(tcp->tcp_dport));
    printf("Source port: %d\n",ntohs(tcp->tcp_sport));

    //Message
    if(data_len > 0){
	    char * buffer = (char *) (packet + sizeof(struct ethheader) + sizeof(struct ipheader) + (tcp->tcp_offx2 >> 4) *4);
	    printf("Message: %s\n",buffer);
    }else{
	    printf("No Message!\n");
    }

  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


