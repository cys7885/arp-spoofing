#include <stdio.h>
#include "utils.h"
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

int arp_relay(char *interface, char *sender_ip, char *target_ip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open interfaceice %s: %s\n", interface, errbuf);
        return -1;
    }
    uint8_t local_mac[6] = {0};
    get_mac(local_mac, interface, WANT_LOCALMAC);
    struct pcap_pkthdr* header;
    const u_char* packet;
    while(1){
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        int check = check_packet(packet, local_mac, sender_ip, target_ip);
        if(!check){
            if(pcap_sendpacket(handle, packet, 1000) != 0)
                return -1;
            printf("[+]send...!");
        }
        else {
            printf("[-]Nop...T.T");
        }
    }
    return 0;
}

int check_packet(const unsigned char *packet, uint8_t local_mac[6], char *sender_ip, char *target_ip){
    struct ethernet_header *ethernet_header;
    ethernet_header = (struct ethernet_header*)packet;
    struct ip_header *ip_header;
    ip_header = (struct ip_header*)(packet+ETH_LENGTH);

    int dst_mac_flag = 0;
    int src_mac_flag = 0;

    if(memcmp(ethernet_header->dst_mac.ether_addr_object, local_mac, 6) == 0)
        dst_mac_flag++;

    if(memcmp(ethernet_header->src_mac.ether_addr_object, sender_mac, 6) == 0)
        src_mac_flag++;
    if((dst_mac_flag&src_mac_flag) == 1){ //sender to target
        printf("sender to target!!!");
        memcpy(ethernet_header->src_mac.ether_addr_object, local_mac, 6);
        memcpy(ethernet_header->dst_mac.ether_addr_object, target_mac, 6);
        return 0;
    }
    return 1;

}
