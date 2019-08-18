#include "stdint.h"
#ifndef UTILS_H
#define UTILS_H

#endif // UTILS_H

#define PACKET_SIZE 42
#define ICMP_SIZE 98
#define TEST 500
#define ETH_LENGTH 14
#define ARPTYPE 0x0806
#define IP_SIZE 4
#define MAC_SIZE 6
#define WANT_LOCALMAC 1
#define WANT_BROADCAST 2
#define ARP_ETHERNET 1
#define IPv4 0x0800
#define ARP_HWSIZE 6
#define ARP_PROTOCOLSIZE 4
#define ARP_REQ 1
#define ARP_REP 2

uint8_t sender_mac[6];
uint8_t target_mac[6];

void get_mac(uint8_t MAC[6], char *interface, int flag);
int arp_request(char *interface, char *target_ip, char *sender_ip);
int check_arp_reply(const unsigned char *packet, uint8_t eth_dst_mac[6]);
char *get_host_ip(char *local_ip, char *interface);
int arp_relay(char *interface, char *sender_ip, char *target_ip);
int check_packet(const unsigned char *packet, uint8_t local_mac[6], char *sender_ip, char *target_ip);

struct ethernet_addr{
  uint8_t ether_addr_object[6];
};

struct ethernet_header{
   struct ethernet_addr dst_mac;
   struct ethernet_addr src_mac;
   uint16_t type;
};

struct ip_addr{
  uint8_t ip_addr_object[4];
};

struct ip_header{
  unsigned char ip_header_length:4;
  unsigned char ip_version:4;
  unsigned char ip_type_of_service;
  unsigned short ip_total_length;
  unsigned short ip_id;
  unsigned char ip_frag_offset:5;
  unsigned char ip_more_fragment:1;
  unsigned char ip_dont_fragment:1;
  unsigned char ip_reserved_zero:1;
  unsigned char ip_frag_offset1;
  unsigned char ip_ttl;
  unsigned char ip_protocol;
  unsigned short ip_header_checksum;
  uint32_t ip_src;
  uint32_t ip_dst;
  //struct ip_addr ip_src;
  //struct ip_addr ip_dst;
};

struct arp_header{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    struct ethernet_addr sendear_mac;
    uint32_t sender_ip;
    struct ethernet_addr target_mac;
    uint32_t target_ip;
}__attribute__((packed));

struct thread_args{
    char *interface;
    char *sender_ip;
    char *target_ip;
};
