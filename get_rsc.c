#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include "utils.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>

void get_mac(uint8_t MAC_addr[6], char *interface, int flag)
{

    if(flag == WANT_LOCALMAC){
        int s;
        struct ifreq ifr;
        s = socket(AF_INET, SOCK_DGRAM, 0);
        strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
        ioctl(s, SIOCGIFHWADDR, &ifr);
        memcpy(MAC_addr, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
     }
    if(flag == WANT_BROADCAST){
        uint8_t addr[6] = {255,255,255,255,255,255};
        memcpy(MAC_addr, addr, MAC_SIZE);
    }

}

char *get_host_ip(char *local_ip, char *interface){
    int s;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(s, SIOCGIFADDR, &ifr);
    local_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

    close(s);
    return local_ip;
}
