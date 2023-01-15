#include "arp.h"
#include "device.h"

int ARPTableID = 0;

int setARPTable(const struct in_addr ip, const u_char* mac){
    // pthread_mutex_lock(&ARPLock);

    if(ARPTableID == MAX_ARPTABLE_LEN){
        fprintf(stderr, "Couldn't add more to ARP table!\n");
        // pthread_mutex_unlock(&ARPLock);
        return -1;
    }

    for(int i = 0; i < ARPTableID; i++){
        if(ARPTable[i].ipaddr.s_addr == ip.s_addr && strcmp((const char*)mac, (const char*)ARPTable[i].macaddr) == 0){
            return 0;
        }
    }
    
    ARPTable[ARPTableID].ipaddr = ip;
    memcpy(ARPTable[ARPTableID].macaddr, mac, 6);
    ARPTableID++;

    // pthread_mutex_unlock(&ARPLock);

    return 0;
}

int matchARPTable(struct in_addr ip, u_char* mac){
    // pthread_mutex_lock(&ARPLock);

    int i;
    for(i = 0; i < ARPTableID; i++){
        if(ARPTable[i].ipaddr.s_addr == ip.s_addr){
            memcpy(mac, ARPTable[i].macaddr, 6);
            // pthread_mutex_unlock(&ARPLock);
            return 0;
        }
    }
    // pthread_mutex_unlock(&ARPLock);
    return -1;
}


int makeARPRequestPayload(int dev, struct in_addr dest, u_char* buf){
    struct ether_arp* arppkt = (struct ether_arp*)buf;
    struct arphdr* ahdr = (struct arphdr*)buf;
    in_addr_t ipaddr;
    
    ahdr->ar_hrd = htons(1);
    ahdr->ar_pro = htons(0x0800);
    ahdr->ar_hln = 6;
    ahdr->ar_pln = 4;
    ahdr->ar_op = htons(1); // 1 - ARP request, 2 - ARP reply

    memcpy(arppkt->arp_sha, rev_devs[dev].mac, ETH_ALEN);
    ipaddr = rev_devs[dev].ipv4addr.s_addr;
    memcpy(arppkt->arp_spa, &ipaddr, 4);

    memset(arppkt->arp_tha, 0, ETH_ALEN);   // When sending, fill it with all zeros.
    ipaddr = dest.s_addr;
    memcpy(arppkt->arp_tpa, &ipaddr, 4);

    return sizeof(struct ether_arp);
}

int makeARPReplyPayload(int dev, struct in_addr dest, u_char* destmac, u_char* buf){
    struct ether_arp* arppkt = (struct ether_arp*)buf;
    struct arphdr* ahdr = (struct arphdr*)buf;
    in_addr_t ipaddr;
    
    ahdr->ar_hrd = htons(1);
    ahdr->ar_pro = htons(0x0800);
    ahdr->ar_hln = 6;
    ahdr->ar_pln = 4;
    ahdr->ar_op = htons(2); // 1 - ARP request, 2 - ARP reply

    memcpy(arppkt->arp_sha, rev_devs[dev].mac, ETH_ALEN);
    ipaddr = rev_devs[dev].ipv4addr.s_addr;
    memcpy(arppkt->arp_spa, &ipaddr, 4);

    memcpy(arppkt->arp_tha, destmac, ETH_ALEN);   // When sending, fill it with all zeros.
    ipaddr = dest.s_addr;
    memcpy(arppkt->arp_tpa, &ipaddr, 4);

    return sizeof(struct ether_arp);
}

void printARPTable(){
    int i;
    in_addr_t temp;
    u_char* cptr;
    struct timeval tv;
    gettimeofday(&tv, NULL);

    printf("[Info] ARP table elements:\n");
    for(i = 0; i < ARPTableID; i++){
        temp = ARPTable[i].ipaddr.s_addr;
        cptr = (u_char*)&temp;
        printf("IPv4 addr:\t%u.%u.%u.%u\t", cptr[0], cptr[1], cptr[2], cptr[3]);
        printf("MAC addr:\t%02x:%02x:%02x:%02x:%02x:%02x\n",
            ARPTable[i].macaddr[0], ARPTable[i].macaddr[1], ARPTable[i].macaddr[2],
            ARPTable[i].macaddr[3], ARPTable[i].macaddr[4], ARPTable[i].macaddr[5]);
    }
    printf("[Info] [%d] ARP table elements exists\n", ARPTableID);
    printf("tv_sec:\t%d\ttv_usec:\t%d\n\n", tv.tv_sec, tv.tv_usec);
}