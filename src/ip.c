#include "ip.h"
#include "arp.h"
#include "packetio.h"
#include "device.h"


extern int device_ID;

int RoutingTableID = 0;
int IPPacketFront = 0;
int IPPacketBack = 0;
pthread_mutex_t IPQueLock;

void pushIPQue(struct IPPacketQueElem* ippkt){
    pthread_mutex_lock(&IPQueLock);
    int tmpback = IPPacketBack + 1;
    if(tmpback == IP_MAX_QUE_LEN){
        tmpback = 0;
    }
    if(tmpback == IPPacketFront){
        fprintf(stderr, "pushIPQue: the queue is full!\n");
        pthread_mutex_unlock(&IPQueLock);
        return;
    }
    
    IPPacketQue[IPPacketBack].ts = ippkt->ts;
    IPPacketQue[IPPacketBack].dest = ippkt->dest;
    IPPacketQue[IPPacketBack].len = ippkt->len;
    IPPacketQue[IPPacketBack].proto = ippkt->proto;
    IPPacketQue[IPPacketBack].src = ippkt->src;
    IPPacketQue[IPPacketBack].ttl = ippkt->ttl;
    memcpy(IPPacketQue[IPPacketBack].buf, ippkt->buf, ippkt->len);

    IPPacketBack = tmpback;

    pthread_mutex_unlock(&IPQueLock);
}

void popIPQue(struct IPPacketQueElem* ippkt){
    pthread_mutex_lock(&IPQueLock);
    if(IPPacketFront == IPPacketBack){
        fprintf(stderr, "popIPQue: the queue is empty!\n");
        pthread_mutex_unlock(&IPQueLock);
        return;
    }

    int tmpfront = IPPacketFront;

    IPPacketFront++;
    if(IPPacketFront == IP_MAX_QUE_LEN){
        IPPacketFront = 0;
    }

    ippkt->ts = IPPacketQue[tmpfront].ts;
    ippkt->dest = IPPacketQue[tmpfront].dest;
    ippkt->len = IPPacketQue[tmpfront].len;
    ippkt->proto = IPPacketQue[tmpfront].proto;
    ippkt->src = IPPacketQue[tmpfront].src;
    ippkt->ttl = IPPacketQue[tmpfront].ttl;
    memcpy(ippkt->buf, IPPacketQue[tmpfront].buf, ippkt->len);

    pthread_mutex_unlock(&IPQueLock);
}

int lenIPQue(){
    return IPPacketFront <= IPPacketBack ? (IPPacketBack - IPPacketFront) : (IPPacketBack + IP_MAX_QUE_LEN - IPPacketFront);
}

int emptyIPQue(){
    return IPPacketFront == IPPacketBack ? 1 : 0;
}

uint16_t calcCheck(struct iphdr* hdrptr){
    uint16_t* ptr = (uint16_t*) hdrptr;
    uint32_t sum = 0, carry;
    uint16_t res = 0;
    int i;

    hdrptr->check = 0;

    // ignore options
    for(i = 0; i < sizeof(struct iphdr) / sizeof(uint16_t); i++){
        sum += (*ptr);
        ptr++;
    }

    carry = sum >> 16;
    while(carry != 0){
        sum = carry + (sum & 0xffff);
        carry = sum >> 16;
    }

    res = ~sum;
    return res;
}

int sendIPPacket ( const struct in_addr src , const struct in_addr dest ,
    int proto , const void * buf , int len, int ttl, struct timeval ts){
        //
        u_char senddata[MAX_DATA_LEN];
        u_char destmac[10];
        int devid;
        struct RoutingTableElem* rte;
        struct in_addr arpqry;
        struct iphdr* hdrptr;
        
        // encapsulate begin
        // ignore TOS & IP options, don't handle fragmentation
        
        hdrptr = (struct iphdr*)senddata;
        hdrptr->version = 4;
        hdrptr->ihl = 5;
        hdrptr->tos = IPTOS_PREC_ROUTINE;   //Delay, Throughput, Reliability = 0
        hdrptr->tot_len = sizeof(struct iphdr) + len;
        hdrptr->id = 0;
        hdrptr->frag_off = 0;
        hdrptr->ttl = ttl;   // may change
        hdrptr->protocol = proto;
        hdrptr->saddr = ntohl(src.s_addr);
        hdrptr->daddr = ntohl(dest.s_addr);
        hdrptr->check = calcCheck(hdrptr);  // calculate checksum

        // printf("%x\n%x\n\n", hdrptr->saddr, hdrptr->daddr);

        // byte order!
        hdrptr->tot_len = htons(hdrptr->tot_len);
        hdrptr->id = htons(hdrptr->id);
        hdrptr->saddr = htonl(hdrptr->saddr);
        hdrptr->daddr = htonl(hdrptr->daddr);
        hdrptr->check = htons(hdrptr->check);

        memcpy(senddata + sizeof(struct iphdr), buf, len);
        // encapsulate end

        // puts("sendIPPacket");
        // printf("size: %d\n", sizeof(struct iphdr));
        // for(int i = 0; i < len; i++){
        //     printf("%02x ", *((u_char*)buf + i));
        //     if((i & 7) == 7)putchar('\n');
        // }
        // putchar('\n');

        // // for(int i = 0; i < len; i++){
        // //     senddata[i + sizeof(struct iphdr)] = *((u_char*)buf + i);
        // // }

        // for(int i = 0; i < len; i++){
        //     printf("%02x ", *((u_char*)senddata + 20 + i));
        //     if((i & 7) == 7)putchar('\n');
        // }
        // putchar('\n');

        if(proto == IP_ROUTING_PROTO){
            // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
            u_char broadcastmac[8]={0xff,0xff,0xff,0xff,0xff,0xff};
            for(int i = 0; i < device_ID; i++){
                if(rev_devs[i].ipv4addr.s_addr == src.s_addr){
                    devid = i;
                    break;
                }
            }
            return sendFrame(senddata, sizeof(struct iphdr) + len, ETH_P_IP, broadcastmac, devid);
        }

        // find out the destmac, using routing table and ARP

        // printf("Going here: %s %d\n", __FILE__ ,__LINE__);

        rte = matchRoutingTable(dest);
        if(rte == NULL){
            // u_char* ptr = &dest;
            // fprintf(stderr, "Couldn't be found in routing table:\t%u.%u.%u.%u\n", ptr[0], ptr[1], ptr[2], ptr[3]);
            // return -1;
            struct IPPacketQueElem ippkt;
            ippkt.src = src;
            ippkt.dest = dest;
            ippkt.proto = proto;
            ippkt.ttl = ttl;
            ippkt.len = len;
            memcpy(ippkt.buf, buf, len);
            ippkt.ts = ts;

            pushIPQue(&ippkt); 
            return 2;
        }
        if(rte->dis == 0){  // the same subnet, then the nextHop should be dest directly
            arpqry = dest;
        }
        else arpqry = rte->nextHop;
        if(matchARPTable(arpqry, destmac) == -1){
            // printf("matchARP Going here: %s %d\n", __FILE__ ,__LINE__);
            struct IPPacketQueElem ippkt;
            ippkt.src = src;
            ippkt.dest = dest;
            ippkt.proto = proto;
            ippkt.ttl = ttl;
            ippkt.len = len;
            memcpy(ippkt.buf, buf, len);
            ippkt.ts = ts;

            pushIPQue(&ippkt);            

            u_char payloadbuf[MAX_DATA_LEN];
            u_char broadcastmac[8] = {0xff,0xff,0xff,0xff,0xff,0xff};
            int paylen = makeARPRequestPayload(rte->srcdev, arpqry, payloadbuf);
            sendFrame(payloadbuf, paylen, ETH_P_ARP, broadcastmac, rte->srcdev);
            return 2;
        }
        devid = rte->srcdev;

        return sendFrame(senddata, sizeof(struct iphdr) + len, ETH_P_IP, destmac, devid);
}

IPPacketReceiveCallback IPCallBack = NULL;

int setIPPacketReceiveCallback(IPPacketReceiveCallback callback){
    IPCallBack = callback;
}

int setRoutingTable( const struct in_addr dest ,
    const struct in_addr mask ,
    const struct in_addr nextHop , int device,
    const int dis, const struct timeval ts){
        if(RoutingTableID >= MAX_TABLE_LEN){
            fprintf(stderr, "setRoutingTable: Couldn't add an element.\n");
            return -1;
        }
        
        //pthread_mutex_lock(&RoutingLock);

        int id =RoutingTableID;
        RoutingTable[id].dest = dest;
        RoutingTable[id].mask = mask;
        RoutingTable[id].dis = dis;
        RoutingTable[id].ts = ts;
        RoutingTable[id].srcdev = device;
        RoutingTable[id].nextHop.s_addr = nextHop.s_addr;
        RoutingTableID++;

        //pthread_mutex_unlock(&RoutingLock);

        return 0;
}

//return 1 if a > b, 0 if a == b, -1 if a <b
int cmptv(struct timeval a, struct timeval b){
    if(a.tv_sec == b.tv_sec){
        if(a.tv_usec == b.tv_usec){
            return 0;
        }
        return a.tv_usec < b.tv_usec ? -1 : 1;
    }
    else return a.tv_sec < b.tv_sec ? -1 : 1;
}

void updateRoutingTable(struct RoutingTableElem rte, int hop, struct in_addr rteip, int dev){
    //pthread_mutex_lock(&RoutingLock);

    int i, flag = 0, dis, rtedis;
    struct timeval tv;
    gettimeofday(&tv, NULL);

    for(i = 0; i < RoutingTableID; i++){
        if(RoutingTable[i].dis == 0){   // itself
            RoutingTable[i].ts = tv;
        }
    }
    if(rte.dis > IP_TTL_THRESHOLD || tv.tv_sec -rte.ts.tv_sec > IP_TIME_ENTRY_THRESHOLD){
        return;
    }

    for(i = 0; i < RoutingTableID; i++){
        if(rte.mask.s_addr == RoutingTable[i].mask.s_addr && rte.dest.s_addr == RoutingTable[i].dest.s_addr){
            flag = 1;
            if(tv.tv_sec - RoutingTable[i].ts.tv_sec > IP_TIME_ENTRY_THRESHOLD){
                dis = IP_TTL_THRESHOLD * 2;
            }
            else dis = RoutingTable[i].dis;
            if(rte.dis + hop < dis){
                RoutingTable[i].nextHop.s_addr = rteip.s_addr;
                RoutingTable[i].srcdev = dev;
                RoutingTable[i].ts = tv;
                RoutingTable[i].dis = rte.dis + hop;
                break;
            }
            else if(rte.dis + hop == dis && cmptv(rte.ts, RoutingTable[i].ts) == 1){
                RoutingTable[i].nextHop.s_addr = rteip.s_addr;
                RoutingTable[i].srcdev = dev;
                RoutingTable[i].ts = tv;
                break;
            }
        }
    }
    if(flag == 0 && RoutingTableID < MAX_TABLE_LEN){  //a new element!
        int id = RoutingTableID;
        RoutingTable[id].dest = rte.dest;
        RoutingTable[id].mask = rte.mask;
        RoutingTable[id].dis = rte.dis + hop;
        RoutingTable[id].ts = tv;
        RoutingTable[id].srcdev = dev;
        RoutingTable[id].nextHop.s_addr = rteip.s_addr;
        RoutingTableID++;
    }

    //pthread_mutex_unlock(&RoutingLock);
}

int countLeadingOnes(in_addr_t mask){
    int ret = 0;
    in_addr_t tmp = 0x80000000;
    while(tmp > 0){
        if(mask < tmp)break;
        mask-=tmp;
        ret++;
        tmp>>=1;
    }
    return ret;
}

struct RoutingTableElem* matchRoutingTable(struct in_addr destIP){
    struct RoutingTableElem* res = NULL;
    in_addr_t destip = destIP.s_addr, mask, rteip;
    int i, tmplen, maxlen = 0;
    struct timeval tv;
    time_t tentry;

    if(destip == IP_BROADCASTING_ADDR){
        fprintf(stderr, "matchRoutingTable: Couldn't use a broadcasting address!\n");
        return NULL;
    }

    //pthread_mutex_lock(&RoutingLock);

    for(i = 0; i < RoutingTableID; i++){
        if(RoutingTable[i].dis == 0){   // itself
            RoutingTable[i].ts = tv;
        }
    }

    for(i = 0; i < RoutingTableID; i++){
        tentry = RoutingTable[i].ts.tv_sec;
        gettimeofday(&tv, NULL);
        if(tv.tv_sec - tentry >= IP_TIME_ENTRY_THRESHOLD){
            continue;   //  this element is out-of-date
        }

        if(RoutingTable[i].dis > IP_TTL_THRESHOLD){
            continue;   //  this element is invalid
        }

        mask = RoutingTable[i].mask.s_addr;
        rteip = RoutingTable[i].dest.s_addr;
        if((destip & mask) == (rteip & mask)){
            tmplen = countLeadingOnes(ntohl(mask));
            if(tmplen > maxlen){    //  longest prefix
                maxlen = tmplen;
                res = &RoutingTable[i];
            }
        }
    }

    //pthread_mutex_unlock(&RoutingLock);

    return res;
}

int makeRoutingPayload(void* buf){
    //pthread_mutex_lock(&RoutingLock);

    int len = 0, i;
    int* iptr = (int*)buf;
    struct RoutingTableElem* rptr = (struct RoutingTableElem*)buf;

    *iptr = RoutingTableID;
    // printf("*iptr:\t%d\n", *iptr);
    rptr++;
    len += sizeof(struct RoutingTableElem); //  alignment
    for(i = 0; i < RoutingTableID; i++){
        memcpy(rptr, &RoutingTable[i], sizeof(struct RoutingTableElem));
        rptr++;
        len += sizeof(struct RoutingTableElem);
    }

    // for(i = 0; i < len; i++){
    //     printf("%02x ", *((u_char*)buf + i));
    //     if((i & 7) == 7)putchar('\n');
    // }
    // putchar('\n');

    //pthread_mutex_unlock(&RoutingLock);

    return len;
}

void initRoutingTable(){
    //pthread_mutex_lock(&RoutingLock);
    int i;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    for(i = 0; i < device_ID; i++){
        struct in_addr dst, msk;
        msk.s_addr = rev_devs[i].netmask.s_addr;
        dst.s_addr = rev_devs[i].ipv4addr.s_addr & msk.s_addr;

        //pthread_mutex_unlock(&RoutingLock);
        setRoutingTable(dst, msk, dst, i, 0, tv);
        //pthread_mutex_lock(&RoutingLock);
    }
    //pthread_mutex_unlock(&RoutingLock);
}

void printRoutingTable(){
    int i, cnt = 0;
    in_addr_t temp;
    u_char* cptr;
    struct timeval tv;
    gettimeofday(&tv, NULL);

    //pthread_mutex_lock(&RoutingLock); 

    for(i = 0; i < RoutingTableID; i++){
        if(RoutingTable[i].dis == 0){   // itself
            RoutingTable[i].ts = tv;
        }
    }

    printf("[Info] Valid routing table elements:\n");
    for(i = 0; i < RoutingTableID; i++){
        if(tv.tv_sec - RoutingTable[i].ts.tv_sec <= IP_TIME_ENTRY_THRESHOLD &&
            RoutingTable[i].dis <= IP_TTL_THRESHOLD){
            temp = RoutingTable[i].dest.s_addr;
            cptr = (u_char*)&temp;
            printf("dest addr:\t%u.%u.%u.%u\n", cptr[0], cptr[1], cptr[2], cptr[3]);

            temp = RoutingTable[i].mask.s_addr;
            cptr = (u_char*)&temp;
            printf("netmask:\t%u.%u.%u.%u\n", cptr[0], cptr[1], cptr[2], cptr[3]);

            temp = RoutingTable[i].nextHop.s_addr;
            cptr = (u_char*)&temp;
            printf("next hop:\t%u.%u.%u.%u\n", cptr[0], cptr[1], cptr[2], cptr[3]);

            printf("srouce device:\t%d %s\n", RoutingTable[i].srcdev, rev_devs[RoutingTable[i].srcdev].name);

            printf("distance:\t%d\n", RoutingTable[i].dis);

            putchar('\n');
        }
        else cnt++;
    }
    printf("[Info] [%d] routing table elements exists, [%d] of them are out of date.\n", RoutingTableID, cnt);
    printf("tv_sec:\t%d\ttv_usec:\t%d\n\n", tv.tv_sec, tv.tv_usec);
    //pthread_mutex_unlock(&RoutingLock);
}

int printIPInfoCallBack(const void * buf,int len){
    int i, j, hops, proto;
    struct iphdr* iph = (struct iphdr*)buf;
    struct in_addr srcip, destip;
    u_char* cptr;
    
    srcip.s_addr = iph->saddr;
    destip.s_addr = iph->daddr;
    if(srcip.s_addr == destip.s_addr){
        return -1;
    }
    proto = iph->protocol;
    
    printf("get an IP packet!\n");
    printf("length: %d\tprotocol: %d\n", len, proto);

    cptr = (u_char*)&srcip;
    printf("source addr:\t%u.%u.%u.%u\n", cptr[0], cptr[1], cptr[2], cptr[3]);
    
    cptr = (u_char*)&destip;
    printf("destination addr:\t%u.%u.%u.%u\n\n", cptr[0], cptr[1], cptr[2], cptr[3]);
   
   
    puts("payload:");

    for(i = sizeof(struct iphdr), j = 0; i < len; i++, j++){
        printf("%02x ", *((u_char*)buf + i));    // hex
        // printf("%c ", *((char*)buf + i));   // char
        if((j & 3) == 3)putchar('\n');
    }
    if((j & 3) != 0)putchar('\n');
    
    putchar('\n');
    // printf("PacketBack:%d PacketFront:%d\n\n", PacketBack, PacketFront);
    return 0;
}