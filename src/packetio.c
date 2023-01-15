#include <netinet/ether.h>
#include "packetio.h"
#include "device.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "socket.h"

extern pcap_t* DeviceHandle[MAX_DEV_NUM];
extern int device_ID;

extern int IPPacketFront;
extern int IPPacketBack;

int sendFrame(const void* buf, int len, int ethtype, const void* destmac, int id){
   
    pcap_t* handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char senddata[MAX_DATA_LEN];
    u_char* ptr;
    int size, i, ret;
    
    // check whether id are valid
    if(checkValidDevice(id) == NULL){
        fprintf(stderr, "Device ID out of range!\n");
        return -1;
    }

    pthread_mutex_lock(&SendLock[id]);
    // encapsulate
    struct ether_header* hdrptr;
    hdrptr = (struct ether_header*) senddata;
    memcpy(hdrptr->ether_dhost, destmac, ETH_ALEN);
    memcpy(hdrptr->ether_shost, rev_devs[id].mac, ETH_ALEN);
    hdrptr->ether_type = htons(ethtype);
    memcpy(senddata + ETH_HLEN, buf, len);

    handler = DeviceHandle[id];
    //pcap_activate(handler);
    ret = pcap_sendpacket(handler, senddata, len + ETH_HLEN);

    // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
    // printf("ret is %d\n\n", ret);
    pthread_mutex_unlock(&SendLock[id]);

    return ret == 0 ? 0 : -1;
}

frameReceiveCallback EthCallBack = NULL;  // callback function for some purpose
extern IPPacketReceiveCallback IPCallBack;
/*
 * When receiving a packet, push it into the RecvdPackets and invoke Callback();
 */ 

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt){ // default handler
    pthread_mutex_lock(&QueLock);
    int pktdevid = (u_int64_t)args;
    int tmpback = PacketBack + 1;
    if(tmpback == MAX_QUE_LEN){
        tmpback = 0;
    }
    if(tmpback == PacketFront){ // The queue is full, just throw the packets.
        pthread_mutex_unlock(&QueLock);
        return;
    }
    

    memcpy(RecvdPackets[PacketBack].data, pkt, header->len);
    RecvdPackets[PacketBack].devid = pktdevid;
    RecvdPackets[PacketBack].len = header->len;
    RecvdPackets[PacketBack].ts = header->ts;

    PacketBack = tmpback;

    if(EthCallBack != NULL)
        EthCallBack(pkt, header -> len, pktdevid);

    // if(IPCallBack != NULL)
    //     IPCallBack(pkt + sizeof(struct ethhdr), header->len - sizeof(struct ethhdr));
    
    pthread_mutex_unlock(&QueLock);
}

int setFrameReceiveCallback(frameReceiveCallback callback){
    EthCallBack = callback;
    return 0;
}

// Here are call-back functions.

int printInfoCallBack(const void * buf,int len,int id){
    int i, j;

    printf("get a packet!\n");
    printf("length: %d\tdevice ID: %d\tdevice name:%s\n", len, id, rev_devs[id].name);

    // print ethernet header begin
    for(i = 0; i < ETH_ALEN; i++){
        printf("%02x ", *((u_char*)buf + i));
    }
    putchar('\n');
    for(; i < 2*ETH_ALEN; i++){
        printf("%02x ", *((u_char*)buf + i));
    }
    putchar('\n');
    for(; i < ETH_HLEN; i++){
        printf("%02x ", *((u_char*)buf + i));
    }
    putchar('\n');
    // print ethernet header end


    for(j = 0; i < len; i++, j++){
        printf("%02x ", *((u_char*)buf + i));    // hex
        // printf("%c ", *((char*)buf + i));   // char
        if((j & 3) == 3)putchar('\n');
    }
    if((j & 3) != 0)putchar('\n');
    
    putchar('\n');
    // printf("PacketBack:%d PacketFront:%d\n\n", PacketBack, PacketFront);
}

extern int EndFlag;

void processIPPacket(struct PacketQueue* pkt){
    struct ethhdr* ethh = (struct ethhdr*) pkt->data;
    struct iphdr* iph = (struct iphdr*)(pkt->data + ETH_HLEN);
    int* intp = (int*)(pkt->data + ETH_HLEN + sizeof(struct iphdr));
    struct RoutingTableElem* rptr = (struct RoutingTableElem*)intp;

    int proto = iph->protocol;
    int len = ntohs(iph->tot_len) - sizeof(struct iphdr);
    uint8_t ttl = iph->ttl; 
    struct in_addr sip, dip;

    sip.s_addr = iph->saddr;
    dip.s_addr = iph->daddr;


    if(proto == IP_ROUTING_PROTO){  //update routing table, protocol occupies one byte
        //printf("Going here: %s %d\n", __FILE__ ,__LINE__);
        int i, cnt = *intp;

        rptr++;
        for(i = 0; i < cnt; i++){
            //printf("Going here: %s %d\n", __FILE__ ,__LINE__);
            updateRoutingTable(*rptr, 1, sip, pkt->devid);
            // since we only send routing packets to neighbors, the hop should always be 1
            rptr++;
        }
    }
    else {  //  check whether the dest is the host itself
        int i, flag = 0;
        in_addr_t dstsubnet, devsubnet;

        for(i = 0; i < device_ID; i++){
            dstsubnet = dip.s_addr & rev_devs[i].netmask.s_addr;
            devsubnet = rev_devs[i].ipv4addr.s_addr & rev_devs[i].netmask.s_addr;
            if(dip.s_addr == rev_devs[i].ipv4addr.s_addr//){
                 || ((dstsubnet == devsubnet) && ((dip.s_addr | rev_devs[i].netmask.s_addr) == 0xffffffff)) ){    //  broadcast
                    flag = 1;
                    // printf("FIND DESTINTATION Going here: %s %d\n", __FILE__ ,__LINE__);
                    break;
                } 
        }
        
        if(flag == 0 && dip.s_addr != sip.s_addr){  // pass the packet to the next hop
            // printf("[PASS] Going here: %s %d\n", __FILE__ ,__LINE__);
            // printf("%x\t%x\t\%d\t%d\t%d\n", sip.s_addr, dip.s_addr, proto, len, ttl);
            
            u_char* buf = pkt->data + ETH_HLEN + sizeof(struct iphdr);
            // puts(buf);
            struct timeval curtv;
            gettimeofday(&curtv, NULL);
            sendIPPacket(sip, dip, proto, buf, len, ttl - 1, curtv);            
        }
        else if(flag == 1 ){    // this is the destination
            // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
            if(IPCallBack != NULL){
                IPCallBack(pkt->data + ETH_HLEN, len + sizeof(struct iphdr));
               
            }
            if(proto == IPPROTO_TCP){
                // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
                u_char* buf = pkt->data + ETH_HLEN + sizeof(struct iphdr);
                processTCPPacket(sip, dip, len, buf);
            }      
        }
    }
}

void processARPPacket(struct PacketQueue* pkt){
    struct ether_header* ethh = (struct ether_header*) pkt->data;
    struct ether_arp* arppkt = (struct ether_arp*)(pkt->data + ETH_HLEN);
    struct arphdr* ahdr = (struct arphdr*)(pkt->data + ETH_HLEN);
    int type = ntohs(ahdr->ar_op);

    struct in_addr sip,dip;
    u_char mac[10];
    u_char buf[MAX_DATA_LEN];
    int len;
    int dev = pkt->devid;

    memcpy(&sip.s_addr, arppkt->arp_spa, 4);
    memcpy(&dip.s_addr, arppkt->arp_tpa, 4);
    memcpy(mac, ethh->ether_shost, ETH_ALEN);

    if(type == 1){  // arp request
    // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
        setARPTable(sip, mac);
        if(rev_devs[dev].ipv4addr.s_addr == dip.s_addr){
            len = makeARPReplyPayload(dev, sip, mac, buf);
            sendFrame(buf, len, ETH_P_ARP, mac, dev);
        }
    }
    else if(type == 2){ // arp reply
    // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
        setARPTable(sip, mac);
    }
}

struct timeval timewait[MAX_SOCK_NUM], finwait[MAX_SOCK_NUM];

void processTCPPacket(const struct in_addr sip, const struct in_addr dip, const int totlen, const void* pkt){
    struct tcphdr* tcph = (struct tcphdr*)pkt;
    int sport = ntohs(tcph->source);
    int dport = ntohs(tcph->dest);
    int seq = ntohl(tcph->seq);
    int ack = ntohl(tcph->ack_seq);
    int flags = tcph->th_flags;
    int window = ntohs(tcph->window);
    u_char* payload = (u_char*)(pkt + sizeof(struct tcphdr));
    int len = totlen - sizeof(struct tcphdr);   //payload length
    int sockid = findSocket(dip, dport);

    if(sockid == -1){
        // no such socket
        // printf("%d\n", dport);
        // printf("no sockets Going here: %s %d\n", __FILE__ ,__LINE__);
        return;
    }

    struct Socket* sock = &Sockets[sockid];
    pthread_mutex_lock(&SocketLock[sockid]);

    char buf[2];    // may be NULL!

    // int lim = MAX_WINDOW_SIZE - (sock->stream.last_byte_rcvd - sock->stream.last_byte_read);
    // //  cannot write the payload into the window
    // if(lim < len){
    //     pthread_mutex_unlock(&SocketLock[sockid]);
    //     return;
    // }

    if(seq + len - 1 >= sock->stream.next_byte_expected + MAX_WINDOW_SIZE - 1){
        pthread_mutex_unlock(&SocketLock[sockid]);
        return;
    }

    // printf("Going here: %s %d\n", __FILE__ ,__LINE__);

    int state = sock->state;
    switch(state){
        case CLOSED_MS: // do nothing
            break;
        case SYN_RECV_MS:
            if(flags == TH_ACK && seq == sock->stream.next_byte_expected){  // may modify
                //  may modify variable
                
                initTCPBuffer(&sock->stream.send_buffer, ack);
                initTCPBuffer(&sock->stream.rcvd_buffer, seq);  // + 1 if last ACK occupies 1 bytes

                sock->stream.last_byte_written = MAX(sock->stream.last_byte_written, ack - 1);
                sock->stream.last_byte_acked = MAX(sock->stream.last_byte_acked, ack - 1);
                sock->stream.last_byte_sent = MAX(sock->stream.last_byte_sent, ack - 1);

                sock->stream.last_byte_read = MAX(sock->stream.last_byte_read, seq - 1);
                sock->stream.next_byte_expected = MAX(sock->stream.next_byte_expected, seq);
                sock->stream.last_byte_rcvd = MAX(sock->stream.last_byte_rcvd, seq - 1);
                
                sock->state = ESTABLISHED_MS;
            }
            break;
        case SYN_SENT_MS:
            // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
            if(flags == TH_SYN | TH_ACK && ack >= sock->stream.last_byte_sent + 1){
                // printf("SYN+ACK Going here: %s %d\n", __FILE__ ,__LINE__);
                
                sock->dport = sport;
                initStreamRecv(sock, seq);
                // may modify variable
                sock->stream.last_byte_acked = MAX(sock->stream.last_byte_acked, ack - 1);
                sock->stream.last_byte_written = MAX(sock->stream.last_byte_written, ack - 1);

                initTCPBuffer(&sock->stream.send_buffer, ack);
                initTCPBuffer(&sock->stream.rcvd_buffer, seq + 1);
                
                // insertBufferList(sock->stream.send_buffer.list, sock->stream.last_byte_sent + 1, 0, TH_ACK);
                sendTCPPacket(sockid, 0, sock->stream.last_byte_sent + 1, TH_ACK, buf);
            
                sock->state = ESTABLISHED_MS;

                // puts("SYN_SENT_MS:");
                // printf("packet ACK:%d SEQ:%d\n", ack, seq);
                // printSocketInfo(sockid);
            }
            break;
        case LISTEN_MS:
            if(flags == TH_SYN){
                pushListenQue(sockid, seq, sip, dip, sport);
                // printf("LISTEN_MS: %d %d %d\n", sockid, seq, sport);
                // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
            }
            break;
        case ESTABLISHED_MS:
            if(flags == (TH_SYN | TH_ACK) && seq <= sock->stream.last_byte_acked){    // retransmission of SYN + ACK
                //copy what was sent before
                // puts("\nSYN+ACK in ESTABLISHED\n");
                sendTCPPacket(sockid, 0, ack, TH_ACK, buf); //  ack = x+1
            }
            if(flags == TH_FIN){
                sock->stream.last_byte_rcvd = MAX(sock->stream.last_byte_rcvd, seq);
                sock->stream.last_byte_acked = MAX(sock->stream.last_byte_acked, ack - 1);
                insertBufferList(sock->stream.rcvd_buffer.list, seq, 1, TH_FIN);
                maintainRcvdBuffer(sockid);

                insertBufferList(sock->stream.send_buffer.list, sock->stream.last_byte_sent + 1, 0, TH_ACK);
                sendTCPPacket(sockid, 0, sock->stream.last_byte_sent + 1, TH_ACK, buf);

                sock->state = CLOSE_WAIT_MS;
                // puts("state: CLOSE_WAIT\n");
            }
            if(flags == TH_ACK){
                // printf("ESTAB:Going here: %s %d\n", __FILE__ ,__LINE__);
                goto normal_reply;
            }
            break;
        case FIN_WAIT1_MS:
            if(flags == TH_ACK){
                if(sock->stream.last_byte_sent == ack - 1){
                    sock->stream.last_byte_rcvd = MAX(sock->stream.last_byte_rcvd, seq + len - 1);
                    sock->stream.last_byte_acked = MAX(sock->stream.last_byte_acked, ack - 1);
 
                    maintainSendBuffer(sockid);
                    maintainRcvdBuffer(sockid);
                    
                    //  should ensure last_byte_sent == last_byte_written
                    //  so that in close(), when FIN is sent, the last_byte_sent will not change
                    gettimeofday(&finwait[sockid], NULL);
                    sock->state = FIN_WAIT2_MS;
                    // puts("state: FIN_WAIT2\n");
                    // set time wait?
                }
                else{
                    goto normal_reply;
                }
            }
            break;
        case FIN_WAIT2_MS:
            if(flags == TH_ACK){
                goto normal_reply;
            }
            else if(flags == TH_FIN | TH_ACK){
                sock->stream.last_byte_rcvd = MAX(sock->stream.last_byte_rcvd, seq);
                sock->stream.last_byte_acked = MAX(sock->stream.last_byte_acked, ack - 1);
                insertBufferList(sock->stream.rcvd_buffer.list, seq, 1, TH_FIN);
                maintainRcvdBuffer(sockid);

                insertBufferList(sock->stream.send_buffer.list, sock->stream.last_byte_sent + 1, 0, TH_ACK);
                sendTCPPacket(sockid, 0, sock->stream.last_byte_sent + 1, TH_ACK, buf);

                gettimeofday(&timewait[sockid], NULL);
                sock->state = TIME_WAIT_MS;
                // puts("state: TIME_WAIT\n");
            }
            break;
        case TIME_WAIT_MS:
            goto normal_reply;
            // check in processPacket
            break;
        case CLOSE_WAIT_MS:
            goto normal_reply;
            break;
        case LAST_ACK_MS:
            if(flags == TH_ACK){
                if(sock->stream.last_byte_sent == ack - 1){
                    //  should ensure last_byte_sent == last_byte_written
                    //  so that in close(), when FIN is sent, the last_byte_sent will not change
                    sock->state = CLOSED_MS;
                    sock->valid = 0;
                }
                else goto normal_reply;
            }
            break;
        case CLOSING_MS:
            // simultaneous closing is not implemented
            break;
        default:
            fprintf(stderr, "processTCPPacket: invalid state\n");
            break;
    }
    pthread_mutex_unlock(&SocketLock[sockid]);
    return;
normal_reply:
    sock->stream.last_byte_rcvd = MAX(sock->stream.last_byte_rcvd, seq + len - 1);
    sock->stream.last_byte_acked = MAX(sock->stream.last_byte_acked, ack - 1);
    sock->window = window;
    
    if(seq >= sock->stream.next_byte_expected){ //  in the window
        if(len != 0){
            int r = insertBufferList(sock->stream.rcvd_buffer.list, seq, len, TH_ACK);
            if(r == 0)writeRcvdBuffer(sockid, len, seq, payload);
        }
        maintainSendBuffer(sockid);
        maintainRcvdBuffer(sockid);
    }
    if(len != 0){
        //  ACK with no payload
        // puts("\nESTABLISHED NORMAL REPLY\n");
        sendTCPPacket(sockid, 0, sock->stream.last_byte_sent + 1, TH_ACK, buf);
    }
    pthread_mutex_unlock(&SocketLock[sockid]);
}

void* processPacket(void* param){
    struct PacketQueue* curpkt;
    struct ether_header* ethh;
    struct iphdr* iph;
    static u_char payloadbuf[MAX_DATA_LEN];// might be smaller, this is for Ethernet II frame

    struct timeval lasttv, curtv;
    gettimeofday(&lasttv, NULL);

    int CP6flag = 0;
    int CP7flag = 0;

    while(EndFlag == 0){
        pthread_mutex_lock(&QueLock);
        // printf("process Packet Going here: %s %d\n", __FILE__ ,__LINE__);

        gettimeofday(&curtv, NULL);
        if(curtv.tv_sec - lasttv.tv_sec >= IP_ROUTING_TIME_INTERVAL_SEC){
            // || curtv.tv_usec - lasttv.tv_usec >= IP_ROUTING_TIME_INTERVAL_USEC ){//  time to send routing packets
            int i, len, ret;
            struct in_addr broadcastaddr, ipaddr, netmsk;

            for(i = 0; i < device_ID; i++){
                ipaddr = rev_devs[i].ipv4addr;
                netmsk = rev_devs[i].netmask;
                broadcastaddr.s_addr = (ipaddr.s_addr & netmsk.s_addr) | (0xffffffff ^ netmsk.s_addr);
                len = makeRoutingPayload(&payloadbuf);
                
                //printf("Going here: %s %d\n", __FILE__ ,__LINE__);

                ret = sendIPPacket(ipaddr, broadcastaddr, IP_ROUTING_PROTO, payloadbuf, len, IP_TTL_THRESHOLD, curtv);
                // since it's a broadcasting, don't need ARP
                //printf("Going here: %s %d\n", __FILE__ ,__LINE__);
            }

            lasttv = curtv;

            // printRoutingTable();
            // printARPTable();
        }
        // printf("Routing_END:Going here: %s %d\n", __FILE__ ,__LINE__);

        if(!emptyIPQue()){
            // printf("emptyIPQue Going here: %s %d\n", __FILE__ ,__LINE__);
            int maxiter = lenIPQue();
            // printf("maxiter: %d\n", maxiter);
            int i;
            struct IPPacketQueElem ippkt;
            for(i = 0; i < maxiter; i++){
                popIPQue(&ippkt);
                // printf("len after pop: %d front:%d back:%d\n\n", lenIPQue(), IPPacketFront, IPPacketBack);
                if(curtv.tv_sec - ippkt.ts.tv_sec <= 10){   // 10 secs
                    // printf("emptyIPQue Going here: %s %d\n", __FILE__ ,__LINE__);
                    sendIPPacket(ippkt.src, ippkt.dest, ippkt.proto, ippkt.buf, ippkt.len, ippkt.ttl, ippkt.ts);
                }
            }
        }
        // printf("emptIPQue_END:Going here: %s %d\n", __FILE__ ,__LINE__);

        while(PacketFront != PacketBack){
            curpkt = &RecvdPackets[PacketFront];
            ethh = (struct ether_header*) curpkt->data;
            iph = (struct iphdr*) (curpkt->data + ETH_HLEN);
            
            int ethtype = ntohs(ethh->ether_type);
            // printf("ethertype: %d\n", ethtype);
            if(ethtype == ETH_P_ARP){
                processARPPacket(curpkt);
            }
            else if(ethtype == ETH_P_IP){
                processIPPacket(curpkt);
            }
           
           //printf("Going here: %s %d\n", __FILE__ ,__LINE__);
            //printf("processPacket: %d %d %d %d\n\n",curpkt->devid,curpkt->len,curpkt->ts.tv_sec, curpkt->ts.tv_usec);
            PacketFront++;
            if(PacketFront == MAX_QUE_LEN){
                PacketFront = 0;
                // printf("Many packets Going here: %s %d\n", __FILE__ ,__LINE__);
            }
        }
        pthread_mutex_unlock(&QueLock);

        // printf("processPacket_END:Going here: %s %d\n", __FILE__ ,__LINE__);

        for(int i = 0; i < MAX_SOCK_NUM; i++){
            pthread_mutex_lock(&SocketLock[i]);
            if(Sockets[i].valid){
                
                checkSendBuffer(i);
            }
            pthread_mutex_unlock(&SocketLock[i]);
        }
        // printf("checkSendBuffer_END:Going here: %s %d\n", __FILE__ ,__LINE__);

        //send TCP packets in TCPSendQue
        for(int i = 0; i < MAX_SOCK_NUM; i++)if(Sockets[i].valid){
            u_char TCPbuf[MAX_DATA_LEN];
            struct timeval ts;
            int len;

            // may check state
            // may lock TCPQue
            pthread_mutex_lock(&TCPQueLock[i]);
            while(TCPSendQueFront[i] != TCPSendQueBack[i]){
                int j = TCPSendQueFront[i];
                
                pthread_mutex_lock(&SocketLock[i]);
                makeTCPPacket(Sockets[i].sip, Sockets[i].dip, Sockets[i].sport, Sockets[i].dport,
                              TCPSendQue[i][j].seq, Sockets[i].stream.next_byte_expected, TCPSendQue[i][j].flags,
                              MAX_WINDOW_SIZE - (Sockets[i].stream.last_byte_rcvd - Sockets[i].stream.next_byte_expected + 1),
                              TCPSendQue[i][j].len, TCPSendQue[i][j].payload, TCPbuf);

                len = TCPSendQue[i][j].len + sizeof(struct tcphdr);
                gettimeofday(&ts, NULL);
                sendIPPacket(Sockets[i].sip, Sockets[i].dip, IPPROTO_TCP, TCPbuf, len, IP_TTL_THRESHOLD, ts);

                pthread_mutex_unlock(&SocketLock[i]);

                TCPSendQueFront[i]++;
                if(TCPSendQueFront[i] == MAX_TCPQUE_LEN){
                    TCPSendQueFront[i] = 0;
                }
            }
            pthread_mutex_unlock(&TCPQueLock[i]);
        }
        // printf("checkTCPPacket_END:Going here: %s %d\n", __FILE__ ,__LINE__);

        // check timestamp for retransmission
        for(int i = 0; i < MAX_SOCK_NUM; i++){
            pthread_mutex_lock(&SocketLock[i]);
            if(Sockets[i].valid){
                checkRetrans(i);
            }
            pthread_mutex_unlock(&SocketLock[i]);
        }
        // printf("checkRetrans_END:Going here: %s %d\n", __FILE__ ,__LINE__);

        // check timestamp for socket with state TIME_WAIT
        for(int i = 0; i < MAX_SOCK_NUM; i++){
            pthread_mutex_lock(&SocketLock[i]);
            if(Sockets[i].valid && Sockets[i].state == TIME_WAIT_MS){
                struct timeval tmpts;
                gettimeofday(&tmpts, NULL);
                if(tmpts.tv_sec - timewait[i].tv_sec >= 2 * TCP_MSL){
                    Sockets[i].state = CLOSED_MS;
                    Sockets[i].valid = 0;
                }
            }
            if(Sockets[i].valid && Sockets[i].state == FIN_WAIT2_MS){
                struct timeval tmpts;
                gettimeofday(&tmpts, NULL);
                if(tmpts.tv_sec - finwait[i].tv_sec >= 2 * TCP_MSL){
                    Sockets[i].state = CLOSED_MS;
                    Sockets[i].valid = 0;
                }
            }
            pthread_mutex_unlock(&SocketLock[i]);
        }

        // printf("checkTimeStamp_END:Going here: %s %d\n", __FILE__ ,__LINE__);


#ifdef checkCP7
        
        if(CP7flag == 0 & rev_devs[0].name[4] == '1'){
            CP7flag = 1;
            int i, len, ret;
            struct in_addr destaddr, ipaddr, netmsk;
            u_char* ptr;
            u_char broadcastmac[8] = {0xff,0xff,0xff,0xff,0xff,0xff};
            static u_char* testbuf = "THIS IS A TEST PACKET!1234567890abcdefghijklmnopqrstuvwxyz";
            u_char CP7payload[MAX_DATA_LEN];

            ipaddr = rev_devs[0].ipv4addr;
            netmsk = rev_devs[0].netmask;
            ptr = &destaddr.s_addr;

            ptr[0] = 0x0a;
            ptr[1] = 0x64;
            ptr[2] = 0x01;
            ptr[3] = 0x02;
            //10.100.1.2

            makeTCPPacket(ipaddr, destaddr,1234,4321,0,1,TH_ACK,MAX_WINDOW_SIZE,strlen(testbuf),testbuf, CP7payload);

            // for(int i = 0; i < 20; i++)printf("%u",CP7payload[i]);
            // putchar('\n');

            len = strlen(testbuf) + sizeof(struct tcphdr);
            printf("%d\n",len);

            struct timeval tmptv;
            gettimeofday(&tmptv, NULL);
            sendIPPacket(ipaddr, destaddr, IPPROTO_TCP, CP7payload, len, IP_TTL_THRESHOLD, tmptv);
        }
#endif

#ifdef checkCP6
        if(CP6flag == 0 & rev_devs[0].name[4] == '1'){
            CP6flag = 1;
            int i, len, ret;
            struct in_addr destaddr, ipaddr, netmsk;
            u_char* ptr;
            u_char broadcastmac[8] = {0xff,0xff,0xff,0xff,0xff,0xff};
            static u_char* testbuf = "THIS IS A TEST PACKET!1234567890abcdefghijklmnopqrstuvwxyz";

            ipaddr = rev_devs[0].ipv4addr;
            netmsk = rev_devs[0].netmask;
            ptr = &destaddr.s_addr;
            
            // ptr[0] = 0x0a;
            // ptr[1] = 0x64;
            // ptr[2] = 0x02;
            // ptr[3] = 0x04;
            //10.100.2.4

            ptr[0] = 0x0a;
            ptr[1] = 0x64;
            ptr[2] = 0x03;
            ptr[3] = 0x02;
             //10.100.3.2

            len = strlen(testbuf);
                
            // printf("sending Going here: %s %d\n", __FILE__ ,__LINE__);
            struct timeval tmptv;
            gettimeofday(&tmptv, NULL);
            sendIPPacket(ipaddr, destaddr, 201, testbuf, len, IP_TTL_THRESHOLD, tmptv);
            gettimeofday(&tmptv, NULL);
            sendIPPacket(ipaddr, destaddr, 201, testbuf, len, IP_TTL_THRESHOLD, tmptv);
            // printf("tmptv: tv_sec: %d\ttv_usec: %d\n", tmptv.tv_sec, tmptv.tv_usec);
        }
#endif
       
        // sleep(1);
    }
}

void* receivePacket(void* dev_id){
    int dev = (u_int64_t)dev_id;

    pcap_t* handle = DeviceHandle[dev];

    pcap_activate(handle);
    pcap_loop(handle, -1, got_packet, (u_char*)dev_id);

    //pthread_exit()
}