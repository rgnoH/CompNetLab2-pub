#include "ip.h"
#include "tcp.h"

uint16_t calcTCPCheck(struct in_addr srcip,struct in_addr destip, int len, struct tcphdr* tcph, void* pkt){
    uint16_t* ptr = (uint16_t*) tcph;
    uint32_t sum = 0, carry;
    uint16_t res = 0;
    int i;
    struct pseudohdr phdr;

    // ignore options
    for(i = 0; i < sizeof(struct tcphdr) / sizeof(uint16_t); i++){
        sum += ntohs(*ptr);
        ptr++;
    }

    //pseudo header
    phdr.srcip.s_addr = ntohl(srcip.s_addr);
    phdr.destip.s_addr = ntohl(destip.s_addr);
    phdr.zeros = 0;
    phdr.proto = IPPROTO_TCP;
    phdr.len = len;

    for(i = 0; i < sizeof(struct pseudohdr) / sizeof(uint16_t); i++){
        sum += (*ptr);
        ptr++;
    }

    //tcp payload, check padding
    ptr = (uint16_t*)pkt;
    for(i = 0; i < (len >> 1); i++){
        sum += (*ptr);
        ptr++;
    }
    if(len & 1){    //padding
        sum += (*ptr) & 0xff00;
    }

    carry = sum >> 16;
    while(carry != 0){
        sum = carry + (sum & 0xffff);
        carry = sum >> 16;
    }

    res = htonl(~sum);
    return res;
}

void makeTCPPacket(const struct in_addr srcip, const struct in_addr destip,
                   const uint16_t sport, const uint16_t dport, 
                   const uint32_t seq, const uint32_t ack, uint8_t flags,
                   uint16_t window, const int len, const void* buf, u_char* pkt){
    struct tcphdr* tcph = (struct tcphdr*)pkt;
    tcph->source = sport;
    tcph->dest = dport;
    tcph->seq = seq;
    tcph->ack_seq = ack;
    tcph->th_flags = flags;
    tcph->window = window;
    tcph->check = 0;
    tcph->urg_ptr = 0;   // ignored
    tcph->th_off = 5;
    memcpy(pkt + sizeof(struct tcphdr), buf, len);

    tcph->source = htons(tcph->source);
    tcph->dest = htons(tcph->dest);
    tcph->window = htons(tcph->window);
    tcph->seq = htonl(tcph->seq);
    tcph->ack_seq = htonl(tcph->ack_seq);

    tcph->check = calcTCPCheck(srcip, destip, len, tcph, pkt);
    
    // struct timeval ts;
    // gettimeofday(&ts, NULL);
    // sendIPPacket(src, dest, IPPROTO_TCP, buf, len, IP_TTL_THRESHOLD, ts);
}

int sendTCPPacket(const int sockfd, const int len, const int seq, const uint8_t flags, const void* buf){
    pthread_mutex_lock(&TCPQueLock[sockfd]);
    int tmpback = TCPSendQueBack[sockfd];

    TCPSendQue[sockfd][tmpback].len = len;
    TCPSendQue[sockfd][tmpback].seq = seq;
    TCPSendQue[sockfd][tmpback].flags = flags;
    memcpy(TCPSendQue[sockfd][tmpback].payload, buf, len);

    tmpback++;
    if(tmpback == MAX_TCPQUE_LEN){
        tmpback = 0;
    }
    if(tmpback == TCPSendQueFront[sockfd]){
        return -1;  //  queue is full
    }
    TCPSendQueBack[sockfd] = tmpback;

    pthread_mutex_unlock(&TCPQueLock[sockfd]);

    // pthread_mutex_lock(&SocketLock[sockfd]);
    if((flags & TH_SYN) || (flags & TH_FIN)){
        Sockets[sockfd].stream.last_byte_sent = MAX(Sockets[sockfd].stream.last_byte_sent, len + seq);  // len = 0
    }
    else Sockets[sockfd].stream.last_byte_sent = MAX(Sockets[sockfd].stream.last_byte_sent, len + seq - 1);
    // pthread_mutex_unlock(&SocketLock[sockfd]);
    // still work when len == 0
    
    //TODO ?
}

void writeSendBuffer(const int sockfd, const int len, const int seq, const void* buf){
    int oldback, newback, remain;
    struct TCPBuffer* tcpbuf = &Sockets[sockfd].stream.send_buffer;
    
    // insertBufferList(&Sockets[sockfd].stream.send_buffer, seq, len, flags);
    Sockets[sockfd].stream.last_byte_written = MAX(Sockets[sockfd].stream.last_byte_written, len + seq - 1);

    //  Always append  in order!
    oldback = Sockets[sockfd].stream.send_buffer.back;
    newback = oldback + len;
    if(newback < MAX_BUFFER_SIZE){
        memcpy(tcpbuf->buf + oldback, buf, len);
        tcpbuf->back = newback;
    }
    else{
        remain = MAX_BUFFER_SIZE - oldback;
        memcpy(tcpbuf->buf + oldback, buf, remain);
        memcpy(tcpbuf->buf, buf + remain, len - remain);
        tcpbuf->back = newback - MAX_BUFFER_SIZE;
    }
}

void writeRcvdBuffer(const int sockfd, const int len, const int seq, const void* buf){
    int lpos, rpos, remain;
    struct TCPBuffer* tcpbuf = &Sockets[sockfd].stream.rcvd_buffer;
    
    // insertBufferList(&Sockets[sockfd].stream.rcvd_buffer, seq, len, flags);

    Sockets[sockfd].stream.last_byte_rcvd = MAX(Sockets[sockfd].stream.last_byte_rcvd, len + seq - 1);
    //  still work when len == 0
   
    //  This function will NOT change offset
    //  Attention: not always append at the back
    
    lpos = getBufferPos(seq, tcpbuf);
    rpos = lpos + len;
    if(rpos < MAX_BUFFER_SIZE){
        memcpy(tcpbuf->buf + lpos, buf, len);
        if(getSeq(rpos, tcpbuf) > getSeq(tcpbuf->back, tcpbuf)){
            tcpbuf->back = rpos;
        }
    }
    else{
        remain = MAX_BUFFER_SIZE - lpos;
        memcpy(tcpbuf->buf + lpos, buf, remain);
        memcpy(tcpbuf->buf, buf + remain, len - remain);
        //this:
        rpos -= MAX_BUFFER_SIZE;
        //
        if(getSeq(rpos, tcpbuf) > getSeq(tcpbuf->back, tcpbuf)){
            tcpbuf->back = rpos;
        }
    }
}

void checkRetrans(int sockfd){  // the SocketLock[sockfd] already locked
    if(Sockets[sockfd].valid == 0)return;
    if(Sockets[sockfd].state == CLOSED_MS)return;
    if(Sockets[sockfd].dport == -1 || Sockets[sockfd].sport == -1)return;

    struct BufferList *cur, *list;
    struct timeval ts;

    list = Sockets[sockfd].stream.send_buffer.list;
    if(list == NULL){
        fprintf(stderr, "checkRetrans: the beginning of list cannot be NULL: %d\n", sockfd);
        return;
    }
    
    cur = list->next;
    gettimeofday(&ts, NULL);

    if(ts.tv_sec - LastRetrans[sockfd].tv_sec >= TCP_RETRANS_THRESHOLD){
        gettimeofday(&LastRetrans[sockfd], NULL);
    }
    else return;

    int window = Sockets[sockfd].window;

    while(cur != NULL){
        // if(ts.tv_sec - cur->ts.tv_sec >= TCP_RETRANS_THRESHOLD &&
        if(Sockets[sockfd].stream.last_byte_acked < cur->seq){
            // may add restriction: in window 
            

            cur->ts = ts;
            // if( (window >> 1) <= cur->len){
                int pos = getBufferPos(cur->seq, &Sockets[sockfd].stream.send_buffer);
                sendTCPPacket(sockfd, cur->len, cur->seq, cur->flags, 
                              Sockets[sockfd].stream.send_buffer.buf + pos);
                // window -= cur->len;
            // }
            
            
            // printf("checkRetrans:seq:%d\tlen:%d\tpos:%d\tlast_byte_acked:%d\n", cur->seq, cur->len, pos, Sockets[sockfd].stream.last_byte_acked);
            
            return;

            // may create a new queue: retrans
        }
        // else if(Sockets[sockfd].stream.last_byte_acked >= cur->seq){
        //     deleteBufferList(list, cur);
        //      // should also maintain the buffer
        // }
        cur = cur->next;
    }
    // puts("EndcheckRetrans\n");
}

void maintainSendBuffer(int sockfd){
    struct TCPBuffer* tcpbuf = &Sockets[sockfd].stream.send_buffer;
    if(tcpbuf->list == NULL){
        fprintf(stderr, "maintainSendBuffer: the beginning of the list cannot be NULL\n");
        return;
    }
    
    // printf("maintainSendBuffer:\tlast_byte_acked:%d\n", Sockets[sockfd].stream.last_byte_acked);

    struct BufferList *cur, *last, *list;

    list = tcpbuf->list;
    last = tcpbuf->list;
    cur = last->next;

    /*
    if(cur != NULL){
        printf("maintainSendBuffer:\tseq:\t%d\tlen:\t%d\tlast_byte_acked:\t%d\n", cur->seq, cur->len, Sockets[sockfd].stream.last_byte_acked);
    }
    else puts("maintainSendBuffer:\tcur is NULL");
    */
    
    while(cur != NULL && (cur->seq <= Sockets[sockfd].stream.last_byte_acked)){ //&& (cur->seq <= tcpbuf->offset)){
        // (-oo, last_byte_acked] all acked
        tcpbuf->front += cur->len;
        tcpbuf->offset += cur->len;  // attention
        //also work for SYN, logically 1 byte but 0 payload
        if(tcpbuf->front >= MAX_BUFFER_SIZE){
            tcpbuf->front -= MAX_BUFFER_SIZE;    
        }

        last = cur;
        cur = cur->next;

        // puts("maintainSendBuffer GOING HERE");
        deleteBufferList(list, last);
        // cannot call this before cur set to a new pointer
    }
}

void maintainRcvdBuffer(int sockfd){
    struct Socket* sock = &Sockets[sockfd];
    struct TCPBuffer* tcpbuf = &sock->stream.rcvd_buffer;
    if(tcpbuf->list == NULL){
        fprintf(stderr, "maintainRcvdBuffer: the beginning of the list cannot be NULL\n");
        return;
    }
    struct BufferList *cur, *last, *list;

    last = tcpbuf->list;
    cur = last->next;
    
    while(cur != NULL && cur->seq <= sock->stream.next_byte_expected){
        sock->stream.next_byte_expected = MAX(cur->seq + cur->len, sock->stream.next_byte_expected);
        cur = cur->next;
    }
}

void checkSendBuffer(int sockfd){   // SocketLock[sockfd] alreay locked
    if(Sockets[sockfd].valid == 0){
        return;
    }
    if(Sockets[sockfd].state == CLOSED_MS
      || Sockets[sockfd].state == LISTEN_MS
      || Sockets[sockfd].state == SYN_RECV_MS
      || Sockets[sockfd].state == SYN_SENT_MS){ //  may change
        return;
    }
    
    struct Socket* sock = &Sockets[sockfd];
    struct TCPBuffer* tcpbuf = &sock->stream.send_buffer;
    int i, seq;
    ssize_t st, ed, len;
    st = sock->stream.last_byte_sent + 1;
    ed = sock->stream.last_byte_written;
    ed = MIN(ed, sock->stream.last_byte_acked + MAX_WINDOW_SIZE);   // within self's window
    ed = MIN(ed, st + (MAX_WINDOW_SIZE>>1) - 1);
    ed = MIN(ed, st + (sock->window >> 1) - 1); //window may not accurate because of delay
    //might consider 0 window case

    static struct timeval checkwin;

    int winsz = MAX_WINDOW_SIZE - (sock->stream.last_byte_rcvd - sock->stream.next_byte_expected + 1);
    if(winsz < (MAX_WINDOW_SIZE>>2)){
        return;
    }

    if(sock->window < (MAX_WINDOW_SIZE >> 2)){
        struct timeval curts;
        gettimeofday(&curts, NULL);
        // if(curts.tv_sec - checkwin.tv_sec <= 2){
        //     return;
        // }
        if((curts.tv_sec - checkwin.tv_sec) * 1000000 + curts.tv_usec -checkwin.tv_usec <= 5000000){
            return;
        }
    }

    if(ed - st <= (MAX_TCP_SEND_SIZE>>2) && ed < sock->stream.last_byte_written){
        struct timeval curts;
        gettimeofday(&curts, NULL);
        // if(curts.tv_sec - checkwin.tv_sec <= 2){
        //     return;
        // }
        if((curts.tv_sec - checkwin.tv_sec) * 1000000 + curts.tv_usec -checkwin.tv_usec <= 1000000){
            return;
        }
    }

    gettimeofday(&checkwin, NULL);

    static u_char payload[MAX_TCP_SEND_SIZE + 5];

    for(i = st; i <= ed; i+= MAX_TCP_SEND_SIZE){
        seq = i;
        if(seq + MAX_TCP_SEND_SIZE - 1 <= ed){
            len = MAX_TCP_SEND_SIZE;
        }
        else{
            len = ed - seq+ 1;
        }
        if(len > 0){
            insertBufferList(tcpbuf->list, seq, len, TH_ACK);
            int lpos = getBufferPos(seq, tcpbuf), rpos;

            rpos = lpos + len;
            if(rpos < MAX_BUFFER_SIZE){
                memcpy(payload, tcpbuf->buf + lpos, len);
            }
            else{
                int remain = MAX_BUFFER_SIZE - lpos;
                memcpy(payload, tcpbuf->buf + lpos, remain);
                memcpy(payload + remain, tcpbuf->buf, len - remain);
            }

            sendTCPPacket(sockfd, len, seq, TH_ACK, payload);
            //here last_byte_sent will be updated, so st chould be stored

            sock->window -= len;

            
        }
    }
}


///////////////////functions for maintaining data structures///////////////////

/////////////////////////// Socket Stream //////////////////////////

void initStreamSend(struct Socket* sock, int num){
    sock->stream.last_byte_written = num;
    sock->stream.last_byte_acked = num;
    sock->stream.last_byte_sent = num;
}

void initStreamRecv(struct Socket* sock, int num){
    sock->stream.last_byte_read = num;
    sock->stream.next_byte_expected = num + 1;
    sock->stream.last_byte_rcvd = num;
}

///////////////////////////Buffer List//////////////////////////

int findFreeBufferListID(){
    int i;
    for(i = 0; i < MAX_BUFFER_SIZE; i++){
        if(BList[i].valid == 0){
            return i;
        }
    }
    return -1;
}

void initBufferList(struct BufferList** lst){
    int id = findFreeBufferListID();
    if(id == -1){
        fprintf(stderr, "initBufferList: not enough space!\n");
        return;
    }
    BList[id].seq = -1;
    BList[id].len = 0;
    BList[id].sent = -1;
    BList[id].valid = 1;
    BList[id].ts.tv_sec = 1 << 29;
    BList[id].next = NULL;
    *lst = &BList[id];
}

// what if repeated pkt?
// send buffer: impossible
// rcvd buffer: retransmission, and can be out of window
int insertBufferList(struct BufferList* head,int seq, int len, uint8_t flags){
    struct BufferList *list, *last, *cur;
    int id;
    
    list = head;
    if(list == NULL){
        fprintf(stderr, "insertBufferList: begin of list should not be NULL\n");
        return -1;
    }

    last = list;
    cur = last->next;

    while(cur != NULL){
        if(cur->seq == seq){    // repeated, throw
            // printf("insertBufferList: pkt already exists!\n");
            return 1;
        }
        if(last->seq <= seq && seq <= cur->seq){
            break;  // last->next should be the position
        }
        last = last->next;
        cur = cur->next;
    }

    id = findFreeBufferListID();
    if(id == -1){
        fprintf(stderr, "initTCPBuffer: not enough space!\n");
        return -1;
    }
     
    BList[id].seq = seq;
    BList[id].len = len;
    gettimeofday(&BList[id].ts, NULL);
    BList[id].valid = 1;
    BList[id].sent = 0;
    BList[id].flags = flags;
    
    last->next = &BList[id];
    BList[id].next = cur;

    return 0;
}

void deleteBufferList(struct BufferList* last, struct BufferList* cur){
    if(last->next != cur){
        fprintf(stderr, "deleteBufferList: last and cur don't match\n");
        return;
    }
    if(cur == NULL || last == NULL){
        fprintf(stderr, "deleteBufferList: cannot refer to a NULL pointer\ncur:%p\tlast:%p\n", cur, last);
        return;
    }
    if(cur->seq == -1){
        fprintf(stderr, "deleteBufferList: cannot delete the beginning of a list\n");
        return;
    }

    // puts("deleteBufferList GOING HERE");

    struct BufferList* next = cur->next;
    
    last->next = next;
    
    cur->valid = 0;
    cur->next = NULL;
    cur->sent = 0;
}

/////////////////////////// Buffer //////////////////////////

void initTCPBuffer(struct TCPBuffer* buffer, int offset){
    buffer->front = 0;
    buffer->back = 0;
    buffer->offset = offset;
}

int lenTCPBuffer(struct TCPBuffer* tcpbuf){
    if(tcpbuf == NULL){
        fprintf(stderr, "lenTCPBuffer: NULL pointer\n");
        return -1;
    }
    int ret = tcpbuf->back - tcpbuf->front;
    return ret >= 0 ? (MAX_BUFFER_SIZE - ret - 1) : (-ret - 1);
}

int getBufferPos(int seq, struct TCPBuffer* tcpbuf){
    int ret = seq - tcpbuf->offset + tcpbuf->front;
    if(ret >= MAX_BUFFER_SIZE)ret -= MAX_BUFFER_SIZE;
    if(ret >= MAX_BUFFER_SIZE)return -1;    // invalid seq
    return ret;
}

int getSeq(int pos, struct TCPBuffer* tcpbuf){
    if(pos >= tcpbuf->front)return pos - tcpbuf->front + tcpbuf->offset;
    return pos - tcpbuf->front + tcpbuf->offset + MAX_BUFFER_SIZE;
}


///////////////////////////Listen Queue///////////////////////////

int lenListenQue(int sockfd){
    int front = Sockets[sockfd].listenque.front;
    int back = Sockets[sockfd].listenque.back;
    return front <= back ? (back - front) : (back + MAX_LISTENQUE_SIZE - front);
}

void initListenQue(int sockfd, int backlog){
    Sockets[sockfd].listenque.backlog = backlog;
    Sockets[sockfd].listenque.front = 0;
    Sockets[sockfd].listenque.back = 0;
}

// may check repeated request
void pushListenQue(int sockfd, int seq, struct in_addr ip, struct in_addr dip, int port){
    if(lenListenQue(sockfd) >= Sockets[sockfd].listenque.backlog + 1){
        return; // simply throw this packet
    }
    struct ListenQue* que = &Sockets[sockfd].listenque;
    int tmpback = que->back;

    que->queue[tmpback].ip = ip;
    que->queue[tmpback].seq = seq;
    que->queue[tmpback].port = port;
    que->queue[tmpback].dip = dip;

    tmpback++;
    if(tmpback == MAX_LISTENQUE_SIZE){
        tmpback = 0;
    }

    que->back = tmpback;
}

int popListenQue(int sockfd, struct in_addr *ip , struct in_addr *dip, int *port, int *seq){
    if(lenListenQue(sockfd) == 0){
        return -1;
    }

    struct ListenQue* que = &Sockets[sockfd].listenque;
    int tmpfront = que->front;

    que->front++;
    if(que->front == MAX_LISTENQUE_SIZE){
        que->front = 0;
    }

    *ip = que->queue[tmpfront].ip;
    *dip = que->queue[tmpfront].dip;
    *port = que->queue[tmpfront].port;
    *seq = que->queue[tmpfront].seq;
}

void printSendBufferListInfo(int sockfd){
    struct BufferList* list = Sockets[sockfd].stream.send_buffer.list, *cur;
    if(list == NULL){
        fprintf(stderr, "printSendBufferListInfo: list cannot be NULL\n");
        return;
    }
    int sum = 0;

    puts("\n[Info]SendBufferList:");
    cur = list->next;
    while(cur != NULL){
        printf("seq:\t%d\tlen:\t%d\tflags:\t", cur->seq, cur->len);
        if(cur->flags & TH_SYN){
            printf("SYN ");
        }
        if(cur->flags & TH_ACK){
            printf("ACK ");
        }
        if(cur->flags & TH_FIN){
            printf("FIN ");
        }
        putchar('\n');
        cur = cur->next;
        sum++;
    }
    printf("Total:\t%d elements.\n\n", sum);
}

void printRcvdBufferListInfo(int sockfd){
    struct BufferList* list = Sockets[sockfd].stream.rcvd_buffer.list, *cur;
    if(list == NULL){
        fprintf(stderr, "printSendBufferListInfo: list cannot be NULL\n");
        return;
    }
    int sum = 0;

    puts("\n[Info]RcvdBufferList:");
    cur = list->next;
    while(cur != NULL){
        printf("seq:\t%d\tlen:\t%d\tflags:\t", cur->seq, cur->len);
        if(cur->flags & TH_SYN){
            printf("SYN ");
        }
        if(cur->flags & TH_ACK){
            printf("ACK ");
        }
        if(cur->flags & TH_FIN){
            printf("FIN ");
        }
        putchar('\n');
        cur = cur->next;
        sum++;
    }
    printf("Total:\t%d elements.\n\n", sum);
}


void printSocketInfo(int sockfd){
    char statestr[13][20] = {
        "XXXXXX",
        "ESTABLISHED", 
        "SYN_SENT",
        "SYN_RECV",
        "FIN_WAIT1",
        "FIN_WAIT2",
        "TIME_WAIT",
        "CLOSED",
        "CLOSE_WAIT",
        "LAST_ACK",
        "LISTEN",
        "CLOSING" 
    };
    struct Socket* sock = &Sockets[sockfd];
    printf("[Info] Socket infomation of socket %d\n", sockfd);
    puts("(basic info):");
    printf("\tvalid:%d\tstate:%s\n", sock->valid, statestr[sock->state]);
    printf("\twindow:%d\n", sock->window);

    in_addr_t temp;
    u_char* cptr;
    temp = sock->sip.s_addr;
    cptr = (u_char*)&temp;
    printf("\tsip:%u.%u.%u.%u\tsport:%d\n", cptr[0], cptr[1], cptr[2], cptr[3], sock->sport);

    temp = sock->dip.s_addr;
    cptr = (u_char*)&temp;
    printf("\tdip:%u.%u.%u.%u\tdport:%d\n", cptr[0], cptr[1], cptr[2], cptr[3], sock->dport);
    ///////////////////////////////////////////////////////////////////////////
    puts("(stream info):");
    printf("last_byte_written:%d\tlast_byte_acked:%d\tlast_byte_sent:%d\t\n",
            sock->stream.last_byte_written, sock->stream.last_byte_acked, sock->stream.last_byte_sent);
    printf("last_byte_read:%d\tnext_byte_expected:%d\tlast_byte_rcvd:%d\t\n",
            sock->stream.last_byte_read, sock->stream.next_byte_expected, sock->stream.last_byte_rcvd);
    ///////////////////////////////////////////////////////////////////////////
    puts("(data structure info):");
    struct ListenQue* queptr;
    queptr = &sock->listenque;
    printf("listenque:\tfront:%d\tback:%d\tbacklog:%d\n",queptr->front, queptr->back, queptr->backlog);
    struct TCPBuffer* tcpbuf;
    tcpbuf = &sock->stream.send_buffer;
    printf("sendbuffer:\tfront:%d\tback:%d\toffset:%d\n", tcpbuf->front, tcpbuf->back, tcpbuf->offset);
    tcpbuf = &sock->stream.rcvd_buffer;
    printf("rcvdbuffer:\tfront:%d\tback:%d\toffset:%d\n", tcpbuf->front, tcpbuf->back, tcpbuf->offset);

    puts("");
}