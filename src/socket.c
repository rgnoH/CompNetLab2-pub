#include "socket.h"
#include "device.h"
#include "ip.h"

int SocketID = 0;

// return -1 if not enough socket
int findFreeSocketID(){
    int i, ret = -1;
    for(i = 0; i < MAX_SOCK_NUM; i++){
        if(Sockets[i].valid == 0){
            ret = i;
            break;
        }
    }
    return ret;
}

void cleanSocket(int sockfd){
    Sockets[sockfd].dport = -1;
    Sockets[sockfd].sport = -1;
    Sockets[sockfd].dip.s_addr = 0;
    Sockets[sockfd].sip.s_addr = 0;
}

int __wrap_socket(int domain , int type , int protocol){
    if(domain == AF_INET && type == SOCK_STREAM){// && protocol == IPPROTO_TCP){
        int ret = findFreeSocketID();
        if(ret == -1){
            return -1;
        }
        
        puts("using wrap socket");

        // clean 
        cleanSocket(ret);
        Sockets[ret].valid = 1;
        Sockets[ret].state = CLOSED_MS;
        Sockets[ret].window = MAX_WINDOW_SIZE;

        initStreamRecv(&Sockets[ret], -1);
        initStreamSend(&Sockets[ret], -1);

        initBufferList(&Sockets[ret].stream.send_buffer.list);
        initBufferList(&Sockets[ret].stream.rcvd_buffer.list);

        gettimeofday(&LastRetrans[ret], NULL);

        // initTCPBuffer(&Sockets[ret].stream.send_buffer,);
        // initTCPBuffer(&Sockets[ret].stream.recv_buffer,);

        // puts("\nsocket():");
        // printSocketInfo(ret);
        // puts("");

        return ret + SOCKET_OFFSET;
    }
    // else return __real_socket(domain, type, protocol);
    else return socket(domain, type, protocol);
}


int __wrap_bind(int socket, const struct sockaddr *address,
    socklen_t address_len){
    //need to check something...
    if(address->sa_family == AF_INET && socket >= SOCKET_OFFSET && socket < MAX_SOCK_NUM + SOCKET_OFFSET){
        socket -= SOCKET_OFFSET;
        if(sizeof(struct sockaddr) != address_len){
            return -1;
        }

        pthread_mutex_lock(&SocketLock[socket]);
        if(Sockets[socket].valid == 0){
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }
        if(Sockets[socket].state != CLOSED_MS || Sockets[socket].sport != -1){
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }

        
        struct sockaddr_in *inaddr = (struct sockaddr_in*)address;
        Sockets[socket].sip = inaddr->sin_addr;
        Sockets[socket].sport = ntohs(inaddr->sin_port);

        pthread_mutex_unlock(&SocketLock[socket]);

        // puts("\nbind():");
        // printSocketInfo(socket);
        // puts("");
        return 0;
    }
    // else return __real_bind(socket, address, address_len);
    else return bind(socket, address, address_len);
}


int __wrap_listen(int socket, int backlog){
    if(socket >= SOCKET_OFFSET && socket < MAX_SOCK_NUM+ SOCKET_OFFSET){
        socket -= SOCKET_OFFSET;

        pthread_mutex_lock(&SocketLock[socket]);
        if(Sockets[socket].valid == 0){
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }
        if(Sockets[socket].state != CLOSED_MS || Sockets[socket].sport == -1 || Sockets[socket].dport != -1){
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }

        if(backlog < 0){
            backlog = 0;
        }
        if(backlog >= MAX_LISTENQUE_SIZE){
            fprintf(stderr, "listen: backlog is too large, cannot exceeds %d\n", MAX_LISTENQUE_SIZE);
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }

        initListenQue(socket, backlog);
        Sockets[socket].state = LISTEN_MS;

        pthread_mutex_unlock(&SocketLock[socket]);

        // puts("\nlisten():");
        // printSocketInfo(socket);
        // puts("");
        return 0;
    }
    // else return __real_listen(socket, backlog);
    else return listen(socket, backlog);
}

extern int device_ID;

int __wrap_connect(int socket, const struct sockaddr *address,
    socklen_t address_len){
    if(socket >= SOCKET_OFFSET && socket < MAX_SOCK_NUM+ SOCKET_OFFSET){
        socket -= SOCKET_OFFSET;

        pthread_mutex_lock(&SocketLock[socket]);
        if(sizeof(struct sockaddr) != address_len){
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }
        if(Sockets[socket].valid == 0){
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }
        if(Sockets[socket].state != CLOSED_MS || Sockets[socket].sport != -1){
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }

        if(device_ID == 0){
            fprintf(stderr, "connect: no devices\n");
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }

        struct sockaddr_in *inaddr = (struct sockaddr_in*)address;
        struct RoutingTableElem* rte;
        rte = matchRoutingTable(inaddr->sin_addr);

        if(rte == NULL){
            fprintf(stderr, "connect: cannot find in routing table\n");
            return -1;
        }

        struct Socket* sock = &Sockets[socket];

        sock->sip = rev_devs[rand() % device_ID].ipv4addr; // may need lock
        sock->sport = rand() & 0xffff;    // may need check

        sock->dip = inaddr->sin_addr;
        sock->dport = ntohs(inaddr->sin_port);

        initStreamSend(sock, rand() & 0xfff);

        // read, expected and rcvd updated in TCPCallBack?

        // initTCPBuffer(&sock->stream.send_buffer, sock->stream.last_byte_sent + 1);
        // rcvd updated in TCPCallBack

        u_char buf[2];  // maybe can be NULL?
        sock->state = SYN_SENT_MS;
        insertBufferList(sock->stream.send_buffer.list,  sock->stream.last_byte_sent + 1, 0, TH_SYN);
        sendTCPPacket(socket, 0, sock->stream.last_byte_sent + 1, TH_SYN, buf);
        
        //check the len again! logically one byte
        //may change, without call of writeSendBuffer
        //or just call insertBufferList?
        pthread_mutex_unlock(&SocketLock[socket]);
        //  unlock it, so that CallBack can push sockaddr into listenQue


        // printSocketInfo(socket);

        struct timeval curt,st;
        gettimeofday(&st, NULL);
        while(1){
            gettimeofday(&curt, NULL);
            if(curt.tv_sec - st.tv_sec >= CONNECT_THRESHOLD){
                break;
            }
            pthread_mutex_lock(&SocketLock[socket]);
            if(sock->state == ESTABLISHED_MS){    //seems no trouble for write/read, for blocking
                //may do NOTHING, state change and ACK sending happen in TCPCallBack

                //sendTCPPacket(socket, 0,sock->stream.last_byte_sent + 1, TH_ACK, buf);
                //writeSendBuffer(socket, 1, sock->stream.last_byte_sent + 1, buf);
                
                //check the len again! logically one byte
                //may change, without call of writeSendBuffer
                //or just call insertBufferList?
                pthread_mutex_unlock(&SocketLock[socket]);
                // puts("\nconnect():");
                // printSocketInfo(socket);
                // puts("");

                return 0;
            }
            else pthread_mutex_unlock(&SocketLock[socket]);
        }

        pthread_mutex_lock(&SocketLock[socket]);
        sock->dip.s_addr = 0;
        sock->dport = -1;
        sock->state = CLOSED_MS;
        pthread_mutex_unlock(&SocketLock[socket]);

        // puts("\nconnect():");
        // printSocketInfo(socket);
        // puts("");

        return -1;
    }
    // else return __real_connect(socket, address, address_len);
     else return connect(socket, address, address_len);
}


int __wrap_accept(int socket, struct sockaddr *address,
    socklen_t *address_len){
    if(socket >= SOCKET_OFFSET && socket < MAX_SOCK_NUM+ SOCKET_OFFSET){
        socket -= SOCKET_OFFSET;

        // printf("Accept Going here: %s %d\n", __FILE__ ,__LINE__);

        // if(address != NULL && sizeof(struct sockaddr) != *address_len){
        //     return -1;
        // }

        // printf("Accept Going here: %s %d\n", __FILE__ ,__LINE__);
        
        pthread_mutex_lock(&SocketLock[socket]);
        if(Sockets[socket].valid == 0){
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }
        // printf("Accept Going here: %s %d\n", __FILE__ ,__LINE__);
        if(Sockets[socket].state != LISTEN_MS || Sockets[socket].dport != -1){
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }
        
        int newsock = findFreeSocketID();
        int dport;
        int seq;
        struct in_addr dip, sip;

        if(newsock == -1){
            pthread_mutex_unlock(&SocketLock[socket]);
            return -1;
        }

        pthread_mutex_unlock(&SocketLock[socket]);
        //  unlock it, so that CallBack can push sockaddr into listenQue
        struct timeval st,cur;
        gettimeofday(&st, NULL);
        while(1){
            pthread_mutex_lock(&SocketLock[socket]);
            int r = popListenQue(socket, &dip, &sip, &dport, &seq);
            pthread_mutex_unlock(&SocketLock[socket]);

            if(r != -1)break;

            // sleep(1);

            gettimeofday(&cur, NULL);
            if(cur.tv_sec - st.tv_sec >= ACCEPT_THRESHOLD){
                // pthread_mutex_unlock(&SocketLock[newsock]);

                // puts("\naccept():");
                // printSocketInfo(socket);
                // puts("");

                return -1;
            }
        }
        
        pthread_mutex_lock(&SocketLock[newsock]);   // this my be wrong ... newsock might be modified, but not in checkpoint
        pthread_mutex_lock(&SocketLock[socket]);

        if(address != NULL){
             struct sockaddr_in *inaddr = (struct sockaddr_in*)address;
            inaddr->sin_port = dport;
            inaddr->sin_addr.s_addr = dip.s_addr;
        }
        if(address_len != NULL)*address_len = sizeof(struct sockaddr_in);

        struct Socket *sock, *nsock;

        sock = &Sockets[socket];
        nsock = &Sockets[newsock];

        nsock->sip = sip;
        int tmp;        
        while((tmp = rand() & 0xffff) == Sockets[socket].sport);

        nsock->sport = tmp;
        nsock->dip = dip;
        nsock->dport = dport;
        nsock->state = SYN_RECV_MS;
        nsock->valid = 1;
        nsock->window = MAX_WINDOW_SIZE;
        
        initStreamRecv(nsock, seq);
        initStreamSend(nsock, rand() & 0xfff);

        initBufferList(&nsock->stream.send_buffer.list);
        initBufferList(&nsock->stream.rcvd_buffer.list);

        //call initTCPBuffer after ESTABLISHED 
        //initTCPBuffer(&Sockets[newsock].stream.send_buffer, Sockets[newsock].stream.last_byte_sent + 1);
        //initTCPBuffer(&Sockets[newsock].stream.rcvd_buffer, Sockets[newsock].stream.next_byte_expected);

        sock->state = LISTEN_MS;  // maybe CLOSED?
        sock->dip.s_addr = 0;
        sock->dport = -1;
        // may invalidate?

        char buf[2];
        insertBufferList(nsock->stream.send_buffer.list, Sockets[newsock].stream.last_byte_sent + 1, 0, TH_SYN | TH_ACK);
        sendTCPPacket(newsock, 0, Sockets[newsock].stream.last_byte_sent + 1, TH_SYN | TH_ACK, buf);

        gettimeofday(&LastRetrans[newsock], NULL);

        pthread_mutex_unlock(&SocketLock[socket]);
        pthread_mutex_unlock(&SocketLock[newsock]);

        struct timeval curt;
        gettimeofday(&st, NULL);
        while(1){
            gettimeofday(&curt, NULL);
            if(curt.tv_sec - st.tv_sec >= CONNECT_THRESHOLD){
                // puts("\naccept():");
                // printSocketInfo(socket);
                // puts("");
                return -1;
            }
            pthread_mutex_lock(&SocketLock[newsock]);
            if(nsock->state == ESTABLISHED_MS){    //seems no trouble for write/read, for blocking
                pthread_mutex_unlock(&SocketLock[newsock]);
                // puts("\naccept():");
                // printSocketInfo(newsock);
                // puts("");
                return newsock + SOCKET_OFFSET;
            }
            else pthread_mutex_unlock(&SocketLock[newsock]);
        }
    }
    // else return __real_accept(socket, address, address_len);
    else  return accept(socket, address, address_len);
}


ssize_t __wrap_read(int fildes, void* buf, size_t nbyte){
    if(fildes >= SOCKET_OFFSET && fildes < MAX_SOCK_NUM+ SOCKET_OFFSET){
        fildes -= SOCKET_OFFSET;

        pthread_mutex_lock(&SocketLock[fildes]);
        if(Sockets[fildes].valid == 0){
            pthread_mutex_unlock(&SocketLock[fildes]);
            return 0;       // may -1
        }
        if(Sockets[fildes].state != ESTABLISHED_MS
            && Sockets[fildes].state != FIN_WAIT1_MS
            && Sockets[fildes].state != FIN_WAIT2_MS
            && Sockets[fildes].state != TIME_WAIT_MS
            && Sockets[fildes].state != CLOSE_WAIT_MS){
                pthread_mutex_unlock(&SocketLock[fildes]);
                return 0;   // may -1
        }

        nbyte = MIN(nbyte, (MAX_WINDOW_SIZE)>>1);

        // printf("using wrap read: %d\n", nbyte);

        int i = 0, frontseq, tmpfront;
        u_char* ptr = (u_char*)buf;
        struct TCPBuffer* tcpbuf;
        struct BufferList *list, *cur;
        size_t remain = nbyte;

        tcpbuf = &Sockets[fildes].stream.rcvd_buffer;
        list = tcpbuf->list;
        

        // read part of the packet
        // blocked version: block until the state changes or read at least 1 byte
        pthread_mutex_unlock(&SocketLock[fildes]);
        struct timeval ts, nts;
        gettimeofday(&ts, NULL);

        while(remain > 0){
            pthread_mutex_lock(&SocketLock[fildes]);
            
            frontseq = getSeq(tcpbuf->front, tcpbuf);
            cur = list->next;
            
            //  if rcvd buffer is not empty, then read should wait until byte expected arrives
            if( cur == NULL || !(cur->seq <= frontseq && frontseq < cur->seq + cur->len)){
                    pthread_mutex_unlock(&SocketLock[fildes]);

                    // if(lenTCPBuffer(tcpbuf) < MAX_BUFFER_SIZE - 1){
                    //     gettimeofday(&ts, NULL);
                    // }

                    gettimeofday(&nts, NULL);
                    if(nts.tv_sec - ts.tv_sec >= 5){   // timeout
                        break;
                    }
                    else continue;  //  not enough space or out of cur
                }
            
            // pthread_mutex_lock(&SocketLock[fildes]);

            //speed up here
            while(remain > 0){
                frontseq = getSeq(tcpbuf->front, tcpbuf);
                cur = list->next;

                if(cur == NULL || !(cur->seq <= frontseq && frontseq < cur->seq + cur->len) || (cur->flags & TH_FIN)){
                    break;
                }
/*
                if(remain > cur->len){
                    tmpfront = tcpbuf->front;
                    tcpbuf->front += cur->len;
                    tcpbuf->offset += cur->len;
                    if(tcpbuf->front >= MAX_BUFFER_SIZE){
                        tcpbuf->front -= MAX_BUFFER_SIZE;
                        int tmp = MAX_BUFFER_SIZE -tmpfront;
                        memcpy(ptr + i, tcpbuf->buf + tmpfront, tmp);
                        memcpy(ptr + (i + tmp), tcpbuf->buf, cur->len - tmp);
                    }
                    else{
                        memcpy(ptr + i, tcpbuf->buf + tmpfront, cur->len);
                    }
                    
                    i += cur->len;
                    remain-= cur->len;
                    deleteBufferList(list, cur);
                }
                else{
                    tmpfront = tcpbuf->front;
                    tcpbuf->front += remain;
                    tcpbuf->offset += remain;
                    if(tcpbuf->front >= MAX_BUFFER_SIZE){
                        tcpbuf->front -= MAX_BUFFER_SIZE;
                        int tmp = MAX_BUFFER_SIZE -tmpfront;
                        memcpy(ptr + i, tcpbuf->buf + tmpfront, tmp);
                        memcpy(ptr + (i + tmp), tcpbuf->buf, remain - tmp);
                    }
                    else{
                        memcpy(ptr + i, tcpbuf->buf + tmpfront, remain);
                    }
                    
                    i += remain;
                    remain = 0;
                }
                break;
*/
// /*
                tmpfront = tcpbuf->front;
                tcpbuf->front++;
                tcpbuf->offset++;
                if(tcpbuf->front == MAX_BUFFER_SIZE){
                    tcpbuf->front = 0;
                }
            
                ptr[i++] = tcpbuf->buf[tmpfront];
                remain--;
            

                if(cur->seq + cur->len == frontseq + 1){
                    deleteBufferList(list, cur);
                }
// */
            }
            gettimeofday(&ts, NULL);    // update timestamp every time a byte read
            pthread_mutex_unlock(&SocketLock[fildes]);
            break;
        }
        pthread_mutex_lock(&SocketLock[fildes]);
        Sockets[fildes].stream.last_byte_read = MAX(Sockets[fildes].stream.last_byte_read, getSeq(tcpbuf->front, tcpbuf) - 1);
        pthread_mutex_unlock(&SocketLock[fildes]);
        return nbyte - remain;
    }
    // else return __real_read(fildes, buf, nbyte);
    else return read(fildes, buf, nbyte);
}


ssize_t __wrap_write(int fildes, const void* buf, size_t nbyte){
    if(fildes >= SOCKET_OFFSET && fildes < MAX_SOCK_NUM+ SOCKET_OFFSET){
        fildes -= SOCKET_OFFSET;

        pthread_mutex_lock(&SocketLock[fildes]);
        if(Sockets[fildes].valid == 0){
            pthread_mutex_unlock(&SocketLock[fildes]);
            return -1;
        }
        if(Sockets[fildes].state != ESTABLISHED_MS){
            pthread_mutex_unlock(&SocketLock[fildes]);
            return -1;  //  can only write when ESTABLISHED
        }

        nbyte = MIN(nbyte, (MAX_WINDOW_SIZE)>>1);

        // puts("using wrap write");

        int seq;
        ssize_t remain = nbyte, len;
        struct TCPBuffer* tcpbuf;
        struct Socket* sock;
        
        sock = &Sockets[fildes];
        tcpbuf = &sock->stream.send_buffer;
        /*
        while(remain > 0){
            if(lenTCPBuffer(tcpbuf) == 0){
                break;
            }

            len = MIN(MAX_TCP_SEND_SIZE, remain);
            len = MIN(len, lenTCPBuffer(tcpbuf));
            
            seq = getSeq(tcpbuf->back, tcpbuf);

            insertBufferList(tcpbuf->list, seq, len, TH_ACK);
            writeSendBuffer(fildes, len, seq, buf + (nbyte - remain));
            // should check send window and rcvd window?
            // sendTCPPacket(fildes, len, seq, TH_ACK, buf + (nbyte -remain));

            remain -= len;
        }
        */
        seq = getSeq(tcpbuf->back, tcpbuf);
        len = MIN(lenTCPBuffer(tcpbuf), remain);
        
        writeSendBuffer(fildes, len, seq, buf);

        while(1){
            pthread_mutex_unlock(&SocketLock[fildes]);
            if(sock->stream.last_byte_written == sock->stream.last_byte_acked){
                pthread_mutex_lock(&SocketLock[fildes]);
                break;
            }
            pthread_mutex_lock(&SocketLock[fildes]);
        }

        pthread_mutex_unlock(&SocketLock[fildes]);
        return len;
    }
    // else return __real_write(fildes, buf, nbyte);
    else return write(fildes, buf, nbyte);
}


int __wrap_close(int fildes){
    if(fildes >= SOCKET_OFFSET && fildes < MAX_SOCK_NUM + SOCKET_OFFSET){
        fildes -= SOCKET_OFFSET;

        pthread_mutex_lock(&SocketLock[fildes]);
        //  puts("CLOSE:BEGIN");

        if(Sockets[fildes].valid == 0){
            pthread_mutex_unlock(&SocketLock[fildes]);
            return -1;
        }
        if(Sockets[fildes].state == CLOSED_MS){
            pthread_mutex_unlock(&SocketLock[fildes]);
            return 0;
        }
        if(Sockets[fildes].state == LISTEN_MS){
            Sockets[fildes].state = CLOSED_MS;
            Sockets[fildes].valid = 0;
            pthread_mutex_unlock(&SocketLock[fildes]);
            return 0;
        }
        if(Sockets[fildes].state == SYN_SENT_MS){
            Sockets[fildes].state = CLOSED_MS;
            Sockets[fildes].valid = 0;
            pthread_mutex_unlock(&SocketLock[fildes]);
            return 0;
        }
        if(Sockets[fildes].state == SYN_RECV_MS || Sockets[fildes].state == ESTABLISHED_MS){
            //  puts("CLOSE: ESTABLISHED");

            pthread_mutex_unlock(&SocketLock[fildes]);
            while(1){
                pthread_mutex_lock(&SocketLock[fildes]);
                if(Sockets[fildes].stream.last_byte_sent == Sockets[fildes].stream.last_byte_written){
                    break;
                }
                pthread_mutex_unlock(&SocketLock[fildes]);
                //  Since user thread cannot call close() and write() at a time, last_byte_written will not change
                //  However, last_byte_sent will change by checkSendBuffer()
            }
            
            Sockets[fildes].state = FIN_WAIT1_MS;
            
            // puts("state: FIN_WAIT1\n");

            u_char buf[2];
            insertBufferList(Sockets[fildes].stream.send_buffer.list, Sockets[fildes].stream.last_byte_sent + 1, 1, TH_FIN);
            sendTCPPacket(fildes, 0, Sockets[fildes].stream.last_byte_sent + 1, TH_FIN, buf);
            pthread_mutex_unlock(&SocketLock[fildes]);
            // do someting?

            struct timeval st, curts;
            gettimeofday(&st, NULL);
            while(1){
                pthread_mutex_lock(&SocketLock[fildes]);
                if(Sockets[fildes].state == CLOSED_MS){
                    Sockets[fildes].valid = 0;
                    pthread_mutex_unlock(&SocketLock[fildes]);
                    break;
                }
                gettimeofday(&curts, NULL);
                if(curts.tv_sec - st.tv_sec >= 10){
                    Sockets[fildes].state = CLOSED_MS;
                    Sockets[fildes].valid = 0;
                    pthread_mutex_unlock(&SocketLock[fildes]);
                    break;
                }
                pthread_mutex_unlock(&SocketLock[fildes]);
            }

            return 0;
        }
        if(Sockets[fildes].state == CLOSE_WAIT_MS){
            pthread_mutex_unlock(&SocketLock[fildes]);
            // puts("CLOSE:GOING CLOSE_WAIT");
            while(1){
                pthread_mutex_lock(&SocketLock[fildes]);
                if(Sockets[fildes].stream.last_byte_sent == Sockets[fildes].stream.last_byte_written){
                    break;
                }
                pthread_mutex_unlock(&SocketLock[fildes]);
                //  Since user thread cannot call close() and write() at a time, last_byte_written will not change
                //  However, last_byte_sent will change by checkSendBuffer()
            }
            
            Sockets[fildes].state = LAST_ACK_MS;
            // puts("state: LAST_ACK\n");

            u_char buf[2];
            insertBufferList(Sockets[fildes].stream.send_buffer.list, Sockets[fildes].stream.last_byte_sent + 1, 1, TH_FIN | TH_ACK);
            sendTCPPacket(fildes, 0, Sockets[fildes].stream.last_byte_sent + 1, TH_FIN | TH_ACK, buf);
            pthread_mutex_unlock(&SocketLock[fildes]);

            struct timeval st, curts;
            gettimeofday(&st, NULL);
            while(1){
                pthread_mutex_lock(&SocketLock[fildes]);
                if(Sockets[fildes].state == CLOSED_MS){
                    Sockets[fildes].valid = 0;
                    pthread_mutex_unlock(&SocketLock[fildes]);
                    break;
                }
                gettimeofday(&curts, NULL);
                if(curts.tv_sec - st.tv_sec >= 10){
                    Sockets[fildes].state = CLOSED_MS;
                    Sockets[fildes].valid = 0;
                    pthread_mutex_unlock(&SocketLock[fildes]);
                    break;
                }
                pthread_mutex_unlock(&SocketLock[fildes]);
            }

            return 0;
        }
    }
    // else return __real_close(fildes);
    else return close(fildes);
}

struct addrinfo AddrInfo;
struct sockaddr_in SockAddrIn;

int __wrap_getaddrinfo(const char *node , const char *service,
    const struct addrinfo *hints,
    struct addrinfo **res){

    struct in_addr ipv4;
    int port;
    
    // check if paramters satisfy restrictions
    if(hints != NULL && (hints->ai_family != AF_INET || hints->ai_socktype != IPPROTO_TCP || hints->ai_flags != 0)){
        return -1;
    }
    if(node != NULL && inet_aton(node, &ipv4) == 0){
        return -1;
    }
    if(service != NULL && (port = atoi(service)) == 0 ){
        return -1;
    }
    if(node == NULL && service == NULL){
        return -1;
    }
    AddrInfo.ai_next = NULL;
    AddrInfo.ai_family = AF_INET;
    AddrInfo.ai_socktype = IPPROTO_TCP;
    AddrInfo.ai_flags = 0;
    if(node != NULL){
        inet_aton(node, &SockAddrIn.sin_addr);
    }
    if(service != NULL){
        SockAddrIn.sin_port = atoi(service);
    }

    AddrInfo.ai_addr = &SockAddrIn;
}

int findSocket(const struct in_addr ip, const int port){
    int i;
    for(i = 0 ;i < MAX_SOCK_NUM; i++){
        if(Sockets[i].valid != 1 || Sockets[i].sport != port){
            continue;
        }
        if(Sockets[i].sip.s_addr == ip.s_addr){
            return i;
        }
        if(Sockets[i].sip.s_addr == htonl(INADDR_ANY)){
            for(int j = 0; j < device_ID; j++){
                if(rev_devs[j].ipv4addr.s_addr == ip.s_addr){
                    return i;
                }
            }
        }
    }
    return -1;
}