#include "inc.h"
#include "device.h"
#include "packetio.h"
#include "arp.h"
#include "ip.h"
// #include "socket.h"

u_char BroadcastMac[8] = {0xff,0xff,0xff,0xff,0xff,0xff};
extern int device_ID;
extern int RoutingTableID;

#define MAX_STR_LEN 4000000
#define TIMES 100

char* str = "from_c_2_s0123456789";
char sendbuf[MAX_STR_LEN];
char rcvd[MAX_STR_LEN];

void cli(char* ipaddr){
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), ret;
    if(fd < 0){
        fprintf(stderr, "socket failed\n");
        return;
        // goto endmain; 
    }

    struct sockaddr_in addr;
    u_char* ptr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    // ptr = &addr.sin_addr.s_addr;
    inet_pton(AF_INET, ipaddr, &addr.sin_addr);

    // ptr[0] = 0x0a;
    // ptr[1] = 0x64;
    // ptr[2] = 0x01;
    // ptr[3] = 0x02;
    //  server: 10.100.1.2:

    ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if(ret < 0){
        fprintf(stderr, "connect failed\n");
        return;
        // goto endmain;
    }

    //write
    
    for(int i = 0; i < 1460 * TIMES; i++){
        sendbuf[i] = '0' + rand() % 10;
    }
    int len = strlen(sendbuf);

    int total = len, remain;

    int totrcvd = 0;
    
    remain = total;
    
    int totalsend = 0;
    
    while(remain > 0){
        int sz, tmp;
        tmp = remain;
        sz = write(fd, sendbuf + totalsend, tmp);
        remain -= sz;
        totalsend += sz;

        sz = read(fd, rcvd + totrcvd, len);
        totrcvd += sz;
    }

// /*
    if(total != totrcvd){
        printf("[ERROR] totrcvd is %d\n", totrcvd);
    }
    else {
        int cmpflag = 1;
        for(int i = 0; i < total;i ++){
            if(sendbuf[i] != rcvd[i]){
                cmpflag = 0;
                break;
            }
        }
        if(cmpflag)puts("Cmp Check passed");
        else puts("[ERROR] cmp failed");
    }

    printf("total byte written:\t%d\n", total - remain);
// */

    close(fd);
}

int main(int argc, char* argv[]){
    if(argc != 2){
        printf("usage: %s <IPaddress>\n", argv[0]);
        return -1;
    }
/*
    int DeviceCnt = 0;
    pcap_if_t *devlist, *backupdevlist;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&devlist, errbuf) == PCAP_ERROR){
        fprintf(stderr, "Couldn't find device: %s\n", errbuf);
        return -1;
    }

    // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
    
    backupdevlist = devlist;    // backup the pointer to free
    while(devlist -> next != NULL){
        if(devlist->name[0] == 'v' ){   // only consider devices add by ourselves
            addDevice(devlist->name);    
        }
        devlist = devlist -> next;
    }
    pcap_freealldevs(backupdevlist);

    initLock();

    initRoutingTable();

    // printDeviceInfo();
    // printRoutingTable();

    // setFrameReceiveCallback(printInfoCallBack);
    // setIPPacketReceiveCallback(printIPInfoCallBack);

    initMainThread();

    // printf("Going here: %s %d\n", __FILE__ ,__LINE__);

    sleep(3);
*/
    for(int loop = 0; loop < 3; loop++){
        cli(argv[1]);
        printf("loop %d passed\n", loop);
    }

    
    return;

/*
    FILE* fp;
    fp = fopen("client_send.txt", "w");
    fprintf(fp, "%s", sendbuf);
    close(fp);
*/
   
    // if(fd >= SOCKET_OFFSET)fd -= SOCKET_OFFSET;
    // // pthread_mutex_lock(&SocketLock[fd]);
    // puts("\nclient: write end");
    // printSocketInfo(fd);
    // pthread_mutex_unlock(&SocketLock[fd]);

    /*
    struct timeval ts,curts;
    gettimeofday(&ts, NULL);
    while(1){
        pthread_mutex_lock(&SocketLock[fd]);
        if(Sockets[fd].stream.last_byte_written == Sockets[fd].stream.last_byte_acked){
            pthread_mutex_unlock(&SocketLock[fd]);
            break;
        }
        gettimeofday(&curts, NULL);
        if(curts.tv_sec - ts.tv_sec > 30)break;
        pthread_mutex_unlock(&SocketLock[fd]);
    }
    */
    //wait until send
    //retransmission
    // close(fd);

// endmain:
//     // printf("%d %d\n", PacketFront, PacketBack);
//     if(fd >= SOCKET_OFFSET)fd -= SOCKET_OFFSET;
//     // pthread_mutex_lock(&SocketLock[fd]);
//     puts("\nlast");
//     printSocketInfo(fd);
//     // pthread_mutex_unlock(&SocketLock[fd]);
    endAllThreads();
}