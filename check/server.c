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

char* str = "from_c_2_s0123456789";
char rcvd[MAX_STR_LEN];

void ser(int fd){
    int newsock = accept(fd, NULL, NULL);
    if(newsock < 0){
        fprintf(stderr, "accept failed\n");
        return;
        // goto endmain;
    }

    //read
    int len = 1460000, sum = 0, totw = 0;
    while(1){
        int sz = read(newsock, rcvd + sum, len);
        // int sz = read(newsock, rcvd, len);
        if(sz == 0){
            printf("total received:%d\n", sum);
            // puts(rcvd);
            break;
        }
        sum += sz;

        int remain = sz;
        while(remain > 0){
            int tmp;
            tmp = MIN(len, remain);
            sz = write(newsock, rcvd + totw, tmp);
            remain -= sz;
            totw+=sz;
        }
    }
    close(newsock);
}

int main(){
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
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), ret;
    if(fd < 0){
        fprintf(stderr, "socket failed\n");
        // goto endmain; 
        return -1;
    }

    struct sockaddr_in addr;
    u_char* ptr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    ptr = &addr.sin_addr.s_addr;

    // ptr[0] = 0x0a;
    // ptr[1] = 0x64;
    // ptr[2] = 0x01;
    // ptr[3] = 0x02;
    //  server: 10.100.1.2:
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if(ret < 0){
        fprintf(stderr, "bind failed\n");
        // goto endmain;
        return -1;
    }

    ret = listen(fd, 3);
    if(ret < 0){
        fprintf(stderr, "listen failed\n");
        // goto endmain;
        return -1;
    }

    for(int loop = 0; loop < 3; loop++){
        ser(fd);
        printf("loop %d passed\n", loop);
    }

    
    // if(sum != totw){
    //     printf("[ERROR] totw is %d\n", totw);
    // }
    // else printf("Check passed\n");
    /*
    int c = 0 ,flag = 1;
    for(int i = 0; i < sum; i++){
        if(rcvd[i] != '0' + c){
            printf("RCVD ERROR:\tpos: %d\tchar:%d\n", i, rcvd[i] - '0');
            flag = 0;
            c = rcvd[i] - '0';
            // break;
        }
        c = c < 9 ? c + 1 : 0;
    }
    if(flag)puts("NO ERROR");
    */

// /*
    // FILE* fp;
    // fp = fopen("server_rcvd.txt", "w");
    // fprintf(fp, "%s", rcvd);
    // close(fp);
// */
    // puts("\nserver: read end");
    // printf("SERVER GOING here: %s %d\n", __FILE__ ,__LINE__);
    
    return;

    // if(newsock < 0){
    //     if(fd >= SOCKET_OFFSET)fd -= SOCKET_OFFSET;
    //     pthread_mutex_lock(&SocketLock[fd]);
    //     printSocketInfo(fd);
    //     pthread_mutex_unlock(&SocketLock[fd]);
    // }
    // else{
    //     if(newsock >= SOCKET_OFFSET)newsock -= SOCKET_OFFSET;
    //     pthread_mutex_lock(&SocketLock[newsock]);
    //     printSocketInfo(newsock);
    //     pthread_mutex_unlock(&SocketLock[newsock]);
    // }

    // close(newsock);
    // close(fd);
    // sleep(30);

// endmain:
//     // printf("%d %d\n", PacketFront, PacketBack);
//     puts("\nlast");
//     if(newsock < 0){
//         if(fd >= SOCKET_OFFSET)fd -= SOCKET_OFFSET;
//         pthread_mutex_lock(&SocketLock[fd]);
//         printSocketInfo(fd);
//         pthread_mutex_unlock(&SocketLock[fd]);
//     }
//     else{
//         if(newsock >= SOCKET_OFFSET)newsock -= SOCKET_OFFSET;
//         pthread_mutex_lock(&SocketLock[newsock]);
//         printSocketInfo(newsock);
//         pthread_mutex_unlock(&SocketLock[newsock]);
//     }
    
    endAllThreads();
}