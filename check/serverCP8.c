#include "inc.h"
#include "device.h"
#include "packetio.h"
#include "arp.h"
#include "ip.h"
#include "socket.h"

u_char BroadcastMac[8] = {0xff,0xff,0xff,0xff,0xff,0xff};
extern int device_ID;
extern int RoutingTableID;

#define MAX_STR_LEN 666666

char* str = "from_c_2_s0123456789";
char rcvd[MAX_STR_LEN];

int main(){
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

    printDeviceInfo();
    // printRoutingTable();

    // setFrameReceiveCallback(printInfoCallBack);
    // setIPPacketReceiveCallback(printIPInfoCallBack);

    initMainThread();

    // printf("Going here: %s %d\n", __FILE__ ,__LINE__);

    sleep(3);
    
    int fd = __wrap_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), ret;
    if(fd < 0){
        fprintf(stderr, "socket failed\n");
        goto endmain; 
    }

    struct sockaddr_in addr;
    u_char* ptr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    ptr = &addr.sin_addr.s_addr;

    ptr[0] = 0x0a;
    ptr[1] = 0x64;
    ptr[2] = 0x01;
    ptr[3] = 0x02;
    //  server: 10.100.1.2:

    ret = __wrap_bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if(ret < 0){
        fprintf(stderr, "bind failed\n");
        goto endmain;
    }

    ret = __wrap_listen(fd, 3);
    if(ret < 0){
        fprintf(stderr, "listen failed\n");
        goto endmain;
    }

    int newsock = __wrap_accept(fd, NULL, NULL);
    if(newsock < 0){
        fprintf(stderr, "accept failed\n");
        goto endmain;
    }

    //read
    int len = strlen(str), sum = 0;
    while(1){
        // int sz = __wrap_read(newsock, rcvd + sum, len);
        int sz = __wrap_read(newsock, rcvd, len);
        if(sz == 0){
            printf("total received:%d\n", sum);
            // puts(rcvd);
            break;
        }
        sum += sz;
    }

    // __wrap_close(newsock);
    // __wrap_close(fd);
    sleep(30);

endmain:
    printf("%d %d\n", PacketFront, PacketBack);
    puts("\nlast");
    if(newsock < 0){
        fd -= SOCKET_OFFSET;
        pthread_mutex_lock(&SocketLock[fd]);
        printSocketInfo(fd);
        pthread_mutex_unlock(&SocketLock[fd]);
    }
    else{
        newsock -= SOCKET_OFFSET;
        pthread_mutex_lock(&SocketLock[newsock]);
        printSocketInfo(newsock);
        pthread_mutex_unlock(&SocketLock[newsock]);
    }
    
    endAllThreads();
}