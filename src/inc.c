#include "inc.h"



int EndFlag = 0;
extern void* processPacket(void* param);    // see packetio.h and packetio.c
extern void endAllDevices();

void initLock(){
    srand(time(NULL));
    pthread_mutex_init(&DevLock, NULL);
    pthread_mutex_init(&QueLock, NULL);
    pthread_mutex_init(&ARPLock, NULL);
    pthread_mutex_init(&RoutingLock, NULL);
    pthread_mutex_init(&TCPQueLock, NULL);
    for(int i = 0; i < MAX_SOCK_NUM; i++){
        pthread_mutex_init(&SocketLock[i], NULL);
        pthread_mutex_init(&TCPQueLock[i], NULL);
    }
}

void initMainThread(){
    pthread_create(&MainThread, NULL, processPacket, NULL);
}

void endAllThreads(){
    EndFlag = 1;
    endAllDevices();
    pthread_join(MainThread, NULL);
}

__attribute__((constructor)) void initLab2(){
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

    sleep(5);
}