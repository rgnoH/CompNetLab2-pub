#include "inc.h"
#include "device.h"
#include "packetio.h"
#include "arp.h"
#include "ip.h"
#include "socket.h"

u_char BroadcastMac[8] = {0xff,0xff,0xff,0xff,0xff,0xff};
extern int device_ID;
extern int RoutingTableID;

#define MAX_STR_LEN 4000000
#define TIMES 100

char* str = "from_c_2_s0123456789";
char sendbuf[MAX_STR_LEN];
char rcvd[MAX_STR_LEN];

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

    initMainThread();
*/
    // printf("Going here: %s %d\n", __FILE__ ,__LINE__);

    sleep(240);

    endAllThreads();
}