#include "inc.h"
#include "device.h"
#include "packetio.h"

u_char BroadcastMac[8] = {0xff,0xff,0xff,0xff,0xff,0xff};

int main(){
    char* dev1 = "v1", *dev2 = "v2", *dev3 = "v3", *dev4 = "v4";
    int DeviceCnt = 0;
    /**
     *      n1           n2            n3
     *  +-------+    +--------+    +--------+
     *  |     v1|----|v2    v3|----|v4      |    
     *  |       |    |        |    |        |
     *  +-------+    +--------+    +--------+
     * 
     */

    initMainThread();
    
    if(addDevice(dev1) != -1){
        printf("Device founded: %s\n", dev1);
        DeviceCnt++;
    }
    if(addDevice(dev2) != -1){
        printf("Device founded: %s\n", dev2);
        DeviceCnt++;
    }
    if(addDevice(dev3) != -1){
        printf("Device founded: %s\n", dev3);
        DeviceCnt++;
    }
    if(addDevice(dev4) != -1){
        printf("Device founded: %s\n", dev4);
        DeviceCnt++;
    }

    setFrameReceiveCallback(printInfoCallBack);
    char buf[128] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for(int i = 0; i < 10; i++){
        for(int j = 0; j < DeviceCnt; j++){
            sendFrame(buf, strlen(buf), ETH_P_IP, BroadcastMac, j);
        }
        sleep(1);
    }

   endAllThreads();
}