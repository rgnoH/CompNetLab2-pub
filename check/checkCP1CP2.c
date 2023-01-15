#include "inc.h"
#include "device.h"
#include "packetio.h"

u_char BroadcastMac[8] = {0xff,0xff,0xff,0xff,0xff,0xff};

int main(){
    char* dev1 = "v1", *dev2 = "v2";
    
    initMainThread();
    
    if(addDevice(dev1) != -1){
        printf("Device founded: %s\n", dev1);
    }
    if(addDevice(dev2) != -1){
        printf("Device founded: %s\n", dev2);
    }

    setFrameReceiveCallback(printInfoCallBack);
    char buf[128] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for(int i = 0; i < 10; i++){
        sendFrame(buf, strlen(buf), ETH_P_IP, BroadcastMac, 0);
        sleep(1);
    }

   endAllThreads();
}