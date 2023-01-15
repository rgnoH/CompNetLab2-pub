#include "device.h"
#include "packetio.h"

int device_ID = 0;
pcap_t* DeviceHandle[MAX_DEV_NUM];

int addDevice(const char* device){
    pthread_mutex_lock(&DevLock);
    pcap_if_t *devlist, *backupdevlist;
    char errbuf[PCAP_ERRBUF_SIZE];

    int i, tmp = -1;

    for(i = 0; i < device_ID; i++){
        if(strcmp(device, rev_devs[i].name) == 0){
           tmp = i;
           break;
        }
    }
    if(tmp != -1)return tmp;    // if the device already exists

    if(pcap_findalldevs(&devlist, errbuf) == PCAP_ERROR){
        fprintf(stderr, "Couldn't find device: %s %s\n", device, errbuf);
        pthread_mutex_unlock(&DevLock);
        return -1;
    }

    // printf("Going here: %s %d\n", __FILE__ ,__LINE__);

    backupdevlist = devlist;    // backup the pointer to free
    while(devlist -> next != NULL){
        if(strcmp(device, devlist -> name) == 0){
            if(device_ID == MAX_DEV_NUM){   // when reach the maximum number, avoid overflow
                fprintf(stderr, "Couldn't add more devices: %d\n", device_ID);
                pcap_freealldevs(backupdevlist);
                pthread_mutex_unlock(&DevLock);
                return -1;
            }

            // Create threads to receive packets. Here is the procedure to create handles.
            pcap_t* handle = pcap_create(device, errbuf);
            if(handle == NULL){
                fprintf(stderr, "Couldn't create a thread!\n");
                pcap_freealldevs(backupdevlist);
                pthread_mutex_unlock(&DevLock);
                return -1;
            }
            pcap_set_immediate_mode(handle, 1);
            pcap_set_timeout(handle, 10);
            DeviceHandle[device_ID] = handle;

            // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
            
            strcpy(rev_devs[device_ID].name, device);
            
            pcap_addr_t *addrs = devlist->addresses;
            while(addrs != NULL){
                if(addrs->addr->sa_family == AF_PACKET){
                    struct sockaddr_ll* lladdr = (struct sockaddr_ll*)addrs->addr;
                    u_char *macaddr = lladdr->sll_addr;
                    memcpy(&rev_devs[device_ID].mac, macaddr, lladdr->sll_halen);
                }
                else if(addrs->addr->sa_family == AF_INET){ //IP
                    struct sockaddr_in* inaddr = (struct sockaddr_in*)addrs->addr;
                    memcpy(&rev_devs[device_ID].ipv4addr, &inaddr->sin_addr, sizeof(inaddr->sin_addr));
                    // get netmask
                    struct sockaddr_in* netmsk = (struct sockaddr_in*)addrs->netmask;
                    memcpy(&rev_devs[device_ID].netmask, &netmsk->sin_addr, sizeof(netmsk->sin_addr));
                }
                addrs = addrs ->next;
            }

            // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
            pthread_create(&SubThreads[device_ID], NULL, receivePacket, (void*)device_ID);
            // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
            pthread_mutex_init(&SendLock[device_ID], NULL);

            pcap_freealldevs(backupdevlist);
            pthread_mutex_unlock(&DevLock);
            // printf("Going here: %s %d\n", __FILE__ ,__LINE__);
            return device_ID++;
        }
        devlist = devlist -> next;
    }

    pcap_freealldevs(backupdevlist);
    fprintf(stderr, "Couldn't find device %s\n", device);
    pthread_mutex_unlock(&DevLock);
    return -1;
}

int findDevice(const char* device){
    pthread_mutex_lock(&DevLock);
    int i;
    for(i = 0; i < device_ID; i++){
        if(strcmp(device, rev_devs[i].name) == 0){
            pthread_mutex_unlock(&DevLock);
            return i;
        }
    }
    pthread_mutex_unlock(&DevLock);
    return -1;
}

struct Device* checkValidDevice(int id){
    pthread_mutex_lock(&DevLock);
    if(id < 0 || id >= device_ID){
        pthread_mutex_unlock(&DevLock);
        return NULL;
    }
    pthread_mutex_unlock(&DevLock);
    return &rev_devs[id];
}

void endAllDevices(){
    int i;
    pthread_mutex_lock(&DevLock);
    for(i = 0; i < device_ID; i++){
        pcap_breakloop(DeviceHandle[i]);
        pthread_join(SubThreads[i], NULL);
    }
    pthread_mutex_unlock(&DevLock);
}

void printDeviceInfo(){
    int i;
    in_addr_t temp;
    u_char* cptr;
    pthread_mutex_lock(&DevLock);
    printf("[Info] %d devices information added:\n", device_ID);
    for(i = 0; i < device_ID; i++){
        printf("%02d device name:\t%s\n", i, rev_devs[i].name);
        printf("MAC address:\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
            rev_devs[i].mac[0], rev_devs[i].mac[1], rev_devs[i].mac[2], rev_devs[i].mac[3], rev_devs[i].mac[4], rev_devs[i].mac[5]);

        temp = rev_devs[i].ipv4addr.s_addr;
        cptr = (u_char*)&temp;
        printf("IPv4 address:\t%u.%u.%u.%u\n", cptr[0], cptr[1], cptr[2], cptr[3]);

        temp = rev_devs[i].netmask.s_addr;
        cptr = (u_char*)&temp;
        printf("netmask:\t%u.%u.%u.%u\n", cptr[0], cptr[1], cptr[2], cptr[3]);

        putchar('\n');
    }
    pthread_mutex_unlock(&DevLock);
}