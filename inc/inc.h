#ifndef _INC_H_
#define _INC_H_

//#define checkCP7

#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>

//max device number and maxlen of a device name
#define MAX_DEV_NUM 32
#define MAX_DEV_LEN 10

//max elements in routing table
#define MAX_TABLE_LEN 64

#define SNAP_LEN 65536
#define MAX_DATA_LEN 1518

//max len of queue
#define MAX_QUE_LEN 512

#define MAX_SOCK_NUM 16

#define MAX(x, y) ((x) < (y) ? (y) : (x))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

struct PacketQueue{
    int devid;
    bpf_u_int32 len; 
    struct timeval ts;
    u_char data[MAX_DATA_LEN];
}RecvdPackets[MAX_QUE_LEN];

int PacketFront, PacketBack;

pthread_t MainThread, SubThreads[MAX_DEV_NUM];

pthread_mutex_t DevLock;
pthread_mutex_t QueLock;
pthread_mutex_t ARPLock;
pthread_mutex_t RoutingLock;
pthread_mutex_t SendLock[MAX_DEV_NUM];

pthread_mutex_t TCPQueLock[MAX_SOCK_NUM];
pthread_mutex_t SocketLock[MAX_SOCK_NUM];

/**
 * @brief Initialize the locks
 * 
 */
void initLock(void);

/**
 * @brief Create the main thread when program begins.
 *        Also initialize others things for threads.
 * 
 */
void initMainThread(void);

/**
 * @brief End all threads when program ends.
 * 
 */
void endAllThreads(void);

__attribute__((constructor)) void initLab2();

#endif