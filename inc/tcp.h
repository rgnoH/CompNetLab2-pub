#ifndef _TCP_H_
#define _TCP_H_

#include "inc.h"
#include <sys/types.h>
#include <netdb.h>
#include <netinet/tcp.h>

enum MachineState{
  ESTABLISHED_MS = 1,
  SYN_SENT_MS,
  SYN_RECV_MS,
  FIN_WAIT1_MS,
  FIN_WAIT2_MS,
  TIME_WAIT_MS,
  CLOSED_MS,
  CLOSE_WAIT_MS,
  LAST_ACK_MS,
  LISTEN_MS,
  CLOSING_MS 
};

struct pseudohdr{
  struct in_addr srcip;
  struct in_addr destip;
  u_int8_t zeros;
  u_int8_t proto;
  u_int16_t len;
};

#define MAX_BUFFER_SIZE 1500000
#define MAX_WINDOW_SIZE 32768
#define MAX_TCP_SEND_SIZE 1460  //  1518 - (14 + 4) - 20 - 20
#define TCP_RETRANS_THRESHOLD 4
#define TCP_MSL 2

#define MAX_BUFFERLIST_SIZE 131072
struct BufferList{
  int seq;
  int len;
  int sent;  // whether it's sent, for sender
  int valid;  // 1 - in use   0 - free
  uint8_t flags;
  struct timeval ts;
  struct BufferList* next;
}BList[MAX_BUFFERLIST_SIZE];//, BListBegin;

struct TCPBuffer{
  int front;  // < front, + MAX_BUFFER_SIZE
  int back;
  int offset; // the seq of front
  
  struct BufferList* list;  // pay attention to check if this equals to NULL
  
  u_char buf[MAX_BUFFER_SIZE];
};

#define MAX_LISTENQUE_SIZE 256
struct ListenQue{
  int front;
  int back;
  int backlog;
  struct{ // simple socket
    int seq;
    int port;
    struct in_addr ip;  //from
    struct in_addr dip;
  }queue[MAX_LISTENQUE_SIZE];
};

struct Socket{
  struct in_addr sip;
  struct in_addr dip;
  int sport;
  int dport;
  int state;
  int valid;//can be reclaimed if valid == 0

  int window; 
  //  simple window, update every time when receving a packet 
  //  initialize
  //  only check when data come from write(), i.e. checkSendBuffer()
  //  0 window corner case?

  // listen queue  
  struct ListenQue listenque;

  struct{
    int last_byte_written;  //  for send buffer, updates when writing buffer
    int last_byte_acked;    //  for send buffer, updates when receiving packets
    int last_byte_sent;     //  for send buffer, updates when sending packets

    int last_byte_read;     //  for rcvd buffer, updates when reading buffer(socket.c:read())
    int next_byte_expected; //  for rcvd buffer, updates when receiving packets
    int last_byte_rcvd;     //  for rcvd buffer, updates when receiving packets
    // window = MAX_WINDOW_SIZE - (last_byte_rcvd - last_byte_read)

    struct TCPBuffer send_buffer;
    struct TCPBuffer rcvd_buffer;
    
  }stream;
}Sockets[MAX_SOCK_NUM];

#define MAX_TCPQUE_LEN 128

struct TCPSendQueElem{
  int seq;
  int len;
  uint8_t flags;
  u_char payload[MAX_TCP_SEND_SIZE];
}TCPSendQue[MAX_SOCK_NUM][MAX_TCPQUE_LEN];

int TCPSendQueFront[MAX_SOCK_NUM];
int TCPSendQueBack[MAX_SOCK_NUM];

struct timeval LastRetrans[MAX_SOCK_NUM];

/**
 * @brief Make an TCP packet, store it in pkt. Ignore urg & urg_ptr.
 *        Flags: TH_FIN, TH_SYN, TH_RST, TH_ACK
 * @param len Length of TCP payload.
 */
void makeTCPPacket(const struct in_addr srcip, const struct in_addr destip,
                   const uint16_t sport, const uint16_t dport, 
                   const uint32_t seq, const uint32_t ack, uint8_t flags,
                   uint16_t window, const int len, const void* buf, u_char* pkt);

//  Push a TCP packet into TCPSendQue, and UPDATE last_byte_sent
//  This function will NOT check the restriction of window size.
//  This function will NOT change the bufferlist or buffer
//  TCPSendQue will be passed to packetio.c:processPacket()
//  Lock TCPQueLock[sockfd] at the beginning, and unlock it before return
//  Will write last_byte_sent, so the function call it should acquire SocketLock[sockfd]
int sendTCPPacket(const int sockfd, const int len, const int seq, const uint8_t flags, const void* buf);

//  Fill in send_buffer and UPDATE last_byte_written
//  This function will NOT check if payload exceeds the buffer.
//  This function will NOT operate buffer list for modularity
//  Better NOT to call this function when len == 0
void writeSendBuffer(const int sockfd, const int len, const int seq, const void* buf);

//  Fill in rcvd_buffer and UPDATE last_byte_rcvd
//  This function will NOT check if payload exceeds the buffer.
//  This function will NOT operate buffer list for modularity
//  Better NOT to call this function when len == 0
void writeRcvdBuffer(const int sockfd, const int len, const int seq, const void* buf);

//  Check timestamp in BufferList for retransmission
//  This function will check the socket's valid bit, state and dport/sport
//  Ensure that last_byte_acked is correct
void checkRetrans(int sockfd);

// pop the pkts already acked in the list, ACCORDING TO last_byte_acked 
// modify buffer and buffer list simultaneously
// call this function after a pkt arrived and last_byte_acked was updated
void maintainSendBuffer(int sockfd);

//  update next_byte_expected according to buffer list
//  do NOT pop pkts in the list, they should be poped in read()
void maintainRcvdBuffer(int sockfd);

//  check the buffer list and cut them into pieces
//  within the range of send window and recv window
//  this function will NOT insert packets out of send window
void checkSendBuffer(int sockfd);

///////////////////functions for data structures///////////////////

/////////////////////////// Socket Stream //////////////////////////

//
void initStreamSend(struct Socket* sock, int num);

void initStreamRecv(struct Socket* sock, int num);

///////////////////////////Buffer List//////////////////////////

int findFreeBufferListID();

//create and initialize the list
void initBufferList(struct BufferList** lst);

// insert the packet into the Buffer List, throw the packet if it's already in the list 
//  -1  error 1 dup 0 normal
int insertBufferList(struct BufferList* head, int seq, int len, const uint8_t flags);

//delete cur, will check whether last and cur are valid
void deleteBufferList(struct BufferList* last, struct BufferList* cur);

/////////////////////////// Buffer //////////////////////////


void initTCPBuffer(struct TCPBuffer* buffer, int offset);

int lenTCPBuffer(struct TCPBuffer* tcpbuf);

int getBufferPos(int seq, struct TCPBuffer* tcpbuf);

int getSeq(int pos, struct TCPBuffer* tcpbuf);

///////////////////////////Listen Queue///////////////////////////

int lenListenQue(int sockfd);

void initListenQue(int sockfd, int backlog);

void pushListenQue(int sockfd, int seq, struct in_addr ip, struct in_addr dip, int port);

int popListenQue(int sockfd, struct in_addr *ip , struct in_addr *dip, int *port, int *seq);


///////////////////functions for debugging ///////////////////

void printSendBufferListInfo(int sockfd);

void printRcvdBufferListInfo(int sockfd);

void printSocketInfo(int sockfd);

#endif