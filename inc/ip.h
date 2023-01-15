/**
* @file ip.h
* @brief Library supporting sending / receiving IP packets encapsulated
    in an Ethernet II frame .
*/

#ifndef _IP_H_
#define _IP_H_

#include "inc.h"
#include "arp.h"
#include <netinet/ip.h>

#define IP_ROUTING_PROTO 200    //  an un assigned protocol number
#define IP_BROADCASTING_ADDR 0xffffffff
#define IP_MASK_ALL 0xffffffff

#define IP_TIME_ENTRY_THRESHOLD 10
#define IP_ROUTING_TIME_INTERVAL_SEC 1
#define IP_ROUTING_TIME_INTERVAL_USEC 750000
#define IP_TTL_THRESHOLD 6
#define IP_MAX_QUE_LEN 256


struct RoutingTableElem{
    struct in_addr dest;
    struct in_addr mask;
    struct in_addr nextHop;
    int srcdev; //id
    int dis;    //hops
    struct timeval ts;  // timestamp
}RoutingTable[MAX_TABLE_LEN];   //one table per host

struct IPPacketQueElem{
    struct in_addr src;
    struct in_addr dest;
    int proto;
    u_char buf[MAX_DATA_LEN];
    int len;
    int ttl;

    // int cnt;
    struct timeval ts;
}IPPacketQue[IP_MAX_QUE_LEN];



int emptyIPQue();

int lenIPQue();

void popIPQue(struct IPPacketQueElem* ippkt);

void pushIPQue(struct IPPacketQueElem* ippkt);

/**
* @brief Calculate checksum of an IP header. Ignore options.
*
* @param hdrptr IP header pointer.
* @return The corresponding checksum .
*/
uint16_t calcCheck(struct iphdr* hdrptr);

/**
* @brief Send an IP packet to specified host.
*
* @param src Source IP address .
* @param dest Destination IP address .
* @param proto Value of ‘ protocol ‘ field in IP header .
* @param buf pointer to IP payload
* @param len Length of IP payload
* @param ttl Value of 'TTL' field in IP header
* @param ts The timestamp used in IPPacketQue
* @return 0 on success , -1 on error .
*/
int sendIPPacket ( const struct in_addr src , const struct in_addr dest ,
    int proto , const void * buf , int len, int ttl, struct timeval ts) ;

/**
* @brief Process an IP packet upon receiving it .
*
* @param buf Pointer to the packet .
* @param len Length of the packet .
* @return 0 on success , -1 on error .
* @see addDevice
*/
typedef int (*IPPacketReceiveCallback)(const void * buf, int len);

/**
* @brief Register a callback function to be called each time an IP
    packet was received .
*
* @param callback The callback function .
* @return 0 on success , -1 on error .
* @see IPPacketReceiveCallback
*/
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback) ;

/**
* @brief This is a callback function. Print simple infomation about the IP packet.
*
* @param buf Pointer to the packet header.
* @param len Length of the packet, including header.
* @return 0 on success , -1 on error .
*/
int printIPInfoCallBack(const void* buf, int len);

/**
* @brief Manully add an item to routing table . Useful when talking
    with real Linux machines .
*
* @param dest The destination IP prefix .
* @param mask The subnet mask of the destination IP prefix .
* @param nextHop IP address of the next hop .
* @param device Name of device to send packets on .
* @param dis Distance between src and dest.
* @param timeval Time stamp.
* @return 0 on success , -1 on error
*/
int setRoutingTable( const struct in_addr dest ,
    const struct in_addr mask ,
    const struct in_addr nextHop , int device,
    const int dis, const struct timeval ts);

/**
* @brief Use a routing table element and hops to update routing table.
*
* @param rte A routing table element from another host.
* @param hop The number of hops between the sender and receiver.
* @param rteip The ipv4 address of the sender.(From the ip header of the frame)
* @param dev The device name of the recevier.
* @return 0 on success , -1 on error
*/
void updateRoutingTable(struct RoutingTableElem rte, int hop, struct in_addr rteip, int dev);

/**
 * @brief  Match the destination IP address.
 *         The input cannot be broadcasting address.
 * @param  destIP Destination IP address, cannot be broadcasting address.
 * @return Pointer to a RoutingTableElem by longest prefix matching with time entry.
 *         NULL if not match. In this case, the program should throw the packet.
 */
struct RoutingTableElem* matchRoutingTable(struct in_addr destIP);

/**
 * @brief Write the routing table ID and routing table and calculate the len.
 * @param buf Pointer to the payload.
 * @return The length of the payload.
 */ 
int makeRoutingPayload(void* buf);

/**
 * @brief Initialize the routing table, by adding the host's devices.
 */
void initRoutingTable(void);

/**
 * @brief Display all routing table elements.
 * 
 */
void printRoutingTable(void);

#endif