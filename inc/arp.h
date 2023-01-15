#ifndef _ARP_H_
#define _ARP_H_

#include "inc.h"
#include <netinet/ether.h>

#define MAX_ARPTABLE_LEN 128

struct ARPTableElem{
    struct in_addr ipaddr;
    u_char macaddr[6];
}ARPTable[MAX_ARPTABLE_LEN];

struct arphdr;

struct ether_arp;

/**
 * @brief Add an element to ARPTable.
 * 
 * @param ip IPv4 address
 * @param mac mac address
 * @return 0 if success. -1 if the table is full.
 */
int setARPTable(const struct in_addr ip, const u_char* mac);

/**
 * @brief Look up the ARPTable to get the mac address.
 * 
 * @param ip IPv4 address
 * @param mac A pointer to corresponding mac address. If success, this function
 *            will fill it.
 * @return 0 if success. -1 if no such mapping.
 */
int matchARPTable(struct in_addr ip, u_char* mac);

/**
 * @brief Write the ARP request payload for a device. Should Call sendFrame() to send frame.
 * 
 * @param dev The device id assigned by addDevice().
 * @param dest The ip address in query.
 * @param buf The pointer to the payload, it will be filled after implementing this function.
 * @return The length of the payload.
 */
int makeARPRequestPayload(int dev, struct in_addr dest, u_char* buf);

/**
 * @brief Write the ARP reply payload for a device. Should Call sendFrame() to send frame.
 * 
 * @param dev The device id assigned by addDevice().
 * @param dest The ip address of the receiver.
 * @param destmac The mac address of the receiver.
 * @param buf The pointer to the payload, it will be filled after implementing this function.
 * @return The length of the payload.
 */
int makeARPReplyPayload(int dev, struct in_addr dest, u_char* destmac, u_char* buf);

/**
 * @brief Display all ARP table elements.
 * 
 */
void printARPTable(void);

#endif