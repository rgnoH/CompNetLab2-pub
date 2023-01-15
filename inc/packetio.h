//#ifndef _PACKETIO_H_
//#define _PACKETIO_H_

#pragma once

#include "inc.h"
#include "ip.h"
#include <netinet/ether.h>

/**
* @brief Encapsulate some data into an Ethernet II frame and send it .
*
* @param buf Pointer to the payload .
* @param len Length of the payload .
* @param ethtype EtherType field value of this frame .
* @param destmac MAC address of the destination .
* @param id ID of the device ( returned by 'addDevice') to send on .
* @return 0 on success , -1 on error .
* @see addDevice
*/
int sendFrame(const void* buf, int len, int ethtype, const void* destmac, int id);

/**
* @brief Process a frame upon receiving it .
*
* @param buf Pointer to the frame .
* @param len Length of the frame .
* @param id ID of the device ( returned by ‘ addDevice ‘) receiving current frame .
* @return 0 on success , -1 on error .
* @see addDevice
*/
typedef int (*frameReceiveCallback)(const void*, int, int);

/**
* @brief Register a callback function to be called each time an Ethernet II frame was received .
*
* @param callback the callback function .
* @return 0 on success , -1 on error .
* @see frameReceiveCallback
*/
int setFrameReceiveCallback(frameReceiveCallback callback);

/**
* @brief Used in pcap_loop(). It's called each time an Ethernet II frame was received.
*        Push the packet into pktque for further processing.
* @param args 
* @param header Ethernet II frame header
* @param pkt point to the begin of the packet
* @see pcap_loop()
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);


// Here are call-back functions.

/**
* @brief This is a callback function. Print simple infomation about the packet.
*
* @param buf Pointer to the frame .
* @param len Length of the frame .
* @param id ID of the device ( returned by ‘ addDevice ‘) receiving current frame .
* @return 0 on success , -1 on error .
* @see frameReceiveCallback
*/
int printInfoCallBack(const void * buf,int len,int id);

/**
* @brief The startup function for main thread to process packets and send routing packets. 
*
*/
void* processPacket(void* param);

/**
* @brief The startup function for sub-thread to receive packets and push them to RecvdPacket. 
*
*/
void* receivePacket(void* dev_id);

//#endif