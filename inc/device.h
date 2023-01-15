// #ifndef _DEVICE_H_
// #define _DEVICE_H_
#pragma once

#include "inc.h"
#include <linux/if_packet.h>
// #include <sys/socket.h>

struct Device{
    char name[MAX_DEV_LEN];
    u_char mac[10];
    struct in_addr ipv4addr;
    struct in_addr netmask;
}rev_devs[MAX_DEV_NUM];

/**
 * @brief Add a device to the library for sending/receiving packets. 
 *        Create sub-threads to receive packets.
 * 
 * @param device Name of network device to send/receive packet on.
 * @return A non-negative _device-ID_ on success, -1 on error. 
 */
int addDevice(const char* device);

/**
* Find a device added by 'addDevice'.
*
* @param device Name of the network device .
* @return A non - negative _device - ID_ on success , -1 if no such device
* was found .
*/
int findDevice(const char* device);

/**
* Check a device id by _device-ID_.
*
* @param id _device-ID_ of the request .
* @return A pointer to the corresponding device on success , NULL if no 
* such device was found .
*/
struct Device* checkValidDevice(int id);

/**
 * @brief Display all device information.
 * 
 */
void printDeviceInfo(void);

// #endif