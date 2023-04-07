/*
*   @ingroup my_examples
*   @{
*       @file       udp.h
*       @brief      udp header file 
*       @author     Stefano Milani <stefano.milani96@gmail.com>
*   }@
*/

#ifndef UDP_H
#define UDP_H

/* needed for posix usleep */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "thread.h"


#define SERVER_MSG_QUEUE_SIZE   (8)
#define SERVER_BUFFER_SIZE      (64)

// Start server thread function
void *_server_thread(void *args);


// Sent UDP packet
int udp_send(char *addr_str, char *port_str, char *data, 
                unsigned int num, unsigned int delay);

// Start UDP server 
int udp_start_server(char *port_str);

#endif // UDP_H
