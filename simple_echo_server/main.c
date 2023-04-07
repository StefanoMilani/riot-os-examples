/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Example application for demonstrating the RIOT's POSIX sockets
 *
 * @author      Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * @}
 * 
 * @modified-by Stefano Milani <stefano.milani96@gmail.com>
 *
 */

#include <stdio.h>

// Useful to UDP server and send msg
#include "msg.h"
#include "udp.h"

// Useful to retrieve IP address
#include "net/ipv6/addr.h"
#include "net/gnrc.h"
#include "net/gnrc/netif.h"


#define MAIN_MSG_QUEUE_SIZE (4)
static msg_t main_msg_queue[MAIN_MSG_QUEUE_SIZE];

int main(void) {
    
    // Get the interfaces and print the addresses
    gnrc_netif_t *netif = NULL;
    while ((netif = gnrc_netif_iter(netif))) { 
        ipv6_addr_t ipv6_addrs[GNRC_NETIF_IPV6_ADDRS_NUMOF];
        int res = gnrc_netapi_get(netif->pid, NETOPT_IPV6_ADDR, 0, ipv6_addrs, sizeof(ipv6_addrs));
        
        if (res < 0) {
           continue;
        }

        for (unsigned i = 0; i < (unsigned)(res / sizeof(ipv6_addr_t)); i++) {
            char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];
            ipv6_addr_to_str(ipv6_addr, &ipv6_addrs[i], IPV6_ADDR_MAX_STR_LEN);
            printf("My address is %s\n", ipv6_addr);
        }

    }

    /* a sendto() call performs an implicit bind(), hence, a message queue is
     * required for the thread executing the shell */
    msg_init_queue(main_msg_queue, MAIN_MSG_QUEUE_SIZE);
    puts("RIOT socket example application");

    // Start UDP server on port 4444
    udp_start_server("4444");

    while(1);

    /* should be never reached */
    return 0;
}
