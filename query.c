/* $Id: query.c 56 2004-12-21 17:04:19Z lennart $ */

/***
  This file is part of mdns-scan.
 
  mdns-scan is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 2 of the
  License, or (at your option) any later version.
 
  mdns-scan is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.
 
  You should have received a copy of the GNU General Public
  License along with mdns-scan; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "dns.h"
#include "util.h"
#include "query.h"

static void mdns_mcast_group(struct sockaddr_in *ret_sa) {
    assert(ret_sa);
    
    ret_sa->sin_family = AF_INET;
    ret_sa->sin_port = htons(5353);
    ret_sa->sin_addr.s_addr = inet_addr("224.0.0.251");
}

int mdns_open_socket(void) {
    struct ip_mreqn mreq;
    struct sockaddr_in sa;
    int fd = -1, ttl, yes;

    mdns_mcast_group(&sa);
        
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        goto fail;
    }
    
    ttl = 255;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        fprintf(stderr, "IP_MULTICAST_TTL failed: %s\n", strerror(errno));
        goto fail;
    }

    yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        fprintf(stderr, "SO_REUSEADDR failed: %s\n", strerror(errno));
        goto fail;
    }

    if (bind(fd, (struct sockaddr*) &sa, sizeof(sa)) < 0) {
        fprintf(stderr, "bind() failed: %s\n", strerror(errno));
        goto fail;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr = sa.sin_addr;
    mreq.imr_address.s_addr = htonl(INADDR_ANY);
    mreq.imr_ifindex = 0;
    
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        fprintf(stderr, "IP_ADD_MEMBERSHIP failed: %s\n", strerror(errno));
        goto fail;
    }

    if (setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes)) < 0) {
        fprintf(stderr, "O_RECVTTL failed: %s\n", strerror(errno));
        goto fail;
    }
    
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes)) < 0) {
        fprintf(stderr, "IP_PKTINFO failed: %s\n", strerror(errno));
        goto fail;
    }
    
    if (set_cloexec(fd) < 0) {
        fprintf(stderr, "FD_CLOEXEC failed: %s\n", strerror(errno));
        goto fail;
    }
    
    if (set_nonblock(fd) < 0) {
        fprintf(stderr, "O_ONONBLOCK failed: %s\n", strerror(errno));
        goto fail;
    }

    return fd;

fail:
    if (fd >= 0)
        close(fd);

    return -1;
}

int mdns_send_dns_packet(int fd, struct dns_packet *p) {
    struct sockaddr_in sa;
    struct msghdr msg;
    struct iovec io;
    struct cmsghdr *cmsg;
    struct in_pktinfo *pkti;
    uint8_t cmsg_data[sizeof(struct cmsghdr) + sizeof(struct in_pktinfo)];
    int i, n;
    struct ifreq ifreq[32];
    struct ifconf ifconf;
    int n_sent = 0;

    assert(fd >= 0 && p);
    assert(dns_packet_check_valid(p) >= 0);

    mdns_mcast_group(&sa);

    memset(&io, 0, sizeof(io));
    io.iov_base = p->data;
    io.iov_len = p->size;

    memset(cmsg_data, 0, sizeof(cmsg_data));
    cmsg = (struct cmsghdr*) cmsg_data;
    cmsg->cmsg_len = sizeof(cmsg_data);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;

    pkti = (struct in_pktinfo*) (cmsg_data + sizeof(struct cmsghdr));
    pkti->ipi_ifindex = 0;
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_data;
    msg.msg_controllen = sizeof(cmsg_data);
    msg.msg_flags = 0;

    ifconf.ifc_req = ifreq;
    ifconf.ifc_len = sizeof(ifreq);
    
    if (ioctl(fd, SIOCGIFCONF, &ifconf) < 0) {
        fprintf(stderr, "SIOCGIFCONF failed: %s\n", strerror(errno));
        return -1;
    }

    for (i = 0, n = ifconf.ifc_len/sizeof(struct ifreq); i < n; i++) {
        struct sockaddr_in *sa;
        u_int32_t s_addr;

        /* Check if this is the loopback device or any other invalid interface */
        sa = (struct sockaddr_in*) &ifreq[i].ifr_addr;
        s_addr = htonl(sa->sin_addr.s_addr);
        if (sa->sin_family != AF_INET ||
            s_addr == INADDR_LOOPBACK ||
            s_addr == INADDR_ANY ||
            s_addr == INADDR_BROADCAST)
            continue;

        if (ioctl(fd, SIOCGIFFLAGS, &ifreq[i]) < 0) 
            continue;  /* Since SIOCGIFCONF and this call is not
                        * issued in a transaction, we ignore errors
                        * here, since the interface may have vanished
                        * since that call */

        /* Check whether this network interface supports multicasts and is up and running */
        if (!(ifreq[i].ifr_flags & IFF_MULTICAST) ||
            !(ifreq[i].ifr_flags & IFF_UP) ||
            !(ifreq[i].ifr_flags & IFF_RUNNING))
            continue;

        if (ioctl(fd, SIOCGIFINDEX, &ifreq[i]) < 0) 
            continue; /* See above why we ignore this error */
        
        pkti->ipi_ifindex = ifreq[i].ifr_ifindex;
        
        for (;;) {
            
            if (sendmsg(fd, &msg, MSG_DONTROUTE) >= 0)
                break;

            if (errno != EAGAIN) {
                fprintf(stderr, "sendmsg() failed: %s\n", strerror(errno));
                return -1;
            }
            
            if (wait_for_write(fd, NULL) < 0)
                return -1;
        }

        n_sent++;
    }

    return n_sent;
}
/* returns -1 on failure; 0 when ok or timeout */
int mdns_recv_dns_packet(int fd, struct dns_packet **ret_packet, uint8_t* ret_ttl, struct timeval *end) {
    struct dns_packet *p= NULL;
    struct msghdr msg;
    struct iovec io;
    int ret = -1;
    uint8_t aux[64];
    assert(fd >= 0);

    p = dns_packet_new();

    io.iov_base = p->data;
    io.iov_len = sizeof(p->data);
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = aux;
    msg.msg_controllen = sizeof(aux);
    msg.msg_flags = 0;
    
    for (;;) {
        ssize_t l;
        int r;
        
        if ((l = recvmsg(fd, &msg, 0)) >= 0) {
            struct cmsghdr *cmsg;
            *ret_ttl = 0;
            
            for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg,cmsg)) {
                if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
                    *ret_ttl = *(uint8_t *) CMSG_DATA(cmsg);
                    break;
                }
            }
                     
            if (cmsg == NULL) {
                fprintf(stderr, "Didn't recieve TTL\n");
                goto fail;
            }

            p->size = (size_t) l;

            *ret_packet = p;
            return 0;
        }

        if (errno != EAGAIN) {
            fprintf(stderr, "recvfrom() failed: %s\n", strerror(errno));
            goto fail;
        }
        
        if ((r = wait_for_read(fd, end)) < 0)
            goto fail;
        else if (r > 0) { /* timeout */
            ret = 0;
            *ret_packet = NULL;
            goto fail;
        }
    }

fail:
    if (p)
        dns_packet_free(p);

    return ret;
}

