/* $Id: mdns-scan.c 56 2004-12-21 17:04:19Z lennart $ */

/***
  This file is part of mdns-scan.
 
  mdns-scan is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
 
  mdns-scan is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.
 
  You should have received a copy of the GNU General Public License
  along with mdns-scan; if not, write to the Free Software Foundation,
  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
***/

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"
#include "query.h"
#include "util.h"

#define SERVICE_RR "_services._dns-sd._udp.local"
#define HASH_TABLE_SIZE 1023

struct hash_entry {
    unsigned hash;
    char *name;
    struct hash_entry *next;
};

struct hash_entry *hash_table[HASH_TABLE_SIZE];

static unsigned hash_func(const char *c) {
    unsigned hash = 0;
    
    for (; *c; c++)
        hash = 31 * hash + *c;

    return hash;
}

static void handle_service(const char *service) {
    struct hash_entry *e;
    unsigned h, i;

    i = (h = hash_func(service)) % HASH_TABLE_SIZE;

    if (hash_table[i]) {
        for (e = hash_table[i]; e; e = e->next)
            if (e->hash == h)
                if (!strcmp(e->name, service))
                    return;
    }

    e = malloc(sizeof(struct hash_entry));
    assert(e);
    e->hash = h;
    e->name = strdup(service);
    assert(e->name);
    e->next = hash_table[i];
    hash_table[i] = e;

    fprintf(stderr, "+ %s\n", service);
}

static void free_hash_table(void) {
    unsigned i;
    struct hash_entry **e;
    
    for (i = 0, e = hash_table; i < HASH_TABLE_SIZE; i++, e++) {
        while (*e) {
            struct hash_entry *n = (*e)->next;

            free((*e)->name);
            free(*e);
            *e = n;
        }
    }
}

static int send_query(int fd, const char*name, uint16_t type) {
    int ret = -1;
    struct dns_packet *p = NULL;

    assert(fd >= 0);

    if (!(p = dns_packet_new())) {
        fprintf(stderr, "Failed to allocate DNS packet.\n");
        goto finish;
    }

    dns_packet_set_field(p, DNS_FIELD_FLAGS, DNS_FLAGS(0, 0, 0, 0, 0, 0, 0, 0, 0, 0));

    if (!dns_packet_append_name(p, name)) {
        fprintf(stderr, "Bad host name\n");
        goto finish;
    }
    
    dns_packet_append_uint16(p, type);
    dns_packet_append_uint16(p, DNS_CLASS_IN);
    dns_packet_set_field(p, DNS_FIELD_QDCOUNT, 1);
    
    if (mdns_send_dns_packet(fd, p) < 0)
        goto finish;
    
    ret = 0;
    
finish:
    if (p)
        dns_packet_free(p);

    return ret;
}

static int handle_packet(int fd, struct dns_packet *p) {
    for (;;) {
        char pname[256];
        uint16_t type, class;
        uint32_t rr_ttl;
        uint16_t rdlength;
        
        if (dns_packet_consume_name(p, pname, sizeof(pname)) < 0 ||
            dns_packet_consume_uint16(p, &type) < 0 ||
            dns_packet_consume_uint16(p, &class) < 0 ||
            dns_packet_consume_uint32(p, &rr_ttl) < 0 ||
            dns_packet_consume_uint16(p, &rdlength) < 0) {
            break;
        }
        
        /* Remove mDNS cache flush bit */
        class &= ~0x8000;
        
        if (type == DNS_TYPE_PTR &&
            class == DNS_CLASS_IN &&
            strcmp(pname, SERVICE_RR) == 0) {
            char service[256];

            if (dns_packet_consume_name(p, service, sizeof(service)) < 0)
                break;

            if (send_query(fd, service, DNS_TYPE_PTR) < 0)
                return -1;

        } else if (type == DNS_TYPE_PTR &&
            class == DNS_CLASS_IN &&
            (strstr(pname, "._tcp.") || strstr(pname, "._udp."))) {
            char service[256];
            
            if (dns_packet_consume_name(p, service, sizeof(service)) < 0)
                break;

            handle_service(service);
        } else
            if (dns_packet_consume_seek(p, rdlength) < 0)
                break;
    }

    return 0;
}

static char rotdash(void) {
    static const char *rd = "/-\\|\\-";
    static const char*c = NULL;

    if (!c || !*c)
        c = rd;
    
    return *(c++);
}

static int event_loop(int fd) {
    struct timeval tv;

    for (;;) {
 
        fprintf(stderr, "Browsing ... %c           \r", rotdash());
        
        if (send_query(fd, SERVICE_RR, DNS_TYPE_PTR) < 0)
            return -1;

        gettimeofday(&tv, NULL);
        timeval_add(&tv, 1000000);
        
        for (;;) {
            struct dns_packet *p = NULL;
            uint8_t ttl;
            int r;
            
            if ((r = mdns_recv_dns_packet(fd, &p, &ttl, &tv)) < 0)
                return -1;

            if (!p) /* Timeout */
                break;

            assert(p);

            if (ttl == 0xFF && dns_packet_check_valid_response(p) >= 0) {
                /* valid packet */
                handle_packet(fd, p);
            }

            dns_packet_free(p);
        }
    }
    
}
    

int main(int argc, char*argv[]) {
    int fd = -1;
    int ret = 1;

    memset(&hash_table, 0, sizeof(hash_table));
    
    if ((fd = mdns_open_socket()) < 0)
        goto finish;

    ret = event_loop(fd) < 0 ? 1 : 0;
    
finish:

    if (fd >= 0)
        close(fd);

    free_hash_table();
    
    return ret;
}
