#ifndef fooqueryhfoo
#define fooqueryhfoo

/* $Id: query.h 51 2004-12-09 23:04:16Z lennart $ */

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

#include <inttypes.h>

int mdns_open_socket(void);

int mdns_send_dns_packet(int fd, struct dns_packet *p);
int mdns_recv_dns_packet(int fd, struct dns_packet **ret_packet, uint8_t* ret_ttl, struct timeval *end);


#endif
