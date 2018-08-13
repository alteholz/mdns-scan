#ifndef fooutilhfoo
#define fooutilhfoo

/* $Id: util.h 51 2004-12-09 23:04:16Z lennart $ */

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

#include <sys/time.h>
#include <time.h>
#include <inttypes.h>

typedef uint64_t usec_t;

usec_t timeval_diff(const struct timeval *a, const struct timeval *b);
int timeval_cmp(const struct timeval *a, const struct timeval *b);
usec_t timeval_age(const struct timeval *tv);
void timeval_add(struct timeval *tv, usec_t v);

int set_nonblock(int fd);
int set_cloexec(int fd);

int wait_for_write(int fd, struct timeval *end);
int wait_for_read(int fd, struct timeval *end);

int domain_cmp(const char *a, const char *b);

/* Check whether a ends with b */
char *ends_with(const char *a, const char *b);

#endif
