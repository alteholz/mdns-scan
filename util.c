/* $Id: util.c 51 2004-12-09 23:04:16Z lennart $ */

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

#include <sys/select.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>

#include "util.h"

/* Calculate the difference between the two specfified timeval
 * timestamsps. */
usec_t timeval_diff(const struct timeval *a, const struct timeval *b) {
    usec_t r;
    assert(a && b);

    /* Check which whan is the earlier time and swap the two arguments if reuqired. */
    if (timeval_cmp(a, b) < 0) {
        const struct timeval *c;
        c = a;
        a = b;
        b = c;
    }

    /* Calculate the second difference*/
    r = ((usec_t) a->tv_sec - b->tv_sec)* 1000000;

    /* Calculate the microsecond difference */
    if (a->tv_usec > b->tv_usec)
        r += ((usec_t) a->tv_usec - b->tv_usec);
    else if (a->tv_usec < b->tv_usec)
        r -= ((usec_t) b->tv_usec - a->tv_usec);

    return r;
}

/* Compare the two timeval structs and return 0 when equal, negative when a < b, positive otherwse */
int timeval_cmp(const struct timeval *a, const struct timeval *b) {
    assert(a && b);

    if (a->tv_sec < b->tv_sec)
        return -1;

    if (a->tv_sec > b->tv_sec)
        return 1;

    if (a->tv_usec < b->tv_usec)
        return -1;

    if (a->tv_usec > b->tv_usec)
        return 1;

    return 0;
}

/* Return the time difference between now and the specified timestamp */
usec_t timeval_age(const struct timeval *tv) {
    struct timeval now;
    assert(tv);
    gettimeofday(&now, NULL);
    return timeval_diff(&now, tv);
}

/* Add the specified time inmicroseconds to the specified timeval structure */
void timeval_add(struct timeval *tv, usec_t v) {
    unsigned long secs;
    assert(tv);
    
    secs = (v/1000000);
    tv->tv_sec += (unsigned long) secs;
    v -= secs*1000000;

    tv->tv_usec += v;

    /* Normalize */
    while (tv->tv_usec >= 1000000) {
        tv->tv_sec++;
        tv->tv_usec -= 1000000;
    }
}

int set_cloexec(int fd) {
    int n;
    assert(fd >= 0);
    
    if ((n = fcntl(fd, F_GETFD)) < 0)
        return -1;

    if (n & FD_CLOEXEC)
        return 0;

    return fcntl(fd, F_SETFD, n|FD_CLOEXEC);
}

int set_nonblock(int fd) {
    int n;
    assert(fd >= 0);

    if ((n = fcntl(fd, F_GETFL)) < 0)
        return -1;

    if (n & O_NONBLOCK)
        return 0;

    return fcntl(fd, F_SETFL, n|O_NONBLOCK);
}

int wait_for_write(int fd, struct timeval *end) {
    struct timeval now;

    if (end)
        gettimeofday(&now, NULL);
    
    for (;;) {
        struct timeval tv;
        fd_set fds;
        int r;
        
        FD_ZERO(&fds);
        FD_SET(fd, &fds);

        if (end) {
            if (timeval_cmp(&now, end) >= 0)
                return 1;

            tv.tv_sec = tv.tv_usec = 0;
            timeval_add(&tv, timeval_diff(end, &now));
        }

        if ((r = select(fd+1, NULL, &fds, NULL, end ? &tv : NULL)) < 0) {
            if (errno != EINTR) {
                fprintf(stderr, "select() failed: %s\n", strerror(errno));
                return -1;
            }
        } else if (r == 0)
            return 1;
        else {
            if (FD_ISSET(fd, &fds))
                return 0;
        }

        if (end)
            gettimeofday(&now, NULL);
    }
}

int wait_for_read(int fd, struct timeval *end) {
    struct timeval now;

    if (end)
        gettimeofday(&now, NULL);

    for (;;) {
        struct timeval tv;
        fd_set fds;
        int r;
        
        FD_ZERO(&fds);
        FD_SET(fd, &fds);

        if (end) {
            if (timeval_cmp(&now, end) >= 0)
                return 1;
            
            tv.tv_sec = tv.tv_usec = 0;
            timeval_add(&tv, timeval_diff(end, &now));
        }
        
        if ((r = select(fd+1, &fds, NULL, NULL, end ? &tv : NULL)) < 0) {
            if (errno != EINTR) {
                fprintf(stderr, "select() failed: %s\n", strerror(errno));
                return -1;
            }
        } else if (r == 0) 
            return 1;
        else {
            
            if (FD_ISSET(fd, &fds))
                return 0;
        }

        if (end)
            gettimeofday(&now, NULL);
    }
}


int domain_cmp(const char *a, const char *b) {
    size_t al, bl;

    al = strlen(a);
    bl = strlen(b);

    if (al > 0 && a[al-1] == '.')
        al --;

    if (bl > 0 && b[bl-1] == '.')
        bl --;

    if (al != bl)
        return al > bl ? 1 : (al < bl ? -1 : 0);

    return strncasecmp(a, b, al);
}

char *ends_with(const char *a, const char *b) {
    size_t k, l;
    char *c;
    k = strlen(a);
    l = strlen(b);
    
    if (l > k)
        return NULL;

    c = (char*) a+k-l;
    
    if (strcmp(c, b) == 0)
        return c;

    return NULL;
}
