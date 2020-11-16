#ifndef WINSOCK_NETSNMP_H
#define WINSOCK_NETSNMP_H

#include <types.h>
#include <external_socket.h>

#ifndef WIN32
#include <time.h>
#endif

#ifndef timerisset
#define timerisset(tvp)         ((tvp)->tv_sec || (tvp)->tv_usec)
#endif

#ifndef timercmp
#define timercmp(tvp, uvp, cmp) \
        ((tvp)->tv_sec cmp (uvp)->tv_sec || \
         (tvp)->tv_sec == (uvp)->tv_sec && (tvp)->tv_usec cmp (uvp)->tv_usec)
#endif

#ifndef timerclear
#define timerclear(tvp)         (tvp)->tv_sec = (tvp)->tv_usec = 0
#endif

/*
 * Structure used in select() call, taken from the BSD file sys/time.h.
 */
#ifndef _STRUCT_TIMEVAL
#define _STRUCT_TIMEVAL
struct timeval {
        long    tv_sec;         /* seconds */
        long    tv_usec;        /* and microseconds */
};
#endif

#endif //WINSOCK_NETSNMP_H
