#ifndef LARGE_FD_SET_H_NETSNMP
#define LARGE_FD_SET_H_NETSNMP

#include "types_netsnmp.h"

/**
 * @file  large_fd_set.h
 *
 * @brief Macro's and functions for manipulation of large file descriptor sets.
 */


#if ! defined(cygwin) && defined(HAVE_WINSOCK_H)
/** Number of bytes needed to store setsize file descriptors. */
#define NETSNMP_FD_SET_BYTES(setsize) (sizeof(fd_set) + sizeof(SOCKET) * (setsize - FD_SETSIZE))

/** Remove all sockets from the set *fdset. */
#define NETSNMP_LARGE_FD_ZERO(fdset) \
    do { (fdset)->lfs_setptr->fd_count = 0; } while (0)
#endif

#endif /* LARGE_FD_SET_H_NETSNMP */
