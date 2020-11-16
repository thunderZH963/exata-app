#ifndef TOOLS_H_NETSNMP
#define TOOLS_H_NETSNMP

/**
 * @file library/tools.h
 * @defgroup util Memory Utility Routines
 * @ingroup library
 * @{
 */
#include "types_netsnmp.h"
#include "snmp_client_netsnmp.h"
#include <ctype.h>

#define SNMP_MAXBUF        (1024 * 4)
#define SNMP_MAXBUF_MEDIUM    1024
#define SNMP_MAXBUF_SMALL    512

/** @def SNMP_FREE(s)
    Frees a pointer only if it is !NULL and sets its value to NULL */
#define SNMP_FREE(s)    if (s) { free((void*)s); s=NULL; }

typedef void*   marker_t;
unsigned long uatime_hdiff(marker_t first, marker_t second);
unsigned long uatime_hdiff(marker_t first, marker_t second);

    /*
     * XXX Not optimal everywhere.
     */
/** @def SNMP_MALLOC_STRUCT(s)
    Mallocs memory of sizeof(struct s), zeros it and returns a pointer to it. */
#define SNMP_MALLOC_STRUCT(s)   (struct s*) calloc(1, sizeof(struct s))

/** @def SNMP_ZERO(s,l)
    Zeros l bytes of memory starting at s. */
#define SNMP_ZERO(s,l)    do { if (s) memset(s, 0, l); } while (0)
#define ROUNDUP8(x)        (((x+7) >> 3) * 8)
#define BYTESIZE(bitsize)       ((bitsize + 7) >> 3)

/*
 * test for NULL pointers before and NULL characters after
 * * comparing possibly non-NULL strings.
 * * WARNING: This function does NOT check for array overflow.
 */
#if WIN32
int
strncasecmp(const char* s1, const char* s2, size_t nch);
int
strcasecmp(const char* s1, const char* s2);
char*
strcasestr(const char* haystack, const char* needle);
#endif
int
memdup(unsigned char**  to, const void*  from, size_t size);

marker_t atime_newMarker(void);
int atime_ready(marker_t pm, int deltaT);
/** @def SNMP_MAX(a, b)
    Computers the maximum of a and b. */
#define SNMP_MAX(a,b) ((a) > (b) ? (a) : (b))

/** @def SNMP_MIN(a, b)
    Computers the minimum of a and b. */
#define SNMP_MIN(a,b) ((a) > (b) ? (b) : (a))

#define snmp_cstrcat(b,l,o,a,s) snmp_strcat(b,l,o,a,(const u_char*)s)

    /*
     * ISTRANSFORM
     * ASSUMES the minimum length for ttype and toid.
     */
#define USM_LENGTH_OID_TRANSFORM    10

#define ISTRANSFORM(ttype, toid)                    \
    !snmp_oid_compare(ttype, USM_LENGTH_OID_TRANSFORM,        \
        usm ## toid ## Protocol, USM_LENGTH_OID_TRANSFORM)

#define ENGINETIME_MAX    2147483647      /* ((2^31)-1) */
#define ENGINEBOOT_MAX    2147483647      /* ((2^31)-1) */


int            snprintf(char* str, size_t count, const char* fmt, ...);

int
snmp_strcat(u_char**  buf, size_t*  buf_len, size_t*  out_len,
            int allow_realloc, const u_char*  s);

int
snmp_realloc(u_char**  buf, size_t*  buf_len);


char*
netsnmp_strdup_and_null(const u_char*  from, size_t from_len);

/* preferred */
int netsnmp_hex_to_binary(u_char**  buf, size_t*  buf_len,
                          size_t*  offset, int allow_realloc,
                          const char* hex, const char* delim);
/* calls netsnmp_hex_to_binary w/delim of " " */
int snmp_hex_to_binary(u_char**  buf, size_t*  buf_len,
                       size_t*  offset, int allow_realloc,
                       const char* hex);
#define QUITFUN(e, l)            \
    if ((e) != SNMPERR_SUCCESS) {    \
        rval = SNMPERR_GENERR;    \
        goto l ;        \
    }
long atime_diff(marker_t first, marker_t second);
#endif /* TOOLS_H_NETSNMP*/
