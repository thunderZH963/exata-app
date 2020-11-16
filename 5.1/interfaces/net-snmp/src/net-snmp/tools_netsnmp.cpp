#include "tools_netsnmp.h"
#include "node.h"
#include "netSnmpAgent.h"

# include <stdarg.h>
# define VA_LOCAL_DECL   va_list ap
# define VA_START(f)     va_start(ap, f)
# define VA_SHIFT(v,t)  ;       /* no-op for ANSI */
# define VA_END          va_end(ap)
/*
 * test for NULL pointers before and NULL characters after
 * * comparing possibly non-NULL strings.
 * * WARNING: This function does NOT check for array overflow.
 */
int
strncasecmp(const char* s1, const char* s2, size_t nch)
{
    size_t          ii;
    int             res = -1;

    if (!s1) {
        if (!s2)
            return 0;
        return (-1);
    }
    if (!s2)
        return (1);

    for (ii = 0; (ii < nch) && *s1 && *s2; ii++, s1++, s2++) {
        res = (int) (tolower(*s1) - tolower(*s2));
        if (res != 0)
            break;
    }

    if (ii == nch) {
        s1--;
        s2--;
    }

    if (!*s1) {
        if (!*s2)
            return 0;
        return (-1);
    }
    if (!*s2)
        return (1);

    return (res);
}

int
strcasecmp(const char* s1, const char* s2)
{
    return strncasecmp(s1, s2, 1000000);
}


/** Duplicates a memory block.
 *  Copies a existing memory location from a pointer to another, newly
    malloced, pointer.

 *    @param to       Pointer to allocate and copy memory to.
 *      @param from     Pointer to copy memory from.
 *      @param size     Size of the data to be copied.
 *
 *    @return SNMPERR_SUCCESS    on success, SNMPERR_GENERR on failure.
 */
int
memdup(unsigned char**  to, const void*  from, size_t size)
{
    if (to == NULL)
        return SNMPERR_GENERR;
    if (from == NULL) {
        *to = NULL;
        return SNMPERR_SUCCESS;
    }
    if ((*to = (unsigned char*) malloc(size)) == NULL)
        return SNMPERR_GENERR;
    memcpy(*to, from, size);
    return SNMPERR_SUCCESS;

}                               /* end memdup() */



/*
 * VARARGS3
 */

/*
 * only glibc2 has this.
 */
#if _WIN32
char*
strcasestr(const char* haystack, const char* needle)
{
    const char*     cp1 = haystack, *cp2 = needle;
    const char*     cx;
    int             tstch1, tstch2;

    if (cp1 && cp2 && *cp1 && *cp2)
        for (cp1 = haystack, cp2 = needle; *cp1;) {
            cx = cp1;
            cp2 = needle;
            do {
                if (!*cp2) {    /* found the needle */
                    return (char*) cx;
                }
                if (!*cp1)
                    break;

                tstch1 = toupper(*cp1);
                tstch2 = toupper(*cp2);
                if (tstch1 != tstch2)
                    break;
                cp1++;
                cp2++;
            }
            while (1);
            if (*cp1)
                cp1++;
        }
    if (cp1 && *cp1)
        return (char*) cp1;

    return NULL;
}
#endif
int
snmp_strcat(u_char**  buf, size_t*  buf_len, size_t*  out_len,
            int allow_realloc, const u_char*  s)
{
    if (buf == NULL || buf_len == NULL || out_len == NULL) {
        return 0;
    }

    if (s == NULL) {
        /*
         * Appending a NULL string always succeeds since it is a NOP.
         */
        return 1;
    }

    while ((*out_len + strlen((const char*) s) + 1) >= *buf_len) {
        if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
            return 0;
        }
    }

    strcpy((char*) (*buf + *out_len), (const char*) s);
    *out_len += strlen((char*) (*buf + *out_len));
    return 1;
}
/**
 * This function increase the size of the buffer pointed at by *buf, which is
 * initially of size *buf_len.  Contents are preserved **AT THE BOTTOM END OF
 * THE BUFFER**.  If memory can be (re-)allocated then it returns 1, else it
 * returns 0.
 *
 * @param buf  pointer to a buffer pointer
 * @param buf_len      pointer to current size of buffer in bytes
 *
 * @note
 * The current re-allocation algorithm is to increase the buffer size by
 * whichever is the greater of 256 bytes or the current buffer size, up to
 * a maximum increase of 8192 bytes.
 */
int
snmp_realloc(u_char**  buf, size_t*  buf_len)
{
    u_char*         new_buf = NULL;
    size_t          new_buf_len = 0;

    if (buf == NULL) {
        return 0;
    }

    if (*buf_len <= 255) {
        new_buf_len = *buf_len + 256;
    } else if (*buf_len > 255 && *buf_len <= 8191) {
        new_buf_len = *buf_len * 2;
    } else if (*buf_len > 8191) {
        new_buf_len = *buf_len + 8192;
    }

    if (*buf == NULL) {
        new_buf = (u_char*) malloc(new_buf_len);
    } else {
        new_buf = (u_char*) realloc(*buf, new_buf_len);
    }

    if (new_buf != NULL) {
        *buf = new_buf;
        *buf_len = new_buf_len;
        return 1;
    } else {
        return 0;
    }
}

/** copies a (possible) unterminated string of a given length into a
 *  new buffer and null terminates it as well (new buffer MAY be one
 *  byte longer to account for this */
char*
netsnmp_strdup_and_null(const u_char*  from, size_t from_len)
{
    char*         ret;

    if (from_len == 0 || from[from_len - 1] != '\0') {
        ret = (char*)malloc(from_len + 1);
        if (!ret)
            return NULL;
        ret[from_len] = '\0';
    } else {
        ret = (char*)malloc(from_len);
        if (!ret)
            return NULL;
        ret[from_len - 1] = '\0';
    }
    memcpy(ret, from, from_len);
    return ret;
}

u_long
uatime_hdiff(marker_t first, marker_t second)
{
    struct timeval* tv1, *tv2, diff;
    u_long          res;

    tv1 = (struct timeval*) first;
    tv2 = (struct timeval*) second;

    diff.tv_sec = tv2->tv_sec - tv1->tv_sec - 1;
    diff.tv_usec = tv2->tv_usec - tv1->tv_usec + 1000000;

    res = ((u_long) diff.tv_sec) * 100 + diff.tv_usec / 10000;
    return res;
}

/**
 * convert an ASCII hex string (with specified delimiters) to binary
 *
 * @param buf     address of a pointer (pointer to pointer) for the output buffer.
 *                If allow_realloc is set, the buffer may be grown via snmp_realloc
 *                to accomodate the data.
 *
 * @param buf_len pointer to a size_t containing the initial size of buf.
 *
 * @param offset On input, a pointer to a size_t indicating an offset into buf.
 *                The  binary data will be stored at this offset.
 *                On output, this pointer will have updated the offset to be
 *                the first byte after the converted data.
 *
 * @param allow_realloc If true, the buffer can be reallocated. If false, and
 *                      the buffer is not large enough to contain the string,
 *                      an error will be returned.
 *
 * @param hex     pointer to hex string to be converted. May be prefixed by
 *                "0x" or "0X".
 *
 * @param delim   point to a string of allowed delimiters between bytes.
 *                If not specified, any non-hex characters will be an error.
 *
 * @retval 1  success
 * @retval 0  error
 */
int
NetSnmpAgent::netsnmp_hex_to_binary(u_char**  buf, size_t*  buf_len, size_t*  offset,
                      int allow_realloc, const char* hex, const char* delim)
{
    int             subid = 0;
    const char*     cp = hex;

    if (buf == NULL || buf_len == NULL || offset == NULL || hex == NULL) {
        return 0;
    }

    if ((*cp == '0') && ((*(cp + 1) == 'x') || (*(cp + 1) == 'X'))) {
        cp += 2;
    }

    while (*cp != '\0') {
        if (!isxdigit((int) *cp) ||
            !isxdigit((int) *(cp+1))) {
            if ((NULL != delim) && (NULL != strchr(delim, *cp))) {
                cp++;
                continue;
            }
            return 0;
        }
        if (sscanf(cp, "%2x", &subid) == 0) {
            return 0;
        }
        /*
         * if we dont' have enough space, realloc.
         * (snmp_realloc will adjust buf_len to new size)
         */
        if ((*offset >= *buf_len) &&
            !(allow_realloc && snmp_realloc(buf, buf_len))) {
            return 0;
        }
        *(*buf + *offset) = (u_char) subid;
        (*offset)++;
        if (*++cp == '\0') {
            /*
             * Odd number of hex digits is an error.
             */
            return 0;
        } else {
            cp++;
        }
    }
    return 1;
}

/**
 * convert an ASCII hex string to binary
 *
 * @note This is a wrapper which calls netsnmp_hex_to_binary with a
 * delimiter string of " ".
 *
 * See netsnmp_hex_to_binary for parameter descriptions.
 *
 * @retval 1  success
 * @retval 0  error
 */
int
NetSnmpAgent::snmp_hex_to_binary(u_char**  buf, size_t*  buf_len, size_t*  offset,
                   int allow_realloc, char* hex)
{
    return netsnmp_hex_to_binary(buf, buf_len, offset, allow_realloc, hex, " ");
}

/**
 * set a time marker.
 */
void
atime_setMarker(marker_t pm)
{
    if (!pm)
        return;
}

/**
 * create a new time marker.
 * NOTE: Caller must free time marker when no longer needed.
 */
marker_t
atime_newMarker(void)
{
    marker_t        pm = (marker_t) calloc(1, sizeof(struct timeval));
    return pm;
}

/**
 * Returns the difference (in msec) between the two markers
 */
long
atime_diff(marker_t first, marker_t second)
{
    struct timeval* tv1, *tv2, diff;

    tv1 = (struct timeval*) first;
    tv2 = (struct timeval*) second;

    diff.tv_sec = tv2->tv_sec - tv1->tv_sec - 1;
    diff.tv_usec = tv2->tv_usec - tv1->tv_usec + 1000000;

    return (diff.tv_sec * 1000 + diff.tv_usec / 1000);
}

/**
 * Test: Has (marked time plus delta) exceeded current time (in msec) ?
 * Returns 0 if test fails or cannot be tested (no marker).
 */
int
atime_ready(marker_t pm, int deltaT)
{
    marker_t        now;
    long            diff;
    if (!pm)
        return 0;

    now = atime_newMarker();

    diff = atime_diff(pm, now);
    free(now);
    if (diff < deltaT)
        return 0;

    return 1;
}
