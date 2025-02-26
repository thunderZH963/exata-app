/*
 * read_config.c
 */
/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright � 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

/** @defgroup read_config parsing various configuration files at run time
 *  @ingroup library
 *
 * The read_config related functions are a fairly extensible  system  of
 * parsing various configuration files at the run time.
 *
 * The idea is that the calling application is able to register
 * handlers for certain tokens specified in certain types
 * of files.  The read_configs function can then be  called
 * to  look  for all the files that it has registrations for,
 * find the first word on each line, and pass  the  remainder
 * to the appropriately registered handler.
 *
 * For persistent configuration storage you will need to use the
 * read_config_read_data, read_config_store, and read_config_store_data
 * APIs in conjunction with first registering a
 * callback so when the agent shutsdown for whatever reason data is written
 * to your configuration files.  The following explains in more detail the
 * sequence to make this happen.
 *
 * This is the callback registration API, you need to call this API with
 * the appropriate parameters in order to configure persistent storage needs.
 *
 *        int snmp_register_callback(int major, int minor,
 *                                   SNMPCallback* new_callback,
 *                                   void* arg);
 *
 * You will need to set major to SNMP_CALLBACK_LIBRARY, minor to
 * SNMP_CALLBACK_STORE_DATA. arg is whatever you want.
 *
 * Your callback function's prototype is:
 * int     (SNMPCallback) (int majorID, int minorID, void* serverarg,
 *                        void* clientarg);
 *
 * The majorID, minorID and clientarg are what you passed in the callback
 * registration above.  When the callback is called you have to essentially
 * transfer all your state from memory to disk. You do this by generating
 * configuration lines into a buffer.  The lines are of the form token
 * followed by token parameters.
 *
 * Finally storing is done using read_config_store(type, buffer);
 * type is the application name this can be obtained from:
 *
 * netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_APPTYPE);
 *
 * Now, reading back the data: This is done by registering a config handler
 * for your token using the register_config_handler function. Your
 * handler will be invoked and you can parse in the data using the
 * read_config_read APIs.
 *
 *  @{
 */
#include "netSnmpAgent.h"
#include "read_config_netsnmp.h"
#include "default_store_netsnmp.h"
#include "tools_netsnmp.h"
#include "mib_netsnmp.h"
#include <sys/stat.h>
#include "net-snmp-config_netsnmp.h"

/*
 * we allow = delimeters here
 */
#define SNMP_CONFIG_DELIMETERS " \t="

void
netsnmp_config_remember_free_list(struct read_config_memory** mem)
{
    struct read_config_memory* tmpmem;
    while (*mem) {
        SNMP_FREE((*mem)->line);
        tmpmem = (*mem)->next;
        SNMP_FREE(*mem);
        *mem = tmpmem;
    }
}

void
NetSnmpAgent::free_config(void)
{
    struct config_files* ctmp = config_files;
    struct config_line* ltmp;

    for (; ctmp != NULL; ctmp = ctmp->next)
    {
        for (ltmp = ctmp->start; ltmp != NULL; ltmp = ltmp->next)
        {
            if (ltmp->free_func)
                (this->*(ltmp->free_func)) ();
        }
    }
}



struct config_line*
 NetSnmpAgent::internal_register_config_handler(const char* type_param,
                 const char* token,
                 void (NetSnmpAgent::*parser) (const char* , char*),
                 void (NetSnmpAgent::*releaser) (void), const char* help,
                 int when)
{
    struct config_files** ctmp = &config_files;
    struct config_line**  ltmp;
    const char*           type = type_param;

    if (type == NULL || *type == '\0') {
        type = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                     NETSNMP_DS_LIB_APPTYPE);
    }

    /*
     * Handle multiple types (recursively)
     */
    if (strchr(type, ':')) {
        struct config_line* ltmp2 = NULL;
        char                buf[STRINGMAX];
        char*               cptr = buf;
        strncpy(buf, type, STRINGMAX - 1);
        buf[STRINGMAX - 1] = '\0';
        while (cptr) {
            char* c = cptr;
            cptr = strchr(cptr, ':');
            if (cptr) {
                *cptr = '\0';
                ++cptr;
            }
            ltmp2 = internal_register_config_handler(c, token, parser,
                                                     releaser, help, when);
        }
        return ltmp2;
    }

    /*
     * Find type in current list  -OR-  create a new file type.
     */
    while (*ctmp != NULL && strcmp((*ctmp)->fileHeader, type)) {
        ctmp = &((*ctmp)->next);
    }

    if (*ctmp == NULL) {
        *ctmp = (struct config_files*)
            calloc(1, sizeof(struct config_files));
        if (!*ctmp) {
            return NULL;
        }
        (*ctmp)->fileHeader = strdup(type);
    }

    /*
     * Find parser type in current list  -OR-  create a new
     * line parser entry.
     */
    ltmp = &((*ctmp)->start);

    while (*ltmp != NULL && strcmp((*ltmp)->config_token, token)) {
        ltmp = &((*ltmp)->next);
    }

    if (*ltmp == NULL) {
        *ltmp = (struct config_line*)
            calloc(1, sizeof(struct config_line));
        if (!*ltmp) {
            return NULL;
        }

        (*ltmp)->config_time = when;
        (*ltmp)->config_token = strdup(token);
        if (help != NULL)
            (*ltmp)->help = strdup(help);
    }

    /*
     * Add/Replace the parse/free functions for the given line type
     * in the given file type.
     */
    (*ltmp)->parse_line = parser;
    (*ltmp)->free_func = releaser;

    return (*ltmp);

}                               /* end register_config_handler() */
struct config_line*
 NetSnmpAgent::register_config_handler(const char* type,
            const char* token,
            void (NetSnmpAgent::* parser) (const char* , char*),
            void (NetSnmpAgent::* releaser) (void), const char* help)
{
    return internal_register_config_handler(type, token, parser, releaser,
                        help, NORMAL_CONFIG);
}



struct config_line*
    NetSnmpAgent::register_app_config_handler(const char* token,
                            void (NetSnmpAgent::*parser) (const char* , char*),
                            void (NetSnmpAgent::*releaser) (void), const char* help)
{
    return (register_config_handler(NULL, token, parser, releaser, help));
}


/*
 * copy_word
 * copies the next 'token' from 'from' into 'to', maximum len-1 characters.
 * currently a token is anything seperate by white space
 * or within quotes (double or single) (i.e. "the red rose"
 * is one token, \"the red rose\" is three tokens)
 * a '\' character will allow a quote character to be treated
 * as a regular character
 * It returns a pointer to first non-white space after the end of the token
 * being copied or to 0 if we reach the end.
 * Note: Partially copied words (greater than len) still returns a !NULL ptr
 * Note: partially copied words are, however, null terminated.
 */

char*
copy_nword(char* from, char* to, int len)
{
    char            quote;
    if (!from || !to)
        return NULL;
    if ((*from == '\"') || (*from == '\'')) {
        quote = *(from++);
        while ((*from != quote) && (*from != 0)) {
            if ((*from == '\\') && (*(from + 1) != 0)) {
                if (len > 0) {  /* don't copy beyond len bytes */
                    *to++ = *(from + 1);
                    if (--len == 0)
                        *(to - 1) = '\0';       /* null protect the last spot */
                }
                from = from + 2;
            } else {
                if (len > 0) {  /* don't copy beyond len bytes */
                    *to++ = *from++;
                    if (--len == 0)
                        *(to - 1) = '\0';       /* null protect the last spot */
                } else
                    from++;
            }
        }
        if (*from == 0) {
        } else
            from++;
    } else {
        while (*from != 0 && !isspace(*from)) {
            if ((*from == '\\') && (*(from + 1) != 0)) {
                if (len > 0) {  /* don't copy beyond len bytes */
                    *to++ = *(from + 1);
                    if (--len == 0)
                        *(to - 1) = '\0';       /* null protect the last spot */
                }
                from = from + 2;
            } else {
                if (len > 0) {  /* don't copy beyond len bytes */
                    *to++ = *from++;
                    if (--len == 0)
                        *(to - 1) = '\0';       /* null protect the last spot */
                } else
                    from++;
            }
        }
    }
    if (len > 0)
        *to = 0;
    from = skip_white(from);
    return (from);
}                               /* copy_word */



/*
 * skip all white spaces and return 1 if found something either end of
 * line or a comment character
 */
char*
skip_white(char* ptr)
{
    if (ptr == NULL)
        return (NULL);
    while (*ptr != 0 && isspace((unsigned char)*ptr))
        ptr++;
    if (*ptr == 0 || *ptr == '#')
        return (NULL);
    return (ptr);
}

struct config_line*
read_config_find_handler(struct config_line* line_handlers,
                         const char* token)
{
    struct config_line* lptr;

    for (lptr = line_handlers; lptr != NULL; lptr = lptr->next) {
        if (!strcasecmp(token, lptr->config_token)) {
            return lptr;
        }
    }
    return NULL;
}
/*
 * searches a config_line linked list for a match
 */
int
NetSnmpAgent::run_config_handler(struct config_line* lptr,
                   const char* token, char* cptr, int when)
{
    char*           cp;
    lptr = read_config_find_handler(lptr, token);
    if (lptr != NULL) {
        if (when == EITHER_CONFIG || lptr->config_time == when) {
            /*
             * Stomp on any trailing whitespace
             */
            cp = &(cptr[strlen(cptr)-1]);
            while (isspace(*cp)) {
                *(cp--) = '\0';
            }
            (this->*(lptr->parse_line)) (token, cptr);
        }
    } else if (when != PREMIB_CONFIG &&
           !netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_NO_TOKEN_WARNINGS)) {
        return SNMPERR_GENERR;
    }
    return SNMPERR_SUCCESS;
}


int
NetSnmpAgent::snmp_config_when(char* line, int when)
{
    char*           cptr, buf[STRINGMAX];
    struct config_line* lptr = NULL;
    struct config_files* ctmp = config_files;

    if (line == NULL) {
        return SNMPERR_GENERR;
    }

    strncpy(buf, line, STRINGMAX);
    buf[STRINGMAX - 1] = '\0';
    cptr = strtok(buf, SNMP_CONFIG_DELIMETERS);
    if (cptr && cptr[0] == '[') {
        if (cptr[strlen(cptr) - 1] != ']') {
            return SNMPERR_GENERR;
        }
        cptr[strlen(cptr) - 1] = '\0';
        lptr = read_config_get_handlers(cptr + 1);
        if (lptr == NULL) {
            return SNMPERR_GENERR;
        }
        cptr = strtok(NULL, SNMP_CONFIG_DELIMETERS);
        lptr = read_config_find_handler(lptr, cptr);
    } else {
        /*
         * we have to find a token
         */
        for (; ctmp != NULL && lptr == NULL; ctmp = ctmp->next)
            lptr = read_config_find_handler(ctmp->start, cptr);
    }
    if (lptr == NULL && netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                      NETSNMP_DS_LIB_NO_TOKEN_WARNINGS)) {
        return SNMPERR_GENERR;
    }

    /*
     * use the original string instead since strtok_r messed up the original
     */
    line = skip_white(line + (cptr - buf) + strlen(cptr) + 1);

    return (run_config_handler(lptr, cptr, line, when));
}

void
NetSnmpAgent::netsnmp_config_process_memory_list(struct read_config_memory** memp,
                                   int when, int clear)
{

    struct read_config_memory* mem;

    if (!memp)
        return;

    mem = *memp;

    while (mem) {
        snmp_config_when(mem->line, when);
        mem = mem->next;
    }

    if (clear)
        netsnmp_config_remember_free_list(memp);
}


void
NetSnmpAgent::netsnmp_config_process_memories_when(int when, int clear)
{
    netsnmp_config_process_memory_list(&memorylist, when, clear);
}

/*
 * read_config_read_memory():
 *
 * similar to read_config_read_data, but expects a generic memory
 * pointer rather than a specific type of pointer.  Len is expected to
 * be the amount of available memory.
 */
char*
NetSnmpAgent::read_config_read_memory(int type, char* readfrom,
                        char* dataptr, size_t*  len)
{
    int*            intp;
    unsigned int*   uintp;
    char            buf[SPRINT_MAX_LEN];

    if (!dataptr || !readfrom)
        return NULL;

    switch (type) {
    case ASN_INTEGER:
        if (*len < sizeof(int))
            return NULL;
        intp = (int*) dataptr;
        readfrom = copy_nword(readfrom, buf, sizeof(buf));
        *intp = atoi(buf);
        *len = sizeof(int);
        return readfrom;

    case ASN_COUNTER:
    case ASN_TIMETICKS:
    case ASN_UNSIGNED:
        if (*len < sizeof(unsigned int))
            return NULL;
        uintp = (unsigned int*) dataptr;
        readfrom = copy_nword(readfrom, buf, sizeof(buf));
        *uintp = strtoul(buf, NULL, 0);
        *len = sizeof(unsigned int);
        return readfrom;

    case ASN_IPADDRESS:
        if (*len < sizeof(int))
            return NULL;
        intp = (int*) dataptr;
        readfrom = copy_nword(readfrom, buf, sizeof(buf));
        if ((*intp == -1) && (strcmp(buf, "255.255.255.255") != 0))
            return NULL;
        *len = sizeof(int);
        return readfrom;

    case ASN_OCTET_STR:
    case ASN_BIT_STR:
    case ASN_PRIV_IMPLIED_OCTET_STR:
        return read_config_read_octet_string(readfrom,
                                             (u_char**) & dataptr, len);

    case ASN_PRIV_IMPLIED_OBJECT_ID:
    case ASN_OBJECT_ID:
        readfrom =
            read_config_read_objid(readfrom, (oid**) & dataptr, len);
        *len *= sizeof(oid);
        return readfrom;

    case ASN_COUNTER64:
        if (*len < sizeof(struct counter64))
            return NULL;
        *len = sizeof(struct counter64);
        read64((struct counter64*) dataptr, readfrom);
        readfrom = skip_token(readfrom);
        return readfrom;
    }

    return NULL;
}


/*
 * read_config_read_octet_string(): reads an octet string that was
 * saved by the read_config_save_octet_string() function
 */
char*
read_config_read_octet_string(char* readfrom, u_char**  str, size_t*  len)
{
    u_char*         cptr = NULL;
    char*           cptr1;
    u_int           tmp;
    int             i;
    size_t          ilen;

    if (readfrom == NULL || str == NULL)
        return NULL;

    if (strncasecmp(readfrom, "0x", 2) == 0) {
        /*
         * A hex string submitted. How long?
         */
        readfrom += 2;
        cptr1 = skip_not_white(readfrom);
        if (cptr1)
            ilen = (cptr1 - readfrom);
        else
            ilen = strlen(readfrom);

        if (ilen % 2) {
            return NULL;
        }
        ilen = ilen / 2;

        /*
         * malloc data space if needed (+1 for good measure)
         */
        if (*str == NULL) {
            if ((cptr = (u_char*) malloc(ilen + 1)) == NULL) {
                return NULL;
            }
            *str = cptr;
        } else {
            /*
             * don't require caller to have +1 for good measure, and
             * bail if not enough space.
             */
            if (ilen > *len) {
                cptr1 = skip_not_white(readfrom);
                return skip_white(cptr1);
            }
            cptr = *str;
        }
        *len = ilen;

        /*
         * copy validated data
         */
        for (i = 0; i < (int) *len; i++) {
            if (1 == sscanf(readfrom, "%2x", &tmp))
                *cptr++ = (u_char) tmp;
            else {
                /*
                 * we may lose memory, but don't know caller's buffer XX free(cptr);
                 */
                return (NULL);
            }
            readfrom += 2;
        }
        /*
         * only null terminate if we have the space
         */
        if (ilen > *len) {
            ilen = *len-1;
            *cptr++ = '\0';
        }
        readfrom = skip_white(readfrom);
    } else {
        /*
         * Normal string
         */

        /*
         * malloc string space if needed (including NULL terminator)
         */
        if (*str == NULL) {
            char            buf[SNMP_MAXBUF];
            readfrom = copy_nword(readfrom, buf, sizeof(buf));

            *len = strlen(buf);
            if ((cptr = (u_char*) malloc(*len + 1)) == NULL)
                return NULL;
            *str = cptr;
            if (cptr) {
                memcpy(cptr, buf, *len + 1);
            }
        } else {
            readfrom = copy_nword(readfrom, (char*) *str, *len);
            *len = strlen((char*) *str);
        }
    }

    return readfrom;
}

/*
 * read_config_read_objid(): reads an objid from a format saved by the above
 */
char*
NetSnmpAgent::read_config_read_objid(char* readfrom, oid**  objid, size_t*  len)
{

    if (objid == NULL || readfrom == NULL || len == NULL)
        return NULL;

    if (*objid == NULL) {
        *len = 0;
        if ((*objid = (oid*) malloc(MAX_OID_LEN * sizeof(oid))) == NULL)
            return NULL;
        *len = MAX_OID_LEN;
    }

    if (strncmp(readfrom, "NULL", 4) == 0) {
        /*
         * null length oid
         */
        *len = 0;
    } else {
        /*
         * qualify the string for read_objid
         */
        char            buf[SPRINT_MAX_LEN];
        copy_nword(readfrom, buf, sizeof(buf));

        if (!read_objid(buf, *objid, len)) {
            *len = 0;
            return NULL;
        }
    }

    readfrom = skip_token(readfrom);
    return readfrom;
}

int
read64(struct counter64*  i64, const char* str)
{
    struct counter64             i64p;
    unsigned int    u;
    int             sign = 0;
    int             ok = 0;

    zeroU64(i64);
    if (*str == '-') {
        sign = 1;
        str++;
    }

    while (*str && isdigit(*str)) {
        ok = 1;
        u = *str - '0';
        multBy10(*i64, &i64p);
        memcpy(i64, &i64p, sizeof(i64p));
        incrByU16(i64, u);
        str++;
    }
    if (sign) {
        i64->high = ~i64->high;
        i64->low = ~i64->low;
        incrByU16(i64, 1);
    }
    return ok;
}

char*
skip_token(char* ptr)
{
    ptr = skip_white(ptr);
    ptr = skip_not_white(ptr);
    ptr = skip_white(ptr);
    return (ptr);
}
char*
skip_not_white(char* ptr)
{
    if (ptr == NULL)
        return (NULL);
    while (*ptr != 0 && !isspace((unsigned char)*ptr))
        ptr++;
    if (*ptr == 0 || *ptr == '#')
        return (NULL);
    return (ptr);
}

void
zeroU64(struct counter64*  pu64)
{
    pu64->low = 0;
    pu64->high = 0;
}                               /* zeroU64 */

/** multBy10 - multiply an unsigned 64-bit integer by 10
*
* call with:
*   u64 - number to be multiplied
*   pu64P - location to store product
*
*/
void
multBy10(struct counter64 u64, struct counter64*  pu64P)
{
    unsigned long   ulT;
    unsigned long   ulP;
    unsigned long   ulK;


    /*
     * lower 16 bits
     */
    ulT = u64.low & 0x0ffff;
    ulP = ulT * 10;
    ulK = ulP >> 16;
    pu64P->low = ulP & 0x0ffff;

    /*
     * next 16
     */
    ulT = (u64.low >> 16) & 0x0ffff;
    ulP = (ulT * 10) + ulK;
    ulK = ulP >> 16;
    pu64P->low = (ulP & 0x0ffff) << 16 | pu64P->low;

    /*
     * next 16 bits
     */
    ulT = u64.high & 0x0ffff;
    ulP = (ulT * 10) + ulK;
    ulK = ulP >> 16;
    pu64P->high = ulP & 0x0ffff;

    /*
     * final 16
     */
    ulT = (u64.high >> 16) & 0x0ffff;
    ulP = (ulT * 10) + ulK;
    ulK = ulP >> 16;
    pu64P->high = (ulP & 0x0ffff) << 16 | pu64P->high;


}                               /* multBy10 */


/** incrByU16 - add an unsigned 16-bit int to an unsigned 64-bit integer
*
* call with:
*   pu64 - number to be incremented
*   u16 - amount to add
*
*/
void
incrByU16(struct counter64*  pu64, unsigned int u16)
{
    unsigned long   ulT1;
    unsigned long   ulT2;
    unsigned long   ulR;
    unsigned long   ulK;


    /*
     * lower 16 bits
     */
    ulT1 = pu64->low;
    ulT2 = ulT1 & 0x0ffff;
    ulR = ulT2 + u16;
    ulK = ulR >> 16;
    if (ulK == 0) {
        pu64->low = ulT1 + u16;
        return;
    }

    /*
     * next 16 bits
     */
    ulT2 = (ulT1 >> 16) & 0x0ffff;
    ulR = ulT2 + 1;
    ulK = ulR >> 16;
    if (ulK == 0) {
        pu64->low = ulT1 + u16;
        return;
    }

    /*
     * next 32 - ignore any overflow
     */
    pu64->low = (ulT1 + u16) & 0x0FFFFFFFFL;
    pu64->high++;
#if SIZEOF_LONG != 4
    pu64->high &= 0xffffffff;
#endif
}                               /* incrByV16 */

/*
 * read_config_save_objid(): saves an objid as a numerical string
 */
char*
read_config_save_objid(char* saveto, oid*  objid, size_t len)
{
    int             i;

    if (len == 0) {
        strcat(saveto, "NULL");
        saveto += strlen(saveto);
        return saveto;
    }

    /*
     * in case len=0, this makes it easier to read it back in
     */
    for (i = 0; i < (int) len; i++) {
        sprintf(saveto, ".%d", objid[i]);
        saveto += strlen(saveto);
    }
    return saveto;
}

/**
 * read_config_store intended for use by applications to store permenant
 * configuration information generated by sets or persistent counters.
 * Appends line to a file named either ENV(SNMP_PERSISTENT_FILE) or
 *   "<NETSNMP_PERSISTENT_DIRECTORY>/<type>.conf".
 * Adds a trailing newline to the stored file if necessary.
 *
 * @param type is the application name
 * @param line is the configuration line written to the application name's
 * configuration file
 *
 * @return void
  */
void
read_config_store(const char* type, const char* line)
{
#ifdef NETSNMP_PERSISTENT_DIRECTORY
    char            file[512], *filep;
    FILE*           fout;
#ifdef NETSNMP_PERSISTENT_MASK
    mode_t          oldmask;
#endif

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_DONT_PERSIST_STATE)
     || netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD)) return;

    /*
     * store configuration directives in the following order of preference:
     * 1. ENV variable SNMP_PERSISTENT_FILE
     * 2. configured <NETSNMP_PERSISTENT_DIRECTORY>/<type>.conf
     */
    if ((filep = netsnmp_getenv("SNMP_PERSISTENT_FILE")) == NULL) {
        snprintf(file, sizeof(file),
                 "%s/%s.conf", get_persistent_directory(), type);
        file[ sizeof(file)-1 ] = 0;
        filep = file;
    }
#ifdef NETSNMP_PERSISTENT_MASK
    oldmask = umask(NETSNMP_PERSISTENT_MASK);
#endif
    if (mkdirhier(filep, NETSNMP_AGENT_DIRECTORY_MODE, 1)) {
        snmp_log(LOG_ERR,
                 "Failed to create the persistent directory for %s\n",
                 file);
    }
    if ((fout = fopen(filep, "a")) != NULL) {
        fprintf(fout, "%s", line);
        if (line[strlen(line)] != '\n')
            fprintf(fout, "\n");
        DEBUGMSGTL(("read_config", "storing: %s\n", line));
        fclose(fout);
    } else {
        snmp_log(LOG_ERR, "read_config_store open failure on %s\n", filep);
    }
#ifdef NETSNMP_PERSISTENT_MASK
    umask(oldmask);
#endif

#endif
}                               /* end read_config_store() */

struct config_line*
NetSnmpAgent::read_config_get_handlers(const char* type)
{
    struct config_files* ctmp = config_files;
    for (; ctmp != NULL && strcmp(ctmp->fileHeader, type);
         ctmp = ctmp->next);
    if (ctmp)
        return ctmp->start;
    return NULL;
}

void
NetSnmpAgent::read_config_with_type_when(const char* filename, const char* type, int when)
{
    struct config_line* ctmp = read_config_get_handlers(type);
    if (ctmp)
        read_config(filename, ctmp, when);
}



void
NetSnmpAgent::read_configs_optional(const char* optional_config, int when)
{
    char* newp, *cp;
    char* type = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_APPTYPE);

    if ((NULL == optional_config) || (NULL == type))
        return;

    newp = strdup(optional_config);      /* strtok_r messes it up */
    cp = strtok(newp, ",");
    while (cp) {
        struct stat     statbuf;
        if (stat(cp, &statbuf)) {
        } else {
            read_config_with_type_when(cp, type, when);
        }
        cp = strtok(NULL, ",");
    }
    free(newp);

}


void
NetSnmpAgent::read_app_config_store(const char* line)
{
    read_config_store(netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                        NETSNMP_DS_LIB_APPTYPE), line);
}


void
NetSnmpAgent::read_premib_configs(void)
{
    char* optional_config = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_OPTIONALCONFIG);

    snmp_call_callbacks(SNMP_CALLBACK_LIBRARY,
                        SNMP_CALLBACK_PRE_PREMIB_READ_CONFIG, NULL);

    if ((NULL != optional_config) && (*optional_config == '-')) {
        read_configs_optional(++optional_config, PREMIB_CONFIG);
        optional_config = NULL; /* clear, so we don't read them twice */
    }

    read_config_files(PREMIB_CONFIG);

    if (NULL != optional_config)
        read_configs_optional(optional_config, PREMIB_CONFIG);

    netsnmp_config_process_memories_when(PREMIB_CONFIG, 0);

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
               NETSNMP_DS_LIB_HAVE_READ_PREMIB_CONFIG, 1);
    snmp_call_callbacks(SNMP_CALLBACK_LIBRARY,
                        SNMP_CALLBACK_POST_PREMIB_READ_CONFIG, NULL);
}


void
NetSnmpAgent::read_configs(void)
{
    char* optional_config = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_OPTIONALCONFIG);

    snmp_call_callbacks(SNMP_CALLBACK_LIBRARY,
                        SNMP_CALLBACK_PRE_READ_CONFIG, NULL);

    if ((NULL != optional_config) && (*optional_config == '-')) {
        read_configs_optional(++optional_config, NORMAL_CONFIG);
        optional_config = NULL; /* clear, so we don't read them twice */
    }

    read_config_files(NORMAL_CONFIG);

    /*
     * do this even when the normal above wasn't done
     */
    if (NULL != optional_config)
        read_configs_optional(optional_config, NORMAL_CONFIG);

    netsnmp_config_process_memories_when(NORMAL_CONFIG, 1);

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
               NETSNMP_DS_LIB_HAVE_READ_CONFIG, 1);
    snmp_call_callbacks(SNMP_CALLBACK_LIBRARY,
                        SNMP_CALLBACK_POST_READ_CONFIG, NULL);
}

/*******************************************************************-o-******
 * read_config
 *
 * Parameters:
 *    *filename
 *    *line_handler
 *     when
 *
 * Read <filename> and process each line in accordance with the list of
 * <line_handler> functions.
 *
 *
 * For each line in <filename>, search the list of <line_handler>'s
 * for an entry that matches the first token on the line.  This comparison is
 * case insensitive.
 *
 * For each match, check that <when> is the designated time for the
 * <line_handler> function to be executed before processing the line.
 */
void
NetSnmpAgent::read_config(const char* filename,
            struct config_line* line_handler, int when)
{

    FILE*           ifile;
    char            line[STRINGMAX], token[STRINGMAX];
    char*           cptr;
    int             i;
    struct config_line* lptr;

    linecount = 0;
    curfilename = (char*)filename;

    if ((ifile = fopen(filename, "r")) == NULL) {
        return;
    }

    while (fgets(line, sizeof(line), ifile) != NULL) {
        lptr = line_handler;
        linecount++;
        cptr = line;
        i = strlen(line) - 1;
        if (line[i] == '\n')
            line[i] = 0;
        /*
         * check blank line or # comment
         */
        if ((cptr = skip_white(cptr))) {
            cptr = copy_nword(cptr, token, sizeof(token));
            if (token[0] == '[') {
                if (token[strlen(token) - 1] != ']') {
                    continue;
                }
                token[strlen(token) - 1] = '\0';
                lptr = read_config_get_handlers(&token[1]);
                if (lptr == NULL) {
                    continue;
                }
                if (cptr == NULL) {
                    /*
                     * change context permanently
                     */
                    line_handler = lptr;
                    continue;
                } else {
                    /*
                     * the rest of this line only applies.
                     */
                    cptr = copy_nword(cptr, token, sizeof(token));
                }
            } else {
                lptr = line_handler;
            }
            if (cptr == NULL) {
            } else {
                run_config_handler(lptr, token, cptr, when);
            }
        }
    }

    fclose(ifile);
    return;

}                               /* end read_config() */


static
void getFileNameFromFilePath(char* filePath, char* fileName)
{
    int i = 0, j = 0;
    char tempFileName[300];
    for (i = (strlen(filePath) - 1) ; i >= 0; i--)
    {
        if (filePath[i] == '\\' || filePath[i] == '/')
            break;
        else
        {
            tempFileName[j++] = filePath[i];
        }

    }
    tempFileName[j] = '\0';
    j = 0;
    for (i = (strlen(tempFileName) - 1); i >= 0 ; i--)
    {
        if (tempFileName[i] == '.')
            break;
        fileName[j++] = tempFileName[i];
    }
    fileName[j] = '\0';


}

void
NetSnmpAgent::read_config_files_in_path(const char* path, struct config_files* ctmp,
                          int when, const char* perspath, const char* persfile)
{
    int             done;
    char            configfile[300];
    char            fileName[100];
    char*           cptr1, *cptr2, *envconfpath;
    struct stat     statbuf;
    getFileNameFromFilePath(this->node->snmpdConfigFilePath , fileName);
    if (strlen(fileName) == 0)
    {
        printQualNetError(this->node,
            (char*)"Incorrect configuration of snmpd conf file");
    }
    if ((NULL == path) || (NULL == ctmp))
        return;

    envconfpath = strdup(path);

    cptr1 = cptr2 = envconfpath;
    done = 0;
    while ((!done) && (*cptr2 != 0)) {
        while (*cptr1 != 0 && *cptr1 != ENV_SEPARATOR_CHAR)
            cptr1++;
        if (*cptr1 == 0)
            done = 1;
        else
            *cptr1 = 0;

        if (stat(cptr2, &statbuf) != 0) {
            /*
             * Directory not there, continue
             */
            cptr2 = ++cptr1;
            continue;
        }

        if (ctmp->fileHeader)
          SNMP_FREE(ctmp->fileHeader);
        ctmp->fileHeader = (char*)malloc(strlen(fileName)+1);
        strcpy(ctmp->fileHeader, fileName);
        snprintf(configfile, sizeof(configfile),
                 "%s/%s.conf", cptr2, ctmp->fileHeader);
        configfile[ sizeof(configfile)-1 ] = 0;
        read_config(configfile, ctmp->start, when);

        if (done)
            break;

        cptr2 = ++cptr1;
    }
    SNMP_FREE(envconfpath);
}

            /*******************************************************************-o-******
 * read_config_files
 *
 * Parameters:
 *    when    == PREMIB_CONFIG, NORMAL_CONFIG  -or-  EITHER_CONFIG
 *
 *
 * Traverse the list of config file types, performing the following actions
 * for each --
 *
 * First, build a search path for config files.  If the contents of
 * environment variable SNMPCONFPATH are NULL, then use the following
 * path list (where the last entry exists only if HOME is non-null):
 *
 *    SNMPSHAREPATH:SNMPLIBPATH:${HOME}/.snmp
 *
 * Then, In each of these directories, read config files by the name of:
 *
 *    <dir>/<fileHeader>.conf        -AND-
 *    <dir>/<fileHeader>.local.conf
 *
 * where <fileHeader> is taken from the config file type structure.
 *
 *
 * PREMIB_CONFIG causes free_config() to be invoked prior to any other action.
 *
 *
 * EXITs if any 'config_errors' are logged while parsing config file lines.
 */
void
NetSnmpAgent::read_config_files(int when)
{
    const char*     confpath, *perspath, *persfile, *envconfpath;
    struct config_files* ctmp = config_files;

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_DONT_PERSIST_STATE)
     || netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_DISABLE_CONFIG_LOAD)) return;

    perspath=NULL;
    config_errors = 0;

    if (when == PREMIB_CONFIG)
        free_config();

    /*
     * these shouldn't change
     */
    confpath = get_configuration_directory();
    /* QualNet chnaging such that it do not read ENV variable */
    persfile = NULL;
    envconfpath = NULL;

    /*
     * read all config file types
     */
    if (envconfpath == NULL) {
        /*
         * read just the config files (no persistent stuff), since
         * persistent path can change via conf file. Then get the
         * current persistent directory, and read files there.
         */
        read_config_files_in_path(confpath, ctmp, when, perspath,
                                  persfile);
    }
    else {
        /*
         * only read path specified by user
         */
        read_config_files_in_path(envconfpath, ctmp, when, perspath,
                                  persfile);
    }

    if (config_errors) {
       /* snmp_log(LOG_ERR, "net-snmp: %d error(s) in config file(s)\n",
                 config_errors);*/
    }
}


static
void getDirectoryFromFilePath(char* filePath, char* directory)
{
    int i = 0, j = 0;
    for (i = (strlen(filePath) - 1) ; i >= 0; i--)
    {
        if (filePath[i] == '\\' || filePath[i] == '/')
            break;
    }
    for (j = 0 ; j < i ; j++)//if (i != 0)
    {
        directory[j] = filePath[j];
    }
    directory[j] = '\0';
}


/*******************************************************************-o-******
 * get_configuration_directory
 *
 * Parameters: -
 * Retrieve the configuration directory or directories.
 * (For backwards compatibility that is:
 *       SNMPCONFPATH, SNMPSHAREPATH, SNMPLIBPATH, HOME/.snmp
 * First check whether the value is set.
 * If not set give it the default value.
 * Return the value.
 * We always retrieve it new, since we have to do it anyway if it is just set.
 */
const char*
NetSnmpAgent::get_configuration_directory(void)
{
    char            defaultPath[SPRINT_MAX_LEN];


    if (NULL == netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                      NETSNMP_DS_LIB_CONFIGURATION_DIR)) {
        defaultPath[ sizeof(defaultPath)-1 ] = 0;
        getDirectoryFromFilePath(this->node->snmpdConfigFilePath ,
                                 defaultPath);
        if (strlen(defaultPath) == 0)
        {
             printQualNetError(this->node,
            (char*)"Incorrect configuration of snmpd conf file");
        }
        set_configuration_directory(defaultPath);
    }
    return (netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                  NETSNMP_DS_LIB_CONFIGURATION_DIR));
}

/*******************************************************************-o-******
 * set_configuration_directory
 *
 * Parameters:
 *      char *dir - value of the directory
 * Sets the configuration directory. Multiple directories can be
 * specified, but need to be seperated by 'ENV_SEPARATOR_CHAR'.
 */
void
NetSnmpAgent::set_configuration_directory(const char* dir)
{
    netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID,
              NETSNMP_DS_LIB_CONFIGURATION_DIR, dir);
}


struct config_line*
NetSnmpAgent::register_prenetsnmp_mib_handler(const char* type,
                                const char* token,
                                void (NetSnmpAgent::*parser) (const char* , char*),
                                void (NetSnmpAgent::*releaser) (void), const char* help)
{
    return internal_register_config_handler(type, token, parser, releaser,
                        help, PREMIB_CONFIG);
}


/*
 * read_config_save_octet_string(): saves an octet string as a length
 * followed by a string of hex
 */
char*
read_config_save_octet_string(char* saveto, u_char*  str, size_t len)
{
    int             i;
    u_char*         cp;

    /*
     * is everything easily printable
     */
    for (i = 0, cp = str; i < (int) len && cp &&
         (isalpha(*cp) || isdigit(*cp) || *cp == ' '); cp++, i++);

    if (len != 0 && i == (int) len) {
        *saveto++ = '"';
        memcpy(saveto, str, len);
        saveto += len;
        *saveto++ = '"';
        *saveto = '\0';
    } else {
        if (str != NULL) {
            sprintf(saveto, "0x");
            saveto += 2;
            for (i = 0; i < (int) len; i++) {
                sprintf(saveto, "%02x", str[i]);
                saveto = saveto + 2;
            }
        } else {
            sprintf(saveto, "\"\"");
            saveto += 2;
        }
    }
    return saveto;
}




/**
 * uregister_config_handler un-registers handlers given a specific type_param
 * and token.
 *
 * @param type_param the configuration file used where the token is located.
 *                   Used to lookup the config file entry
 *
 * @param token      the token that is being unregistered
 *
 * @return void
 */
void
NetSnmpAgent::unregister_config_handler(const char* type_param, const char* token)
{
    struct config_files** ctmp = &config_files;
    struct config_line**  ltmp;
    const char*           type = type_param;

    if (type == NULL || *type == '\0') {
        type = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                     NETSNMP_DS_LIB_APPTYPE);
    }

    /*
     * Handle multiple types (recursively)
     */
    if (strchr(type, ':')) {
        char                buf[STRINGMAX];
        char*               cptr = buf;
        strncpy(buf, type, STRINGMAX - 1);
        buf[STRINGMAX - 1] = '\0';
        while (cptr) {
            char* c = cptr;
            cptr = strchr(cptr, ':');
            if (cptr) {
                *cptr = '\0';
                ++cptr;
            }
            unregister_config_handler(c, token);
        }
        return;
    }

    /*
     * find type in current list
     */
    while (*ctmp != NULL && strcmp((*ctmp)->fileHeader, type)) {
        ctmp = &((*ctmp)->next);
    }

    if (*ctmp == NULL) {
        /*
         * Not found, return.
         */
        return;
    }

    ltmp = &((*ctmp)->start);
    if (*ltmp == NULL) {
        /*
         * Not found, return.
         */
        return;
    }
    if (strcmp((*ltmp)->config_token, token) == 0) {
        /*
         * found it at the top of the list
         */
        struct config_line* ltmp2 = (*ltmp)->next;
        SNMP_FREE((*ltmp)->config_token);
        SNMP_FREE((*ltmp)->help);
        SNMP_FREE(*ltmp);
        (*ctmp)->start = ltmp2;
        return;
    }
    while ((*ltmp)->next != NULL
           && strcmp((*ltmp)->next->config_token, token)) {
        ltmp = &((*ltmp)->next);
    }
    if ((*ltmp)->next != NULL) {
        struct config_line* ltmp2 = (*ltmp)->next->next;
        SNMP_FREE((*ltmp)->next->config_token);
        SNMP_FREE((*ltmp)->next->help);
        SNMP_FREE((*ltmp)->next);
        (*ltmp)->next = ltmp2;
    }
}

void
NetSnmpAgent::unregister_all_config_handlers(void)
{
    struct config_files* ctmp, *save;
    struct config_line* ltmp;

    free_config();

    /*
     * Keep using config_files until there are no more!
     */
    for (ctmp = config_files; ctmp;) {
        for (ltmp = ctmp->start; ltmp; ltmp = ctmp->start) {
            unregister_config_handler(ctmp->fileHeader,
                                      ltmp->config_token);
        }
        SNMP_FREE(ctmp->fileHeader);
        save = ctmp->next;
        SNMP_FREE(ctmp);
        ctmp = save;
        config_files = save;
    }
}
