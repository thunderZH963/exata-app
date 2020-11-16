/*
 *  read_config.h: reads configuration files for extensible sections.
 *
 */


#ifndef READ_CONFIG_H_NETSNMP
#define READ_CONFIG_H_NETSNMP

#include "snmp_netsnmp.h"
#include "types_netsnmp.h"

#define STRINGMAX 1024

#define NORMAL_CONFIG 0
#define PREMIB_CONFIG 1
#define EITHER_CONFIG 2

    /*
     * defined types (from the SMI, RFC 1157)
     */
#ifndef ASN_IPADDRESS
#define ASN_IPADDRESS   (ASN_APPLICATION | 0)
#endif
#define ASN_COUNTER    (ASN_APPLICATION | 1)
#define ASN_GAUGE    (ASN_APPLICATION | 2)
#define ASN_UNSIGNED    (ASN_APPLICATION | 2)   /* RFC 1902 - same as GAUGE */
#ifndef ASN_TIMETICKS
#define ASN_TIMETICKS   (ASN_APPLICATION | 3)
#endif

#define ASN_NSAP    (ASN_APPLICATION | 5)   /* historic - don't use */
#define ASN_UINTEGER    (ASN_APPLICATION | 7)   /* historic - don't use */

class NetSnmpAgent;

    struct config_line {
        char*           config_token;   /* Label for each line parser
                                         * in the given file. */
        void            (NetSnmpAgent::* parse_line) (const char* , char*);
        void            (NetSnmpAgent::* free_func) (void);
        struct config_line* next;
        char            config_time;    /* {NORMAL,PREMIB,EITHER}_CONFIG */
        char*           help;
    };


        struct read_config_memory {
        char*           line;
        struct read_config_memory* next;
    };


        /*
     * Defines a set of file types and the parse and free functions
     * which process the syntax following a given token in a given file.
     */
    struct config_files {
        char*           fileHeader;     /* Label for entire file. */
        struct config_line* start;
        struct config_files* next;
    };

char*           copy_nword(char* , char* , int);

char*
skip_white(char* ptr);




        char*           read_config_read_octet_string(char* readfrom,
                                                  u_char**  str,
                                                  size_t*  len);

            int
                    read64(struct counter64*  i64, const char* str);
char*
skip_token(char* ptr);
char*
skip_not_white(char* ptr);
void
zeroU64(struct counter64*  pu64);
void
multBy10(struct counter64 u64, struct counter64*  pu64P);
void
incrByU16(struct counter64*  pu64, unsigned int u16);

char*
read_config_save_objid(char* saveto, oid*  objid, size_t len);

void
read_config_store(const char* type, const char* line);

 char*           read_config_save_octet_string(char* saveto,
                                                  u_char*  str,
                                                  size_t len);


#endif /* READ_CONFIG_H_NETSNMP */


