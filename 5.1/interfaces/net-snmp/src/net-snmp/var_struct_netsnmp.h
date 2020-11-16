#ifndef VAR_STRUCT_H_NETSNMP
#define VAR_STRUCT_H_NETSNMP
/*
 * The subtree structure contains a subtree prefix which applies to
 * all variables in the associated variable list.
 *
 * By converting to a tree of subtree structures, entries can
 * now be subtrees of another subtree in the structure. i.e:
 * 1.2
 * 1.2.0
 */

#define UCD_REGISTRY_OID_MAX_LEN    128
#include "snmp_vars_netsnmp.h"
#include "agent_handler_netsnmp.h"
/*
 * subtree flags
 */
#define FULLY_QUALIFIED_INSTANCE    0x01
#define SUBTREE_ATTACHED            0x02

typedef struct netsnmp_subtree_s {
    unsigned int*           name_a;    /* objid prefix of registered subtree */
    unsigned char          namelen;    /* number of subid's in name above */
    unsigned int*            start_a;    /* objid of start of covered range */
    unsigned char          start_len;  /* number of subid's in start name */
    unsigned int*            end_a;    /* objid of end of covered range   */
    unsigned char          end_len;    /* number of subid's in end name */
    struct variable* variables; /* pointer to variables array */
    int             variables_len;      /* number of entries in above array */
    int             variables_width;    /* sizeof each variable entry */
    char*           label_a;    /* calling module's label */
    netsnmp_session* session;
    unsigned char          flags;
    unsigned char          priority;
    int             timeout;
    struct netsnmp_subtree_s* next;       /* List of 'sibling' subtrees */
    struct netsnmp_subtree_s* prev;       /* (doubly-linked list) */
    struct netsnmp_subtree_s* children;   /* List of 'child' subtrees */
    int             range_subid;
    unsigned int             range_ubound;
    struct netsnmp_handler_registration_s* reginfo;      /* new API */
    int             cacheid;
    int             global_cacheid;
    size_t          oid_off;
} netsnmp_subtree;

#endif /* VAR_STRUCT_H_NETSNMP */
