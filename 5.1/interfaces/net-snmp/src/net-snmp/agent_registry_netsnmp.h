#ifndef AGENT_REGISTRY_H_NETSNMP
#define AGENT_REGISTRY_H_NETSNMP

#include "types_netsnmp.h"
#include "agent_handler_netsnmp.h"
#include "var_struct_netsnmp.h"


#define MIB_REGISTERED_OK         0
#define MIB_DUPLICATE_REGISTRATION    -1
#define MIB_REGISTRATION_FAILED        -2
#define MIB_UNREGISTERED_OK         0
#define MIB_NO_SUCH_REGISTRATION    -1
#define MIB_UNREGISTRATION_FAILED    -2
#define DEFAULT_MIB_PRIORITY        127

int netsnmp_get_lookup_cache_size(void);

#define SUBTREE_DEFAULT_CACHE_SIZE 8
#define SUBTREE_MAX_CACHE_SIZE     32

/*
 * REGISTER_MIB(): This macro simply loads register_mib with less pain:
 *
 * descr:   A short description of the mib group being loaded.
 * var:     The variable structure to load.
 * vartype: The variable structure used to define it (variable[2, 4, ...])
 * theoid:  An *initialized* *exact length* oid pointer.
 *          (sizeof(theoid) *must* return the number of elements!)
 */

#define REGISTER_MIB(descr, var, vartype, theoid)                       \
    register_mib(descr, (struct variable*) var, sizeof(struct vartype),\
               sizeof(var)/sizeof(struct vartype),                      \
               theoid, sizeof(theoid)/sizeof(oid))

struct view_parameters {
    netsnmp_pdu*    pdu;
    oid*            name;
    size_t          namelen;
    int             test;
    int             errorcode;        /*  Do not change unless you're
                        specifying an error, as it starts
                        in a success state.  */
    int             check_subtree;
};

struct register_parameters {
    oid*                          name;
    size_t                        namelen;
    int                           priority;
    int                           range_subid;
    oid                           range_ubound;
    int                           timeout;
    u_char                        flags;
    const char*                   contextName;
    netsnmp_session*              session;
    struct netsnmp_handler_registration_s* reginfo;
};

typedef struct subtree_context_cache_s {
    char*                context_name;
    struct netsnmp_subtree_s*        first_subtree;
    struct subtree_context_cache_s*    next;
} subtree_context_cache;

#define MIB_REGISTERED_OK         0
#define MIB_DUPLICATE_REGISTRATION    -1
#define MIB_REGISTRATION_FAILED        -2
#define MIB_UNREGISTERED_OK         0
#define MIB_NO_SUCH_REGISTRATION    -1
#define MIB_UNREGISTRATION_FAILED    -2
#define DEFAULT_MIB_PRIORITY        127

int netsnmp_get_lookup_cache_size(void);

#define SUBTREE_DEFAULT_CACHE_SIZE 8
#define SUBTREE_MAX_CACHE_SIZE     32

typedef struct lookup_cache_s {
   struct netsnmp_subtree_s* next;
   struct netsnmp_subtree_s* previous;
} lookup_cache;

typedef struct lookup_cache_context_s {
   char* context;
   struct lookup_cache_context_s* next;
   int thecachecount;
   int currentpos;
   lookup_cache cache[SUBTREE_MAX_CACHE_SIZE];
} lookup_cache_context;

int     unregister_mib_context       (unsigned long* , size_t, int, int,
                        unsigned long,
                        const char*);

int
netsnmp_register_mib(const char* moduleName,
                     struct variable* var,
                     size_t varsize,
                     size_t numvars,
                     unsigned int*  mibloc,
                     size_t mibloclen,
                     int priority,
                     int range_subid,
                     unsigned long range_ubound,
                     netsnmp_session*  ss,
                     const char* context,
                     int timeout,
                     int flags,
                     struct netsnmp_handler_registration_s* reginfo,
                     int perform_callback);

#endif /* AGENT_REGISTRY_H_NETSNMP */
