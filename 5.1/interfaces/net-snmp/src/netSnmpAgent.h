// Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.
//                          600 Corporate Pointe
//                          Suite 1200
//                          Culver City, CA 90230
//                          info@scalable-networks.com
//
// This source code is licensed, not sold, and is subject to a written
// license agreement.  Among other things, no portion of this source
// code may be copied, transmitted, disclosed, displayed, distributed,
// translated, used as the basis for a derivative work, or used, in
// whole or in part, for any program or purpose other than its intended
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

#ifndef NETSNMPAGENT_H
#define NETSNMPAGENT_H

#include "api.h"
#include "node.h"
#include "types_netsnmp.h"
#include "agent_handler_netsnmp.h"
#include "snmp_vars_netsnmp.h"
#include "agent_registry_netsnmp.h"
#include "var_struct_netsnmp.h"
#include "callback_netsnmp.h"
#include "default_store_netsnmp.h"
#include "read_config_netsnmp.h"
#include "app_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "agent_trap_netsnmp.h"
#include "snmp_enum_netsnmp.h"
#include "parse_netsnmp.h"
#include "table_dataset_netsnmp.h"
#include "snmp_transport_netsnmp.h"
#include "mib_modules_netsnmp.h"
#include "system_mib_netsnmp.h"
#include "watcher_netsnmp.h"
#include "containers_netsnmp.h"
#include "snmp_alarm_netsnmp.h"
#include "snmp_secmod_netsnmp.h"
#include "snmpusm_netsnmp.h"
#include "lcd_time_netsnmp.h"
#include "snmpCallbackDomain_netsnmp.h"
#include "cache_handler_netsnmp.h"
#include "table_iterator_netsnmp.h"
#include "random.h"

#define MASTER_AGENT 0
#define SUB_AGENT    1
#define MAX_ARGS 128
#define SPRINT_MAX_LEN  2560
#define SNMP_MAX_MSG_LENGTH 1500
#define SNMP_MALLOC_TYPEDEF(td)  (td*) calloc(1, sizeof(td))
#define MAX_COMMUNITY_LENGTH 128
#define SNMP_PDU_V1TRAP             (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x4)

#ifndef SNMP_MSG_INFORM
#define SNMP_MSG_INFORM (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x6)
#endif

#ifdef NETSNMP_INTERFACE
#define SNMP_IPADDRESS   (ASN_APPLICATION | 0)
#define SNMP_COUNTER     (ASN_APPLICATION | 1)
#define SNMP_GAUGE       (ASN_APPLICATION | 2)
#define SNMP_UINTEGER    (ASN_APPLICATION | 2)
#define SNMP_TIMETICKS   (ASN_APPLICATION | 3)
#define SNMP_OPAQUE      (ASN_APPLICATION | 4)
#define SNMP_NSAP        (ASN_APPLICATION | 5)
#define SNMP_COUNTER64   (ASN_APPLICATION | 6)
#define NO_MIBINSTANCE NULL
#define INDEX   2
#ifndef ACCESS_PARA
#define ACCESS_PARA
#define RONLY       4   /* variable has only read access    */
#define RWRITE      8   /* variable has write access    */
#define NOACCESS    16  /* variable is not accessible   */
#endif
#define ACCESS      28  /* Variable its access      */
#define OLDSTUB     32  /* Variable is implemented with old stub api */

/* MIB object ipForwarding = ip, 1 */
#define I_ipForwarding  1
#define O_ipForwarding  1, 3, 6, 1, 2, 1, 4, 1

/* MIB object ipDefaultTTL = ip, 2 */
#define I_ipDefaultTTL  2
#define O_ipDefaultTTL  1, 3, 6, 1, 2, 1, 4, 2

/* MIB object ipInReceives = ip, 3 */
#define I_ipInReceives  3
#define O_ipInReceives  1, 3, 6, 1, 2, 1, 4, 3

/* MIB object ipOutDatagrams = ip, 4 */
#define I_ipInHdrErrors 4
#define O_InHdrErrors   1, 3, 6, 1, 2, 1, 4, 4

/* MIB object ipTable = ip, 5 */
#define I_ipInAddrErrors    5
#define O_ipInADdrErrors    1, 3, 6, 1, 2, 1, 4, 5

/* MIB object ipTable = ip, 6 */
#define I_ipForwDatagrams   6
#define O_ipForwDatagrams   1, 3, 6, 1, 2, 1, 4, 6

/* MIB object ipInUnknownProtos = ip, 7 */
#define I_ipInUnknownProtos 7
#define O_ipInUnknownProtos 1, 3, 6, 1, 2, 1, 4, 7

/* MIB object ipInDiscards = ip, 8 */
#define I_ipInDiscards  8
#define O_ipInDiscards  1, 3, 6, 1, 2, 1, 4, 8

/* MIB object ipInDelivers = ip, 9 */
#define I_ipInDelivers  9
#define O_ipInDelivers  1, 3, 6, 1, 2, 1, 4, 9

/* MIB object ipOutRequests = ip, 10 */
#define I_ipOutRequests 10
#define O_ipOutRequests 1, 3, 6, 1, 2, 1, 4, 10

/* MIB object ipOutDiscards = ip, 11 */
#define I_ipOutDiscards 11
#define O_ipOutDiscards 1, 3, 6, 1, 2, 1, 4, 11

/* MIB object ipOutNoRoutes = ip, 12*/
#define I_ipOutNoRoutes 12
#define O_ipOutNoRoutes 1, 3, 6, 1, 2, 1, 4, 12

/* MIB object ipReasmTimeout = ip, 13*/
#define I_ipReasmTimeout 13
#define O_ipReasmTimeout    1, 3, 6, 1, 2, 1, 4, 13

/* MIB object ipReasmReqds = ip, 14*/
#define I_ipReasmReqds 14
#define O_ipReasmReqds  1, 3, 6, 1, 2, 1, 4, 14

/* MIB object ipReasmOKs = ip, 15*/
#define I_ipReasmOKs 15
#define O_ipReasmOKs    1, 3, 6, 1, 2, 1, 4, 15

/* MIB object ipReasmFails = ip, 16 */
#define I_ipReasmFails 16
#define O_ipReasmFails  1, 3, 6, 1, 2, 1, 4, 16

/* MIB object ipFragsOK = ip, 17 */
#define I_ipFragsOK 17
#define O_ipFragsOK 1, 3, 6, 1, 2, 1, 4, 17

/* MIB object ipFragsFails = ip, 18 */
#define I_ipFragsFails 18
#define O_ipFragsFails  1, 3, 6, 1, 2, 1, 4, 18

/* MIB object ipFragsCreates = ip, 19 */
#define I_ipFragsCreates 19
#define O_ipFragsCreates    1, 3, 6, 1, 2, 1, 4, 19

/* MIB object ipAddrTable = ip, 20 */
#define I_ipAddrTable 20
#define O_ipAddrTable   1, 3, 6, 1, 2, 1, 4, 20

/* MIB object ipAddrEntry = ipAddrTable, 1 */
#define I_ipAddrEntry 1
#define O_ipAddrEntry   1, 3, 6, 1, 2, 1, 4, 20, 1

/* MIB object ipAdEntAddr = ipAddrEntry, 1 */
#define I_ipAdEntAddr 1
#define O_ipAdEntAddr   1, 3, 6, 1, 2, 1, 4, 20, 1, 1

/* MIB object ipAdEntIfIndex = ipAddrEntry, 2 */
#define I_ipAdEntIfIndex 2
#define O_ipAdEntIfIndex    1, 3, 6, 1, 2, 1, 4, 20, 1, 2

/* MIB object ipAdEntNetMask = ipAddrEntry, 3 */
#define I_ipAdEntNetMask 3
#define O_ipAdEntNetMask    1, 3, 6, 1, 2, 1, 4, 20, 1, 3

/* MIB object ipAdEntBcastAddr = ipAddrEntry, 4 */
#define I_ipAdEntBcastAddr 4
#define O_ipAdEntBcastAddr  1, 3, 6, 1, 2, 1, 4, 20, 1, 4

/* MIB object ipAdEntReasmMaxSiz = ipAddrEntry, 5 */
#define I_ipAdEntReasmMaxSize 5
#define O_ipAdEntReasmMaxSize   1, 3, 6, 1, 2, 1, 4, 20, 1, 5

/* MIB object ipRouteTable = ip, 21 */
#define I_ipRouteTable 21
#define O_ipRouteTable  1, 3, 6, 1, 2, 1, 4, 21

/* MIB object ipRouteEntry = ipRouteTable, 1 */
#define I_ipRouteEntry 1
#define O_ipRouteEntry  1, 3, 6, 1, 2, 1, 4, 21, 1

/* MIB object ipRouteDest = ipRouteEntry, 1 */
#define I_ipRouteDest 1
#define O_ipRouteDest   1, 3, 6, 1, 2, 1, 4, 21, 1, 1

/* MIB object ipRouteIfIndex = ipRouteEntry, 2 */
#define I_ipRouteIfIndex 2
#define O_ipRouteIfIndex    1, 3, 6, 1, 2, 1, 4, 21, 1, 2

/* MIB object ipRouteMetric1 = ipRouteEntry, 3 */
#define I_ipRouteMetric1 3
#define O_ipRouteMetric1    1, 3, 6, 1, 2, 1, 4, 21, 1, 3

/* MIB object ipRouteMetric2 = ipRouteEntry, 4 */
#define I_ipRouteMetric2 4
#define O_ipRouteMetric2    1, 3, 6, 1, 2, 1, 4, 21, 1, 4

/* MIB object ipRouteMetric3 = ipRouteEntry, 5 */
#define I_ipRouteMetric3 5
#define O_ipRouteMetric3    1, 3, 6, 1, 2, 1, 4, 21, 1, 5

/* MIB object ipRouteMetric4 = ipRouteEntry, 6 */
#define I_ipRouteMetric4 6
#define O_ipRouteMetric4    1, 3, 6, 1, 2, 1, 4, 21, 1, 6

/* MIB object ipRouteNextHop = ipRouteEntry, 7 */
#define I_ipRouteNextHop 7
#define O_ipRouteNextHop    1, 3, 6, 1, 2, 1, 4, 21, 1, 7

/* MIB object ipRouteType = ipRouteEntry, 8 */
#define I_ipRouteType 8
#define O_ipRouteType   1, 3, 6, 1, 2, 1, 4, 21, 1, 8

/* MIB object ipRouteProto = ipRouteEntry, 9 */
#define I_ipRouteProto 9
#define O_ipRouteProto  1, 3, 6, 1, 2, 1, 4, 21, 1, 9

/* MIB object ipRouteAge = ipRouteEntry, 10 */
#define I_ipRouteAge 10
#define O_ipRouteAge    1, 3, 6, 1, 2, 1, 4, 21, 1, 10

/* MIB object ipRouteMask = ipRouteEntry, 11 */
#define I_ipRouteMask 11
#define O_ipRouteMask   1, 3, 6, 1, 2, 1, 4, 21, 1, 11

/* MIB object ipRouteMetric5 = ipRouteEntry, 12 */
#define I_ipRouteMetric5 12
#define O_ipRouteMetric5    1, 3, 6, 1, 2, 1, 4, 21, 1, 12

/* MIB object ipRouteInfo = ipRouteEntry, 13 */
#define I_ipRouteInfo 13
#define O_ipRouteInfo   1, 3, 6, 1, 2, 1, 4, 21, 1, 13

/* MIB object ipNetToMediaTable = ip, 22 */
#define I_ipNetToMediaTable 22
#define O_ipNetToMediaTable 1, 3, 6, 1, 2, 1, 4, 22

/* MIB object ipNetToMediaEntry = ipNetToMediaTable, 1 */
#define I_ipNetToMediaEntry 1
#define O_ipNetToMediaEntry 1, 3, 6, 1, 2, 1, 4, 22, 1

/* MIB object ipNetToMediaIfIndex = ipNetToMediaEntry, 1 */
#define I_ipNetToMediaIfIndex 1
#define O_ipNetToMediaIfIndex   1, 3, 6, 1, 2, 1, 4, 22, 1, 1

/* MIB object ipNetToMediaPhysAddress = ipNetToMediaEntry, 2 */
#define I_ipNetToMediaPhysAddress 2
#define O_ipNetToMediaPhysAddress   1, 3, 6, 1, 2, 1, 4, 22, 1, 2

/* MIB object ipNetToMediaNetAddress = ipNetToMediaEntry, 3 */
#define I_ipNetToMediaNetAddress 3
#define O_ipNetToMediaNetAddress    1, 3, 6, 1, 2, 1, 4, 22, 1, 3

/* MIB object ipNetToMediaType = ipNetToMediaEntry, 4 */
#define I_ipNetToMediaType 4
#define O_ipNetToMediaType  1, 3, 6, 1, 2, 1, 4, 22, 1, 4

/* MIB object ipRoutingDiscards = ip, 23 */
#define I_ipRoutingDiscards 23
#define O_ipRoutingDiscards 1, 3, 6, 1, 2, 1, 4, 23


#endif


#define SNMP_PDU_V2TRAP     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x7)
struct trap_sink {
    netsnmp_session* sesp;
    struct trap_sink* next;
    int             pdutype;
    int             version;
};

struct agent_add_trap_args {
    netsnmp_session* ss;
    int             confirm;
};

#define SEND_NOTRAP_NOINFORM -1
#define SEND_TRAP 1
#define SEND_INFORM 2

#define INTERFACE_DOWN 0
#define INTERFACE_UP 1

typedef struct struct_app_SNMPv3_Message appSNMPv3Message;

typedef struct _com2SecEntry {
    char            community[256];
    unsigned long   network;
    unsigned long   mask;
    char            secName[34];
    char            contextName[34];
    struct _com2SecEntry* next;
} com2SecEntry;



/*
 * NAME:        snmp_get_statistic.
 * PURPOSE:     to get statistics of a given parameter of a netSnmpAgent
 *              (whose object is a member of the node).
 * PARAMETERS:  which - indicating which parameter.
 *              node - pointer to the node.
 * RETURN:      none.
 */
u_int snmp_get_statistic(int which,Node* node);





/*
 * Class NAME:  NetSnmpAgent.
 * PURPOSE:     Root Class for The NetSnmpAgent.This Object of this
 *              Class represent the Snmpv3 enabled nodes in Qualnet.
 */
class NetSnmpAgent
{
private:

    Node* node;
    int done_init_agent;
    unsigned char* currPacket;
    int currPacketSize;
    subtree_context_cache* context_subtrees;
    lookup_cache_context* thecontextcache;
    struct snmp_gen_callback
           *thecallbacks[MAX_CALLBACK_IDS][MAX_CALLBACK_SUBIDS];
    int _callback_need_init;
    int _locks[MAX_CALLBACK_IDS][MAX_CALLBACK_SUBIDS];

    int
    netsnmp_ds_integers[NETSNMP_DS_MAX_IDS][NETSNMP_DS_MAX_SUBIDS];
    char
    netsnmp_ds_booleans[NETSNMP_DS_MAX_IDS][NETSNMP_DS_MAX_SUBIDS/8];
    char
    *netsnmp_ds_strings[NETSNMP_DS_MAX_IDS][NETSNMP_DS_MAX_SUBIDS];
    void
    *netsnmp_ds_voids[NETSNMP_DS_MAX_IDS][NETSNMP_DS_MAX_SUBIDS];

    netsnmp_session* main_session;
    int snmp_enableauthentraps;
    int snmp_enableauthentrapsset;
    struct config_files* config_files;
    struct trap_sink* sinks;
    char* snmp_trapcommunity;
    int      traptype;
    netsnmp_ds_read_config* netsnmp_ds_configs;
    const char*  stores [NETSNMP_DS_MAX_IDS];
    int netsnmp_ds_parse_boolean(char* line);
    int netsnmp_ds_set_int(int storeid, int which, int value);
    int netsnmp_ds_get_int(int storeid, int which);
    int doneit;
    struct snmp_enum_list*** snmp_enum_lists;
    unsigned int    current_maj_num;
    unsigned int    current_min_num;
    struct snmp_enum_list_str* sliststorage;
    netsnmp_data_list* handler_reg;
    netsnmp_data_list* auto_tables;
    struct tree*        tree_head;
    struct tree* tree_top;
    char*    Prefix;
    struct module* module_head;
    const char*     File;
    int             mibLine;
    int      anonymous;
    int      current_module;
    char*    last_err_module;
    struct tok* buckets[HASHSIZE];
    struct NetSnmpNode* nbuckets[NHASHSIZE];
    struct tree* tbuckets[NHASHSIZE];
    struct objgroup* objgroups;
    struct objgroup* objects;
    struct objgroup* notifs;
    struct module_import root_imports[NUMBER_OF_ROOT_NODES];
    struct NetSnmpNode* orphan_nodes;
    struct module_compatability* module_map_head;
    struct tc tclist[MAXTC];
    int      translation_table[256];
    int      max_module;
    int need_shutdown;
    struct usmUser* noNameUser;
    struct usmUser* userList;

    module_init_list* initlist;
    module_init_list* noinitlist;
    char     version_descr[SYS_STRING_LEN];
    char     sysContact[SYS_STRING_LEN];
    char     sysName[SYS_STRING_LEN];
    char     sysLocation[SYS_STRING_LEN];
    oid      sysObjectID[MAX_OID_LEN];
    size_t   sysObjectIDLength;
    oid*      version_sysoid;
    int      version_sysoid_len;
    int      sysServices ;
    int      sysServicesConfiged ;
    oid*      version_id;
    int      version_id_len;
    int      sysContactSet;
    int      sysLocationSet;
    int      sysNameSet;
    int      init_snmp_init_done;
    char     _init_snmp_init_done;
    netsnmp_container* containers;
    struct snmp_alarm* thealarms;
    int      start_alarms;
    unsigned int regnum;
    struct vacm_viewEntry* viewList, *viewScanPtr;
    struct vacm_accessEntry* accessList , *accessScanPtr ;
    struct vacm_groupEntry* groupList , *groupScanPtr;
    struct netsnmp_lookup_domain* domains;
    struct netsnmp_lookup_target* targets;
    struct read_config_memory* memorylist;
    int             linecount;
    char*     curfilename;
    int      config_errors;
    char*    confmibdir;
    char*    confmibs;
    int _mibindex;   /* Last index in use */
    int _mibindex_max;   /* Size of index array */
    char**     _mibindexes ;
    u_long   engineBoots;
    unsigned int engineIDType;
    unsigned char* engineID;
    size_t   engineIDLength;
    unsigned char* engineIDNic;
    unsigned int engineIDIsSet;  /* flag if ID set by config */
    unsigned char* oldEngineID;
    size_t   oldEngineIDLength;
    struct timeval snmpv3starttime;
    /*
     * Set up default snmpv3 parameter value storage.
     */
    oid* defaultAuthType;
    size_t   defaultAuthTypeLen;
    const oid* defaultPrivType;
    size_t   defaultPrivTypeLen;

    u_int    dummy_etime, dummy_eboot;       /* For ISENGINEKNOWN(). */
    struct snmp_secmod_list* registered_services;
    SNMPCallback set_default_secmod;
    Enginetime etimelist[ETIMELIST_SIZE];
    long     Reqid;      /* MT_LIB_REQUESTID */
    long     Msgid;      /* MT_LIB_MESSAGEID */
    long     Sessid;     /* MT_LIB_SESSIONID */
    long     Transid;    /* MT_LIB_TRANSID */
    netsnmp_agent_session* netsnmp_agent_queued_list;
    agent_set_cache* Sets;
    netsnmp_agent_session* netsnmp_processing_set;
    int netsnmp_running;

public:
    netsnmp_pdu* currentPDU;
    struct snmp_session_list* Sessions;
    UdpToAppRecv* info;
    int version;
    unsigned char  community[MAX_COMMUNITY_LENGTH];
    int     communityLength;
    int        request_id;
    unsigned char*   response_version;
    unsigned char*   response_pdu;
    unsigned char*   response_request_id;
    unsigned char*   response_error_index;
    unsigned char*   response_error_status;
    unsigned char*   responseVarbind;
    unsigned char*   response_first_varbind;
    unsigned char*   response_packet_end;
    int         response_length;
    unsigned char   response[ SNMP_MAX_MSG_LENGTH * 2 ];
    unsigned char*   trap_enterprise;
    unsigned char      pdutype;
    int trapCommunityLength;
    unsigned char  trapCommunity[MAX_COMMUNITY_LENGTH];
    netsnmp_cache*  cache_head;
    u_int    statistics[MAX_STATS];
    char SYSTEM_NAME_NETSNMP[256];
    com2SecEntry*   com2SecList;
    com2SecEntry* com2SecListLast;
    RandomSeed snmpRandomSeed;

    NetSnmpAgent();
    ~NetSnmpAgent();
    void NetSnmpAgentInit(Node* node);
    void setNodePtr(Node* nodePtr)
    {
        node = nodePtr;
    }

    int init_agent(const char*);
    void setup_tree(void);
    int netsnmp_register_null(unsigned int* , size_t);
    int netsnmp_register_null_context
            (unsigned int* , size_t, const char* contextName);
    int netsnmp_register_handler(netsnmp_handler_registration
                                             *reginfo);
    int agent_check_and_process(int length);
    void snmp_read (void);
    void snmp_read2 (void);
    void netsnmp_check_outstanding_agent_requests(void);
    void send_trap(Node* node, Message* msg,int trap);
    int netsnmp_send_traps(int trap, int specific,oid*  enterprise,
        int enterprise_length,netsnmp_variable_list* vars,
        char*  context, int flags);
    int netsnmp_send_traps2(int trap, int specific,oid*  enterprise,
        int enterprise_length,netsnmp_variable_list* vars,
        char*  context, int flags);
        
    void send_v2trap(netsnmp_variable_list * vars);
    void netsnmp_set_lookup_cache_size(int newsize);
    int netsnmp_subtree_load(struct netsnmp_subtree_s* new_sub,
        const char* context_name);
    struct netsnmp_subtree_s* netsnmp_subtree_find_first(
                                const char* context_name);
    struct netsnmp_subtree_s* netsnmp_subtree_find (unsigned int* ,
        size_t, struct netsnmp_subtree_s* ,const char* context_name);

    struct netsnmp_subtree_s
    *netsnmp_subtree_find_prev(unsigned int* , size_t,
                                struct netsnmp_subtree_s* ,
                        const char* context_name);
    struct netsnmp_subtree_s
    *netsnmp_subtree_find_next(unsigned int* , size_t,
                                struct netsnmp_subtree_s* ,
                        const char* context_name);
    struct netsnmp_subtree_s*
    add_subtree(struct netsnmp_subtree_s* new_tree,
                 const char* context_name);
    struct netsnmp_subtree_s*
        netsnmp_subtree_replace_first(struct netsnmp_subtree_s* new_tree,
                  const char* context_name);

    lookup_cache*
    lookup_cache_find(const char* context, unsigned int* name,
                        size_t name_len, int* retcmp);
    lookup_cache_context*
            get_context_lookup_cache(const char* context);

    netsnmp_pdu* convert_v2pdu_to_v1(netsnmp_pdu* template_v2pdu);
    netsnmp_pdu* convert_v1pdu_to_v2(netsnmp_pdu* template_v1pdu);

    void
    lookup_cache_add(const char* context,
                    struct netsnmp_subtree_s* next,
                    struct netsnmp_subtree_s* previous);
    int
    unregister_mib_context(unsigned int* , size_t, int, int,
                            unsigned long, const char*);
    void
    invalidate_lookup_cache(const char* context);
    void
    netsnmp_subtree_unload(struct netsnmp_subtree_s* sub,
                        struct netsnmp_subtree_s* prev,
                        const char* context);
    int
    snmp_call_callbacks(int major, int minor, void* caller_arg);

    void            init_callbacks(void);
    int netsnmp_get_lookup_cache_size(void);

    int
    netsnmp_ds_set_boolean(int storeid, int which, int value);
    int
    netsnmp_ds_get_boolean(int storeid, int which);
    int
    netsnmp_ds_set_string(int storeid, int which, const char* value);
    char
    *netsnmp_ds_get_string(int storeid, int which);
    void            init_agent_read_config(const char*);
    struct config_line*
    register_app_config_handler(const char* token,
                            void (NetSnmpAgent::*parser)
                                 (const char* , char*),
                            void (NetSnmpAgent::*releaser)
                                 (void),
                            const char* help);
    struct config_line*
    register_config_handler(const char* type,
                        const char* token,
                        void (NetSnmpAgent::*parser)
                             (const char* , char*),
                        void (NetSnmpAgent::*releaser)
                             (void),
                        const char* help);

    struct config_line*
    internal_register_config_handler(const char* type_param,
                                const char* token,
                                void (NetSnmpAgent::*parser)
                                (const char* , char*),
                                void (NetSnmpAgent::*releaser)
                                (void),
                                const char* help,
                                int when);
    void
    snmpd_parse_config_authtrap(const char* token, char* cptr);
    void
            snmpd_parse_config_trapsink(const char* token, char* cptr);
    void            snmpd_free_trapsinks(void);
    void            snmpd_parse_config_trap2sink(const char* , char*);
    void            snmpd_parse_config_informsink(const char* , char*);
    void            snmpd_parse_config_trapsess(const char* , char*);
    int create_trap_session2(const char* sink, const char* sinkport,
             char* com, int version, int pdutype);
    int
    create_v1_trap_session(char* sink,
                            const char* sinkport,
                            char* com);
    int
    create_v2_inform_session(const char* sink,
                             const char* sinkport,
                             char* com);
    void
    trapOptProc(int argc, char* const* argv, int opt);
    void snmpd_parse_config_trapcommunity(const char* , char*);
    void snmpd_free_trapcommunity(void);

    int netsnmp_ds_register_config(u_char type, const char* ftype,
                                       const char* token, int storeid,
                                       int which);
    void netsnmp_ds_handle_config(const char* token, char* line);
    void
    snmpd_set_agent_user(const char* token, char* cptr);
    void
    snmpd_set_agent_group(const char* token, char* cptr);
    void
    snmpd_set_agent_address(const char* token, char* cptr);
    void
    netsnmp_init_handler_conf(void);
    void
    parse_injectHandler_conf(const char* token, char* cptr);

    void
    snmpd_register_config_handler(const char* token,
                                    void (NetSnmpAgent::*parser)
                                        (const char* , char*),
                                    void (NetSnmpAgent::*releaser)
                                        (void),
                                    const char* help);
    int
    handler_mark_doneit(int majorID, int minorID,
                void* serverarg, void* clientarg);
    int
    netsnmp_register_callback(int major, int minor,
                              int (NetSnmpAgent::*new_callback)(
                                  int majorID, int minorID,
            void* serverarg, void* clientarg),
            void* arg, int priority);
    int
    snmp_register_callback(int major, int minor,
                            int (NetSnmpAgent::*new_callback)
                                (int majorID, int minorID,
            void* serverarg, void* clientarg),
            void* arg);
    int se_add_pair_to_slist(const char* listname,
                             char* label,
                                 int value);
    struct snmp_enum_list*
    se_find_slist(const char* listname);
    int netsnmp_register_callback(int major, int minor,
                                  SNMPCallback*  new_callback,
                                  void* arg, int priority);
    void netsnmp_init_serialize(void);
    void netsnmp_register_handler_by_name(const char* ,
                                        netsnmp_mib_handler*);
    void netsnmp_init_helpers(void);
    void netsnmp_init_read_only_helper(void);
    void netsnmp_init_bulk_to_next_helper(void);
    void netsnmp_init_table_dataset(void);
    void
    netsnmp_config_parse_table_set(const char* token, char* line);

    oid
    *snmp_parse_oid(const char* argv, oid*  root, size_t*  rootlen);

    struct tree*    get_tree(const oid* , size_t, struct tree*);
    void
    _table_set_add_indexes (netsnmp_table_data_set* table_set,
                            struct tree* tp);
    void
    netsnmp_config_parse_add_row (const char* token, char* line);
    void
    netsnmp_register_auto_data_table(netsnmp_table_data_set* table_set,
                              char* registration_name);
    struct tree
    *netsnmp_read_module (const char* name);
    int
    get_module_node (const char* fname, const char* module,
                oid*  objid, size_t*  objidlen);

    int
    get_node (const char* name, oid*  objid, size_t*  objidlen);
    int
    _add_strings_to_oid (struct tree* tp, char* cp,
                    oid*  objid, size_t*  objidlen, size_t maxlen);
    int
    get_wild_node (const char* name, oid*  objid, size_t*  objidlen);
    int
    read_objid (const char* input, oid*  output, size_t*  out_len);
    char
    *read_config_read_objid (char* readfrom,
                             oid**  objid,
                             size_t*  len);
    char
    *read_config_read_memory (int type, char* readfrom,
                               char* dataptr, size_t*  len);
    void
    netsnmp_init_mib_internals (void);
    int
    read_module_internal (const char* name);

    struct
    NetSnmpNode* parse(FILE*  fp, struct NetSnmpNode* root);
    int
    parseQuoteString(FILE*  fp, char* token, int maxtlen);
    int
    get_token(FILE*  fp, char* token, int maxtlen);
    int
    is_labelchar(int ich);
    void
    scan_objlist(struct NetSnmpNode* root, struct module* mp,
                        struct objgroup* list, const char* error);
    void
    do_linkup(struct module* mp, struct NetSnmpNode* np);
    void
    init_node_hash(struct NetSnmpNode* nodes);
    int
    get_tc_index(const char* descriptor, int modid);
    void
    do_subtree(struct tree* root, struct NetSnmpNode** nodes);
    void
    new_module(const char* name, const char* file);
    struct
    NetSnmpNode*  parse_objectgroup(FILE*  fp, char* name,
                                        int what, struct objgroup** ol);

    struct NetSnmpNode*
    parse_objecttype(FILE*  fp, char* name);
    struct NetSnmpNode*
    parse_trapDefinition(FILE*  fp, char* name);
    struct NetSnmpNode*
    parse_notificationDefinition(FILE*  fp, char* name);
    struct NetSnmpNode*
    parse_compliance(FILE*  fp, char* name);
    struct NetSnmpNode*
    parse_capabilities(FILE*  fp, char* name);
    struct NetSnmpNode*
    parse_objectid(FILE*  fp, char* name);
    struct NetSnmpNode*
    parse_asntype(FILE*  fp, char* name, int* ntype, char* ntoken);

    int
    read_module_replacements(const char* name);
    void
    print_module_not_found(const char* cp);

    int which_module(const char* name);
    struct tree*
    find_tree_node(const char* name, int modid);
    struct tree*
    find_best_tree_node(const char* pattrn,
                        struct tree* tree_top,
            u_int*  match);
    void build_translation_table(void);
    void init_tree_roots(void);
    void tree_from_node(struct tree* tp, struct NetSnmpNode* np);
    void set_function(struct tree* subtree);

    int
    sprint_realloc_object_identifier(u_char**  buf, size_t*  buf_len,
                         size_t*  out_len, int allow_realloc,
                         const netsnmp_variable_list*  var,
                         const struct enum_list* enums,
                         const char* hint, const char* units);

    int
    sprint_realloc_octet_string(u_char**  buf, size_t*  buf_len,
                        size_t*  out_len, int allow_realloc,
                        const netsnmp_variable_list*  var,
                        const struct enum_list* enums, const char* hint,
                        const char* units);

    int
    sprint_realloc_integer(u_char**  buf, size_t*  buf_len,
                    size_t*  out_len,
                   int allow_realloc,
                   const netsnmp_variable_list*  var,
                   const struct enum_list* enums,
                   const char* hint, const char* units);

    int sprint_realloc_by_type(u_char**  buf, size_t*  buf_len,
                    size_t*  out_len,
                   int allow_realloc,
                   const netsnmp_variable_list*  var,
                   const struct enum_list* enums,
                   const char* hint, const char* units);

    struct tree*
    netsnmp_sprint_realloc_objid_tree(u_char**  buf, size_t*  buf_len,
                              size_t*  out_len, int allow_realloc,
                              int* buf_overflow,const oid*  objid,
                              size_t objidlen);

    int
    sprint_realloc_hexstring(u_char**  buf, size_t*  buf_len,
                             size_t*  out_len, int allow_realloc,
                             const u_char*  cp, size_t len);

    int
    sprint_realloc_asciistring(u_char**  buf, size_t*  buf_len,
                               size_t*  out_len, int allow_realloc,
                               const u_char*  cp, size_t len);
    int
    sprint_realloc_hinted_integer(u_char**  buf, size_t*  buf_len,
                                  size_t*  out_len, int allow_realloc,
                                  long val, const char decimaltype,
                                  const char* hint, const char* units);
    int
    sprint_realloc_bitstring(u_char**  buf, size_t*  buf_len,
                             size_t*  out_len,
                             int allow_realloc,
                             const netsnmp_variable_list*  var,
                             const struct enum_list* enums,
                             const char* hint, const char* units);
    int
    sprint_realloc_badtype(u_char**  buf, size_t*  buf_len,
                           size_t*  out_len,
                           int allow_realloc,
                           const netsnmp_variable_list*  var,
                           const struct enum_list* enums,
                           const char* hint, const char* units);
    struct tree*
    _get_realloc_symbol(const oid*  objid,
                        size_t objidlen,
                        struct tree* subtree,
                        u_char**  buf,
                        size_t*  buf_len,
                        size_t*  out_len,
                        int allow_realloc,
                        int* buf_overflow,
                        struct index_list* in_dices,
                        size_t*  end_of_known);

    char*  module_name(int modid, char* cp);

    int
    _sprint_hexstring_line(u_char**  buf, size_t*  buf_len,
                            size_t*  out_len,
                            int allow_realloc,
                            const u_char*  cp,
                            size_t line_len);
    int
    dump_realloc_oid_to_string(const oid*  objid, size_t objidlen,
                               u_char**  buf, size_t*  buf_len,
                               size_t*  out_len, int allow_realloc,
                               char quotechar);

    int
    dump_realloc_oid_to_inetaddress(const int addr_type,
                                    const oid*  objid,
                                    size_t objidlen,
                                    u_char**  buf,
                                    size_t*  buf_len,
                                    size_t*  out_len,
                                    int allow_realloc,
                                    char quotechar);

    void merge_anon_children(struct tree* tp1, struct tree* tp2);

    void free_tree(struct tree* Tree);

    void unlink_tree(struct tree* tp);

    void unlink_tbucket(struct tree* tp);

    struct NetSnmpNode* alloc_node(int modid);

    int get_tc(const char* descriptor, int modid,
                int* tc_index,struct enum_list** ep,
                struct range_list** rp, char** hint);

    struct enum_list*
    parse_enumlist(FILE*  fp, struct enum_list** retp);
    struct range_list*
    parse_ranges(FILE*  fp, struct range_list** retp);
    struct index_list*
    getIndexes(FILE*  fp, struct index_list** retp);

    int tossObjectIdentifier(FILE*  fp);

    struct NetSnmpNode*
    merge_parse_objectid(struct NetSnmpNode* np,
        FILE*  fp, char* name);

    struct varbind_list*
    getVarbinds(FILE*  fp, struct varbind_list** retp);

    int compliance_lookup(const char* name, int modid);

    int eat_syntax(FILE*  fp, char* token, int maxtoken);

    int getoid(FILE*  fp, struct subid_s* id, int length);

    char*  get_tc_descriptor(int tc_index);

    char*  get_tc_description(int tc_index);

    int snprint_objid(char* buf, size_t buf_len,
                  const oid*  objid, size_t objidlen);


    int sprint_realloc_objid(u_char**  buf, size_t*  buf_len,
                         size_t*  out_len, int allow_realloc,
                         const oid*  objid, size_t objidlen);

    Netsnmp_Node_Handler
    netsnmp_table_data_set_helper_handler;

    netsnmp_mib_handler*
    netsnmp_get_table_data_set_handler(netsnmp_table_data_set*);

    int
    netsnmp_register_table_data_set(netsnmp_handler_registration* ,
                                    netsnmp_table_data_set* ,
                                    netsnmp_table_registration_info*);

    void
    netsnmp_oid_stash_store(netsnmp_oid_stash_node* root,
                                     const char* tokenname,
                                     NetSNMPStashDump* dumpfn,
                                     oid* curoid, size_t curoid_len);

    SNMPCallback netsnmp_oid_stash_store_all;

    netsnmp_pdu* snmp_pdu_create(int command);
    int check_access(netsnmp_pdu* pdu);

    netsnmp_agent_session* agent_delegated_list;
    int netsnmp_remove_from_delegated(netsnmp_agent_session* asp);
    void free_agent_snmp_session(netsnmp_agent_session* asp);
    void snmp_free_pdu(netsnmp_pdu* pdu);

    /*
     * find a security service definition
     */
    struct snmp_secmod_def* find_sec_mod(int);

    void
    netsnmp_free_agent_request_info(netsnmp_agent_request_info* ari);
    void
    netsnmp_remove_and_free_agent_snmp_session(
        netsnmp_agent_session* asp);
    void* netsnmp_get_list_data(netsnmp_data_list* head,
                                const char* name);
    void* netsnmp_request_get_list_data(netsnmp_request_info* request,
        const char* name);
    void netsnmp_free_request_data_set(netsnmp_request_info* request);
    void netsnmp_free_request_data_sets(netsnmp_request_info* request);


    int netsnmp_callback_hook_parse(netsnmp_session*  sp,
                                    netsnmp_pdu* pdu,
                                    u_char*  packetptr,
                                    size_t len);

    int netsnmp_callback_hook_build(netsnmp_session*  sp,
                                    netsnmp_pdu* pdu,
                                    u_char*  ptk,
                                    size_t*  len);

    int netsnmp_callback_check_packet(u_char*  pkt, size_t len);

    netsnmp_pdu* netsnmp_callback_create_pdu(
                    netsnmp_transport* transport,
                    void* opaque, size_t olength);

    void*  snmp_sess_add_ex(netsnmp_session*  in_session,
        netsnmp_transport* transport,
    int (NetSnmpAgent::*fpre_parse)(
        netsnmp_session* , netsnmp_transport* , void* , int),
    int (NetSnmpAgent::*fparse)(
        netsnmp_session* , netsnmp_pdu* , u_char* , size_t),
    int (NetSnmpAgent::*fpost_parse)(
        netsnmp_session* , netsnmp_pdu* , int),
    int (NetSnmpAgent::*fbuild)(
        netsnmp_session* , netsnmp_pdu* , u_char* , size_t*),
    int (NetSnmpAgent::*frbuild)(
        netsnmp_session* , netsnmp_pdu* , u_char** , size_t* ,
    size_t*),
    int (NetSnmpAgent::*fcheck)(
        u_char* , size_t), netsnmp_pdu*
                           (NetSnmpAgent::*fcreate_pdu)(
                           netsnmp_transport* ,
                           void* , size_t));

    int snmp_sess_close(void* sessp);

    struct snmp_session_list*
    _sess_copy(netsnmp_session*  in_session);
    struct snmp_session_list*
    snmp_sess_copy(netsnmp_session*  pss);

    void
    netsnmp_free_agent_data_sets(netsnmp_agent_request_info* ari);
    Netsnmp_Node_Handler table_helper_handler;

    netsnmp_mib_handler*
    netsnmp_get_table_handler(netsnmp_table_registration_info* tabreq);
    netsnmp_oid_stash_node**
    netsnmp_table_get_or_create_row_stash(
                        netsnmp_agent_request_info* reqinfo,
                        const u_char* storage_name);

    netsnmp_table_row*
    netsnmp_extract_table_row(netsnmp_request_info*);
    netsnmp_table_request_info*
    netsnmp_extract_table_info(netsnmp_request_info*);

    Netsnmp_Node_Handler netsnmp_table_data_helper_handler;

    netsnmp_mib_handler*
    netsnmp_get_table_data_handler(netsnmp_table_data* table);

    int
    netsnmp_register_table_data(netsnmp_handler_registration* reginfo,
                                netsnmp_table_data* table,
                                netsnmp_table_registration_info*
                                table_info);

    void
    table_helper_cleanup(netsnmp_agent_request_info* reqinfo,
                 netsnmp_request_info* request, int status);

    void            init_mib_modules(void);

    int
            _shutdown_mib_modules(int majorID, int minorID,
                                  void* serve, void* client);

    int             should_init(const char* module_name);
    void init_system_mib(void);
    void
    system_parse_config_sysdescr(const char* token, char* cptr);

    void
    system_parse_config_sysloc(const char* token, char* cptr);

    void
    system_parse_config_syscon(const char* token, char* cptr);

    void
    system_parse_config_sysname(const char* token, char* cptr);

    void
    system_parse_config_sysServices(const char* token, char* cptr);

    void
    system_parse_config_sysObjectID(const char* token, char* cptr);

    int
    system_store(int a, int b, void* c, void* d);



    void
    snmpd_store_config(const char* line);

    void
    read_app_config_store(const char* line);

    int
    netsnmp_register_instance(netsnmp_handler_registration*  reginfo);

    int
    netsnmp_register_num_file_instance(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    const char* file_name,
                                    int asn_type, int mode,
                                    Netsnmp_Node_Handler*  subhandler,
                                    const char* contextName);

    int
    netsnmp_register_watched_instance(
                                    netsnmp_handler_registration* reginfo,
                                    netsnmp_watcher_info*         winfo);

    int
    netsnmp_register_read_only_ulong_instance(
                                    const char*  name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    u_long*  it,
                                    Netsnmp_Node_Handler*  subhandler);

    int
    netsnmp_register_ulong_instance(const char*  name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    u_long*  it,
                                    Netsnmp_Node_Handler*  subhandler);

    int
    netsnmp_register_read_only_counter32_instance(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    u_long*  it,
                                    Netsnmp_Node_Handler* subhandler);
    int
    netsnmp_register_read_only_long_instance(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    long* it,
                                    Netsnmp_Node_Handler*  subhandler);
    int
    netsnmp_register_long_instance(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    long* it,
                                    Netsnmp_Node_Handler*  subhandler);

    int
    netsnmp_register_read_only_int_instance(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len, int* it,
                                    Netsnmp_Node_Handler*  subhandler);

    int
    netsnmp_register_int_instance(const char* name,
                                  const oid*  reg_oid,
                                  size_t reg_oid_len, int* it,
                                  Netsnmp_Node_Handler*  subhandler);



    int
    netsnmp_register_read_only_ulong_instance_context(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    u_long*  it,
                                    Netsnmp_Node_Handler
                                    * subhandler,
                                    const char* contextName);
    int
    netsnmp_register_ulong_instance_context(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    u_long*  it,
                                    Netsnmp_Node_Handler*  subhandler,
                                    const char* contextName);
    int
    netsnmp_register_read_only_counter32_instance_context(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    u_long*  it,
                                    Netsnmp_Node_Handler
                                    * subhandler,
                                    const char* contextName);
    int
    netsnmp_register_read_only_long_instance_context(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    long* it,
                                    Netsnmp_Node_Handler
                                    * subhandler,
                                    const char* contextName);
    int
    netsnmp_register_long_instance_context(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    long* it,
                                    Netsnmp_Node_Handler*  subhandler,
                                    const char* contextName);

    int
    netsnmp_register_read_only_int_instance_context(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len, int* it,
                                    Netsnmp_Node_Handler*
                                    subhandler,
                                    const char* contextName);



    int
    netsnmp_register_int_instance_context(
                                    const char* name,
                                  const oid*  reg_oid,
                                  size_t reg_oid_len, int* it,
                                  Netsnmp_Node_Handler*  subhandler,
                                  const char* contextName);

    int
    netsnmp_register_read_only_instance(
                            netsnmp_handler_registration* reginfo);

    int
    netsnmp_register_scalar(netsnmp_handler_registration* reginfo);

    int
    netsnmp_register_watched_spinlock(
                            netsnmp_handler_registration* reginfo,
                            int* spinlock);

    int
    netsnmp_register_ulong_scalar(
                                const char* name,
                                const oid*  reg_oid,
                                size_t reg_oid_len,
                          u_long*  it,
                          Netsnmp_Node_Handler*  subhandler);
    int
    netsnmp_register_read_only_ulong_scalar(
                                const char* name,
                                const oid*  reg_oid,
                                size_t reg_oid_len,
                          u_long*  it,
                          Netsnmp_Node_Handler*  subhandler);
    int
    netsnmp_register_long_scalar(
                                const char* name,
                                const oid*  reg_oid,
                                size_t reg_oid_len,
                          long*  it,
                          Netsnmp_Node_Handler*  subhandler);
    int
    netsnmp_register_read_only_long_scalar(
                                const char* name,
                                const oid*  reg_oid,
                                size_t reg_oid_len,
                          long*  it,
                          Netsnmp_Node_Handler*  subhandler);
    int
    netsnmp_register_int_scalar(const char* name,
                                const oid*  reg_oid,
                                size_t reg_oid_len,
                          int*  it,
                          Netsnmp_Node_Handler*  subhandler);

    int
    netsnmp_register_read_only_int_scalar(
                                const char* name,
                                const oid*  reg_oid,
                                size_t reg_oid_len,
                          int*  it,
                          Netsnmp_Node_Handler*  subhandler);
    int
    netsnmp_register_read_only_counter32_scalar(
                                const char* name,
                                const oid*  reg_oid,
                                size_t reg_oid_len,
                          u_long*  it,
                          Netsnmp_Node_Handler*  subhandler);

    int
    netsnmp_watched_timestamp_register(
                                netsnmp_mib_handler* whandler,
                                   netsnmp_handler_registration* reginfo,
                                   marker_t timestamp);

    int netsnmp_register_watched_timestamp(
                                netsnmp_handler_registration* reginfo,
                                   marker_t timestamp);


    int netsnmp_register_read_only_scalar(
                                netsnmp_handler_registration* reginfo);

    int netsnmp_register_watched_scalar(
                                netsnmp_handler_registration* reginfo,
                                   netsnmp_watcher_info*         winfo);

    int
    netsnmp_register_read_only_uint_instance(
                                const char* name,
                                     const oid*  reg_oid,
                                     size_t reg_oid_len,
                                     unsigned int* it,
                                     Netsnmp_Node_Handler*  subhandler);


    int
    netsnmp_register_uint_instance(
                                const char* name,
                                const oid*  reg_oid,
                                size_t reg_oid_len,
                                unsigned int* it,
                                Netsnmp_Node_Handler*  subhandler);

    int
        register_read_only_int_instance(
                                    const char* name,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    int* it,
                                    Netsnmp_Node_Handler*  subhandler);


    int
    register_read_only_int_instance_context(
                                const char* name,
                                const oid*  reg_oid,
                                size_t reg_oid_len,
                                    int* it,
                                    Netsnmp_Node_Handler*  subhandler,
                                    const char* contextName);


    void            init_snmp(const char*);
    void _init_snmp(void);
    void snmp_init_statistics(void);
    void register_mib_handlers(void);
    int netsnmp_ds_register_premib(u_char type, const char* ftype,
                                       const char* token, int storeid,
                                       int which);;

        void register_default_handlers(void);

    void
    init_snmpv3(const char* type);

    int
    init_snmp_enum(const char* type);

    void
    init_vacm(void);

    void
    read_premib_configs(void);

    void
    netsnmp_init_mib(void);

    void
    read_configs(void);

    int
            netsnmp_register_default_domain(const char* application,
                                            const char* domain);
    int
            netsnmp_register_default_target(const char* application,
                                            const char* domain,
                    const char* target);

    void
    netsnmp_register_service_handlers(void);

    void
    read_configs_optional(const char* optional_config, int when);

    void
            read_config_with_type_when(const char* filename,
                                       const char* type, int when);

    struct config_line*
    read_config_get_handlers(const char* type);

    void
    read_config(const char* filename,
                struct config_line* line_handler, int when);

    void
    read_config_files(int when);


    void
    netsnmp_config_process_memories_when(int when, int clear);

    void
    netsnmp_config_process_memory_list(
                                struct read_config_memory** memp,
                                int when, int clear);

    int
    snmp_config_when(char* line, int when);

    int
    run_config_handler(struct config_line* lptr,
                       const char* token, char* cptr, int when);

    void
    free_config(void);

    const char*
    get_configuration_directory(void);

    void
            read_config_files_in_path(const char* path,
                                      struct config_files* ctmp,
                                      int when,
                                      const char* perspath,
                                      const char* persfile);

    void
    set_configuration_directory(const char* dir);

    void
    handle_mibdirs_conf(const char* token, char* line);

    struct config_line*
    register_prenetsnmp_mib_handler(const char* type,
                                    const char* token,
                                            void (NetSnmpAgent::*parser)(
                                                const char* , char*),
                                            void (NetSnmpAgent::*releaser)(
                                                void), const char* help);

     void
    handle_mibs_conf(const char* token, char* line);

      void
    handle_mibfile_conf(const char* token, char* line);

      struct tree*
    read_mib(const char* filename);

      void
    handle_print_numeric(const char* token, char* line);
      char*
    netsnmp_get_mib_directory(void);
    void
    netsnmp_fixup_mib_directory(void);

    void
    netsnmp_set_mib_directory(const char* dir);

    void
    netsnmp_mibindex_load(void);

    int
    add_mibdir(const char* dirname);

    int
    add_mibfile(const char* tmpstr, const char* d_name, FILE* ip);

    struct tree*
    read_all_mibs(void);

    void
    adopt_orphans(void);

    FILE*
    netsnmp_mibindex_new(const char* dirname);


    char*
    netsnmp_mibindex_lookup(const char* dirname);

    int
    _mibindex_add(const char* dirname, int i);

    void
    se_read_conf(const char* word, char* cptr);

    struct snmp_enum_list*
    se_find_list(unsigned int major, unsigned int minor);

    int
    se_add_pair(unsigned int major, unsigned int minor,
                        char* label, int value);

    int
    se_store_in_list(struct snmp_enum_list* new_list,
                  unsigned int major, unsigned int minor);

    void            snmpv3_authtype_conf(const char* word, char* cptr);
    const oid*      get_default_authtype(size_t*);
    void            snmpv3_privtype_conf(const char* word, char* cptr);
    const oid*      get_default_privtype(size_t*);
    void snmpv3_secLevel_conf(const char* word, char* cptr);
    int
    snmpv3_options(char* optarg, netsnmp_session*  session,
                    char** Apsz, char** Xpsz,
                    int argc, char* const* argv);

    int setup_engineID(u_char**  eidp, const char* text);
    int free_engineID(int majorid, int minorid, void* serverarg,
                  void* clientarg);
    int free_enginetime_on_shutdown(int majorid, int minorid,
                                    void* serverarg, void* clientarg);
    void            engineBoots_conf(const char* , char*);
    void            engineIDType_conf(const char* , char*);
    void            engineIDNic_conf(const char* , char*);
    void            engineID_conf(const char* word, char* cptr);
    void version_conf(const char* word, char* cptr);
    void oldengineID_conf(const char* word, char* cptr);
    void exactEngineID_conf(const char* word, char* cptr);
    int             snmpv3_store(int majorID, int minorID, void* serverarg,
                                 void* clientarg);
    void            init_secmod(void);
    int             register_sec_mod(int, const char* ,
                                 struct snmp_secmod_def*);
    char*           se_find_label_in_slist(const char* listname,
                                           int value);
    int             unregister_sec_mod(int);
    void            clear_sec_mod(void);
    int             se_find_value_in_slist(const char* listname,
                                           const char* label);
    void            init_usm(void);
    int
    init_snmpv3_post_config(int majorid, int minorid,
                            void* serverarg, void* clientarg);

    int
    init_snmpv3_post_premib_config(int majorid, int minorid,
                                   void* serverarg, void* clientarg);

    void            usm_set_password(const char* token, char* line);
    u_long          snmpv3_local_snmpEngineBoots(void);
    size_t          snmpv3_get_engineID(u_char*  buf, size_t buflen);
    u_char*         snmpv3_generate_engineID(size_t*);
    void            usm_parse_create_usmUser(const char* token,
                                             char* line);
    unsigned long          snmpv3_local_snmpEngineTime(void);
    void get_enginetime_alarm(unsigned int regnum, void* clientargs);
    void netsnmp_container_init_list(void);
    void netsnmp_container_free_list(void);
    int
    netsnmp_container_register_with_compare(
                                        const char* name,
                                        netsnmp_factory* f,
                                        netsnmp_container_compare* c);
    int
    netsnmp_container_register(const char* name, netsnmp_factory* f);

    void netsnmp_container_null_init(void);
    void netsnmp_container_ssll_init(void);
    void netsnmp_container_binary_array_init(void);

    netsnmp_factory*
    netsnmp_container_get_factory(const char* type);
    netsnmp_factory*
    netsnmp_container_find_factory(const char* type_list);
    container_type*
    netsnmp_container_get_ct(const char* type);
    container_type*
    netsnmp_container_find_ct(const char* type_list);
    netsnmp_container*
    netsnmp_container_find(const char* type_list);
    netsnmp_container*
    netsnmp_container_get(const char* type);
    struct snmp_alarm* sa_find_next(void);
    int             get_next_alarm_delay_time(struct timeval* delta);
    struct snmp_alarm* sa_find_specific(unsigned int clientreg);
    void            vacm_save(const char* token, const char* type);
    int             store_vacm(int majorID, int minorID, void* serverarg,
                               void* clientarg);
    void            vacm_parse_config_view(const char* token, char* line);
    void vacm_scanViewInit(void);
    struct vacm_viewEntry* vacm_scanViewNext(void);
    struct vacm_groupEntry* vacm_getGroupEntry(int, const char*);
    void            vacm_scanGroupInit(void);
    struct vacm_groupEntry* vacm_scanGroupNext(void);
    struct vacm_groupEntry* vacm_createGroupEntry(int, const char*);
    void            vacm_parse_config_group(const char* token, char* line);
    void            vacm_destroyGroupEntry(int, const char*);
    void            vacm_destroyAllGroupEntries(void);
    struct vacm_accessEntry* vacm_getAccessEntry(const char* ,
                                                     const char* ,
                                                     int, int);
    char*
    _vacm_parse_config_access_common(struct vacm_accessEntry** aptr,
                                         char* line);
    void            vacm_parse_config_auth_access(const char* token,
                                             char* line);
    void            vacm_parse_config_access(const char* token,
                                             char* line);
    void            vacm_scanAccessInit(void);
    struct vacm_accessEntry* vacm_scanAccessNext(void);
        struct vacm_accessEntry* vacm_createAccessEntry(
                                        const char* ,
                                                    const char* , int,
                                                    int);
    void            vacm_destroyAccessEntry(const char* , const char* ,
                                            int, int);
    void            vacm_destroyAllAccessEntries(void);
    int             vacm_is_configured(void);
    struct vacm_viewEntry* vacm_getViewEntry(const char* ,
                                             oid* , size_t,
                                             int);
    int vacm_checkSubtree(const char* , oid* , size_t);
    struct vacm_viewEntry* vacm_createViewEntry(const char* , oid* ,
                                                size_t);
    void            vacm_destroyViewEntry(const char* , oid* , size_t);
    void            vacm_destroyAllViewEntries(void);
    void netsnmp_clear_default_domain(void);
    void netsnmp_register_user_domain(const char* token, char* cptr);
    void netsnmp_clear_user_domain(void);
    const char* const*
    netsnmp_lookup_default_domains(const char* application);
    const char* netsnmp_lookup_default_domain(const char* application);
    void netsnmp_clear_default_target(void);
    void netsnmp_register_user_target(const char* token, char* cptr);
    void netsnmp_clear_user_target(void);
    const char* netsnmp_lookup_default_target(const char* application,
                                                  const char* domain);
    int             usm_set_salt(u_char*  iv,
                                 size_t*  iv_length,
                                 u_char*  priv_salt,
                                 size_t priv_salt_length,
                                 u_char*  msgSalt);
    int             usm_generate_out_msg(int, u_char* , size_t, int, int,
                                         u_char* , size_t, char* , size_t,
                                         int, u_char* , size_t, void* ,
                                         u_char* , size_t* , u_char** ,
                                         size_t*);
        SecmodOutMsg    usm_secmod_generate_out_msg;
    int             usm_check_and_update_timeliness(u_char*  secEngineID,
                                            size_t secEngineIDLen,
                                            u_int boots_uint,
                                            u_int time_uint,
                                            int* error);
    int             usm_process_in_msg(int, size_t, u_char* , int, int,
                                   u_char* , size_t, u_char* ,
                                   size_t* , char* , size_t* ,
                                   u_char** , size_t* , size_t* ,
                                   void** , netsnmp_session* , u_char);
    SecmodInMsg     usm_secmod_process_in_msg;
    int             init_usm_post_config(int majorid, int minorid,
                                        void* serverarg, void* clientarg);
    int deinit_usm_post_config(int majorid, int minorid,
                               void* serverarg, void* clientarg);
    int             snmpv3_make_report(netsnmp_pdu* pdu, int error);

    void usm_handle_report(void* sessp, netsnmp_transport* transport,
                            netsnmp_session* session,
                            int result, netsnmp_pdu* pdu);

    int             set_enginetime(u_char*  engineID, u_int engineID_len,
                                   u_int engine_boot, u_int engine_time,
                                   u_int authenticated);

    int             snmp_sess_async_send(void* , netsnmp_pdu*);
        int _sess_async_send(void* sessp, netsnmp_pdu* pdu);
    int             snmp_sess_send(void* , netsnmp_pdu*);
    int             snmp_sess_select_info2(void* , int*);
    int snmp_sess_select_info(void* sessp,int* block);
    int             snmp_close(netsnmp_session*);
    int             usm_rgenerate_out_msg(int, u_char* , size_t, int, int,
                                          u_char* , size_t, char* , size_t,
                                          int, u_char* , size_t, void* ,
                                          u_char** , size_t* , size_t*);
    int usm_secmod_rgenerate_out_msg(
                            struct snmp_secmod_outgoing_params* parms);

    void            usm_parse_config_usmUser(const char* token,
                                             char* line);

    void            init_usm_conf(const char* app);
    SNMPCallback    usm_store_users;
    struct usmUser* usm_create_initial_user(const char* name,
                                            const oid*  authProtocol,
                                            size_t authProtocolLen,
                                            const oid*  privProtocol,
                                            size_t privProtocolLen);
    struct usmUser* usm_read_user(char* line);

    int get_enginetime(u_char*  engineID,
                       u_int engineID_len,
                               u_int*  engine_boot,
                               u_int*  engine_time,
                               u_int authenticated);

    int             get_enginetime_ex(u_char*  engineID,
                                  u_int engineID_len,
                                  u_int*  engine_boot,
                                  u_int*  engine_time,
                                  u_int*  last_engine_time,
                                  u_int authenticated);
    void free_enginetime(unsigned char* engineID, size_t engineID_len);
    void free_etimelist(void);
    Enginetime
    search_enginetime_list(u_char*  engineID, u_int engineID_len);
    u_char*         asn_build_string(u_char* , size_t* , u_char,
                                     const u_char* , size_t);
    u_char*
    snmpv3_header_build(netsnmp_session*  session, netsnmp_pdu* pdu,
                    u_char*  packet, size_t*  out_length,
                    size_t length, u_char**  msg_hdr_e);

    u_char*
    snmpv3_scopedPDU_header_build(netsnmp_pdu* pdu,
                                      u_char*  packet,
                                      size_t*  out_length,
                              u_char**  spdu_e);

    int asn_realloc_rbuild_string(
                                u_char**  pkt,
                                          size_t*  pkt_len,
                                          size_t*  offset,
                                          int allow_realloc,
                                          u_char type,
                                          const u_char*  data,
                                          size_t data_size);
    int asn_realloc_rbuild_bitstring(
                                u_char**  pkt,
                                             size_t*  pkt_len,
                                             size_t*  offset,
                                             int allow_realloc,
                                             u_char type,
                                             const u_char*  data,
                                             size_t data_size);

    int usm_parse_security_parameters(
                                u_char*  secParams,
                                              size_t remaining,
                                              u_char*  secEngineID,
                                              size_t*  secEngineIDLen,
                                              u_int*  boots_uint,
                                              u_int*  time_uint,
                                              char* secName,
                                              size_t*  secNameLen,
                                              u_char*  signature,
                                              size_t*
                                              signature_length,
                                              u_char*  salt,
                                              size_t*  salt_length,
                                              u_char**  data_ptr);
    u_char*         asn_parse_string(u_char* , size_t* , u_char* ,
                                         u_char* , size_t*);
    u_char*         snmp_build_var_op(u_char* , oid* , size_t* , u_char,
                                          size_t, u_char* , size_t*);

    int snmp_sess_synch_response(void* sessp,
                     netsnmp_pdu* pdu, netsnmp_pdu** response);
    netsnmp_session* snmp_sess_session(void*);
    int _sess_process_packet(void* sessp, netsnmp_session*  sp,
        struct snmp_internal_session* isp,netsnmp_transport* transport,
        void* opaque, int olength,u_char*  packetptr, int length);
    int _snmp_parse(void* sessp, netsnmp_session*  session,
        netsnmp_pdu* pdu, u_char*  data, size_t length);
    int snmp_parse(void* sessp, netsnmp_session*  pss,
        netsnmp_pdu* pdu, u_char*  data, size_t length);
    long snmp_get_next_reqid(void);
    long snmp_get_next_msgid(void);
    u_char* snmp_pdu_build(netsnmp_pdu* pdu, u_char*  cp,
        size_t*  out_length);
    int _snmp_build(u_char**  pkt, size_t*  pkt_len, size_t*  offset,
        netsnmp_session*  session, netsnmp_pdu* pdu);
    int snmp_build(u_char**  pkt, size_t*  pkt_len, size_t*  offset,
       netsnmp_session*  pss, netsnmp_pdu* pdu);
    int snmpv3_packet_build(netsnmp_session* , netsnmp_pdu* pdu,
        u_char*  packet, size_t*  out_length, u_char*  pdu_data,
        size_t pdu_data_len);
    int snmpv3_build(u_char**  pkt, size_t*  pkt_len,
        size_t*  offset, netsnmp_session*  session,netsnmp_pdu* pdu);
    struct usmUser* usm_get_user_from_list(u_char*  engineID,
        size_t engineIDLen, char* name, struct usmUser* userList,
        int use_default);
    struct usmUser* usm_get_userList(void);
    struct usmUser* usm_add_user(struct usmUser* user);
    struct usmUser* usm_remove_user(struct usmUser* user);
    struct usmUser* usm_get_user(u_char*  engineID,
        size_t engineIDLen, char* name);
    int create_user_from_session(netsnmp_session*  session);
    int snmpv3_engineID_probe(struct snmp_session_list* slp,
        netsnmp_session*  in_session);
    int snmpv3_build_probe_pdu(netsnmp_pdu** pdu);
    int snmpv3_parse(netsnmp_pdu* pdu, u_char*  data, size_t*  length,
        u_char**  after_header, netsnmp_session*  sess);
    int snmp_sess_read2(void*);
    int snmp_sess_read(void* sessp);
    int _sess_read(void* sessp);
    int snmp_pdu_parse(netsnmp_pdu* pdu,
                       u_char*  data,
                       size_t*  length);
    long snmp_get_next_transid(void);

    int netsnmp_agent_check_packet(netsnmp_session* ,
        struct netsnmp_transport_s* , void* , int);
    int netsnmp_agent_check_parse(netsnmp_session* ,
                                  netsnmp_pdu* , int);
    int netsnmp_addrcache_add(const char* addr);
    netsnmp_callback_pass* callback_pop_queue(int num);
    int snmpv3_packet_realloc_rbuild(u_char**  pkt, size_t*  pkt_len,
                                 size_t*  offset,
                                 netsnmp_session*  session,
                                 netsnmp_pdu* pdu, u_char*  pdu_data,
                                 size_t pdu_data_len);

    int snmp_pdu_realloc_rbuild(u_char**  pkt, size_t*  pkt_len,
                            size_t*  offset, netsnmp_pdu* pdu);
    int snmpv3_scopedPDU_header_realloc_rbuild(
                                u_char**  pkt, size_t*  pkt_len,
                                   size_t*  offset, netsnmp_pdu* pdu,
                                   size_t body_len);
    int snmpv3_header_realloc_rbuild(u_char**  pkt, size_t*  pkt_len,
                         size_t*  offset, netsnmp_session*  session,
                         netsnmp_pdu* pdu);
    int snmp_realloc_rbuild_var_op(u_char**  pkt, size_t*  pkt_len,
                       size_t*  offset, int allow_realloc,
                       const oid*  var_name, size_t*  var_name_len,
                       u_char var_val_type,
                       u_char*  var_val, size_t var_val_len);
    int asn_realloc_rbuild_unsigned_int(u_char**  pkt,
                                        size_t*  pkt_len,
                            size_t*  offset, int r,
                                        u_char type,
                                        const u_long*  intp,
                                        size_t intsize);
    int asn_realloc_rbuild_objid(u_char**  pkt,
                                 size_t*  pkt_len,
                                 size_t*  offset,
                                 int r, u_char type,
                                 const oid*  objid,
                                 size_t objidlength);
    int asn_realloc_rbuild_unsigned_int64(u_char**  pkt,
                                          size_t*  pkt_len,
                                          size_t*  offset,
                                          int r, u_char type,
                                          counter64* cp,
                                          size_t countersize);
    int asn_realloc_rbuild_null(u_char**  pkt, size_t*  pkt_len,
                    size_t*  offset, int r, u_char type);
    int sendResponse(char* response,int length);
    char*  buildHexString(char a[],int len);

    void _init_agent_callback_transport(void);
    int handle_snmp_packet(int op, snmp_session*  session,
                           int reqid, netsnmp_pdu* pdu,
                           void* magic);
    snmp_session* netsnmp_callback_open(
                            int attach_to,
                            int (NetSnmpAgent::*return_func) (
                                                int op,
                                                snmp_session
                                                * session,
                                                int reqid,
                                                netsnmp_pdu
                                                *pdu,
                                                void* magic),
                            int (NetSnmpAgent::*fpre_parse) (
                                        snmp_session* ,
                                        struct netsnmp_transport_s* ,
                                        void* , int),
                            int (NetSnmpAgent::*fpost_parse) (
                                                snmp_session* ,
                                                       netsnmp_pdu* ,
                                                       int));
    int snmp_synch_input(int op, struct snmp_session*  session,
                            int reqid, struct snmp_pdu* pdu, void* magic);
    netsnmp_transport* netsnmp_callback_transport(int);
    int
    netsnmp_callback_recv(netsnmp_transport* t, void* buf, int size,
          void** opaque, int* olength);
    int
    netsnmp_callback_send(netsnmp_transport* t, void* buf, int size,
          void** opaque, int* olength);
    int netsnmp_callback_close(netsnmp_transport* t);
    int netsnmp_callback_accept(netsnmp_transport* t);
    char*
    netsnmp_callback_fmtaddr(netsnmp_transport* t,
                             void* data, int len);
    void            snmp_sess_init(snmp_session*);
    snmp_session* snmp_add_full(
                        netsnmp_session*  in_session,
                        struct netsnmp_transport_s* transport,
                        int (NetSnmpAgent::*fpre_parse) (
                                            snmp_session* ,
                                          struct
                                          netsnmp_transport_s
                                          *, void* , int),
                        int (NetSnmpAgent::*fparse) (
                                            snmp_session* ,
                                            netsnmp_pdu* ,
                                            u_char* ,
                                      size_t),
                        int (NetSnmpAgent::*fpost_parse) (
                                            snmp_session* ,
                                            netsnmp_pdu* ,
                                            int),
                        int (NetSnmpAgent::*fbuild) (
                                            snmp_session* ,
                                            netsnmp_pdu* ,
                                            u_char* ,
                                      size_t*),
                        int (NetSnmpAgent::*frbuild) (
                                            snmp_session* ,
                                       netsnmp_pdu* ,
                                            u_char** ,
                                            size_t* ,
                                       size_t*),
                        int (NetSnmpAgent::*fcheck) (
                                            u_char* ,
                                            size_t),
                        netsnmp_pdu*
                        (NetSnmpAgent::*fcreate_pdu) (
                                    struct netsnmp_transport_s
                                    *, void* , size_t));
    long snmp_get_next_sessid(void);
    void init_usmConf(void);
    void init_vacm_conf(void);
    void init_vacm_config_tokens(void);
    void vacm_free_group(void);
    void vacm_parse_group(const char* , char*);
    void vacm_free_access(void);
    void vacm_parse_access(const char* , char*);
    void vacm_parse_setaccess(const char* , char*);
    void vacm_parse_authuser(const char* , char*);
    void vacm_parse_authcommunity(const char* , char*);
    void vacm_create_simple(const char* , char* , int, int);
    void vacm_parse_rouser(const char* , char*);
    void vacm_parse_rocovacm_parse_rwusermmunity(const char* , char*);
    void vacm_parse_rwcommunity(const char* , char*);
    void vacm_parse_rocommunity6(const char* , char*);
    void vacm_parse_rwcommunity6(const char* , char*);
    void vacm_parse_view(const char* , char*);
    int vacm_standard_views (int majorID, int minorID,
                    void* serverarg, void* clientarg);
    void vacm_free_view(void);
    int vacm_warn_if_not_configured (int majorID, int minorID,
                                void* serverarg, void* clientarg);
    void vacm_parse_authaccess(const char* , char*);
    void init_vacm_snmpd_easy_tokens(void);
    int vacm_in_view_callback (int majorID, int minorID,
                                void* serverarg, void* clientarg);
    int _vacm_parse_access_common(const char* token, char* param,
                                  char** st, char** name,
                                  char** context, int* imodel,
                      int* ilevel, int* iprefix);
    int vacm_parse_authtokens(const char* token, char** confline);
    void vacm_gen_com2sec(int commcount, const char* community,
                          const char* addressname,
                          const char* publishtoken,
                          void (NetSnmpAgent::*parser)(const char* , char*),
                          char* secname, size_t secname_len,
                          char* viewname, size_t viewname_len,
                          int version);
    int vacm_check_view_contents(netsnmp_pdu* , oid* , size_t,
                                          int, int, int);
    int vacm_check_view(netsnmp_pdu* , oid* , size_t, int, int);
    int vacm_in_view(netsnmp_pdu* , oid* , size_t, int);

    void
        vacm_parse_rocommunity(const char* token, char* confline);
    void
    vacm_parse_rwuser(const char* token, char* confline);
    int
    netsnmp_handle_request(netsnmp_agent_session* asp, int status);
    int
    netsnmp_wrap_up_request(netsnmp_agent_session* asp, int status);
    int
    netsnmp_check_for_delegated_and_add(netsnmp_agent_session* asp);
    int handle_pdu(netsnmp_agent_session* asp);
    int netsnmp_add_queued(netsnmp_agent_session* asp);
    int netsnmp_check_delegated_chain_for(netsnmp_agent_session* asp);
    int get_set_cache(netsnmp_agent_session* asp);
    int netsnmp_create_subtree_cache(netsnmp_agent_session* asp);
    int in_a_view(oid* name, size_t* namelen,
                  netsnmp_pdu* pdu, int type);
    netsnmp_request_info*
    netsnmp_add_varbind_to_cache(netsnmp_agent_session* asp,
                                 int vbcount,
                                 netsnmp_variable_list*  varbind_ptr,
                                 struct netsnmp_subtree_s* tp);
    int check_acm(netsnmp_agent_session* asp, u_char type);
    int handle_var_requests(netsnmp_agent_session* asp);
    int handle_getnext_loop(netsnmp_agent_session* asp);
    int handle_set_loop(netsnmp_agent_session* asp);
    int netsnmp_check_for_delegated(netsnmp_agent_session* asp);
    agent_set_cache*  save_set_cache(netsnmp_agent_session* asp);
    int netsnmp_acm_check_subtree  (netsnmp_pdu* , oid* , size_t);
    int netsnmp_reassign_requests(netsnmp_agent_session* asp);
    int handle_set(netsnmp_agent_session* asp);
    netsnmp_pdu* _clone_pdu_header(netsnmp_pdu* pdu);
    netsnmp_pdu*  _clone_pdu (netsnmp_pdu* pdu, int drop_err);
    netsnmp_pdu*    snmp_clone_pdu(netsnmp_pdu* pdu);
    netsnmp_agent_session* init_agent_snmp_session(netsnmp_session* ,
                                                   netsnmp_pdu*);
    int snmp_select_info(int* block);
    void setCurrentPacket(unsigned char* packet, int packetSize);

    int snmp_send(netsnmp_session*  session, netsnmp_pdu* pdu);
    int snmp_async_send(netsnmp_session*  session, netsnmp_pdu* pdu);
    void*  snmp_sess_pointer(netsnmp_session*  session);

    unsigned char*  AsnBuildSequence(unsigned char*  data,
                                     int* datalength,
                                     unsigned char type,
                                     int length);
    unsigned char* AsnBuildHeader(register unsigned char* data,
                                  int* datalength,
    unsigned char type, int length);
    unsigned char*  AsnBuildInt(unsigned char* data,
                                int* datalength,
                                unsigned char type,
                                int* intp,
                                int intsize);
    unsigned char*  AsnBuildUnsignedInt(unsigned char*  data,
                                        int*  datalength,
                                        char type,
                                        unsigned long* intp,
                                        int intsize);
    unsigned char*  AsnBuildHeaderWithTruth(unsigned char* data,
                                            int* datalength,
                                            unsigned char type,
                                            int length, int truth);
    unsigned char*  AsnBuildLength(unsigned char* data,
                                   int* datalength,
         int length, int truth);
    unsigned char*  AsnBuildString(unsigned char* data,
                                   int* datalength,
                                   unsigned char type,
                                   char* string, int strlength);
    unsigned char* AsnBuildObjId(register unsigned char* data,
                                 int* datalength,
                                 unsigned char type,
                                 oid* objid,
                                 int objidlength);
    unsigned char*  AsnBuildNull(unsigned char* data,
                                 int* datalength,
                                 unsigned char type);
    unsigned char*  SnmpBuildResponse();
    int Snmpv1SendTrap(int trapValue);
    int Snmpv2SendTrap(int trapValue);
    int Snmpv3SendTrap(int trapValue);

#ifdef JNE_LIB
    int SendHmsLogoutTrap(int trapValue, netsnmp_variable_list* vars);
#endif

    char*  buildhexstring(char a[],int len);
    int snmp_hex_to_binary(u_char**  buf, size_t*  buf_len,
                           size_t*  offset,int allow_realloc,
                           char* hex);
    int netsnmp_hex_to_binary(u_char**  buf, size_t*  buf_len,
                              size_t*  offset,int allow_realloc,
                              const char* hex, const char* delim);
    void send_trap_to_sess(netsnmp_session*  sess,
                           netsnmp_pdu* template_pdu);
    int snmp_parse_args(int argc,
                        char** argv,
                        netsnmp_session*  session,
                        const char* localOpts,
                        void (NetSnmpAgent::*proc)(int, char* const* ,
                                                   int));
    netsnmp_session*  snmp_add(netsnmp_session*  in_session,
                               netsnmp_transport* transport,
                                   int (NetSnmpAgent::*fpre_parse)(
                                                    netsnmp_session* ,
                                                    netsnmp_transport* ,
                                                    void* , int),
                                   int (NetSnmpAgent::*fpost_parse)(
                                                    netsnmp_session* ,
                                                    netsnmp_pdu* , int));
    int add_trap_session(netsnmp_session*  ss, int pdutype,
                             int confirm, int version);
    int snmp_callback_available(int major, int minor);
    void free_trap_session(struct trap_sink* sp);
    int netsnmp_register_mib(const char* moduleName,
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
                     netsnmp_handler_registration* reginfo,
                     int perform_callback);
    netsnmp_mib_handler*  netsnmp_get_bulk_to_next_handler(void);
    int netsnmp_register_serialize(netsnmp_handler_registration*
                                     reginfo);
    int netsnmp_register_scalar_group(netsnmp_handler_registration*
                                        reginfo, oid first, oid last);
    int
    netsnmp_inject_handler_before(netsnmp_handler_registration*
                                    reginfo,
                                    netsnmp_mib_handler* handler,
                                    const char* before_what);
    int netsnmp_inject_handler(netsnmp_handler_registration* reginfo,
                       netsnmp_mib_handler* handler);
    void netsnmp_inject_handler_into_subtree(
                                    struct netsnmp_subtree_s* tp,
                                    const char* name,
                                    netsnmp_mib_handler* handler,
                                    const char* before_what);
    netsnmp_handler_registration*  get_reg(const char* name,
                                    const char* ourname,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len,
                                    void* it,
                                    int modes,
                                    Netsnmp_Node_Handler*  scalarh,
                                    Netsnmp_Node_Handler*  subhandler,
                                    const char* contextName);
    int   netsnmp_register_table(
                                   netsnmp_handler_registration*
                                   reginfo,
                                   netsnmp_table_registration_info*
                                   tabreq);
    netsnmp_handler_registration*
    netsnmp_create_handler_registration(
                                    const char* name,
                                    Netsnmp_Node_Handler*
                                    handler_access_method,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len, int modes);
    netsnmp_mib_handler* netsnmp_get_cache_handler(int,
                                                        NetsnmpCacheLoad* ,
                                                        NetsnmpCacheFree* ,
                                                        const oid*, int);

    void     init_ip(void);

    int netsnmp_call_handler(netsnmp_mib_handler* next_handler,
                                         netsnmp_handler_registration
                                         *reginfo,
                                         netsnmp_agent_request_info
                                         *reqinfo,
                                         netsnmp_request_info* requests);

    int netsnmp_call_handlers(netsnmp_handler_registration
                                *reginfo,
                                netsnmp_agent_request_info
                                *reqinfo,
                                netsnmp_request_info* requests);
    int netsnmp_register_old_api(const char* moduleName,
                             struct variable* var,
                             size_t varsize,
                             size_t numvars,
                             oid*  mibloc,
                             size_t mibloclen,
                             int priority,
                             int range_subid,
                             oid range_ubound,
                             netsnmp_session*  ss,
                                     const char* context, int timeout,
                                     int flags);
    int register_mib_context(const char* , struct variable* ,
                        size_t, size_t, oid* , size_t,
                        int, int, oid, netsnmp_session* ,
                        const char* , int, int);
    int register_mib_range(const char* , struct variable* ,
                        size_t, size_t, oid* , size_t,
                        int, int, oid, netsnmp_session*);
    int register_mib_priority(const char* , struct variable* ,
                        size_t, size_t, oid* , size_t,
                        int);
    int register_mib(const char* , struct variable* ,
                 size_t, size_t, oid* , size_t);
    void init_interfaces(void);
    netsnmp_cache*
    netsnmp_cache_create(int timeout, NetsnmpCacheLoad*  load_hook,
                     NetsnmpCacheFree*  free_hook,
                     const oid*  rootoid, int rootoid_len);
    int             _cache_load(netsnmp_cache* cache);
    netsnmp_mib_handler*
    netsnmp_cache_handler_get(netsnmp_cache* cache);
    void init_tcp(void);
    void init_snmp_mib(void);
    void init_udp(void);
    void init_udpTable(void);
    void netsnmp_table_helper_add_indexes(
                netsnmp_table_registration_info* tinfo, ...);
    int
    netsnmp_register_table_iterator(netsnmp_handler_registration* reginfo,
                                    netsnmp_iterator_info* iinfo);
    netsnmp_mib_handler*
    netsnmp_get_table_iterator_handler(netsnmp_iterator_info*
                                           iinfo);
    void netsnmp_init_stash_cache_helper(void);
    netsnmp_mib_handler*
    netsnmp_get_timed_bare_stash_cache_handler(int timeout,
                                               oid* rootoid,
                                               size_t rootoid_len);
    netsnmp_mib_handler* netsnmp_get_stash_cache_handler(void);
    netsnmp_mib_handler* netsnmp_get_bare_stash_cache_handler(void);
    void init_at(void);
    void init_icmp(void);
    u_int snmp_increment_statistic(int which);
    u_int snmp_increment_statistic_by(int which, int count);
    void snmp_free_session(netsnmp_session*  s);
    int netsnmp_callback_clear_client_arg(void* ptr, int i, int j);
    void netsnmp_ds_shutdown(void);
    void unregister_config_handler(const char* type_param,
                                    const char* token);
    void clear_callback(void);
    void shutdown_mib(void);
    void unload_all_mibs(void);
    void unload_module_by_ID(int modID, struct tree* tree_top);
    int snmp_close_sessions(void);
    void unregister_all_config_handlers(void);
    void clear_snmp_enum(void);
    void clear_user_list(void);
    void clear_context(void);
    void clear_lookup_cache(void);
    void netsnmp_context_subtree_free();
    subtree_context_cache* get_top_context_cache(void);
    void netsnmp_clear_handler_list(void);
    void init_snmpQualnetTutorialMIB(void);
    void netsnmp_udp_parse_security(const char* token, char* param);
    void netsnmp_udp_com2SecList_free(void);
    int  netsnmp_udp_getSecName(void* opaque, int olength,
                       const char* community,
                       size_t community_len, char** secName,
                       char** contextName);
#ifdef JNE_LIB
    void init_jtrsMiMIB(void);
    void init_jtrsMdlMIB(void);
    void init_jtrsSiSAdapterMIB(void);
    void init_jtrsWnwMIB(void);
    void init_jtrsHms(void);
    void init_hmsNotification(void);
    void init_hmsChannel(void);
    void init_hmsWfSrw10cStatus(void);
    void init_hmsWfSrw10cStat(void);
    void init_hmsWfSrw10cCtrl(void);
    void init_hmsWfSrw10cConfig(void);
    void init_ittrSrwStats(void); // LFXG Move this code over into ./interfaces/jne/mib/*
#endif
};

#endif /*NETSNMP_H */
