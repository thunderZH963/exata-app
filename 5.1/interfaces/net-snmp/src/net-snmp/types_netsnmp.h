#ifndef NET_SNMP_TYPES_H_NETSNMP
#define NET_SNMP_TYPES_H_NETSNMP

#include "winsock_netsnmp.h"
#include "asn1_netsnmp.h"

class NetSnmpAgent;
typedef void*   marker_t;

typedef unsigned char u_char ;
typedef unsigned long u_long ;
typedef unsigned int u_int ;
typedef unsigned short u_short ;
typedef u_int oid;

#ifndef HAVE_IN_ADDR_T
typedef u_int in_addr_t;
#endif

typedef struct netsnmp_index_s {
    size_t      len;
    oid*         oids;
} netsnmp_index;


typedef struct netsnmp_void_array_s {
    size_t  size;
    void**  array;
} netsnmp_void_array;

/*
* references to various types
*/
typedef struct netsnmp_ref_void {
    void*  val;
} netsnmp_ref_void;

typedef union {
    u_long  ul;
    u_int   ui;
    u_short us;
    u_char  uc;
    long    sl;
    int     si;
    short   ss;
    char    sc;
    char*   cp;
    void*   vp;
} netsnmp_cvalue;

typedef struct netsnmp_ref_size_t_s {
    size_t val;
} * netsnmp_ref_size_t;

#define USM_AUTH_KU_LEN     32
#define USM_PRIV_KU_LEN     32

#ifndef MAX_OID_LEN
#define MAX_OID_LEN     64
#endif
/** @typedef struct snmp_session netsnmp_session
 * Typedefs the snmp_session struct intonetsnmp_session */
        struct snmp_session;
typedef struct snmp_session netsnmp_session;
    /*
     *  For the initial release, this will just refer to the
     *  relevant UCD header files.
     *    In due course, the types and structures relevant to the
     *  Net-SNMP API will be identified, and defined here directly.
     *
     *  But for the time being, this header file is primarily a placeholder,
     *  to allow application writers to adopt the new header file names.
     */

typedef union {
   long*           integer;
   unsigned char*         string;
   unsigned int*            objid;
   unsigned char*         bitstring;
   struct counter64* counter64;
   #ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
   float*          floatVal;
   double*         doubleVal;

   #endif
    } netsnmp_vardata;

/** @typedef struct variable_list netsnmp_variable_list
 * Typedefs the variable_list struct into netsnmp_variable_list */
/** @struct variable_list
 * The netsnmp variable list binding structure, it's typedef'd to
 * netsnmp_variable_list.
 */
typedef struct variable_list {
   /** NULL for last variable */
   struct variable_list* next_variable;
   /** Object identifier of variable */
   // ******************************************** to be noted ********************************
   unsigned int* name;
   /** number of subid's in name */
   size_t name_length;
   /** ASN type of variable */
   unsigned char type;
   /** value of variable */
    netsnmp_vardata val;
   /** the length of the value to be copied into buf */
   size_t val_len;
   /** 90 percentile < 24. */
   // ******************************************** to be noted ********************************
   unsigned int name_loc[MAX_OID_LEN];
   /** 90 percentile < 40. */
   unsigned char buf[40];
   /** (Opaque) hook for additional data */
   void* data;
   /** callback to free above */
   void (*dataFreeHook)(void*);
   int index;
} netsnmp_variable_list;

/** @typedef struct snmp_pdu to netsnmp_pdu
 * Typedefs the snmp_pdu struct into netsnmp_pdu */
/** @struct snmp_pdu
 * The snmp protocol data unit.
 */
typedef struct snmp_pdu {

#define non_repeaters    errstat
#define max_repetitions errindex

    /*
     * Protocol-version independent fields
     */
    /** snmp version */
    long            version;
    /** Type of this PDU */
    int             command;
    /** Request id - note: not incremented on retries */
    long            reqid;
    /** Message id for V3 messages note: incremented for each retry */
    long            msgid;
    /** Unique ID for incoming transactions */
    long            transid;
    /** Session id for AgentX messages */
    long            sessid;
    /** Error status (non_repeaters in GetBulk) */
    long            errstat;
    /** Error index (max_repetitions in GetBulk) */
    long            errindex;
    /** Uptime */
    unsigned long          time;
    unsigned long          flags;

    int             securityModel;
    /** noAuthNoPriv, authNoPriv, authPriv */
    int             securityLevel;
    int             msgParseModel;

    /**
     * Transport-specific opaque data.  This replaces the IP-centric address
     * field.
     */

    void*           transport_data;
    int             transport_data_length;

    /**
     * The actual transport domain.  This SHOULD NOT BE FREE()D.
     */

    const unsigned long*      tDomain;
    size_t          tDomainLen;

    netsnmp_variable_list* variables;


    /*
     * SNMPv1 & SNMPv2c fields
     */
    /** community for outgoing requests. */
    unsigned char*         community;
    /** length of community name. */
    size_t          community_len;

    /*
     * Trap information
     */
    /** System OID */
    unsigned int*            enterprise;
    size_t          enterprise_length;
    /** trap type */
    long            trap_type;
    /** specific type */
    long            specific_type;
    /** This is ONLY used for v1 TRAPs  */
    unsigned char   agent_addr[4];

    /*
     *  SNMPv3 fields
     */
    /** context snmpEngineID */
    unsigned char*         contextEngineID;
    /** Length of contextEngineID */
    size_t          contextEngineIDLen;
    /** authoritative contextName */
    char*           contextName;
    /** Length of contextName */
    size_t          contextNameLen;
    /** authoritative snmpEngineID for security */
    unsigned char*         securityEngineID;
    /** Length of securityEngineID */
    size_t          securityEngineIDLen;
    /** on behalf of this principal */
    char*           securityName;
    /** Length of securityName. */
    size_t          securityNameLen;

    /*
     * AgentX fields
     *      (also uses SNMPv1 community field)
     */
    int             priority;
    int             range_subid;

    void*           securityStateRef;
} netsnmp_pdu;


typedef int        (*snmp_callback) (int, netsnmp_session* , int,
                                          netsnmp_pdu* , void*);
typedef int     (*netsnmp_callback) (int, netsnmp_session* , int,
                                          netsnmp_pdu* , void*);

/** @struct snmp_session
 * The snmp session structure.
 */

struct snmp_session {
    /*
     * Protocol-version independent fields
     */
    /** snmp version */
    long            version;
    /** Number of retries before timeout. */
    int             retries;
    /** Number of uS until first timeout, then exponential backoff */
    long            timeout;
    unsigned long          flags;
    struct snmp_session* subsession;
    struct snmp_session* next;

    /** name or address of default peer (may include transport specifier and/or port number) */
    char*           peername;
    /** UDP port number of peer. (NO LONGER USED - USE peername INSTEAD) */
    unsigned short         remote_port;
    /** My Domain name or dotted IP address, 0 for default */
    char*           localname;
    /** My UDP port number, 0 for default, picked randomly */
    unsigned short         local_port;
    /**
     * Authentication function or NULL if null authentication is used
     */
    unsigned char*         (*authenticator) (u_char* , size_t* , u_char* , size_t);
    /** Function to interpret incoming data */
    int     (NetSnmpAgent::*callback) (int, netsnmp_session* , int,
                                          netsnmp_pdu* , void*);
    /**
     * Pointer to data that the callback function may consider important
     */
    void*           callback_magic;
    /** copy of system errno */
    int             s_errno;
    /** copy of library errno */
    int             s_snmp_errno;
    /** Session id - AgentX only */
    long            sessid;

    /*
     * SNMPv1 & SNMPv2c fields
     */
    /** community for outgoing requests. */
    unsigned char*         community;
    /** Length of community name. */
    size_t          community_len;
    /**  Largest message to try to receive.  */
    size_t          rcvMsgMaxSize;
    /**  Largest message to try to send.  */
    size_t          sndMsgMaxSize;

    /*
     * SNMPv3 fields
     */
    /** are we the authoritative engine? */
    unsigned char          isAuthoritative;
    /** authoritative snmpEngineID */
    unsigned char*         contextEngineID;
    /** Length of contextEngineID */
    size_t          contextEngineIDLen;
    /** initial engineBoots for remote engine */
   unsigned int           engineBoots;
    /** initial engineTime for remote engine */
   unsigned int           engineTime;
    /** authoritative contextName */
    char*           contextName;
    /** Length of contextName */
    size_t          contextNameLen;
    /** authoritative snmpEngineID */
    unsigned char*         securityEngineID;
    /** Length of contextEngineID */
    size_t          securityEngineIDLen;
    /** on behalf of this principal */
    char*           securityName;
    /** Length of securityName. */
    size_t          securityNameLen;

    /** auth protocol oid */
    unsigned int*            securityAuthProto;
    /** Length of auth protocol oid */
    size_t          securityAuthProtoLen;
    /** Ku for auth protocol XXX */
    unsigned char          securityAuthKey[USM_AUTH_KU_LEN];
    /** Length of Ku for auth protocol */
    size_t          securityAuthKeyLen;
    /** Kul for auth protocol */
    unsigned char*          securityAuthLocalKey;
    /** Length of Kul for auth protocol XXX */
    size_t          securityAuthLocalKeyLen;

    /** priv protocol oid */
    unsigned int*             securityPrivProto;
    /** Length of priv protocol oid */
    size_t          securityPrivProtoLen;
    /** Ku for privacy protocol XXX */
    unsigned char          securityPrivKey[USM_PRIV_KU_LEN];
    /** Length of Ku for priv protocol */
    size_t          securityPrivKeyLen;
    /** Kul for priv protocol */
    unsigned char*          securityPrivLocalKey;
    /** Length of Kul for priv protocol XXX */
    size_t          securityPrivLocalKeyLen;

    /** snmp security model, v1, v2c, usm */
    int             securityModel;
    /** noAuthNoPriv, authNoPriv, authPriv */
    int             securityLevel;
    /** target param name */
    char*           paramName;

    /**
     * security module specific
     */
    void*           securityInfo;

    /**
     * use as you want data
     *
     *     used by 'SNMP_FLAGS_RESP_CALLBACK' handling in the agent
     * XXX: or should we add a new field into this structure?
     */
    void*           myvoid;
};

    void            atime_setMarker(marker_t pm);
#endif /*NET_SNMP_TYPES_H_NETSNMP */
