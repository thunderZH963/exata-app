/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
#ifndef SNMP_API_H_NETSNMP
#define SNMP_API_H_NETSNMP

#include "types_netsnmp.h"
#include "snmp_transport_netsnmp.h"
#define SET_SNMP_ERROR(x) snmp_errno=(x)

/*
 * A list of all the outstanding requests for a particular session.
 */
#ifdef SNMP_NEED_REQUEST_LIST
typedef struct request_list {
    struct request_list* next_request;
    long            request_id;     /* request id */
    long            message_id;     /* message id */
    netsnmp_callback callback;      /* user callback per request (NULL if unused) */
    void*           cb_data;        /* user callback data per request (NULL if unused) */
    int             retries;        /* Number of retries */
    u_long          timeout;        /* length to wait for timeout */
    struct timeval  time;   /* Time this request was made */
    struct timeval  expire; /* time this request is due to expire */
    struct snmp_session* session;
    netsnmp_pdu*    pdu;    /* The pdu for this request
                 * (saved so it can be retransmitted */
} netsnmp_request_list;
#endif                          /* SNMP_NEED_REQUEST_LIST */

    /*
     * Set fields in session and pdu to the following to get a default or unconfigured value.
     */
#define SNMP_DEFAULT_COMMUNITY_LEN  0   /* to get a default community name */
#define SNMP_DEFAULT_RETRIES        -1
#define SNMP_DEFAULT_TIMEOUT        -1
#define SNMP_DEFAULT_REMPORT        0
#define SNMP_DEFAULT_REQID        -1
#define SNMP_DEFAULT_MSGID        -1
#define SNMP_DEFAULT_ERRSTAT        -1
#define SNMP_DEFAULT_ERRINDEX        -1
#define SNMP_DEFAULT_ADDRESS        0
#define SNMP_DEFAULT_PEERNAME        NULL
#define SNMP_DEFAULT_ENTERPRISE_LENGTH    0
#define SNMP_DEFAULT_TIME        0
#define SNMP_DEFAULT_VERSION        -1
#define SNMP_DEFAULT_SECMODEL        -1
#define SNMP_DEFAULT_CONTEXT        ""

#ifndef NETSNMP_DISABLE_MD5
#define SNMP_DEFAULT_AUTH_PROTO     usmHMACMD5AuthProtocol
#else
#define SNMP_DEFAULT_AUTH_PROTO     usmHMACSHA1AuthProtocol
#endif
#define SNMP_DEFAULT_AUTH_PROTOLEN  USM_LENGTH_OID_TRANSFORM
#ifndef NETSNMP_DISABLE_DES
#define SNMP_DEFAULT_PRIV_PROTO     usmDESPrivProtocol
#else
#define SNMP_DEFAULT_PRIV_PROTO     usmAESPrivProtocol
#endif
#define SNMP_DEFAULT_PRIV_PROTOLEN  USM_LENGTH_OID_TRANSFORM



#define SNMP_MAX_MSG_SIZE          1472 /* ethernet MTU minus IP/UDP header */
#define SNMP_MAX_MSG_V3_HDRS       (4+3+4+7+7+3+7+16)   /* fudge factor=16 */
#define SNMP_MAX_ENG_SIZE          32
#define SNMP_MAX_SEC_NAME_SIZE     256
#define SNMP_MAX_CONTEXT_SIZE      256
#define SNMP_SEC_PARAM_BUF_SIZE    256

    /*
     * Error return values.
     *
     * SNMPERR_SUCCESS is the non-PDU "success" code.
     *
     * XXX  These should be merged with SNMP_ERR_* defines and confined
     *      to values < 0.  ???
     */
#define SNMPERR_SUCCESS            (0)     /* XXX  Non-PDU "success" code. */
#define SNMPERR_GENERR            (-1)
#define SNMPERR_BAD_LOCPORT        (-2)
#define SNMPERR_BAD_ADDRESS        (-3)
#define SNMPERR_BAD_SESSION        (-4)
#define SNMPERR_TOO_LONG        (-5)
#define SNMPERR_NO_SOCKET        (-6)
#define SNMPERR_V2_IN_V1        (-7)
#define SNMPERR_V1_IN_V2        (-8)
#define SNMPERR_BAD_REPEATERS        (-9)
#define SNMPERR_BAD_REPETITIONS        (-10)
#define SNMPERR_BAD_ASN1_BUILD        (-11)
#define SNMPERR_BAD_SENDTO        (-12)
#define SNMPERR_BAD_PARSE        (-13)
#define SNMPERR_BAD_VERSION        (-14)
#define SNMPERR_BAD_SRC_PARTY        (-15)
#define SNMPERR_BAD_DST_PARTY        (-16)
#define SNMPERR_BAD_CONTEXT        (-17)
#define SNMPERR_BAD_COMMUNITY        (-18)
#define SNMPERR_NOAUTH_DESPRIV        (-19)
#define SNMPERR_BAD_ACL            (-20)
#define SNMPERR_BAD_PARTY        (-21)
#define SNMPERR_ABORT            (-22)
#define SNMPERR_UNKNOWN_PDU        (-23)
#define SNMPERR_TIMEOUT         (-24)
#define SNMPERR_BAD_RECVFROM         (-25)
#define SNMPERR_BAD_ENG_ID         (-26)
#define SNMPERR_BAD_SEC_NAME         (-27)
#define SNMPERR_BAD_SEC_LEVEL         (-28)
#define SNMPERR_ASN_PARSE_ERR           (-29)
#define SNMPERR_UNKNOWN_SEC_MODEL     (-30)
#define SNMPERR_INVALID_MSG             (-31)
#define SNMPERR_UNKNOWN_ENG_ID          (-32)
#define SNMPERR_UNKNOWN_USER_NAME     (-33)
#define SNMPERR_UNSUPPORTED_SEC_LEVEL     (-34)
#define SNMPERR_AUTHENTICATION_FAILURE     (-35)
#define SNMPERR_NOT_IN_TIME_WINDOW     (-36)
#define SNMPERR_DECRYPTION_ERR          (-37)
#define SNMPERR_SC_GENERAL_FAILURE    (-38)
#define SNMPERR_SC_NOT_CONFIGURED    (-39)
#define SNMPERR_KT_NOT_AVAILABLE    (-40)
#define SNMPERR_UNKNOWN_REPORT          (-41)
#define SNMPERR_USM_GENERICERROR        (-42)
#define SNMPERR_USM_UNKNOWNSECURITYNAME        (-43)
#define SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL    (-44)
#define SNMPERR_USM_ENCRYPTIONERROR        (-45)
#define SNMPERR_USM_AUTHENTICATIONFAILURE    (-46)
#define SNMPERR_USM_PARSEERROR            (-47)
#define SNMPERR_USM_UNKNOWNENGINEID        (-48)
#define SNMPERR_USM_NOTINTIMEWINDOW        (-49)
#define SNMPERR_USM_DECRYPTIONERROR        (-50)
#define SNMPERR_NOMIB            (-51)
#define SNMPERR_RANGE            (-52)
#define SNMPERR_MAX_SUBID        (-53)
#define SNMPERR_BAD_SUBID        (-54)
#define SNMPERR_LONG_OID        (-55)
#define SNMPERR_BAD_NAME        (-56)
#define SNMPERR_VALUE            (-57)
#define SNMPERR_UNKNOWN_OBJID        (-58)
#define SNMPERR_NULL_PDU        (-59)
#define SNMPERR_NO_VARS            (-60)
#define SNMPERR_VAR_TYPE        (-61)
#define SNMPERR_MALLOC            (-62)
#define SNMPERR_KRB5            (-63)
#define SNMPERR_PROTOCOL        (-64)
#define SNMPERR_OID_NONINCREASING       (-65)
#define SNMPERR_JUST_A_CONTEXT_PROBE    (-66)

#define SNMPERR_MAX            (-66)

//static long     Reqid = 0;      /* MT_LIB_REQUESTID */
//static long     Msgid = 0;      /* MT_LIB_MESSAGEID */
//static long     Sessid = 0;     /* MT_LIB_SESSIONID */
//static long     Transid = 0;    /* MT_LIB_TRANSID */


#include "types_netsnmp.h"

void            snmp_free_var_internals(netsnmp_variable_list*);     /* frees contents only */

/*
 * @file snmp_api.h - API for access to snmp.
 *
 * @addtogroup library
 *
 * Caution: when using this library in a multi-threaded application,
 * the values of global variables "snmp_errno" and "snmp_detail"
 * cannot be reliably determined.  Suggest using snmp_error()
 * to obtain the library error codes.
 *
 * @{
 */

#define SNMP_DEFAULT_ERRSTAT        -1
#define SNMP_DEFAULT_ERRINDEX        -1
#define SNMP_DEFAULT_VERSION        -1
#define SNMP_DEFAULT_SECMODEL        -1
unsigned int*  snmp_duplicate_objid(const unsigned int*   objToCopy, size_t);
int snmp_oid_compare(const oid*  in_name1,size_t len1, const oid*  in_name2, size_t len2);
netsnmp_variable_list*  snmp_varlist_add_variable(netsnmp_variable_list**  varlist,
                                                  const oid*  name,
                                                  size_t name_length,
                                                  u_char type,
                                                  const void*  value,
                                                  size_t len);

int             netsnmp_oid_equals(const unsigned int* , size_t,
                                   const unsigned int* ,
                                   size_t);

int             netsnmp_oid_compare_ll(const unsigned int*  in_name1,
                                           size_t len1, const unsigned int*  in_name2,
                                           size_t len2, size_t* offpt);

netsnmp_variable_list*
snmp_varlist_add_variable(netsnmp_variable_list**  varlist,
                          const oid*  name,
                          size_t name_length,
                          u_char type, const void*  value, size_t len);
void
snmp_set_detail(const char* detail_string);
#define NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE    1
#define NETSNMP_CALLBACK_OP_TIMED_OUT        2
#define NETSNMP_CALLBACK_OP_SEND_FAILED        3
#define NETSNMP_CALLBACK_OP_CONNECT        4
#define NETSNMP_CALLBACK_OP_DISCONNECT        5


/*
* mpd stats
*/
#define   STAT_SNMPUNKNOWNSECURITYMODELS     0
#define   STAT_SNMPINVALIDMSGS               1
#define   STAT_SNMPUNKNOWNPDUHANDLERS        2
#define   STAT_MPD_STATS_START               STAT_SNMPUNKNOWNSECURITYMODELS
#define   STAT_MPD_STATS_END                 STAT_SNMPUNKNOWNPDUHANDLERS

#define  MAX_STATS                           44

    /*
     * target mib counters
     */
#define  STAT_SNMPUNAVAILABLECONTEXTS         41
#define  STAT_SNMPUNKNOWNCONTEXTS         42
#define  STAT_TARGET_STATS_START             STAT_SNMPUNAVAILABLECONTEXTS
#define  STAT_TARGET_STATS_END               STAT_SNMPUNKNOWNCONTEXTS

    /*
     * usm stats
     */
#define   STAT_USMSTATSUNSUPPORTEDSECLEVELS  3
#define   STAT_USMSTATSNOTINTIMEWINDOWS      4
#define   STAT_USMSTATSUNKNOWNUSERNAMES      5
#define   STAT_USMSTATSUNKNOWNENGINEIDS      6
#define   STAT_USMSTATSWRONGDIGESTS          7
#define   STAT_USMSTATSDECRYPTIONERRORS      8
#define   STAT_USM_STATS_START               STAT_USMSTATSUNSUPPORTEDSECLEVELS
#define   STAT_USM_STATS_END                 STAT_USMSTATSDECRYPTIONERRORS


    /*
     * snmp counters
     */
#define  STAT_SNMPINPKTS                     9
#define  STAT_SNMPOUTPKTS                    10
#define  STAT_SNMPINBADVERSIONS              11
#define  STAT_SNMPINBADCOMMUNITYNAMES        12
#define  STAT_SNMPINBADCOMMUNITYUSES         13
#define  STAT_SNMPINASNPARSEERRS             14


    /*
     * authoritative engine definitions
     */
#define SNMP_SESS_NONAUTHORITATIVE 0    /* should be 0 to default to this */
#define SNMP_SESS_AUTHORITATIVE    1    /* don't learn engineIDs */
#define SNMP_SESS_UNKNOWNAUTH      2    /* sometimes (like NRs) */


#define SNMP_FLAGS_UDP_BROADCAST   0x800
#define SNMP_FLAGS_RESP_CALLBACK   0x400      /* Additional callback on response */
#define SNMP_FLAGS_USER_CREATED    0x200      /* USM user has been created */
#define SNMP_FLAGS_DONT_PROBE      0x100      /* don't probe for an engineID */
#define SNMP_FLAGS_STREAM_SOCKET   0x80
#define SNMP_FLAGS_LISTENING       0x40 /* Server stream sockets only */
#define SNMP_FLAGS_SUBSESSION      0x20
#define SNMP_FLAGS_STRIKE2         0x02
#define SNMP_FLAGS_STRIKE1         0x01

    /*
     * to determine type of Report from varbind_list
     */
#define REPORT_STATS_LEN 9
#define REPORT_snmpUnknownSecurityModels_NUM 1
#define REPORT_snmpInvalidMsgs_NUM 2
#define REPORT_usmStatsUnsupportedSecLevels_NUM 1
#define REPORT_usmStatsNotInTimeWindows_NUM 2
#define REPORT_usmStatsUnknownUserNames_NUM 3
#define REPORT_usmStatsUnknownEngineIDs_NUM 4
#define REPORT_usmStatsWrongDigests_NUM 5
#define REPORT_usmStatsDecryptionErrors_NUM 6

    /*
     * #define  STAT_SNMPINBADTYPES              15
     */
#define  STAT_SNMPINTOOBIGS                  16
#define  STAT_SNMPINNOSUCHNAMES              17
#define  STAT_SNMPINBADVALUES                18
#define  STAT_SNMPINREADONLYS                19
#define  STAT_SNMPINGENERRS                  20
#define  STAT_SNMPINTOTALREQVARS             21
#define  STAT_SNMPINTOTALSETVARS             22
#define  STAT_SNMPINGETREQUESTS              23
#define  STAT_SNMPINGETNEXTS                 24
#define  STAT_SNMPINSETREQUESTS              25
#define  STAT_SNMPINGETRESPONSES             26
#define  STAT_SNMPINTRAPS                    27
#define  STAT_SNMPOUTTOOBIGS                 28
#define  STAT_SNMPOUTNOSUCHNAMES             29
#define  STAT_SNMPOUTBADVALUES               30

    /*
     * #define  STAT_SNMPOUTREADONLYS            31
     */
#define  STAT_SNMPOUTGENERRS                 32
#define  STAT_SNMPOUTGETREQUESTS             33
#define  STAT_SNMPOUTGETNEXTS                34
#define  STAT_SNMPOUTSETREQUESTS             35
#define  STAT_SNMPOUTGETRESPONSES            36
#define  STAT_SNMPOUTTRAPS                   37
#define  AUTHTRAPENABLE                      38
#define  STAT_INFORM_ACK                     39
#define  STAT_OUTINFORM                      40
#define  STAT_INBULKREQ                      43

    /*
     * set to one to ignore unauthenticated Reports
     */
#define SNMPV3_IGNORE_UNAUTH_REPORTS 0

class NetSnmpAgent;

typedef struct request_list {
    struct request_list* next_request;
    long            request_id;     /* request id */
    long            message_id;     /* message id */
    int     (NetSnmpAgent::*callback) (int, netsnmp_session* , int,
                                          netsnmp_pdu* , void*);
    void*           cb_data;        /* user callback data per request (NULL if unused) */
    int             retries;        /* Number of retries */
    u_long          timeout;        /* length to wait for timeout */
    struct timeval  time;   /* Time this request was made */
    struct timeval  expire; /* time this request is due to expire */
    struct snmp_session* session;
    netsnmp_pdu*    pdu;    /* The pdu for this request
                 * (saved so it can be retransmitted */
} netsnmp_request_list;

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    netsnmp_request_list* requests;     /* Info about outstanding requests */
    netsnmp_request_list* requestsEnd;  /* ptr to end of list */
    int             (NetSnmpAgent::*hook_pre) (netsnmp_session* , netsnmp_transport* ,
                                 void* , int);
    int             (NetSnmpAgent::*hook_parse) (netsnmp_session* , netsnmp_pdu* ,
                                   u_char* , size_t);
    int             (NetSnmpAgent::*hook_post) (netsnmp_session* , netsnmp_pdu* , int);
    int             (NetSnmpAgent::*hook_build) (netsnmp_session* , netsnmp_pdu* ,
                                   u_char* , size_t*);
    int             (NetSnmpAgent::*hook_realloc_build) (netsnmp_session* ,
                                           netsnmp_pdu* , u_char** ,
                                           size_t* , size_t*);
    int             (NetSnmpAgent::*check_packet) (u_char* , size_t);
    netsnmp_pdu*    (NetSnmpAgent::*hook_create_pdu) (netsnmp_transport* ,
                                        void* , size_t);

    u_char*         packet;
    size_t          packet_len, packet_size;
};

/*
 * The list of active/open sessions.
 */
struct snmp_session_list {
    struct snmp_session_list* next;
    netsnmp_session* session;
    netsnmp_transport* transport;
    struct snmp_internal_session* internal;
};

int             snmp_oid_ncompare(const oid* , size_t, const oid* ,
                                      size_t, size_t);


netsnmp_session*
snmp_sess_session(void* sessp);
int snmp_sess_synch_response(void* sessp, netsnmp_pdu* pdu,
                             netsnmp_pdu** response);

const char*     snmp_pdu_type(int type);

int             snmpv3_get_report_type(netsnmp_pdu* pdu);

long snmp_get_next_sessid(void);

u_char* snmpv3_scopedPDU_parse(netsnmp_pdu* pdu, u_char*  cp, size_t*  length);

int netsnmp_oid_find_prefix(const oid*  in_name1, size_t len1,
                            const oid*  in_name2, size_t len2);

int check_for_inform_ack(oid obj[]);

#endif /* SNMP_API_H_NETSNMP */


