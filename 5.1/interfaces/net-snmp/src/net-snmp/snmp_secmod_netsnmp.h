#ifndef SNMP_SECMOD_H_NETSNMP
#define SNMP_SECMOD_H_NETSNMP
#include "snmp_transport_netsnmp.h"



/* Locally defined security models.
 * (Net-SNMP enterprise number = 8072)*256 + local_num
 */
#define NETSNMP_KSM_SECURITY_MODEL     2066432
#define NETSNMP_TSM_SECURITY_MODEL     2066434

struct snmp_secmod_def;
class NetSnmpAgent;
/*
 * parameter information passed to security model routines
 */
struct snmp_secmod_outgoing_params {
    int             msgProcModel;
    u_char*         globalData;
    size_t          globalDataLen;
    int             maxMsgSize;
    int             secModel;
    u_char*         secEngineID;
    size_t          secEngineIDLen;
    char*           secName;
    size_t          secNameLen;
    int             secLevel;
    u_char*         scopedPdu;
    size_t          scopedPduLen;
    void*           secStateRef;
    u_char*         secParams;
    size_t*         secParamsLen;
    u_char**        wholeMsg;
    size_t*         wholeMsgLen;
    size_t*         wholeMsgOffset;
    netsnmp_pdu*    pdu;        /* IN - the pdu getting encoded            */
    netsnmp_session* session;   /* IN - session sending the message        */
};

struct snmp_secmod_incoming_params {
    int             msgProcModel;       /* IN */
    size_t          maxMsgSize; /* IN     - Used to calc maxSizeResponse.  */

    u_char*         secParams;  /* IN     - BER encoded securityParameters. */
    int             secModel;   /* IN */
    int             secLevel;   /* IN     - AuthNoPriv; authPriv etc.      */

    u_char*         wholeMsg;   /* IN     - Original v3 message.           */
    size_t          wholeMsgLen;        /* IN     - Msg length.                    */

    u_char*         secEngineID;        /* OUT    - Pointer snmpEngineID.          */
    size_t*         secEngineIDLen;     /* IN/OUT - Len available; len returned.   */
    /*
     * NOTE: Memory provided by caller.
     */

    char*           secName;    /* OUT    - Pointer to securityName.       */
    size_t*         secNameLen; /* IN/OUT - Len available; len returned.   */

    u_char**        scopedPdu;  /* OUT    - Pointer to plaintext scopedPdu. */
    size_t*         scopedPduLen;       /* IN/OUT - Len available; len returned.   */

    size_t*         maxSizeResponse;    /* OUT    - Max size of Response PDU.      */
    void**          secStateRef;        /* OUT    - Ref to security state.         */
    netsnmp_session* sess;      /* IN     - session which got the message  */
    netsnmp_pdu*    pdu;        /* IN     - the pdu getting parsed         */
    u_char          msg_flags;  /* IN     - v3 Message flags.              */
};


/*
 * function pointers:
 */

/*
 * free's a given security module's data; called at unregistration time
 */
typedef int     (SecmodSessionCallback) (netsnmp_session*);
typedef int     (SecmodPduCallback) (netsnmp_pdu*);
typedef int     (Secmod2PduCallback) (netsnmp_pdu* , netsnmp_pdu*);
typedef int     (SecmodOutMsg) (struct snmp_secmod_outgoing_params*);
typedef int     (SecmodInMsg) (struct snmp_secmod_incoming_params*);
typedef void    (SecmodFreeState) (void*);
typedef void    (SecmodHandleReport) (void* sessp,
                                      netsnmp_transport* transport,
                                      netsnmp_session* ,
                                      int result,
                                      netsnmp_pdu* origpdu);
typedef int     (SecmodDiscoveryMethod) (void* slp,
                                         netsnmp_session* session);


/*
 * internal list
 */
struct snmp_secmod_list {
    int securityModel;
    struct snmp_secmod_def* secDef;
    struct snmp_secmod_list* next;
};

/*
 * definition of a security module
 */

/*
 * all of these callback functions except the encoding and decoding
 * routines are optional.  The rest of them are available if need.
 */
struct snmp_secmod_def {
    /*
     * session maniplation functions
     */
    SecmodSessionCallback* session_open;        /* called in snmp_sess_open()  */
    SecmodSessionCallback* session_close;       /* called in snmp_sess_close() */

    /*
     * pdu manipulation routines
     */
    SecmodPduCallback* pdu_free;        /* called in free_pdu() */
    Secmod2PduCallback* pdu_clone;      /* called in snmp_clone_pdu() */
    SecmodPduCallback* pdu_timeout;     /* called when request timesout */
    SecmodFreeState* pdu_free_state_ref;        /* frees pdu->securityStateRef */

    /*
     * de/encoding routines: mandatory
     */
    int     (NetSnmpAgent::*encode_reverse) (struct snmp_secmod_outgoing_params*);
    int     (NetSnmpAgent::*encode_forward) (struct snmp_secmod_outgoing_params*);
    int     (NetSnmpAgent::*decode) (struct snmp_secmod_incoming_params*);

   /*
    * error and report handling
    */
   void    (NetSnmpAgent::*handle_report) (void* sessp,
                                      netsnmp_transport* transport,
                                      netsnmp_session* ,
                                      int result,
                                      netsnmp_pdu* origpdu);


   /*
    * default engineID discovery mechanism
    */
   SecmodDiscoveryMethod* probe_engineid;
};

#endif                          /* SNMPSECMOD_H_NETSNMP */
