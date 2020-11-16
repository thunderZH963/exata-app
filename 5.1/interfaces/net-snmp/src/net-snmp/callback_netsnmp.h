/*
 * callback.c: A generic callback mechanism
 */

#ifndef CALLBACK_H_NETSNMP
#define CALLBACK_H_NETSNMP

   /*
     * SNMP_CALLBACK_LIBRARY minor types
     */
#define SNMP_CALLBACK_POST_READ_CONFIG            0
#define SNMP_CALLBACK_STORE_DATA            1
#define SNMP_CALLBACK_SHUTDOWN                2
#define SNMP_CALLBACK_POST_PREMIB_READ_CONFIG    3
#define SNMP_CALLBACK_LOGGING            4
#define SNMP_CALLBACK_SESSION_INIT        5
#define SNMP_CALLBACK_PRE_READ_CONFIG            7
#define SNMP_CALLBACK_PRE_PREMIB_READ_CONFIG    8

class NetSnmpAgent;
/*
     * Callback Major Types
     */
#define SNMP_CALLBACK_LIBRARY     0
#define SNMP_CALLBACK_APPLICATION 1

#define MAX_CALLBACK_IDS    2
#define MAX_CALLBACK_SUBIDS 16



    /*
     * Callback priority (lower priority numbers called first(
     */
#define NETSNMP_CALLBACK_HIGHEST_PRIORITY      -1024
#define NETSNMP_CALLBACK_DEFAULT_PRIORITY       0
#define NETSNMP_CALLBACK_LOWEST_PRIORITY        1024

typedef int     (SNMPCallback) (int majorID, int minorID,
                                    void* serverarg, void* clientarg);
    struct snmp_gen_callback {
        int (NetSnmpAgent::*sc_callback) (int majorID, int minorID,
        void* serverarg, void* clientarg) ;
        void*           sc_client_arg;
        int             priority;
        struct snmp_gen_callback* next;
    };

int             snmp_call_callbacks(int major, int minor,
                                        void* caller_arg);

#endif /* CALLBACK_H_NETSNMP */
