#ifndef SNMP_ALARM_H
#define SNMP_ALARM_H


#include "net-snmp-config_netsnmp.h"

    typedef void    (SNMPAlarmCallback) (unsigned int clientreg,
                                         void* clientarg);

    /*
     * alarm flags
     */
#define SA_REPEAT 0x01          /* keep repeating every X seconds */

    struct snmp_alarm {
        struct timeval  t;
        unsigned int    flags;
        unsigned int    clientreg;
        struct timeval  t_last;
        struct timeval  t_next;
        void*           clientarg;
        SNMPAlarmCallback* thecallback;
        struct snmp_alarm* next;
    };

#endif                          /* SNMP_ALARM_H */
