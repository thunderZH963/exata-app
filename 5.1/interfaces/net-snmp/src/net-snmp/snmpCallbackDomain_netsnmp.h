#ifndef _SNMPCALLBACKDOMAIN_H_NETSNMP
#define _SNMPCALLBACKDOMAIN_H_NETSNMP

typedef struct netsnmp_callback_pass_s {
    int             return_transport_num;
    netsnmp_pdu*    pdu;
    struct netsnmp_callback_pass_s* next;
} netsnmp_callback_pass;

typedef struct netsnmp_callback_info_s {
    int             linkedto;
    void*           parent_data;
    netsnmp_callback_pass* data;
    int             callback_num;
    int             pipefds[2];
} netsnmp_callback_info;

#endif/*_SNMPCALLBACKDOMAIN_H*/
