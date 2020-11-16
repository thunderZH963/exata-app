#ifndef OLD_API_H_NETSNMP
#define OLD_API_H_NETSNMP

#define OLD_API_NAME "old_api"

typedef struct old_opi_cache_s {
    u_char*         data;
    WriteMethod*    write_method;
} netsnmp_old_api_cache;

Netsnmp_Node_Handler netsnmp_old_api_helper;

#endif                          /* OLD_API_H_NETSNMP */
