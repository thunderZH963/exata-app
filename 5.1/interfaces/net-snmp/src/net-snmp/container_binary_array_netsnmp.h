/*
 * binary_array.h
 * $Id: container_binary_array.h 16726 2007-10-15 20:52:11Z rstory $
 */

#ifndef BINARY_ARRAY_H_NETSNMP
#define BINARY_ARRAY_H_NETSNMP


#include "asn1_netsnmp.h"
#include "containers_netsnmp.h"
#include "factory_netsnmp.h"

    /*
     * initialize binary array container. call at startup.
     */

    /*
     * get an container which uses an binary_array for storage
     */
    netsnmp_container*    netsnmp_container_get_binary_array(void);

    /*
     * get a factory for producing binary_array objects
     */
    netsnmp_factory*      netsnmp_container_get_binary_array_factory(void);


    int netsnmp_binary_array_remove(netsnmp_container* c, const void* key,
                                    void** save);

    void netsnmp_binary_array_release(netsnmp_container* c);

    int netsnmp_binary_array_options_set(netsnmp_container* c, int set, u_int flags);


#endif
