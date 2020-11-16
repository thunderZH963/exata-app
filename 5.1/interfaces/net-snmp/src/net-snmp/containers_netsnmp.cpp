/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright (C) 2007 Apple, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
#include "containers_netsnmp.h"
#include "netSnmpAgent.h"
#include "container_binary_array_netsnmp.h"
#include "container_list_ssll_netsnmp.h"
#include "container_null_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "tools_netsnmp.h"

static void
_factory_free(void* dat, void* context)
{
    container_type* data = (container_type*)dat;
    if (data == NULL)
    return;

    if (data->name != NULL) {
    free((void*)data->name); /* SNMP_FREE wasted on object about to be freed */
    }
    free(data); /* SNMP_FREE wasted on param */
}

/*------------------------------------------------------------------
 */
void
NetSnmpAgent::netsnmp_container_init_list(void)
{
    if (NULL != containers)
        return;

    /*
     * create a binary arry container to hold container
     * factories
     */
    containers = netsnmp_container_get_binary_array();
    containers->compare = netsnmp_compare_cstring;

    /*
     * register containers
     */
    netsnmp_container_binary_array_init();
    netsnmp_container_ssll_init();
    netsnmp_container_null_init();

    /*
     * default aliases for some containers
     */
    netsnmp_container_register("table_container",
                               netsnmp_container_get_factory("binary_array"));
    netsnmp_container_register("linked_list",
                               netsnmp_container_get_factory("sorted_singly_linked_list"));
    netsnmp_container_register("ssll_container",
                               netsnmp_container_get_factory("sorted_singly_linked_list"));

    netsnmp_container_register_with_compare
        ("cstring", netsnmp_container_get_factory("binary_array"),
         netsnmp_compare_direct_cstring);

    netsnmp_container_register_with_compare
        ("string", netsnmp_container_get_factory("binary_array"),
         netsnmp_compare_cstring);
    netsnmp_container_register_with_compare
        ("string_binary_array", netsnmp_container_get_factory("binary_array"),
         netsnmp_compare_cstring);

}

void
NetSnmpAgent::netsnmp_container_free_list(void)
{
    if (containers == NULL)
    return;

    /*
     * free memory used by each factory entry
     */
    CONTAINER_FOR_EACH(containers, ((netsnmp_container_obj_func*)_factory_free), NULL);

    /*
     * free factory container
     */
    CONTAINER_FREE(containers);
    containers = NULL;
}

int
NetSnmpAgent::netsnmp_container_register_with_compare(const char* name, netsnmp_factory* f,
                                        netsnmp_container_compare*  c)
{
    container_type* ct, tmp;

    if (NULL==containers)
        return -1;

    tmp.name = (char*)name;
    ct = (container_type*)CONTAINER_FIND(containers, &tmp);
    if (NULL!=ct) {
        ct->factory = f;
    }
    else {
        ct = SNMP_MALLOC_TYPEDEF(container_type);
        if (NULL == ct)
            return -1;
        ct->name = strdup(name);
        ct->factory = f;
        ct->compare = c;
        CONTAINER_INSERT(containers, ct);
    }
    return 0;
}

int
NetSnmpAgent::netsnmp_container_register(const char* name, netsnmp_factory* f)
{
    return netsnmp_container_register_with_compare(name, f, NULL);
}

/*------------------------------------------------------------------
 */
netsnmp_factory*
NetSnmpAgent::netsnmp_container_get_factory(const char* type)
{
    container_type ct, *found;

    if (NULL==containers)
        return NULL;

    ct.name = type;
    found = (container_type*)CONTAINER_FIND(containers, &ct);

    return found ? found->factory : NULL;
}

netsnmp_factory*
NetSnmpAgent::netsnmp_container_find_factory(const char* type_list)
{
    netsnmp_factory*   f = NULL;
    char*              list, *entry;

    if (NULL==type_list)
        return NULL;

    list = strdup(type_list);
    entry = strtok(list, ":");
    while (entry) {
        f = netsnmp_container_get_factory(entry);
        if (NULL != f)
            break;
        entry = strtok(NULL, ":");
    }

    free(list);
    return f;
}

/*------------------------------------------------------------------
 */
container_type*
NetSnmpAgent::netsnmp_container_get_ct(const char* type)
{
    container_type ct;

    if (NULL == containers)
        return NULL;

    ct.name = type;
    return (container_type*)CONTAINER_FIND(containers, &ct);
}

container_type*
NetSnmpAgent::netsnmp_container_find_ct(const char* type_list)
{
    container_type*    ct = NULL;
    char*              list, *entry;

    if (NULL==type_list)
        return NULL;

    list = strdup(type_list);
    entry = strtok(list, ":");
    while (entry) {
        ct = netsnmp_container_get_ct(entry);
        if (NULL != ct)
            break;
        entry = strtok(NULL, ":");
    }

    free(list);
    return ct;
}



/*------------------------------------------------------------------
 */
netsnmp_container*
NetSnmpAgent::netsnmp_container_get(const char* type)
{
    netsnmp_container* c;
    container_type* ct = netsnmp_container_get_ct(type);
    if (ct) {
        c = (netsnmp_container*)(ct->factory->produce());
        if (c && ct->compare)
            c->compare = ct->compare;
        return c;
    }

    return NULL;
}

/*------------------------------------------------------------------
 */
netsnmp_container*
NetSnmpAgent::netsnmp_container_find(const char* type)
{
    container_type* ct = netsnmp_container_find_ct(type);
    netsnmp_container* c = ct ? (netsnmp_container*)(ct->factory->produce()) : NULL;

    /*
     * provide default compare
     */
    if (c) {
        if (ct->compare)
            c->compare = ct->compare;
        else if (NULL == c->compare)
            c->compare = netsnmp_compare_netsnmp_index;
    }

    return c;
}

/*------------------------------------------------------------------
 */
void
netsnmp_container_add_index(netsnmp_container* primary,
                            netsnmp_container* new_index)
{
    netsnmp_container* curr = primary;

    if ((NULL == new_index) || (NULL == primary)) {
        return;
    }

    while (curr->next)
        curr = curr->next;

    curr->next = new_index;
    new_index->prev = curr;
}

#ifndef NETSNMP_USE_INLINE /* default is to inline */

/*------------------------------------------------------------------
 * These functions should EXACTLY match the inline version in
 * container.h. If you change one, change them both.
 */
int CONTAINER_INSERT_HELPER(netsnmp_container* x, const void* k)
{
    while (x && x->insert_filter && x->insert_filter(x,k) == 1)
        x = x->next;
    if (x) {
        int rc = x->insert(x,k);
        if (rc)
        {
        }
        else {
            rc = CONTAINER_INSERT_HELPER(x->next, k);
            if (rc)
                x->remove(x,k);
        }
        return rc;
    }
    return 0;
}

/*------------------------------------------------------------------
 * These functions should EXACTLY match the inline version in
 * container.h. If you change one, change them both.
 */
int CONTAINER_INSERT(netsnmp_container* x, const void* k)
{
    /** start at first container */
    while (x->prev)
        x = x->prev;
    return CONTAINER_INSERT_HELPER(x, k);
}

/*------------------------------------------------------------------
 * These functions should EXACTLY match the inline version in
 * container.h. If you change one, change them both.
 */
int CONTAINER_REMOVE(netsnmp_container* x, const void* k)
{
    int rc2, rc = 0;

    /** start at last container */
    while (x->next)
        x = x->next;
    while (x) {
        rc2 = x->remove(x,k);
        /** ignore remove errors if there is a filter in place */
        if ((rc2) && (NULL == x->insert_filter)) {
            rc = rc2;
        }
        x = x->prev;

    }
    return rc;
}

/*------------------------------------------------------------------
 * These functions should EXACTLY match the inline version in
 * container.h. If you change one, change them both.
 */
int CONTAINER_FREE(netsnmp_container* x)
{
    int  rc2, rc = 0;

    /** start at last container */
    while (x->next)
        x = x->next;
    while (x) {
        netsnmp_container* tmp;
        const char* name;
        tmp = x->prev;
        name = x->container_name;
        if (NULL != x->container_name)
            SNMP_FREE(x->container_name);
        rc2 = x->cfree(x);
        if (rc2) {
            rc = rc2;
        }
        x = tmp;
    }
    return rc;
}

/*------------------------------------------------------------------
 * These functions should EXACTLY match the function version in
 * container.c. If you change one, change them both.
 */
/*
 * clear all containers. When clearing the *first* container, and
 * *only* the first container, call the function f for each item.
 * After calling this function, all containers should be empty.
 */
void CONTAINER_CLEAR(netsnmp_container* x, netsnmp_container_obj_func* f,
                    void* c)
{
    /** start at last container */
    while (x->next)
        x = x->next;
    while (x->prev) {
        x->clear(x, NULL, c);
        x = x->prev;
    }
    x->clear(x, f, c);
}

/*------------------------------------------------------------------
 * These functions should EXACTLY match the function version in
 * container.c. If you change one, change them both.
 */
/*
 * Find a sub-container with the given name
 */
netsnmp_container* SUBCONTAINER_FIND(netsnmp_container* x,
                                     const char* name)
{
    if ((NULL == x) || (NULL == name))
        return NULL;

    /** start at first container */
    while (x->prev)
        x = x->prev;
    while (x) {
        if ((NULL != x->container_name) && (0 == strcmp(name,x->container_name)))
            break;
        x = x->next;
    }
    return x;
}
#endif


/*------------------------------------------------------------------
 */
void
netsnmp_init_container(netsnmp_container*         c,
                       netsnmp_container_rc*      init,
                       netsnmp_container_rc*      cfree,
                       netsnmp_container_size*    size,
                       netsnmp_container_compare* cmp,
                       netsnmp_container_op*      ins,
                       netsnmp_container_op*      rem,
                       netsnmp_container_rtn*     fnd)
{
    if (c == NULL)
        return;

    c->init = init;
    c->cfree = cfree;
    c->get_size = size;
    c->compare = cmp;
    c->insert = ins;
    c->remove = rem;
    c->find = fnd;
}

/*------------------------------------------------------------------
 *
 * simple comparison routines
 *
 */
int
netsnmp_compare_netsnmp_index(const void* lhs, const void* rhs)
{
    int rc;
    rc = snmp_oid_compare(((const netsnmp_index*) lhs)->oids,
                          ((const netsnmp_index*) lhs)->len,
                          ((const netsnmp_index*) rhs)->oids,
                          ((const netsnmp_index*) rhs)->len);
    return rc;
}

int
netsnmp_ncompare_netsnmp_index(const void* lhs, const void* rhs)
{
    int rc;
    rc = snmp_oid_ncompare(((const netsnmp_index*) lhs)->oids,
                           ((const netsnmp_index*) lhs)->len,
                           ((const netsnmp_index*) rhs)->oids,
                           ((const netsnmp_index*) rhs)->len,
                           ((const netsnmp_index*) rhs)->len);
    return rc;
}

int
netsnmp_compare_cstring(const void*  lhs, const void*  rhs)
{
    return strcmp(((const container_type*)lhs)->name,
                  ((const container_type*)rhs)->name);
}

int
netsnmp_ncompare_cstring(const void*  lhs, const void*  rhs)
{
    return strncmp(((const container_type*)lhs)->name,
                   ((const container_type*)rhs)->name,
                   strlen(((const container_type*)rhs)->name));
}

int
netsnmp_compare_direct_cstring(const void*  lhs, const void*  rhs)
{
    return strcmp((const char*)lhs, (const char*)rhs);
}

/*
 * compare two memory buffers
 *
 * since snmp strings aren't NULL terminated, we can't use strcmp. So
 * compare up to the length of the smaller, and then use length to
 * break any ties.
 */
int
netsnmp_compare_mem(const char*  lhs, size_t lhs_len,
                    const char*  rhs, size_t rhs_len)
{
    int rc, min = SNMP_MIN(lhs_len, rhs_len);

    rc = memcmp(lhs, rhs, min);
    if ((rc==0) && (lhs_len != rhs_len)) {
        if (lhs_len < rhs_len)
            rc = -1;
        else
            rc = 1;
    }

    return rc;
}

/*------------------------------------------------------------------
 * netsnmp_container_simple_free
 *
 * useful function to pass to CONTAINER_FOR_EACH, when a simple
 * free is needed for every item.
 */
void
netsnmp_container_simple_free(void* data, void* context)
{
    if (data == NULL)
    return;
    free((void*)data); /* SNMP_FREE wasted on param */
}
