/*
 * container_null.c
 * $Id: container_null.c 16924 2008-05-09 21:35:32Z magfr $
 *
 * see comments in header file.
 *
 */


/** @defgroup null_container null_container
 *  Helps you implement specialized containers.
 *  @ingroup container
 *
 *  This is a simple container that doesn't actually contain anything.
 *  All the methods simply log a //DEBUG message and return.
 *
 *  The original intent for this container is as a wrapper for a specialized
 *  container. Implement the functions you need, create a null_container,
 *  and override the default functions with your specialized versions.
 *
 *  You can use the 'container:null' //DEBUG token to see what functions are
 *  being called, to help determine if you need to implement them.
 *
 *  @{
 */

/**********************************************************************
 *
 * container
 *
 */

#include "container_null_netsnmp.h"
#include "netSnmpAgent.h"

static void*
_null_find(netsnmp_container* container, const void* data)
{
    return NULL;
}

static void*
_null_find_next(netsnmp_container* container, const void* data)
{
    return NULL;
}

static int
_null_insert(netsnmp_container* container, const void* data)
{
    return 0;
}

static int
_null_remove(netsnmp_container* container, const void* data)
{
    return 0;
}

static int
_null_free(netsnmp_container* container)
{
    free(container);
    return 0;
}

static int
_null_init(netsnmp_container* container)
{
    return 0;
}

static size_t
_null_size(netsnmp_container* container)
{
    return 0;
}

static void
_null_for_each(netsnmp_container* container, netsnmp_container_obj_func* f,
             void* context)
{
}

static netsnmp_void_array*
_null_get_subset(netsnmp_container* container, void* data)
{
    return NULL;
}

static void
_null_clear(netsnmp_container* container, netsnmp_container_obj_func* f,
                 void* context)
{
}

/**********************************************************************
 *
 * factory
 *
 */

netsnmp_container*
netsnmp_container_get_null(void)
{
    /*
     * allocate memory
     */
    netsnmp_container* c;
    c = (netsnmp_container*) calloc(1, sizeof(netsnmp_container));

    if (NULL==c) {
        return NULL;
    }

    c->container_data = NULL;

    c->get_size = _null_size;
    c->init = _null_init;
    c->cfree = _null_free;
    c->insert = _null_insert;
    c->remove = _null_remove;
    c->find = _null_find;
    c->find_next = _null_find_next;
    c->get_subset = _null_get_subset;
    c->get_iterator = NULL; /* _null_iterator; */
    c->for_each = _null_for_each;
    c->clear = _null_clear;

    return c;
}

netsnmp_factory*
netsnmp_container_get_null_factory(void)
{
    static netsnmp_factory f = { "null",
                                 (netsnmp_factory_produce_f*)
                                 netsnmp_container_get_null};
    return &f;
}

void
NetSnmpAgent::netsnmp_container_null_init(void)
{
    netsnmp_container_register("null",
                               netsnmp_container_get_null_factory());
}
