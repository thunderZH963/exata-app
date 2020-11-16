/*
 * netsnmp_data_list.c
 *
 * $Id: data_list.c 16927 2008-05-10 09:33:15Z magfr $
 */
/** @defgroup data_list generic linked-list data handling with a string as a key.
 * @ingroup library
 * @{
*/

#include "data_list_netsnmp.h"
#include "tools_netsnmp.h"
#include "node.h"
#include "netSnmpAgent.h"

/** @defgroup data_list generic linked-list data handling with a string as a key.
 * @ingroup library
 * @{
*/

/** frees the data and a name at a given data_list node.
 * Note that this doesn't free the node itself.
 * @param node the node for which the data should be freed
 */
void
netsnmp_free_list_data(netsnmp_data_list* node)
{
    Netsnmp_Free_List_Data* beer;
    if (!node)
        return;

    beer = node->free_func;
    if (beer)
        (beer) (node->data);
    SNMP_FREE(node->name);
}


/** returns a data_list node's data for a given name within a data_list
 * @param head the head node of a data_list
 * @param name the name to find
 * @return a pointer to the data cached at that node
 */
 void*
     NetSnmpAgent::netsnmp_get_list_data(netsnmp_data_list* head, const char* name)
{
    if (!name)
        return NULL;
    for (; head; head = head->next)
        if (head->name && strcmp(head->name, name) == 0)
            break;
    if (head)
        return head->data;
    return NULL;
}

/** returns a data_list node's data for a given name within a data_list
 * @param head the head node of a data_list
 * @param name the name to find
 * @return a pointer to the data cached at that node
 */
 void*
netsnmp_get_list_data(netsnmp_data_list* head, const char* name)
{
    if (!name)
        return NULL;
    for (; head; head = head->next)
        if (head->name && strcmp(head->name, name) == 0)
            break;
    if (head)
        return head->data;
    return NULL;
}

 /** adds creates a data_list node given a name, data and a free function ptr.
 * @param name the name of the node to cache the data.
 * @param data the data to be stored under that name
 * @param beer A function that can free the data pointer (in the future)
 * @return a newly created data_list node which can be given to the netsnmp_add_list_data function.
 */
netsnmp_data_list*
netsnmp_create_data_list(const char* name, void* data,
                         Netsnmp_Free_List_Data*  beer)
{
    netsnmp_data_list* node;

    if (!name)
        return NULL;
    node = SNMP_MALLOC_TYPEDEF(netsnmp_data_list);
    if (!node)
        return NULL;
    node->name = strdup(name);
    node->data = data;
    node->free_func = beer;
    return node;
}


/** adds data to a datalist
 * @note netsnmp_data_list_add_node is preferred
 * @param head a pointer to the head node of a data_list
 * @param node a node to stash in the data_list
 */
/**  */
 void
netsnmp_add_list_data(netsnmp_data_list** head, netsnmp_data_list* node)
{
    netsnmp_data_list_add_node(head, node);
}

 /** adds data to a datalist
 * @param head a pointer to the head node of a data_list
 * @param node a node to stash in the data_list
 */
 void
netsnmp_data_list_add_node(netsnmp_data_list** head, netsnmp_data_list* node)
{
    netsnmp_data_list* ptr = NULL;

    if (!*head) {
        *head = node;
        return;
    }

    if (ptr)                    /* should always be true */
        ptr->next = node;
}

 /** Removes a named node from a data_list (and frees it)
 * @param realhead a pointer to the head node of a data_list
 * @param name the name to find and remove
 * @return 0 on successful find-and-delete, 1 otherwise.
 */
int
netsnmp_remove_list_node(netsnmp_data_list** realhead, const char* name)
{
    netsnmp_data_list* head, *prev;
    if (!name)
        return 1;
    for (head = *realhead, prev = NULL; head;
         prev = head, head = head->next) {
        if (head->name && strcmp(head->name, name) == 0) {
            if (prev)
                prev->next = head->next;
            else
                *realhead = head->next;
            netsnmp_free_list_data(head);
            free(head);
            return 0;
        }
    }
    return 1;
}

/** frees all data and nodes in a list.
 * @param head the top node of the list to be freed.
 */
void
netsnmp_free_all_list_data(netsnmp_data_list* head)
{
    netsnmp_data_list* tmpptr;
    for (; head;) {
        netsnmp_free_list_data(head);
        tmpptr = head;
        head = head->next;
        SNMP_FREE(tmpptr);
    }
}
