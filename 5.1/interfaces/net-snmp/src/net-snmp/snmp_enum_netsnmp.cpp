#include "netSnmpAgent.h"
#include "snmp_enum_netsnmp.h"
#include "tools_netsnmp.h"

/*
 * remember a list of enums based on a lookup name.
 */
struct snmp_enum_list*
NetSnmpAgent::se_find_slist(const char* listname)
{
    struct snmp_enum_list_str* sptr, *lastp = NULL;
    if (!listname)
        return NULL;

    for (sptr = sliststorage;
         sptr != NULL; lastp = sptr, sptr = sptr->next)
        if (sptr->name && strcmp(sptr->name, listname) == 0)
            return sptr->list;

    return NULL;
}


int
se_add_pair_to_list(struct snmp_enum_list** list, char* label, int value)
{
    struct snmp_enum_list* lastnode = NULL;

    if (!list)
        return SE_DNE;

    while (*list) {
        if ((*list)->value == value)
            return (SE_ALREADY_THERE);
        lastnode = (*list);
        (*list) = (*list)->next;
    }

    if (lastnode) {
        lastnode->next = SNMP_MALLOC_STRUCT(snmp_enum_list);
        lastnode = lastnode->next;
    } else {
        (*list) = SNMP_MALLOC_STRUCT(snmp_enum_list);
        lastnode = (*list);
    }
    if (!lastnode)
        return (SE_NOMEM);
    lastnode->label = label;
    lastnode->value = value;
    lastnode->next = NULL;
    return (SE_OK);
}


int
NetSnmpAgent::se_add_pair_to_slist(const char* listname, char* label, int value)
{
    struct snmp_enum_list* list = se_find_slist(listname);
    int             created = (list) ? 1 : 0;
    int             ret = se_add_pair_to_list(&list, label, value);

    if (!created) {
        struct snmp_enum_list_str* sptr =
            SNMP_MALLOC_STRUCT(snmp_enum_list_str);
        if (!sptr)
            return SE_NOMEM;
        sptr->next = sliststorage;
        sptr->name = strdup(listname);
        sptr->list = list;
        sliststorage = sptr;
    }
    return ret;
}


int
NetSnmpAgent::init_snmp_enum(const char* type)
{
    int             i;

    if (!snmp_enum_lists)
        snmp_enum_lists = (struct snmp_enum_list***)
            calloc(1, sizeof(struct snmp_enum_list**) * SE_MAX_IDS);
    if (!snmp_enum_lists)
        return SE_NOMEM;
    current_maj_num = SE_MAX_IDS;

    for (i = 0; i < SE_MAX_IDS; i++) {
        if (!snmp_enum_lists[i])
            snmp_enum_lists[i] = (struct snmp_enum_list**)
                calloc(1, sizeof(struct snmp_enum_list*) * SE_MAX_SUBIDS);
        if (!snmp_enum_lists[i])
            return SE_NOMEM;
    }
    current_min_num = SE_MAX_SUBIDS;

    if (!sliststorage)
        sliststorage = NULL;

    register_config_handler(type, "enum", &NetSnmpAgent::se_read_conf, NULL, NULL);
    return SE_OK;
}

struct snmp_enum_list*
    NetSnmpAgent::se_find_list(unsigned int major, unsigned int minor)
{
    if (major > current_maj_num || minor > current_min_num)
        return NULL;

    return snmp_enum_lists[major][minor];
}

int
NetSnmpAgent::se_add_pair(unsigned int major, unsigned int minor, char* label, int value)
{
    struct snmp_enum_list* list = se_find_list(major, minor);
    int             created = (list) ? 1 : 0;
    int             ret = se_add_pair_to_list(&list, label, value);
    if (!created)
        se_store_in_list(list, major, minor);
    return ret;
}

void
NetSnmpAgent::se_read_conf(const char* word, char* cptr)
{
    int major, minor;
    int value;
    char* cp, *cp2;
    char e_name[BUFSIZ];
    char e_enum[  BUFSIZ];

    if (!cptr || *cptr=='\0')
        return;

    /*
     * Extract the first token
     *   (which should be the name of the list)
     */
    cp = copy_nword(cptr, e_name, sizeof(e_name));
    cp = skip_white(cp);
    if (!cp || *cp=='\0')
        return;


    /*
     * Add each remaining enumeration to the list,
     *   using the appropriate style interface
     */
    if (sscanf(e_name, "%d:%d", &major, &minor) == 2) {
        /*
         *  Numeric major/minor style
         */
        while (1) {
            cp = copy_nword(cp, e_enum, sizeof(e_enum));
            if (sscanf(e_enum, "%d:", &value) != 1) {
                break;
            }
            cp2 = e_enum;
            while (*(cp2++) != ':')
                ;
            se_add_pair(major, minor, cp2, value);
            if (!cp)
                break;
        }
    } else {
        /*
         *  Named enumeration
         */
        while (1) {
            cp = copy_nword(cp, e_enum, sizeof(e_enum));
            if (sscanf(e_enum, "%d:", &value) != 1) {
                break;
            }
            cp2 = e_enum;
            while (*(cp2++) != ':')
                ;
            se_add_pair_to_slist(e_name, cp2, value);
            if (!cp)
                break;
        }
    }
}

int
NetSnmpAgent::se_store_in_list(struct snmp_enum_list* new_list,
              unsigned int major, unsigned int minor)
{
    int             ret = SE_OK;

    if (major > current_maj_num || minor > current_min_num) {
        /*
         * XXX: realloc
         */
        return SE_NOMEM;
    }


    if (snmp_enum_lists[major][minor] != NULL)
        ret = SE_ALREADY_THERE;

    snmp_enum_lists[major][minor] = new_list;

    return ret;
}

char*
se_find_label_in_list(struct snmp_enum_list* list, int value)
{
    if (!list)
        return NULL;
    while (list) {
        if (list->value == value)
            return (list->label);
        list = list->next;
    }
    return NULL;
}


int
se_find_value_in_list(struct snmp_enum_list* list, const char* label)
{
    if (!list)
        return SE_DNE;          /* XXX: um, no good solution here */
    while (list) {
        if (strcmp(list->label, label) == 0)
            return (list->value);
        list = list->next;
    }

    return SE_DNE;              /* XXX: um, no good solution here */
}

char*
NetSnmpAgent::se_find_label_in_slist(const char* listname, int value)
{
    return (se_find_label_in_list(se_find_slist(listname), value));
}

int
NetSnmpAgent::se_find_value_in_slist(const char* listname, const char* label)
{
    return (se_find_value_in_list(se_find_slist(listname), label));
}


void
NetSnmpAgent::clear_snmp_enum(void)
{
    struct snmp_enum_list_str* sptr = sliststorage, *next = NULL;
    struct snmp_enum_list* list = NULL, *nextlist = NULL;
    int i;

    while (sptr != NULL) {
    next = sptr->next;
    list = sptr->list;
    while (list != NULL) {
        nextlist = list->next;
        SNMP_FREE(list->label);
        SNMP_FREE(list);
        list = nextlist;
    }
    SNMP_FREE(sptr->name);
    SNMP_FREE(sptr);
    sptr = next;
    }
    sliststorage = NULL;

    if (snmp_enum_lists) {
        for (i = 0; i < SE_MAX_IDS; i++) {
            if (snmp_enum_lists[i])
                SNMP_FREE(snmp_enum_lists[i]);
        }
        SNMP_FREE(snmp_enum_lists);
    }
}
