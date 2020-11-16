/*
 * agent_registry.c
 */
/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
/** @defgroup agent_registry Maintain a registry of MIB subtrees, together with related information regarding mibmodule, sessions, etc
 *   @ingroup agent
 *
 * @{
 */

#include "netSnmpAgent.h"
#include "var_struct_netsnmp.h"
#include "agent_registry_netsnmp.h"
#include "tools_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "asn1_netsnmp.h"

#include "snmp_api_netsnmp.h"
#include "types_netsnmp.h"

#include "callback_netsnmp.h"
#include "agent_callback_netsnmp.h"
#include "default_store_netsnmp.h"
#include "ds_agent_netsnmp.h"
#include "vacm_netsnmp.h"
#include "ds_agent_netsnmp.h"
#include "old_api_netsnmp.h"

int lookup_cache_size = 0; /*enabled later after registrations are loaded */

/*
 * check_acces: determines if a given snmp_pdu is ever going to be
 * allowed to do anynthing or if it's not going to ever be
 * authenticated.
 */
int
NetSnmpAgent::check_access(netsnmp_pdu* pdu)
{                               /* IN - pdu being checked */
    struct view_parameters view_parms;
    view_parms.pdu = pdu;
    view_parms.name = NULL;
    view_parms.namelen = 0;
    view_parms.errorcode = 0;
    view_parms.check_subtree = 0;

    if (pdu->flags & UCD_MSG_FLAG_ALWAYS_IN_VIEW) {
    /* Enable bypassing of view-based access control */
        return 0;
    }

    switch (pdu->version) {
#ifndef NETSNMP_DISABLE_SNMPV1
    case SNMP_VERSION_1:
#endif
#ifndef NETSNMP_DISABLE_SNMPV2C
    case SNMP_VERSION_2c:
#endif
    case SNMP_VERSION_3:
        snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,
                            SNMPD_CALLBACK_ACM_CHECK_INITIAL, &view_parms);
        return view_parms.errorcode;
    }
    return 1;
}

void
netsnmp_subtree_free(netsnmp_subtree* a)
{
    if (a != NULL) {
        if (a->variables != NULL && netsnmp_oid_equals(a->name_a, a->namelen,
                 a->start_a, a->start_len) == 0) {
          SNMP_FREE(a->variables);
        }
        SNMP_FREE(a->name_a);
        a->namelen = 0;
        SNMP_FREE(a->start_a);
        a->start_len = 0;
        SNMP_FREE(a->end_a);
        a->end_len = 0;
        SNMP_FREE(a->label_a);
        netsnmp_handler_registration_free(a->reginfo);
        a->reginfo = NULL;
        SNMP_FREE(a);
    }
}

netsnmp_subtree*
netsnmp_subtree_deepcopy(netsnmp_subtree* a)
{
  netsnmp_subtree* b = (netsnmp_subtree*)calloc(1, sizeof(netsnmp_subtree));

  if (b != NULL) {
    memcpy(b, a, sizeof(netsnmp_subtree));
    b->name_a  = snmp_duplicate_objid(a->name_a,  a->namelen);
    b->start_a = snmp_duplicate_objid(a->start_a, a->start_len);
    b->end_a   = snmp_duplicate_objid(a->end_a,   a->end_len);
    b->label_a = strdup(a->label_a);

    if (b->name_a == NULL || b->start_a == NULL ||
    b->end_a  == NULL || b->label_a == NULL) {
      netsnmp_subtree_free(b);
      return NULL;
    }

    if (a->variables != NULL) {
      b->variables = (struct variable*)malloc(a->variables_len*
                           a->variables_width);
      if (b->variables != NULL) {
    memcpy(b->variables, a->variables,a->variables_len*a->variables_width);
      } else {
    netsnmp_subtree_free(b);
    return NULL;
      }
    }

    if (a->reginfo != NULL) {
      b->reginfo = netsnmp_handler_registration_dup(a->reginfo);
      if (b->reginfo == NULL) {
    netsnmp_subtree_free(b);
    return NULL;
      }
    }
  }
  return b;
}
void
netsnmp_subtree_change_next(netsnmp_subtree* ptr, netsnmp_subtree* thenext)
{
    ptr->next = thenext;
    if (thenext)
        netsnmp_oid_compare_ll(ptr->start_a,
                               ptr->start_len,
                               thenext->start_a,
                               thenext->start_len,
                               &thenext->oid_off);
}
 void
netsnmp_subtree_change_prev(netsnmp_subtree* ptr, netsnmp_subtree* theprev)
{
    ptr->prev = theprev;
    if (theprev)
        netsnmp_oid_compare_ll(theprev->start_a,
                               theprev->start_len,
                               ptr->start_a,
                               ptr->start_len,
                               &ptr->oid_off);
}

        /*
         *  Split the subtree into two at the specified point,
         *    returning the new (second) subtree
         */
netsnmp_subtree*
netsnmp_subtree_split(netsnmp_subtree* current, unsigned int name[], int name_len)
{
    struct variable* vp = NULL;
    netsnmp_subtree* new_sub,* ptr;
    int i = 0, rc = 0, rc2 = 0;
    size_t common_len = 0;
    char* cp;
    unsigned int* tmp_a,* tmp_b;

    if (snmp_oid_compare(name, name_len, current->end_a, current->end_len)>0) {
    /* Split comes after the end of this subtree */
        return NULL;
    }

    new_sub = netsnmp_subtree_deepcopy(current);
    if (new_sub == NULL) {
        return NULL;
    }

    /*  Set up the point of division.  */
    tmp_a = snmp_duplicate_objid(name, name_len);
    if (tmp_a == NULL) {
        netsnmp_subtree_free(new_sub);
        return NULL;
    }
    tmp_b = snmp_duplicate_objid(name, name_len);
    if (tmp_b == NULL) {
        netsnmp_subtree_free(new_sub);
        SNMP_FREE(tmp_a);
        return NULL;
    }

    SNMP_FREE(current->end_a);
    current->end_a = tmp_a;
    current->end_len = (u_char) name_len;
    if (new_sub->start_a != NULL) {
        SNMP_FREE(new_sub->start_a);
    }
    new_sub->start_a = tmp_b;
    new_sub->start_len = (u_char) name_len;

    /*  Split the variables between the two new subtrees.  */
    i = current->variables_len;
    current->variables_len = 0;

    for (vp = current->variables; i > 0; i--) {
    /*  Note that the variable "name" field omits the prefix common to the
        whole registration, hence the strange comparison here.  */

    rc = snmp_oid_compare(vp->name, vp->namelen,
                  name     + current->namelen,
                  name_len - current->namelen);

        if (name_len - current->namelen > vp->namelen) {
            common_len = vp->namelen;
        } else {
            common_len = name_len - current->namelen;
        }

        rc2 = snmp_oid_compare(vp->name, common_len,
                               name + current->namelen, common_len);

        if (rc >= 0) {
            break;  /* All following variables belong to the second subtree */
    }

        current->variables_len++;
        if (rc2 < 0) {
            new_sub->variables_len--;
            cp = (char*) new_sub->variables;
            new_sub->variables = (struct variable*)(cp +
                             new_sub->variables_width);
        }
        vp = (struct variable*) ((char*) vp + current->variables_width);
    }

    /* Delegated trees should retain their variables regardless */
    if (current->variables_len > 0 &&
        IS_DELEGATED((unsigned char) current->variables[0].type)) {
        new_sub->variables_len = 1;
        new_sub->variables = current->variables;
    }

    /* Propogate this split down through any children */
    if (current->children) {
        new_sub->children = netsnmp_subtree_split(current->children,
                          name, name_len);
    }

    /* Retain the correct linking of the list */
    for (ptr = current; ptr != NULL; ptr = ptr->children) {
        netsnmp_subtree_change_next(ptr, new_sub);
    }
    for (ptr = new_sub; ptr != NULL; ptr = ptr->children) {
        netsnmp_subtree_change_prev(ptr, current);
    }
    for (ptr = new_sub->next; ptr != NULL; ptr=ptr->children) {
        netsnmp_subtree_change_prev(ptr, new_sub);
    }

    return new_sub;
}

void
NetSnmpAgent::invalidate_lookup_cache(const char* context) {
    lookup_cache_context* cptr;
    if ((cptr = get_context_lookup_cache(context)) != NULL) {
        cptr->thecachecount = 0;
        cptr->currentpos = 0;
    }
}

static void
register_mib_detach_node(netsnmp_subtree* s)
{
    if (s != NULL) {
        s->flags = s->flags & ~SUBTREE_ATTACHED;
    }
}

void
NetSnmpAgent::netsnmp_subtree_unload(netsnmp_subtree* sub,
                                netsnmp_subtree* prev, const char* context)
{
    netsnmp_subtree* ptr;

    if (prev != NULL) {         /* non-leading entries are easy */
        prev->children = sub->children;
        invalidate_lookup_cache(context);
        return;
    }
    /*
     * otherwise, we need to amend our neighbours as well
     */

    if (sub->children == NULL) {        /* just remove this node completely */
        for (ptr = sub->prev; ptr; ptr = ptr->children) {
            netsnmp_subtree_change_next(ptr, sub->next);
        }
        for (ptr = sub->next; ptr; ptr = ptr->children) {
            netsnmp_subtree_change_prev(ptr, sub->prev);
        }

        if (sub->prev == NULL) {
            netsnmp_subtree_replace_first(sub->next, context);
        }

    } else {
        for (ptr = sub->prev; ptr; ptr = ptr->children)
            netsnmp_subtree_change_next(ptr, sub->children);
        for (ptr = sub->next; ptr; ptr = ptr->children)
            netsnmp_subtree_change_prev(ptr, sub->children);

        if (sub->prev == NULL) {
            netsnmp_subtree_replace_first(sub->children, context);
        }
    }
    invalidate_lookup_cache(context);
}

/**
 * Unregisters an OID that has an associated context name value.
 * Typically used when a module has multiple contexts defined.  The parameters
 * priority, range_subid, and range_ubound should be used in conjunction with
 * agentx, see RFC 2741, otherwise these values should always be 0.
 *
 * @param name  the specific OID to unregister if it conatins the associated
 *              context.
 *
 * @param len   the length of the OID, use  OID_LENGTH macro.
 *
 * @param priority  a value between 1 and 255, used to achieve a desired
 *                  configuration when different sessions register identical or
 *                  overlapping regions.  Subagents with no particular
 *                  knowledge of priority should register with the default
 *                  value of 127.
 *
 * @param range_subid  permits specifying a range in place of one of a subtree
 *                     sub-identifiers.  When this value is zero, no range is
 *                     being specified.
 *
 * @param range_ubound  the upper bound of a sub-identifier's range.
 *                      This field is present only if range_subid is not 0.
 *
 * @param context  a context name that has been created
 *
 * @return
 *
 */
int
NetSnmpAgent::unregister_mib_context(unsigned int*  name, size_t len, int priority,
                       int range_subid, unsigned long range_ubound,
                       const char* context)
{
    netsnmp_subtree* list,* myptr;
    netsnmp_subtree* prev,* child,* next; /* loop through children */
    struct register_parameters reg_parms;
    int old_lookup_cache_val = netsnmp_get_lookup_cache_size();
    int unregistering = 1;
    int orig_subid_val = -1;

    netsnmp_set_lookup_cache_size(0);

    if ((range_subid != 0) &&  (range_subid <= (int) len))
        orig_subid_val = name[range_subid-1];

    while (unregistering){

        list = netsnmp_subtree_find(name, len, netsnmp_subtree_find_first(context),
                    context);
        if (list == NULL) {
            return MIB_NO_SUCH_REGISTRATION;
        }

        for (child = list, prev = NULL; child != NULL;
            prev = child, child = child->children) {
            if (netsnmp_oid_equals(child->name_a, child->namelen, name, len) == 0 &&
                child->priority == priority) {
                break;              /* found it */
             }
        }

        if (child == NULL) {
            return MIB_NO_SUCH_REGISTRATION;
        }

        netsnmp_subtree_unload(child, prev, context);
        myptr = child;              /* remember this for later */

        /*
        *  Now handle any occurances in the following subtrees,
        *      as a result of splitting this range.  Due to the
        *      nature of the way such splits work, the first
        *      subtree 'slice' that doesn't refer to the given
        *      name marks the end of the original region.
        *
        *  This should also serve to register ranges.
        */

        for (list = myptr->next; list != NULL; list = next) {
            next = list->next; /* list gets freed sometimes; cache next */
            for (child = list, prev = NULL; child != NULL;
                prev = child, child = child->children) {
                if ((netsnmp_oid_equals(child->name_a, child->namelen,
                    name, len) == 0) &&
            (child->priority == priority)) {
                    netsnmp_subtree_unload(child, prev, context);
                    netsnmp_subtree_free(child);
                    break;
                }
            }
            if (child == NULL)      /* Didn't find the given name */
                break;
        }

        /* Maybe we are in a range... */
        if (orig_subid_val != -1){
            if (++name[range_subid-1] >= orig_subid_val+range_ubound)
                {
                unregistering=0;
                name[range_subid-1] = orig_subid_val;
                }
        }
        else {
            unregistering=0;
        }
    }

    memset(&reg_parms, 0x0, sizeof(reg_parms));
    reg_parms.name = name;
    reg_parms.namelen = len;
    reg_parms.priority = priority;
    reg_parms.range_subid = range_subid;
    reg_parms.range_ubound = range_ubound;
    reg_parms.flags = 0x00;     /*  this is okay I think  */
    reg_parms.contextName = context;
    snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,
                        SNMPD_CALLBACK_UNREGISTER_OID, &reg_parms);

    netsnmp_subtree_free(myptr);
    netsnmp_set_lookup_cache_size(old_lookup_cache_val);
    invalidate_lookup_cache(context);
    return MIB_UNREGISTERED_OK;
}


netsnmp_subtree*
NetSnmpAgent::netsnmp_subtree_find_first(const char* context_name)
{
    subtree_context_cache* ptr;

    if (!context_name) {
        context_name = "";
    }

    for (ptr = context_subtrees; ptr != NULL; ptr = ptr->next) {
        if (ptr->context_name != NULL &&
        strcmp(ptr->context_name, context_name) == 0) {
            return ptr->first_subtree;
        }
    }
    return NULL;
}

netsnmp_subtree*
NetSnmpAgent::add_subtree(netsnmp_subtree* new_tree, const char* context_name)
{
    subtree_context_cache* ptr = SNMP_MALLOC_TYPEDEF(subtree_context_cache);

    if (!context_name) {
        context_name = "";
    }

    if (!ptr) {
        return NULL;
    }

    ptr->next = context_subtrees;
    ptr->first_subtree = new_tree;
    ptr->context_name = strdup(context_name);
    context_subtrees = ptr;

    return ptr->first_subtree;
}

netsnmp_subtree*
NetSnmpAgent::netsnmp_subtree_replace_first(netsnmp_subtree* new_tree,
                  const char* context_name)
{
    subtree_context_cache* ptr;
    if (!context_name) {
        context_name = "";
    }
    for (ptr = context_subtrees; ptr != NULL; ptr = ptr->next) {
        if (ptr->context_name != NULL &&
        strcmp(ptr->context_name, context_name) == 0) {
            ptr->first_subtree = new_tree;
            return ptr->first_subtree;
        }
    }
    return add_subtree(new_tree, context_name);
}


int
NetSnmpAgent::netsnmp_subtree_load(netsnmp_subtree* new_sub, const char* context_name)
{
    netsnmp_subtree* tree1,* tree2,* new2;
    netsnmp_subtree* prev,* next;
    int             res, rc = 0;

    if (new_sub == NULL) {
        return MIB_REGISTERED_OK;       /* Degenerate case */
    }

    if (!netsnmp_subtree_find_first(context_name)) {
        static int inloop = 0;
        if (!inloop) {
            unsigned int ccitt[1]           = { 0 };
            unsigned int iso[1]             = { 1 };
            unsigned int joint_ccitt_iso[1] = { 2 };
            inloop = 1;
            netsnmp_register_null_context(snmp_duplicate_objid(ccitt, 1), 1,
                                          context_name);
            netsnmp_register_null_context(snmp_duplicate_objid(iso, 1), 1,
                                          context_name);
            netsnmp_register_null_context(snmp_duplicate_objid(joint_ccitt_iso, 1),
                                          1, context_name);
            inloop = 0;
        }
    }

    /*  Find the subtree that contains the start of the new subtree (if
    any)...*/

    tree1 = netsnmp_subtree_find(new_sub->start_a, new_sub->start_len,
                 NULL, context_name);

    /*  ... and the subtree that follows the new one (NULL implies this is the
    final region covered).  */

    if (tree1 == NULL) {
    tree2 = netsnmp_subtree_find_next(new_sub->start_a, new_sub->start_len,
                      NULL, context_name);
    } else {
    tree2 = tree1->next;
    }

    /*  Handle new subtrees that start in virgin territory.  */

    if (tree1 == NULL) {
    new2 = NULL;
    /*  Is there any overlap with later subtrees?  */
    if (tree2 && snmp_oid_compare(new_sub->end_a, new_sub->end_len,
                      tree2->start_a, tree2->start_len) > 0) {
        new2 = (netsnmp_subtree_split(new_sub,
                     (unsigned int*)tree2->start_a, tree2->start_len));
    }

    /*  Link the new subtree (less any overlapping region) with the list of
        existing registrations.  */

    if (tree2) {
            netsnmp_subtree_change_prev(new_sub, tree2->prev);
            netsnmp_subtree_change_prev(tree2, new_sub);
    } else {
            netsnmp_subtree_change_prev(new_sub,
                                        netsnmp_subtree_find_prev(new_sub->start_a,
                                                                  new_sub->start_len, NULL, context_name));

        if (new_sub->prev) {
                netsnmp_subtree_change_next(new_sub->prev, new_sub);
        } else {
        netsnmp_subtree_replace_first(new_sub, context_name);
        }

            netsnmp_subtree_change_next(new_sub, tree2);

        /* If there was any overlap, recurse to merge in the overlapping
           region (including anything that may follow the overlap).  */
        if (new2) {
        return netsnmp_subtree_load(new2, context_name);
        }
    }
    } else {
    /*  If the new subtree starts *within* an existing registration
        (rather than at the same point as it), then split the existing
        subtree at this point.  */

    if (netsnmp_oid_equals(new_sub->start_a, new_sub->start_len,
                 tree1->start_a,   tree1->start_len) != 0) {
        tree1 = netsnmp_subtree_split(tree1, (unsigned int*)new_sub->start_a,
                      new_sub->start_len);
    }

        if (tree1 == NULL) {
            return MIB_REGISTRATION_FAILED;
    }

    /*  Now consider the end of this existing subtree:

        If it matches the new subtree precisely,
                simply merge the new one into the list of children

        If it includes the whole of the new subtree,
            split it at the appropriate point, and merge again

        If the new subtree extends beyond this existing region,
                split it, and recurse to merge the two parts.  */

    rc = snmp_oid_compare(new_sub->end_a, new_sub->end_len,
                  tree1->end_a, tree1->end_len);

        switch (rc) {

    case -1:
        /*  Existing subtree contains new one.  */
        netsnmp_subtree_split(tree1, (unsigned int*)new_sub->end_a, new_sub->end_len);
        /* Fall Through */

    case  0:
        /*  The two trees match precisely.  */

        /*  Note: This is the only point where the original registration
            OID ("name") is used.  */

        prev = NULL;
        next = tree1;

        while (next && next->namelen > new_sub->namelen) {
        prev = next;
        next = next->children;
        }

        while (next && next->namelen == new_sub->namelen &&
           next->priority < new_sub->priority) {
        prev = next;
        next = next->children;
        }

        if (next && (next->namelen  == new_sub->namelen) &&
            (next->priority == new_sub->priority)) {
            return MIB_DUPLICATE_REGISTRATION;
        }

        if (prev) {
        prev->children    = new_sub;
        new_sub->children = next;
                netsnmp_subtree_change_prev(new_sub, prev->prev);
                netsnmp_subtree_change_next(new_sub, prev->next);
        } else {
        new_sub->children = next;
                netsnmp_subtree_change_prev(new_sub, next->prev);
                netsnmp_subtree_change_next(new_sub, next->next);

        for (next = new_sub->next; next != NULL;next = next->children){
                    netsnmp_subtree_change_prev(next, new_sub);
        }

        for (prev = new_sub->prev; prev != NULL;prev = prev->children){
                    netsnmp_subtree_change_next(prev, new_sub);
        }
        }
        break;

    case  1:
        /*  New subtree contains the existing one.  */
        new2 = netsnmp_subtree_split(new_sub, (unsigned int*)tree1->end_a,tree1->end_len);
        res = netsnmp_subtree_load(new_sub, context_name);
        if (res != MIB_REGISTERED_OK) {
        netsnmp_subtree_free(new2);
        return res;
        }
        return netsnmp_subtree_load(new2, context_name);
    }
    }
    return 0;
}
inline lookup_cache_context*
NetSnmpAgent::get_context_lookup_cache(const char* context) {
    lookup_cache_context* ptr;
    if (!context)
        context = "";

    for (ptr = thecontextcache; ptr; ptr = ptr->next) {
        if (strcmp(ptr->context, context) == 0)
            break;
    }
    if (!ptr) {
        if (netsnmp_subtree_find_first(context)) {
            ptr = SNMP_MALLOC_TYPEDEF(lookup_cache_context);
            ptr->next = thecontextcache;
            ptr->context = strdup(context);
            thecontextcache = ptr;
        } else {
            return NULL;
        }
    }
    return ptr;
}

lookup_cache*
NetSnmpAgent::lookup_cache_find(const char* context, unsigned int* name, size_t name_len,
                  int* retcmp) {
    lookup_cache_context* cptr;
    lookup_cache* ret = NULL;
    int cmp;
    int i;

    if ((cptr = get_context_lookup_cache(context)) == NULL)
        return NULL;

    for (i = 0; i < cptr->thecachecount && i < lookup_cache_size; i++) {
        if (cptr->cache[i].previous->start_a)
            cmp = snmp_oid_compare(name, name_len,
                                   cptr->cache[i].previous->start_a,
                                   cptr->cache[i].previous->start_len);
        else
            cmp = 1;
        if (cmp >= 0) {
            *retcmp = cmp;
            ret = &(cptr->cache[i]);
        }
    }
    return ret;
}

void
NetSnmpAgent::setup_tree(void)
{
    unsigned int  ccitt[1]           = { 0 };
    unsigned int  iso[1]             = { 1 };
    unsigned int  joint_ccitt_iso[1] = { 2 };

    netsnmp_register_null(snmp_duplicate_objid(ccitt, 1), 1);
    netsnmp_register_null(snmp_duplicate_objid(iso, 1), 1);
    netsnmp_register_null(snmp_duplicate_objid(joint_ccitt_iso, 1), 1);
}

int
NetSnmpAgent::netsnmp_register_mib(const char* moduleName,
                     struct variable* var,
                     size_t varsize,
                     size_t numvars,
                     unsigned int*  mibloc,
                     size_t mibloclen,
                     int priority,
                     int range_subid,
                     unsigned long range_ubound,
                     netsnmp_session*  ss,
                     const char* context,
                     int timeout,
                     int flags,
                     netsnmp_handler_registration* reginfo,
                     int perform_callback)
{
    netsnmp_subtree* subtree,* sub2;
    int             res, i;
    struct register_parameters reg_parms;
    int old_lookup_cache_val = netsnmp_get_lookup_cache_size();

    if (moduleName == NULL ||
        mibloc     == NULL) {
        /* Shouldn't happen ??? */
        netsnmp_handler_registration_free(reginfo);
        return MIB_REGISTRATION_FAILED;
    }
    subtree = (netsnmp_subtree*)calloc(1, sizeof(netsnmp_subtree));
    if (subtree == NULL) {
        netsnmp_handler_registration_free(reginfo);
        return MIB_REGISTRATION_FAILED;
    }

    /*  Create the new subtree node being registered.  */

    subtree->reginfo = reginfo;
    subtree->name_a  = snmp_duplicate_objid(mibloc, mibloclen);
    subtree->start_a = snmp_duplicate_objid(mibloc, mibloclen);
    subtree->end_a   = snmp_duplicate_objid(mibloc, mibloclen);
    subtree->label_a = strdup(moduleName);
    if (subtree->name_a == NULL || subtree->start_a == NULL ||
    subtree->end_a  == NULL || subtree->label_a == NULL) {
    netsnmp_subtree_free(subtree); /* also frees reginfo */
    return MIB_REGISTRATION_FAILED;
    }
    subtree->namelen   = (unsigned char)mibloclen;
    subtree->start_len = (unsigned char)mibloclen;
    subtree->end_len   = (unsigned char)mibloclen;
    subtree->end_a[mibloclen - 1]++;

    if (var != NULL) {
    subtree->variables = (struct variable*)malloc(varsize*numvars);
    if (subtree->variables == NULL) {
        netsnmp_subtree_free(subtree); /* also frees reginfo */
        return MIB_REGISTRATION_FAILED;
    }
    memcpy(subtree->variables, var, numvars*varsize);
    subtree->variables_len = numvars;
    subtree->variables_width = varsize;
    }
    subtree->priority = (u_char) priority;
    subtree->timeout = timeout;
    subtree->range_subid = range_subid;
    subtree->range_ubound = range_ubound;
    subtree->session = ss;
    subtree->flags = (unsigned char)flags;    /*  used to identify instance oids  */
    subtree->flags |= SUBTREE_ATTACHED;
    subtree->global_cacheid = reginfo->global_cacheid;

    netsnmp_set_lookup_cache_size(0);
    res = netsnmp_subtree_load(subtree, context);

    /*  If registering a range, use the first subtree as a template for the
    rest of the range.  */

   if (res == MIB_REGISTERED_OK && range_subid != 0) {
        for (i = mibloc[range_subid - 1] + 1; i <= (int)range_ubound; i++) {
            sub2 = netsnmp_subtree_deepcopy(subtree);

        if (sub2 == NULL) {
                unregister_mib_context(mibloc, mibloclen, priority,
                                       range_subid, range_ubound, context);
                netsnmp_set_lookup_cache_size(old_lookup_cache_val);
                invalidate_lookup_cache(context);
                return MIB_REGISTRATION_FAILED;
            }


            sub2->name_a[range_subid - 1]  = i;
            sub2->start_a[range_subid - 1] = i;
            sub2->end_a[range_subid - 1]   = i;     /* XXX - ???? */
            if (range_subid == (int)mibloclen) {
                ++sub2->end_a[range_subid - 1];
            }
            sub2->flags |= SUBTREE_ATTACHED;
            sub2->global_cacheid = reginfo->global_cacheid;
            /* FRQ This is essential for requests to succeed! */
            sub2->reginfo->rootoid[range_subid - 1]  = i;

            res = netsnmp_subtree_load(sub2, context);
            if (res != MIB_REGISTERED_OK) {
                unregister_mib_context(mibloc, mibloclen, priority,
                                       range_subid, range_ubound, context);
        netsnmp_subtree_free(sub2);
                netsnmp_set_lookup_cache_size(old_lookup_cache_val);
                invalidate_lookup_cache(context);
                return res;
            }
        }
    } else if (res == MIB_DUPLICATE_REGISTRATION ||
               res == MIB_REGISTRATION_FAILED) {
        netsnmp_set_lookup_cache_size(old_lookup_cache_val);
        invalidate_lookup_cache(context);
        netsnmp_subtree_free(subtree);
        return res;
    }

    /*
     * mark the MIB as detached, if there's no master agent present as of now
     */
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                   NETSNMP_DS_AGENT_ROLE) != MASTER_AGENT) {
        if (main_session == NULL) {
            register_mib_detach_node(subtree);
    }
    }

    if (res == MIB_REGISTERED_OK && perform_callback) {
        memset(&reg_parms, 0x0, sizeof(reg_parms));
        reg_parms.name = mibloc;
        reg_parms.namelen = mibloclen;
        reg_parms.priority = priority;
        reg_parms.range_subid = range_subid;
        reg_parms.range_ubound = range_ubound;
        reg_parms.timeout = timeout;
        reg_parms.flags = (unsigned char) flags;
        reg_parms.contextName = context;
        reg_parms.session = ss;
        reg_parms.reginfo = reginfo;
        reg_parms.contextName = context;
        snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,
                            SNMPD_CALLBACK_REGISTER_OID, &reg_parms);
    }

    netsnmp_set_lookup_cache_size(old_lookup_cache_val);
    invalidate_lookup_cache(context);
    return res;
}

/** retrieves the current value of the lookup cache size
 *  @return the current lookup cache size
 */
int
NetSnmpAgent::netsnmp_get_lookup_cache_size(void) {
    return lookup_cache_size;
}

/** set the lookup cache size for optimized agent registration performance.
 * @param newsize set to the maximum size of a cache for a given
 * context.  Set to 0 to completely disable caching, or to -1 to set
 * to the default cache size (8), or to a number of your chosing.  The
 * rough guide is that it should be equal to the maximum number of
 * simultanious managers you expect to talk to the agent (M) times 80%
 * (or so, he says randomly) the average number (N) of varbinds you
 * expect to receive in a given request for a manager.  ie, M times N.
 * Bigger does NOT necessarily mean better.  Certainly 16 should be an
 * upper limit.  32 is the hard coded limit.
 */
void
NetSnmpAgent::netsnmp_set_lookup_cache_size(int newsize) {
    if (newsize < 0)
        lookup_cache_size = SUBTREE_DEFAULT_CACHE_SIZE;
    else if (newsize < SUBTREE_MAX_CACHE_SIZE)
        lookup_cache_size = newsize;
    else
        lookup_cache_size = SUBTREE_MAX_CACHE_SIZE;
}


netsnmp_subtree*
NetSnmpAgent::netsnmp_subtree_find(unsigned int* name, size_t len, netsnmp_subtree* subtree,
             const char* context_name)
{
    netsnmp_subtree* myptr;

    myptr = netsnmp_subtree_find_prev(name, len, subtree, context_name);
    if (myptr && myptr->end_a &&
        snmp_oid_compare(name, len, myptr->end_a, myptr->end_len)<0) {
        return myptr;
    }

    return NULL;
}
inline void
lookup_cache_replace(lookup_cache* ptr,
                     netsnmp_subtree* next, netsnmp_subtree* previous) {

    ptr->next = next;
    ptr->previous = previous;
}


void
NetSnmpAgent::lookup_cache_add(const char* context,
                 netsnmp_subtree* next, netsnmp_subtree* previous) {
    lookup_cache_context* cptr;

    if ((cptr = get_context_lookup_cache(context)) == NULL)
        return;

    if (cptr->thecachecount < lookup_cache_size)
        cptr->thecachecount++;

    cptr->cache[cptr->currentpos].next = next;
    cptr->cache[cptr->currentpos].previous = previous;

    if (++cptr->currentpos >= lookup_cache_size)
        cptr->currentpos = 0;
}

netsnmp_subtree*
NetSnmpAgent::netsnmp_subtree_find_prev(unsigned int* name, size_t len,
            netsnmp_subtree* subtree,
            const char* context_name)
{
    lookup_cache* lookup_cache = NULL;
    netsnmp_subtree* myptr = NULL,* previous = NULL;
    int cmp = 1;
    size_t ll_off = 0;

    if (subtree) {
        myptr = subtree;
    } else {
    /* look through everything */
        if (lookup_cache_size) {
            lookup_cache = lookup_cache_find(context_name, name, len, &cmp);
            if (lookup_cache) {
                myptr = lookup_cache->next;
                previous = lookup_cache->previous;
            }
            if (!myptr)
                myptr = netsnmp_subtree_find_first(context_name);
        } else {
            myptr = netsnmp_subtree_find_first(context_name);
        }
    }

    /*
     * this optimization causes a segfault on sf cf alpha-linux1.
     * ifdef out until someone figures out why and fixes it. xxx-rks 20051117
     */
    for (; myptr != NULL; previous = myptr, myptr = myptr->next) {
        if (!(ll_off && myptr->oid_off && myptr->oid_off > ll_off) &&
            snmp_oid_compare(name, len, myptr->start_a, myptr->start_len) < 0) {
            if (lookup_cache_size && previous && cmp) {
                if (lookup_cache) {
                    lookup_cache_replace(lookup_cache, myptr, previous);
                } else {
                    lookup_cache_add(context_name, myptr, previous);
                }
            }
            return previous;
        }
    }
    return previous;
}


netsnmp_subtree*
NetSnmpAgent::netsnmp_subtree_find_next(unsigned int* name, size_t len,
              netsnmp_subtree* subtree, const char* context_name)
{
    netsnmp_subtree* myptr = NULL;

    myptr = netsnmp_subtree_find_prev(name, len, subtree, context_name);

    if (myptr != NULL) {
        myptr = myptr->next;
        while (myptr != NULL && (myptr->variables == NULL ||
                 myptr->variables_len == 0)) {
            myptr = myptr->next;
        }
        return myptr;
    } else if (subtree != NULL && snmp_oid_compare(name, len,
                   subtree->start_a, subtree->start_len) < 0) {
        return subtree;
    } else {
        return NULL;
    }
}

/*
 * in_a_view: determines if a given snmp_pdu is allowed to see a
 * given name/namelen OID pointer
 * name         IN - name of var, OUT - name matched
 * nameLen      IN -number of sub-ids in name, OUT - subid-is in matched name
 * pi           IN - relevant auth info re PDU
 * cvp          IN - relevant auth info re mib module
 */

int
NetSnmpAgent::in_a_view(oid* name, size_t* namelen, netsnmp_pdu* pdu, int type)
{
    struct view_parameters view_parms;

    if (pdu->flags & UCD_MSG_FLAG_ALWAYS_IN_VIEW) {
    /* Enable bypassing of view-based access control */
        return VACM_SUCCESS;
    }

    /*
     * check for v1 and counter64s, since snmpv1 doesn't support it
     */
#ifndef NETSNMP_DISABLE_SNMPV1
    if (pdu->version == SNMP_VERSION_1 && type == ASN_COUNTER64) {
        return VACM_NOTINVIEW;
    }
#endif

    view_parms.pdu = pdu;
    view_parms.name = name;
    if (namelen != NULL) {
        view_parms.namelen = *namelen;
    } else {
        view_parms.namelen = 0;
    }
    view_parms.errorcode = 0;
    view_parms.check_subtree = 0;

    switch (pdu->version) {
#ifndef NETSNMP_DISABLE_SNMPV1
    case SNMP_VERSION_1:
#endif
#ifndef NETSNMP_DISABLE_SNMPV2C
    case SNMP_VERSION_2c:
#endif
    case SNMP_VERSION_3:
        snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,
                            SNMPD_CALLBACK_ACM_CHECK, &view_parms);
        return view_parms.errorcode;
    }
    return VACM_NOSECNAME;
}

/** checks to see if everything within a
 *  given subtree is either: in view, not in view, or possibly both.
 *  If the entire subtree is not-in-view we can use this information to
 *  skip calling the sub-handlers entirely.
 *  @returns 0 if entire subtree is accessible, 5 if not and 7 if
 *  portions are both.  1 on error (illegal pdu version).
 */
int
NetSnmpAgent::netsnmp_acm_check_subtree(netsnmp_pdu* pdu, oid* name, size_t namelen)
{                               /* IN - pdu being checked */
    struct view_parameters view_parms;
    view_parms.pdu = pdu;
    view_parms.name = name;
    view_parms.namelen = namelen;
    view_parms.errorcode = 0;
    view_parms.check_subtree = 1;

    if (pdu->flags & UCD_MSG_FLAG_ALWAYS_IN_VIEW) {
    /* Enable bypassing of view-based access control */
        return 0;
    }

    switch (pdu->version) {
#ifndef NETSNMP_DISABLE_SNMPV1
    case SNMP_VERSION_1:
#endif
#ifndef NETSNMP_DISABLE_SNMPV2C
    case SNMP_VERSION_2c:
#endif
    case SNMP_VERSION_3:
        snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,
                            SNMPD_CALLBACK_ACM_CHECK_SUBTREE, &view_parms);
        return view_parms.errorcode;
    }
    return 1;
}

int
NetSnmpAgent::register_mib_context(const char* moduleName,
                     struct variable* var,
                     size_t varsize,
                     size_t numvars,
                     oid*  mibloc,
                     size_t mibloclen,
                     int priority,
                     int range_subid,
                     oid range_ubound,
                     netsnmp_session*  ss,
                     const char* context, int timeout, int flags)
{
    return netsnmp_register_old_api(moduleName, var, varsize, numvars,
                                    mibloc, mibloclen, priority,
                                    range_subid, range_ubound, ss, context,
                                    timeout, flags);
}

int
NetSnmpAgent::register_mib_range(const char* moduleName,
                   struct variable* var,
                   size_t varsize,
                   size_t numvars,
                   oid*  mibloc,
                   size_t mibloclen,
                   int priority,
                   int range_subid, oid range_ubound, netsnmp_session*  ss)
{
    return register_mib_context(moduleName, var, varsize, numvars,
                                mibloc, mibloclen, priority,
                                range_subid, range_ubound, ss, "", -1, 0);
}

int
NetSnmpAgent::register_mib_priority(const char* moduleName,
                      struct variable* var,
                      size_t varsize,
                      size_t numvars,
                      oid*  mibloc, size_t mibloclen, int priority)
{
    return register_mib_range(moduleName, var, varsize, numvars,
                              mibloc, mibloclen, priority, 0, 0, NULL);
}

int
NetSnmpAgent::register_mib(const char* moduleName,
             struct variable* var,
             size_t varsize,
             size_t numvars, oid*  mibloc, size_t mibloclen)
{
    return register_mib_priority(moduleName, var, varsize, numvars,
                                 mibloc, mibloclen, DEFAULT_MIB_PRIORITY);
}

void
netsnmp_complete_subtree_free(netsnmp_subtree* a)
{
    bool b = 0;
    if (a != NULL) {
        if (a->variables != NULL && netsnmp_oid_equals(a->name_a, a->namelen,
                 a->start_a, a->start_len) == 0) {
          SNMP_FREE(a->variables);
    }
    if (a->name_a != NULL)
    {
        b = 1;
        SNMP_FREE(a->name_a);
    }
    a->namelen = 0;
    SNMP_FREE(a->start_a);
    a->start_len = 0;
    SNMP_FREE(a->end_a);
    a->end_len = 0;
    SNMP_FREE(a->label_a);
    netsnmp_handler_registration_free(a->reginfo);
    a->reginfo = NULL;
    a->flags = 0;
    if (a->next != NULL)
    {
        netsnmp_complete_subtree_free(a->next);
        a->next = NULL;
    }
    if (b == 1)
    {
        SNMP_FREE(a);
    }
  }
}

void
netsnmp_subtree_join(netsnmp_subtree* root)
{
    netsnmp_subtree* s,* tmp,* c,* d;

    while (root != NULL) {
        s = root->next;
        while (s != NULL /*&& root->reginfo == s->reginfo*/) {
            tmp = s->next;
             SNMP_FREE(root->end_a);
            root->end_a   = s->end_a;
            root->end_len = s->end_len;
            s->end_a      = NULL;

            for (c = root; c != NULL; c = c->children) {
                netsnmp_subtree_change_next(c, s->next);
            }
            for (c = s; c != NULL; c = c->children) {
                netsnmp_subtree_change_prev(c, root);
            }
            /*
             * Probably need to free children too?
             */
            for (c = s->children; c != NULL; c = d) {
                d = c->children;
                netsnmp_subtree_free(c);
            }
            netsnmp_subtree_free(s);
            s = tmp;
        }
        root = root->next;
    }
}

void
NetSnmpAgent::netsnmp_context_subtree_free()
{
    if (context_subtrees)
    {
        SNMP_FREE(context_subtrees->context_name);
        netsnmp_subtree_join(context_subtrees->first_subtree);
        context_subtrees->first_subtree = NULL;
        if (context_subtrees->next != NULL)
        {
            context_subtrees = context_subtrees->next;
            netsnmp_context_subtree_free();
        }
        context_subtrees = NULL;
    }
}

void
clear_subtree (netsnmp_subtree* sub) {

    netsnmp_subtree* nxt;

    if (sub == NULL)
    return;

    for (nxt = sub; nxt;) {
        if (nxt->children != NULL) {
            clear_subtree(nxt->children);
        }
        sub = nxt;
        nxt = nxt->next;
        netsnmp_subtree_free(sub);
    }

}

void
NetSnmpAgent::clear_context(void)
{

    subtree_context_cache* ptr = NULL,* next = NULL;

    ptr = get_top_context_cache();
    while (ptr) {
    next = ptr->next;

    if (ptr->first_subtree) {
        clear_subtree(ptr->first_subtree);
    }

    SNMP_FREE(ptr->context_name);
        SNMP_FREE(ptr);

    ptr = next;
    }
    context_subtrees = NULL; /* !!! */
    clear_lookup_cache();
}

void
NetSnmpAgent::clear_lookup_cache(void)
{

    lookup_cache_context* ptr = NULL, *next = NULL;

    ptr = thecontextcache;
    while (ptr) {
        next = ptr->next;
        SNMP_FREE(ptr->context);
        SNMP_FREE(ptr);
        ptr = next;
    }
    thecontextcache = NULL; /* !!! */
}

subtree_context_cache*
NetSnmpAgent::get_top_context_cache(void)
{
    return context_subtrees;
}
