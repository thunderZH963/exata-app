


/*
 * The scalar group helper is designed to implement a group of
 * scalar objects all in one go, making use of the scalar and
 * instance helpers.
 *
 * GETNEXTs are auto-converted to a GET.  Non-valid GETs are dropped.
 * The client-provided handler just needs to check the OID name to
 * see which object is being requested, but can otherwise assume that
 * things are fine.
 */

typedef struct netsnmp_scalar_group_s {
    oid lbound;        /* XXX - or do we need a more flexible arrangement? */
    oid ubound;
} netsnmp_scalar_group;

netsnmp_mib_handler*
netsnmp_get_scalar_group_handler(oid first, oid last);

int
netsnmp_scalar_group_helper_handler(netsnmp_mib_handler* handler,
                                netsnmp_handler_registration* reginfo,
                                netsnmp_agent_request_info* reqinfo,
                                netsnmp_request_info* requests,Node* node);
