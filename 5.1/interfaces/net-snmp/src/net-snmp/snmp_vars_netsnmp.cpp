/*
 * snmp_vars.c - return a pointer to the named variable.
 */
/**
 * @addtogroup library
 *
 * @{
 */
/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/***********************************************************
    Copyright 1988, 1989, 1990 by Carnegie Mellon University
    Copyright 1989    TGV, Incorporated

              All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU and TGV not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CMU AND TGV DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL CMU OR TGV BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
******************************************************************/
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

/*
 * additions, fixes and enhancements for Linux by Erik Schoenfelder
 * (schoenfr@ibr.cs.tu-bs.de) 1994/1995.
 * Linux additions taken from CMU to UCD stack by Jennifer Bray of Origin
 * (jbray@origin-at.co.uk) 1997
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

/*
 * XXXWWW merge todo: incl/excl range changes in differences between
 * 1.194 and 1.199
 */

#include "netSnmpAgent.h"

netsnmp_session* callback_master_sess = NULL;

int             callback_master_num = -1;

struct module_init_list* initlist = NULL;
struct module_init_list* noinitlist = NULL;

void
NetSnmpAgent::_init_agent_callback_transport(void)
{
    /*
     * always register a callback transport for internal use
     */
    callback_master_sess = netsnmp_callback_open(0, &NetSnmpAgent::handle_snmp_packet,
                                                 &NetSnmpAgent::netsnmp_agent_check_packet,
                                                 &NetSnmpAgent::netsnmp_agent_check_parse);
    if (callback_master_sess)
        callback_master_num = callback_master_sess->local_port;
}



/**
 * Initialize the agent.  Calls into init_agent_read_config to set tha app's
 * configuration file in the appropriate default storage space,
 *  NETSNMP_DS_LIB_APPTYPE.  Need to call init_agent before calling init_snmp.
 *
 * @param app the configuration file to be read in, gets stored in default
 *        storage
 *
 * @return Returns non-zero on failure and zero on success.
 *
 * @see init_snmp
 */

int
NetSnmpAgent::init_agent(const char* app)
{
        int             r = 0;

    if (++done_init_agent > 1) {
        return r;
    }
    setup_tree();

    init_agent_read_config(app);

    _init_agent_callback_transport();

    netsnmp_init_helpers();
#  include "agent_module_inits_netsnmp.h"
    return r;
}                               /* end init_agent() */

int
NetSnmpAgent::should_init(const char* module_name)
{
    struct module_init_list* listp;

    /*
     * a definitive list takes priority
     */
    if (initlist) {
        listp = initlist;
        while (listp) {
            if (strcmp(listp->module_name, module_name) == 0) {
               /* DEBUGMSGTL(("mib_init", "initializing: %s\n",
                            module_name));*/
                return DO_INITIALIZE;
            }
            listp = listp->next;
        }
        return DONT_INITIALIZE;
    }

    /*
     * initialize it only if not on the bad list (bad module, no bone)
     */
    if (noinitlist) {
        listp = noinitlist;
        while (listp) {
            if (strcmp(listp->module_name, module_name) == 0) {
                return DONT_INITIALIZE;
            }
            listp = listp->next;
        }
    }

    /*
     * initialize it
     */
    return DO_INITIALIZE;
}
