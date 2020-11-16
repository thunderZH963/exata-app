/*
 * default_store.c: storage space for defaults
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
/** @defgroup default_store storage space for defaults
 *  @ingroup library
 *
       The purpose of the default storage is three-fold:

       1)     To create a global storage space without creating a
              whole  bunch  of globally accessible variables or a
              whole bunch of access functions to work  with  more
              privately restricted variables.

       2)     To provide a single location where the thread lock-
              ing needs to be implemented. At the  time  of  this
              writing,  however,  thread  locking  is  not yet in
              place.

       3)     To reduce the number of cross dependencies  between
              code  pieces that may or may not be linked together
              in the long run. This provides for a  single  loca-
              tion  in which configuration data, for example, can
              be stored for a separate section of code  that  may
              not be linked in to the application in question.

       The functions defined here implement these goals.

       Currently, three data types are supported: booleans, inte-
       gers, and strings. Each of these data types have  separate
       storage  spaces.  In  addition, the storage space for each
       data type is divided further  by  the  application  level.
       Currently,  there  are  two  storage  spaces. The first is
       reserved for  the  SNMP  library  itself.  The  second  is
       intended  for  use  in applications and is not modified or
       checked by the library, and, therefore, this is the  space
       usable by you.

       These definitions correspond with the "storid" argument to the API
       - \#define NETSNMP_DS_LIBRARY_ID     0
       - \#define NETSNMP_DS_APPLICATION_ID 1
       - \#define NETSNMP_DS_TOKEN_ID       2

       These definitions correspond with the "which" argument to the API,
       when the storeid argument is NETSNMP_DS_LIBRARY_ID

       library booleans

       - \#define NETSNMP_DS_LIB_MIB_ERRORS          0
       - \#define NETSNMP_DS_LIB_SAVE_MIB_DESCRS     1
       - \#define NETSNMP_DS_LIB_MIB_COMMENT_TERM    2
       - \#define NETSNMP_DS_LIB_MIB_PARSE_LABEL     3
       - \#define NETSNMP_DS_LIB_DUMP_PACKET         4
       - \#define NETSNMP_DS_LIB_LOG_TIMESTAMP       5
       - \#define NETSNMP_DS_LIB_DONT_READ_CONFIGS   6
       - \#define NETSNMP_DS_LIB_MIB_REPLACE         7 replace objects from latest module
       - \#define NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM  8 print only numeric enum values
       - \#define NETSNMP_DS_LIB_PRINT_NUMERIC_OIDS  9 print only numeric enum values
       - \#define NETSNMP_DS_LIB_DONT_BREAKDOWN_OIDS 10 dont print oid indexes specially
       - \#define NETSNMP_DS_LIB_ALARM_DONT_USE_SIG  11 don't use the alarm() signal
       - \#define NETSNMP_DS_LIB_PRINT_FULL_OID      12 print fully qualified oids
       - \#define NETSNMP_DS_LIB_QUICK_PRINT         13 print very brief output for parsing
       - \#define NETSNMP_DS_LIB_RANDOM_ACCESS       14 random access to oid labels
       - \#define NETSNMP_DS_LIB_REGEX_ACCESS        15 regex matching to oid labels
       - \#define NETSNMP_DS_LIB_DONT_CHECK_RANGE    16 don't check values for ranges on send
       - \#define NETSNMP_DS_LIB_NO_TOKEN_WARNINGS   17 no warn about unknown config tokens
       - \#define NETSNMP_DS_LIB_NUMERIC_TIMETICKS   18 print timeticks as a number
       - \#define NETSNMP_DS_LIB_ESCAPE_QUOTES       19 shell escape quote marks in oids
       - \#define NETSNMP_DS_LIB_REVERSE_ENCODE      20 encode packets from back to front
       - \#define NETSNMP_DS_LIB_PRINT_BARE_VALUE    21 just print value (not OID = value)
       - \#define NETSNMP_DS_LIB_EXTENDED_INDEX      22 print extended index format [x1][x2]
       - \#define NETSNMP_DS_LIB_PRINT_HEX_TEXT      23 print ASCII text along with hex strings
       - \#define NETSNMP_DS_LIB_PRINT_UCD_STYLE_OID 24 print OID's using the UCD-style prefix suppression
       - \#define NETSNMP_DS_LIB_READ_UCD_STYLE_OID  25 require top-level OIDs to be prefixed with a dot
       - \#define NETSNMP_DS_LIB_HAVE_READ_PREMIB_CONFIG 26 have the pre-mib parsing config tokens been processed
       - \#define NETSNMP_DS_LIB_HAVE_READ_CONFIG    27 have the config tokens been processed
       - \#define NETSNMP_DS_LIB_QUICKE_PRINT        28
       - \#define NETSNMP_DS_LIB_DONT_PRINT_UNITS    29 don't print UNITS suffix
       - \#define NETSNMP_DS_LIB_NO_DISPLAY_HINT     30 don't apply DISPLAY-HINTs
       - \#define NETSNMP_DS_LIB_16BIT_IDS           31 restrict requestIDs, etc to 16-bit values
       - \#define NETSNMP_DS_LIB_DONT_PERSIST_STATE  32 don't save/load any persistant state
       - \#define NETSNMP_DS_LIB_2DIGIT_HEX_OUTPUT   33 print a leading 0 on hex values <= 'f'


       library integers

       - \#define NETSNMP_DS_LIB_MIB_WARNINGS  0
       - \#define NETSNMP_DS_LIB_SECLEVEL      1
       - \#define NETSNMP_DS_LIB_SNMPVERSION   2
       - \#define NETSNMP_DS_LIB_DEFAULT_PORT  3
       - \#define NETSNMP_DS_LIB_OID_OUTPUT_FORMAT  4
       - \#define NETSNMP_DS_LIB_STRING_OUTPUT_FORMAT 5

       library strings

       - \#define NETSNMP_DS_LIB_SECNAME           0
       - \#define NETSNMP_DS_LIB_CONTEXT           1
       - \#define NETSNMP_DS_LIB_PASSPHRASE        2
       - \#define NETSNMP_DS_LIB_AUTHPASSPHRASE    3
       - \#define NETSNMP_DS_LIB_PRIVPASSPHRASE    4
       - \#define NETSNMP_DS_LIB_OPTIONALCONFIG    5
       - \#define NETSNMP_DS_LIB_APPTYPE           6
       - \#define NETSNMP_DS_LIB_COMMUNITY         7
       - \#define NETSNMP_DS_LIB_PERSISTENT_DIR    8
       - \#define NETSNMP_DS_LIB_CONFIGURATION_DIR 9
       - \#define NETSNMP_DS_LIB_SECMODEL          10
       - \#define NETSNMP_DS_LIB_MIBDIRS           11
       - \#define NETSNMP_DS_LIB_OIDSUFFIX         12
       - \#define NETSNMP_DS_LIB_OIDPREFIX         13
       - \#define NETSNMP_DS_LIB_CLIENT_ADDR       14
       - \#define NETSNMP_DS_LIB_TEMP_FILE_PATTERN 15
       - \#define NETSNMP_DS_LIB_AUTHMASTERKEY     16
       - \#define NETSNMP_DS_LIB_PRIVMASTERKEY     17
       - \#define NETSNMP_DS_LIB_AUTHLOCALIZEDKEY  18
       - \#define NETSNMP_DS_LIB_PRIVLOCALIZEDKEY  19

 *  @{
 */
#include "default_store_netsnmp.h"
#include "netSnmpAgent.h"
#include "snmp_api_netsnmp.h"
#include "tools_netsnmp.h"

int
NetSnmpAgent::netsnmp_ds_get_boolean(int storeid, int which)
{
    if (storeid < 0 || storeid >= NETSNMP_DS_MAX_IDS ||
    which   < 0 || which   >= NETSNMP_DS_MAX_SUBIDS) {
        return SNMPERR_GENERR;
    }

    return (netsnmp_ds_booleans[storeid][which/8] & (1 << (which % 8))) ? 1:0;
}

int
NetSnmpAgent::netsnmp_ds_set_string(int storeid, int which, const char* value)
{
    if (storeid < 0 || storeid >= NETSNMP_DS_MAX_IDS ||
    which   < 0 || which   >= NETSNMP_DS_MAX_SUBIDS) {
        return SNMPERR_GENERR;
    }

    /*
     * is some silly person is calling us with our own pointer?
     */
    if (netsnmp_ds_strings[storeid][which] == value)
        return SNMPERR_SUCCESS;

    if (netsnmp_ds_strings[storeid][which] != NULL) {
        free(netsnmp_ds_strings[storeid][which]);
    netsnmp_ds_strings[storeid][which] = NULL;
    }

    if (value) {
        netsnmp_ds_strings[storeid][which] = strdup(value);
    } else {
        netsnmp_ds_strings[storeid][which] = NULL;
    }

    return SNMPERR_SUCCESS;
}

char*
NetSnmpAgent::netsnmp_ds_get_string(int storeid, int which)
{
    if (storeid < 0 || storeid >= NETSNMP_DS_MAX_IDS ||
    which   < 0 || which   >= NETSNMP_DS_MAX_SUBIDS) {
        return NULL;
    }

    return netsnmp_ds_strings[storeid][which];
}


int
NetSnmpAgent::netsnmp_ds_register_config(u_char type, const char* ftype,
                const char* token,
               int storeid, int which)
{
    netsnmp_ds_read_config* drsp;

    if (storeid < 0 || storeid >= NETSNMP_DS_MAX_IDS    ||
    which   < 0 || which   >= NETSNMP_DS_MAX_SUBIDS || token == NULL) {
        return SNMPERR_GENERR;
    }

    if (netsnmp_ds_configs == NULL) {
        netsnmp_ds_configs = SNMP_MALLOC_TYPEDEF(netsnmp_ds_read_config);
        if (netsnmp_ds_configs == NULL)
            return SNMPERR_GENERR;
        drsp = netsnmp_ds_configs;
    } else {
        for (drsp = netsnmp_ds_configs; drsp->next != NULL; drsp = drsp->next);
        drsp->next = SNMP_MALLOC_TYPEDEF(netsnmp_ds_read_config);
        if (drsp->next == NULL)
            return SNMPERR_GENERR;
        drsp = drsp->next;
    }

    drsp->type    = type;
    drsp->ftype   = strdup(ftype);
    drsp->token   = strdup(token);
    drsp->storeid = storeid;
    drsp->which   = which;

    switch (type) {
    case ASN_BOOLEAN:
        register_config_handler(ftype, token,
                                &NetSnmpAgent::netsnmp_ds_handle_config, NULL,
                                "(1|yes|true|0|no|false)");
        break;

    case ASN_INTEGER:
        register_config_handler(ftype, token,
                                &NetSnmpAgent::netsnmp_ds_handle_config, NULL,
                                "integerValue");
        break;

    case ASN_OCTET_STR:
        register_config_handler(ftype, token,
                                &NetSnmpAgent::netsnmp_ds_handle_config, NULL,
                                "string");
        break;

    }
    return SNMPERR_SUCCESS;
}

void
NetSnmpAgent::netsnmp_ds_handle_config(const char* token, char* line)
{
    netsnmp_ds_read_config* drsp;
    char            buf[SNMP_MAXBUF];
    char*           value, *endptr;
    int             itmp;

    for (drsp = netsnmp_ds_configs;
         drsp != NULL && strcasecmp(token, drsp->token) != 0;
         drsp = drsp->next);

    if (drsp != NULL) {

        switch (drsp->type) {
        case ASN_BOOLEAN:
            itmp = netsnmp_ds_parse_boolean(line);
            if (itmp != -1)
                netsnmp_ds_set_boolean(drsp->storeid, drsp->which, itmp);
            break;

        case ASN_INTEGER:
            value = strtok(line, " \t\n");
            itmp = strtol(value, &endptr, 10);
            if (*endptr != 0) {
        } else {
                netsnmp_ds_set_int(drsp->storeid, drsp->which, itmp);
        }
            break;

        case ASN_OCTET_STR:
            if (*line == '"') {
                copy_nword(line, buf, sizeof(buf));
                netsnmp_ds_set_string(drsp->storeid, drsp->which, buf);
            } else {
                netsnmp_ds_set_string(drsp->storeid, drsp->which, line);
            }
            break;

        default:
            break;
        }
    }
}

int
NetSnmpAgent::netsnmp_ds_parse_boolean(char* line)
{
    char*           value, *endptr;
    int             itmp;

    value = strtok(line, " \t\n");
    if (strcasecmp(value, "yes") == 0 ||
    strcasecmp(value, "true") == 0) {
        return 1;
    } else if (strcasecmp(value, "no") == 0 ||
           strcasecmp(value, "false") == 0) {
        return 0;
    } else {
        itmp = strtol(value, &endptr, 10);
        if (*endptr != 0 || itmp < 0 || itmp > 1) {
            return -1;
    }
        return itmp;
    }
}

int
NetSnmpAgent::netsnmp_ds_set_int(int storeid, int which, int value)
{
    if (storeid < 0 || storeid >= NETSNMP_DS_MAX_IDS ||
    which   < 0 || which   >= NETSNMP_DS_MAX_SUBIDS) {
        return SNMPERR_GENERR;
    }

    netsnmp_ds_integers[storeid][which] = value;
    return SNMPERR_SUCCESS;
}

int
NetSnmpAgent::netsnmp_ds_get_int(int storeid, int which)
{
    if (storeid < 0 || storeid >= NETSNMP_DS_MAX_IDS ||
    which   < 0 || which   >= NETSNMP_DS_MAX_SUBIDS) {
        return SNMPERR_GENERR;
    }

    return netsnmp_ds_integers[storeid][which];
}

/**
 * Stores "true" or "false" given an int value for value into
 * netsnmp_ds_booleans[store][which] slot.
 *
 * @param storeid an index to the boolean storage container's first index(store)
 *
 * @param which an index to the boolean storage container's second index(which)
 *
 * @param value if > 0, "true" is set into the slot otherwise "false"
 *
 * @return Returns SNMPPERR_GENERR if the storeid and which parameters do not
 * correspond to a valid slot, or  SNMPERR_SUCCESS otherwise.
 */
int
NetSnmpAgent::netsnmp_ds_set_boolean(int storeid, int which, int value)
{
    if (storeid < 0 || storeid >= NETSNMP_DS_MAX_IDS ||
    which   < 0 || which   >= NETSNMP_DS_MAX_SUBIDS) {
        return SNMPERR_GENERR;
    }

    if (value > 0) {
        netsnmp_ds_booleans[storeid][which/8] |= (1 << (which % 8));
    } else {
        netsnmp_ds_booleans[storeid][which/8] &= (0xff7f >> (7 - (which % 8)));
    }

    return SNMPERR_SUCCESS;
}


int
NetSnmpAgent::netsnmp_ds_register_premib(u_char type, const char* ftype, const char* token,
               int storeid, int which)
{
    netsnmp_ds_read_config* drsp;

    if (storeid < 0 || storeid >= NETSNMP_DS_MAX_IDS    ||
    which   < 0 || which   >= NETSNMP_DS_MAX_SUBIDS || token == NULL) {
        return SNMPERR_GENERR;
    }

    if (netsnmp_ds_configs == NULL) {
        netsnmp_ds_configs = SNMP_MALLOC_TYPEDEF(netsnmp_ds_read_config);
        if (netsnmp_ds_configs == NULL)
            return SNMPERR_GENERR;
        drsp = netsnmp_ds_configs;
    } else {
        for (drsp = netsnmp_ds_configs; drsp->next != NULL; drsp = drsp->next);
        drsp->next = SNMP_MALLOC_TYPEDEF(netsnmp_ds_read_config);
        if (drsp->next == NULL)
            return SNMPERR_GENERR;
        drsp = drsp->next;
    }

    drsp->type    = type;
    drsp->ftype   = strdup(ftype);
    drsp->token   = strdup(token);
    drsp->storeid = storeid;
    drsp->which   = which;

    switch (type) {
    case ASN_BOOLEAN:
        register_prenetsnmp_mib_handler(ftype, token, &NetSnmpAgent::netsnmp_ds_handle_config,
                                        NULL, "(1|yes|true|0|no|false)");
        break;

    case ASN_INTEGER:
        register_prenetsnmp_mib_handler(ftype, token, &NetSnmpAgent::netsnmp_ds_handle_config,
                                        NULL, "integerValue");
        break;

    case ASN_OCTET_STR:
        register_prenetsnmp_mib_handler(ftype, token, &NetSnmpAgent::netsnmp_ds_handle_config,
                                        NULL, "string");
        break;

    }
    return SNMPERR_SUCCESS;
}




void
NetSnmpAgent::netsnmp_ds_shutdown(void)
{
    netsnmp_ds_read_config* drsp;
    int             i, j;

    for (drsp = netsnmp_ds_configs; drsp; drsp = netsnmp_ds_configs) {
        netsnmp_ds_configs = drsp->next;

        if (drsp->ftype && drsp->token) {
            unregister_config_handler(drsp->ftype, drsp->token);
        }
    if (drsp->ftype != NULL) {
        free(drsp->ftype);
    }
    if (drsp->token != NULL) {
        free(drsp->token);
    }
        free(drsp);
    }

    for (i = 0; i < NETSNMP_DS_MAX_IDS; i++) {
        for (j = 0; j < NETSNMP_DS_MAX_SUBIDS; j++) {
            if (netsnmp_ds_strings[i][j] != NULL) {
                free(netsnmp_ds_strings[i][j]);
                netsnmp_ds_strings[i][j] = NULL;
            }
        }
    }
}
