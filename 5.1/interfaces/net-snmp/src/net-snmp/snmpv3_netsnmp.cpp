/*
 * snmpv3.c
 */

#include "snmpv3_netsnmp.h"
#include "tools_netsnmp.h"
#include "netSnmpAgent.h"
#include "snmp_api_netsnmp.h"
#include "snmpusm_netsnmp.h"
#include "transform_oids_netsnmp.h"
#include "net-snmp-config_netsnmp.h"
#include "lcd_time_netsnmp.h"
#include "keytools_netsnmp.h"
#include "scapi_netsnmp.h"
#include "default_store_netsnmp.h"
#include "read_config_netsnmp.h"
#include "system_netsnmp.h"
#include <clock.h>
#include <math.h>
#include <errno.h>
/* this is probably an over-kill ifdef, but why not */
#if defined(HAVE_SYS_TIMES_H) && defined(HAVE_UNISTD_H) && defined(HAVE_TIMES) && defined(_SC_CLK_TCK) && defined(HAVE_SYSCONF) && defined(UINT_MAX)

#define SNMP_USE_TIMES 1

static Int32 clockticks = 0;
static unsigned int lastcalltime = 0;
static unsigned int wrapcounter = 0;

#endif /* times() tests */

#if defined(IFHWADDRLEN) && defined(SIOCGIFHWADDR)
static int      getHwAddress(const char* networkDevice, char* addressOut);
#endif

void
NetSnmpAgent::snmpv3_authtype_conf(const char* word, char* cptr)
{
#ifndef NETSNMP_DISABLE_MD5
    if (strcasecmp(cptr, "MD5") == 0)
        defaultAuthType = usmHMACMD5AuthProtocol;
    else
#endif
    if (strcasecmp(cptr, "SHA") == 0)
        defaultAuthType = usmHMACSHA1AuthProtocol;
    defaultAuthTypeLen = USM_LENGTH_OID_TRANSFORM;
}

const oid*
NetSnmpAgent::get_default_authtype(size_t*  len)
{
    if (defaultAuthType == NULL) {
        defaultAuthType = SNMP_DEFAULT_AUTH_PROTO;
        defaultAuthTypeLen = SNMP_DEFAULT_AUTH_PROTOLEN;
    }
    if (len)
        *len = defaultAuthTypeLen;
    return defaultAuthType;
}

void
NetSnmpAgent::snmpv3_privtype_conf(const char* word, char* cptr)
{
    int testcase = 0;

#ifndef NETSNMP_DISABLE_DES
    if (strcasecmp(cptr, "DES") == 0) {
        testcase = 1;
        defaultPrivType = usmDESPrivProtocol;
    }
#endif

#if HAVE_AES
    /* XXX AES: assumes oid length == des oid length */
    if (strcasecmp(cptr, "AES128") == 0 ||
        strcasecmp(cptr, "AES") == 0) {
        testcase = 1;
        defaultPrivType = usmAES128PrivProtocol;
    }
#endif
    if (testcase == 0)
        /*config_perror("Unknown privacy type");*/
    defaultPrivTypeLen = SNMP_DEFAULT_PRIV_PROTOLEN;
}

const oid*
NetSnmpAgent::get_default_privtype(size_t*  len)
{
    if (defaultPrivType == NULL) {
#ifndef NETSNMP_DISABLE_DES
        defaultPrivType = usmDESPrivProtocol;
# else
        defaultPrivType = usmAESPrivProtocol;
# endif
        defaultPrivTypeLen = USM_LENGTH_OID_TRANSFORM;
    }
    if (len)
        *len = defaultPrivTypeLen;
    return defaultPrivType;
}

/*******************************************************************-o-******
 * snmpv3_secLevel_conf
 *
 * Parameters:
 *    *word
 *    *cptr
 *
 * Line syntax:
 *    defSecurityLevel "noAuthNoPriv" | "authNoPriv" | "authPriv"
 */

int
parse_secLevel_conf(const char* word, char* cptr) {
    if (strcasecmp(cptr, "noAuthNoPriv") == 0 || strcmp(cptr, "1") == 0 ||
    strcasecmp(cptr, "nanp") == 0) {
        return SNMP_SEC_LEVEL_NOAUTH;
    } else if (strcasecmp(cptr, "authNoPriv") == 0 || strcmp(cptr, "2") == 0 ||
           strcasecmp(cptr, "anp") == 0) {
        return SNMP_SEC_LEVEL_AUTHNOPRIV;
    } else if (strcasecmp(cptr, "authPriv") == 0 || strcmp(cptr, "3") == 0 ||
           strcasecmp(cptr, "ap") == 0) {
        return SNMP_SEC_LEVEL_AUTHPRIV;
    } else {
        return -1;
    }
}

void
NetSnmpAgent::snmpv3_secLevel_conf(const char* word, char* cptr)
{
    int             secLevel;

    if ((secLevel = parse_secLevel_conf(word, cptr)) >= 0) {
        netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
               NETSNMP_DS_LIB_SECLEVEL, secLevel);
    }
}


int
NetSnmpAgent::snmpv3_options(char* optarg, netsnmp_session*  session, char** Apsz,
               char** Xpsz, int argc, char* const* argv)
{
    char*           cp = optarg;
    int testcase;
    optarg++;
    /*
     * Support '... -3x=value ....' syntax
     */
    if (*optarg == '=') {
        optarg++;
    }
    /*
     * and '.... "-3x value" ....'  (*with* the quotes)
     */
    while (*optarg && isspace(*optarg)) {
        optarg++;
    }

    switch (*cp) {

    case 'Z':
        errno=0;
        session->engineBoots = strtoul(optarg, &cp, 10);
        if (errno || cp == optarg) {
            ERROR_ReportWarning("Need engine boots value after -3Z "
                                "flag.\n");
            return (-1);
        }
        if (*cp == ',') {
            char* endptr;
            cp++;
            session->engineTime = strtoul(cp, &endptr, 10);
            if (errno || cp == endptr) {
                ERROR_ReportWarning("Need engine time after \"-3Z "
                                    "engineBoot,\".\n");
                return (-1);
            }
        } else {
            ERROR_ReportWarning("Need engine time after \"-3Z "
                                "engineBoot,\".\n");
            return (-1);
        }
        break;

    case 'e':{
            size_t          ebuf_len = 32, eout_len = 0;
            u_char*         ebuf = (u_char*) malloc(ebuf_len);

            if (ebuf == NULL) {
                ERROR_ReportWarning("malloc failure processing -3e "
                                    "flag.\n");
                return (-1);
            }
            if (!snmp_hex_to_binary
                (&ebuf, &ebuf_len, &eout_len, 1, optarg)) {
                ERROR_ReportWarning("Bad engine ID value after -3e "
                                    "flag.\n");
                SNMP_FREE(ebuf);
                return (-1);
            }
            session->securityEngineID = ebuf;
            session->securityEngineIDLen = eout_len;
            break;
        }

    case 'E':{
            size_t          ebuf_len = 32, eout_len = 0;
            u_char*         ebuf = (u_char*) malloc(ebuf_len);

            if (ebuf == NULL) {
                ERROR_ReportWarning("malloc failure processing -3E"
                                    " flag.\n");
                return (-1);
            }
            if (!snmp_hex_to_binary
                (&ebuf, &ebuf_len, &eout_len, 1, optarg)) {
                ERROR_ReportWarning("Bad engine ID value after -3E "
                                    "flag.\n");
                SNMP_FREE(ebuf);
                return (-1);
            }
            session->contextEngineID = ebuf;
            session->contextEngineIDLen = eout_len;
            break;
        }

    case 'n':
        session->contextName = optarg;
        session->contextNameLen = strlen(optarg);
        break;

    case 'u':
        session->securityName = optarg;
        session->securityNameLen = strlen(optarg);
        break;

    case 'l':
        if (!strcasecmp(optarg, "noAuthNoPriv") || !strcmp(optarg, "1") ||
            !strcasecmp(optarg, "nanp")) {
            session->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
        } else if (!strcasecmp(optarg, "authNoPriv")
                   || !strcmp(optarg, "2") || !strcasecmp(optarg, "anp")) {
            session->securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
        } else if (!strcasecmp(optarg, "authPriv") || !strcmp(optarg, "3")
                   || !strcasecmp(optarg, "ap")) {
            session->securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
        } else {
            ERROR_ReportWarningArgs("Invalid security level specified after "
                                    "-3l flag: %s\n", optarg);
            return (-1);
        }

        break;

    case 'a':
#ifndef NETSNMP_DISABLE_MD5
        if (!strcasecmp(optarg, "MD5")) {
            session->securityAuthProto = (UInt32*)usmHMACMD5AuthProtocol;
            session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
        } else
#endif
            if (!strcasecmp(optarg, "SHA")) {
            session->securityAuthProto = (UInt32*)usmHMACSHA1AuthProtocol;
            session->securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
        } else {
            ERROR_ReportWarningArgs("Invalid authentication protocol "
                                    "specified after -3a flag: %s\n",
                                    optarg);
            return (-1);
        }
        break;

    case 'x':
        testcase = 0;
#ifndef NETSNMP_DISABLE_DES
        if (!strcasecmp(optarg, "DES")) {
            session->securityPrivProto = (unsigned int*)usmDESPrivProtocol;
            session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
            testcase = 1;
        }
#endif
#ifdef HAVE_AES
        if (!strcasecmp(optarg, "AES128") ||
            strcasecmp(optarg, "AES")) {
            session->securityPrivProto = usmAES128PrivProtocol;
            session->securityPrivProtoLen = USM_PRIV_PROTO_AES128_LEN;
            testcase = 1;
        }
#endif
        if (testcase == 0) {
            ERROR_ReportWarningArgs("Invalid privacy protocol specified "
                                    "after -3x flag: %s\n", optarg);
            return (-1);
        }
        break;

    case 'A':
        *Apsz = optarg;
        break;

    case 'X':
        *Xpsz = optarg;
        break;

    case 'm': {
        size_t bufSize = sizeof(session->securityAuthKey);
        u_char* tmpp = session->securityAuthKey;
        if (!snmp_hex_to_binary(&tmpp, &bufSize,
                                &session->securityAuthKeyLen, 0, optarg)) {
            ERROR_ReportWarning("Bad key value after -3m flag.\n");
            return (-1);
        }
        break;
    }

    case 'M': {
        size_t bufSize = sizeof(session->securityPrivKey);
        u_char* tmpp = session->securityPrivKey;
        if (!snmp_hex_to_binary(&tmpp, &bufSize,
             &session->securityPrivKeyLen, 0, optarg)) {
            ERROR_ReportWarning("Bad key value after -3M flag.\n");
            return (-1);
        }
        break;
    }

    case 'k': {
        size_t          kbuf_len = 32, kout_len = 0;
        u_char*         kbuf = (u_char*) malloc(kbuf_len);

        if (kbuf == NULL) {
            ERROR_ReportWarning("malloc failure processing -3k flag.\n");
            return (-1);
        }
        if (!snmp_hex_to_binary
            (&kbuf, &kbuf_len, &kout_len, 1, optarg)) {
            ERROR_ReportWarning("Bad key value after -3k flag.\n");
            SNMP_FREE(kbuf);
            return (-1);
        }
        session->securityAuthLocalKey = kbuf;
        session->securityAuthLocalKeyLen = kout_len;
        break;
    }

    case 'K': {
        size_t          kbuf_len = 32, kout_len = 0;
        u_char*         kbuf = (u_char*) malloc(kbuf_len);

        if (kbuf == NULL) {
            ERROR_ReportWarning("malloc failure processing -3K flag.\n");
            return (-1);
        }
        if (!snmp_hex_to_binary
            (&kbuf, &kbuf_len, &kout_len, 1, optarg)) {
            ERROR_ReportWarning("Bad key value after -3K flag.\n");
            SNMP_FREE(kbuf);
            return (-1);
        }
        session->securityPrivLocalKey = kbuf;
        session->securityPrivLocalKeyLen = kout_len;
        break;
    }

    default:
        ERROR_ReportWarningArgs("Unknown SNMPv3 option passed to -3:"
                                " %c.\n", *cp);
        return -1;
    }
    return 0;
}

/*******************************************************************-o-******
 * setup_engineID
 *
 * Parameters:
 *    **eidp
 *     *text    Printable (?) text to be plugged into the snmpEngineID.
 *
 * Return:
 *    Length of allocated engineID string in bytes,  -OR-
 *    -1 on error.
 *
 *
 * Create an snmpEngineID using text and the local IP address.  If eidp
 * is defined, use it to return a pointer to the newly allocated data.
 * Otherwise, use the result to define engineID defined in this module.
 *
 * Line syntax:
 *    engineID <text> | NULL
 *
 * XXX    What if a node has multiple interfaces?
 * XXX    What if multiple engines all choose the same address?
 *      (answer:  You're screwed, because you might need a kul database
 *       which is dependant on the current engineID.  Enumeration and other
 *       tricks won't work).
 */
int
NetSnmpAgent::setup_engineID(u_char**  eidp, const char* text)
{
    int             enterpriseid = NETSNMP_ENTERPRISE_OID,
        netsnmpoid = NETSNMP_OID,
        localsetup = (eidp) ? 0 : 1;

        EXTERNAL_hton(&enterpriseid, sizeof(enterpriseid));
        EXTERNAL_hton(&netsnmpoid, sizeof(netsnmpoid));

    /*
     * Use local engineID if *eidp == NULL.
     */
#ifdef HAVE_GETHOSTNAME
    u_char          buf[SNMP_MAXBUF_SMALL];
    struct hostent* hent = NULL;
#endif
    u_char*         bufp = NULL;
    size_t          len;
    int             localEngineIDType = engineIDType;
    int             tmpint;
    time_t          tmptime;

    engineIDIsSet = 1;

#ifdef HAVE_GETHOSTNAME
#ifdef AF_INET6
    /*
     * see if they selected IPV4 or IPV6 support
     */
    if ((ENGINEID_TYPE_IPV6 == localEngineIDType) ||
        (ENGINEID_TYPE_IPV4 == localEngineIDType)) {
        /*
         * get the host name and save the information
         */
        gethostname((char*) buf, sizeof(buf));
        hent = gethostbyname((char*) buf);
        if (hent && hent->h_addrtype == AF_INET6) {
            localEngineIDType = ENGINEID_TYPE_IPV6;
        } else {
            /*
             * Not IPV6 so we go with default
             */
            localEngineIDType = ENGINEID_TYPE_IPV4;
        }
    }
#else
    /*
     * No IPV6 support.  Check if they selected IPV6 engineID type.
     *  If so make it IPV4 instead
     */
    if (ENGINEID_TYPE_IPV6 == localEngineIDType) {
        localEngineIDType = ENGINEID_TYPE_IPV4;
    }
    if (ENGINEID_TYPE_IPV4 == localEngineIDType) {
        /*
         * get the host name and save the information
         */
        gethostname((char*) buf, sizeof(buf));
        hent = gethostbyname((char*) buf);
    }
# endif
#endif                          /* HAVE_GETHOSTNAME */

    /*
     * Determine if we have text and if so setup our localEngineIDType
     * * appropriately.
     */
    if (NULL != text) {
        engineIDType = localEngineIDType = ENGINEID_TYPE_TEXT;
    }
    /*
     * Determine length of the engineID string.
     */
    len = 5;                    /* always have 5 leading bytes */
    switch (localEngineIDType) {
    case ENGINEID_TYPE_TEXT:
        if (NULL == text) {
            return -1;
        }
        len += strlen(text);    /* 5 leading bytes+text. No NULL char */
        break;
#if defined(IFHWADDRLEN) && defined(SIOCGIFHWADDR)
    case ENGINEID_TYPE_MACADDR:        /* MAC address */
        len += 6;               /* + 6 bytes for MAC address */
        break;
#endif
    case ENGINEID_TYPE_IPV4:   /* IPv4 */
        len += 4;               /* + 4 byte IPV4 address */
        break;
    case ENGINEID_TYPE_IPV6:   /* IPv6 */
        len += 16;              /* + 16 byte IPV6 address */
        break;
    case ENGINEID_TYPE_NETSNMP_RND:        /* Net-SNMP specific encoding */
        if (engineID)           /* already setup, keep current value */
            return engineIDLength;
        if (oldEngineID) {
            len = oldEngineIDLength;
        } else {
            len += sizeof(int) + sizeof(time_t);
        }
        break;
    default:
        localEngineIDType = ENGINEID_TYPE_IPV4; /* make into IPV4 */
        len += 4;               /* + 4 byte IPv4 address */
        break;
    }                           /* switch */


    /*
     * Allocate memory and store enterprise ID.
     */
    if ((bufp = (u_char*) malloc(len)) == NULL) {
        return -1;
    }
    if (localEngineIDType == ENGINEID_TYPE_NETSNMP_RND)
        /*
         * we must use the net-snmp enterprise id here, regardless
         */
        memcpy(bufp, &netsnmpoid, sizeof(netsnmpoid));    /* XXX Must be 4 bytes! */
    else
        memcpy(bufp, &enterpriseid, sizeof(enterpriseid));      /* XXX Must be 4 bytes! */

    bufp[0] |= 0x80;


    /*
     * Store the given text  -OR-   the first found IP address
     *  -OR-  the MAC address  -OR-  random elements
     * (the latter being the recommended default)
     */
    switch (localEngineIDType) {
    case ENGINEID_TYPE_NETSNMP_RND:
        if (oldEngineID) {
            /*
             * keep our previous notion of the engineID
             */
            memcpy(bufp, oldEngineID, oldEngineIDLength);
        } else {
            /*
             * Here we've desigend our own ENGINEID that is not based on
             * an address which may change and may even become conflicting
             * in the future like most of the default v3 engineID types
             * suffer from.
             *
             * Ours is built from 2 fairly random elements: a random number and
             * the current time in seconds.  This method suffers from boxes
             * that may not have a correct clock setting and random number
             * seed at startup, but few OSes should have that problem.
             */
            bufp[4] = ENGINEID_TYPE_NETSNMP_RND;
            tmpint = RANDOM_nrand(snmpRandomSeed);
            memcpy(bufp + 5, &tmpint, sizeof(tmpint));
            tmptime = time(NULL);
            memcpy(bufp + 5 + sizeof(tmpint), &tmptime, sizeof(tmptime));
        }
        break;
    case ENGINEID_TYPE_TEXT:
        bufp[4] = ENGINEID_TYPE_TEXT;
        memcpy((char*) bufp + 5, (text), strlen(text));
        break;
#ifdef HAVE_GETHOSTNAME
#ifdef AF_INET6
    case ENGINEID_TYPE_IPV6:
        bufp[4] = ENGINEID_TYPE_IPV6;
        memcpy(bufp + 5, hent->h_addr_list[0], hent->h_length);
        break;
#endif
#endif
#if defined(IFHWADDRLEN) && defined(SIOCGIFHWADDR)
    case ENGINEID_TYPE_MACADDR:
        {
            int             x;
            bufp[4] = ENGINEID_TYPE_MACADDR;
            /*
             * use default NIC if none provided
             */
            if (NULL == engineIDNic) {
          x = getHwAddress(DEFAULT_NIC, (char*)&bufp[5]);
            } else {
          x = getHwAddress((char*)engineIDNic, (char*)&bufp[5]);
            }
            if (0 != x)
                /*
                 * function failed fill MAC address with zeros
                 */
            {
                memset(&bufp[5], 0, 6);
            }
        }
        break;
#endif
    case ENGINEID_TYPE_IPV4:
    default:
        bufp[4] = ENGINEID_TYPE_IPV4;
#ifdef HAVE_GETHOSTNAME
        if (hent && hent->h_addrtype == AF_INET) {
            memcpy(bufp + 5, hent->h_addr_list[0], hent->h_length);
        } else {                /* Unknown address type.  Default to 127.0.0.1. */

            bufp[5] = 127;
            bufp[6] = 0;
            bufp[7] = 0;
            bufp[8] = 1;
        }
#else                           /* HAVE_GETHOSTNAME */
        /*
         * Unknown address type.  Default to 127.0.0.1.
         */
        bufp[5] = 127;
        bufp[6] = 0;
        bufp[7] = 0;
        bufp[8] = 1;
#endif                          /* HAVE_GETHOSTNAME */
        break;
    }
   
    //TODO Remove later when testing is done, BONG
    //Hardcoded values into engineID for easy decryption of packets in wireshark
    bufp[9] = 11;
    bufp[10] = 11;
    bufp[11] = 11;
    bufp[12] = 78;

    bufp[4] = 1;
    bufp[5] = 190;
    bufp[6] = 0;
    bufp[7] = 1;
    bufp[8] = 2;

    len = 9;

    /*
     * Pass the string back to the calling environment, or use it for
     * our local engineID.
     */
    if (localsetup) {
        SNMP_FREE(engineID);
        engineID = bufp;
        engineIDLength = len;

    } else {
        *eidp = bufp;
    }


    return len;

}                               /* end setup_engineID() */

int
NetSnmpAgent::free_engineID(int majorid, int minorid, void* serverarg,
          void* clientarg)
{
    SNMP_FREE(engineID);
    SNMP_FREE(engineIDNic);
    SNMP_FREE(oldEngineID);
    engineIDIsSet = 0;
    return 0;
}

int
NetSnmpAgent::free_enginetime_on_shutdown(int majorid, int minorid, void* serverarg,
                void* clientarg)
{
    if (engineID != NULL)
    free_enginetime(engineID, engineIDLength);
    return 0;
}

void
NetSnmpAgent::usm_parse_create_usmUser(const char* token, char* line)
{
    char*           cp;
    char            buf[SNMP_MAXBUF_MEDIUM];
    struct usmUser* newuser;
    u_char          userKey[SNMP_MAXBUF_SMALL], *tmpp;
    size_t          userKeyLen = SNMP_MAXBUF_SMALL;
    size_t          privKeyLen = 0;
    size_t          ret;
    int             ret2;
    int             testcase;

    newuser = usm_create_user();

    /*
     * READ: Security Name
     */
    cp = copy_nword(line, buf, sizeof(buf));

    /*
     * might be a -e ENGINEID argument
     */
    if (strcmp(buf, "-e") == 0) {
        size_t          ebuf_len = 32, eout_len = 0;
        u_char*         ebuf = (u_char*) malloc(ebuf_len);

        if (ebuf == NULL) {
            /*config_perror("malloc failure processing -e flag");*/
            usm_free_user(newuser);
            return;
        }

        /*
         * Get the specified engineid from the line.
         */
        cp = copy_nword(cp, buf, sizeof(buf));
        if (!snmp_hex_to_binary(&ebuf, &ebuf_len, &eout_len, 1, buf)) {
            usm_free_user(newuser);
            SNMP_FREE(ebuf);
            return;
        }

        newuser->engineID = ebuf;
        newuser->engineIDLen = eout_len;
        cp = copy_nword(cp, buf, sizeof(buf));
    } else {
        newuser->engineID = snmpv3_generate_engineID(&ret);
        if (ret == 0) {
            usm_free_user(newuser);
            return;
        }
        newuser->engineIDLen = ret;
    }

    newuser->secName = strdup(buf);
    newuser->name = strdup(buf);

    if (!cp)
        goto add;               /* no authentication or privacy type */

    /*
     * READ: Authentication Type
     */
#ifndef NETSNMP_DISABLE_MD5
    if (strncmp(cp, "MD5", 3) == 0) {
        memcpy(newuser->authProtocol, usmHMACMD5AuthProtocol,
               sizeof(usmHMACMD5AuthProtocol));
    } else
#endif
        if (strncmp(cp, "SHA", 3) == 0) {
        memcpy(newuser->authProtocol, usmHMACSHA1AuthProtocol,
               sizeof(usmHMACSHA1AuthProtocol));
    } else {
        usm_free_user(newuser);
        return;
    }

    cp = skip_token(cp);

    /*
     * READ: Authentication Pass Phrase or key
     */
    if (!cp) {
        usm_free_user(newuser);
        return;
    }
    cp = copy_nword(cp, buf, sizeof(buf));
    if (strcmp(buf,"-m") == 0) {
        /* a master key is specified */
        cp = copy_nword(cp, buf, sizeof(buf));
        ret = sizeof(userKey);
        tmpp = userKey;
        userKeyLen = 0;
        if (!snmp_hex_to_binary(&tmpp, &ret, &userKeyLen, 0, buf)) {
            usm_free_user(newuser);
            return;
        }
    } else if (strcmp(buf,"-l") != 0) {
        /* a password is specified */
        userKeyLen = sizeof(userKey);
        ret2 = generate_Ku(newuser->authProtocol, newuser->authProtocolLen,
                          (u_char*) buf, strlen(buf), userKey, &userKeyLen);
        if (ret2 != SNMPERR_SUCCESS) {
            usm_free_user(newuser);
            return;
        }
    }

    /*
     * And turn it into a localized key
     */
    ret2 = sc_get_properlength(newuser->authProtocol,
                               newuser->authProtocolLen);
    if (ret2 <= 0) {
    usm_free_user(newuser);
        return;
    }
    newuser->authKey = (u_char*) malloc(ret2);

    if (strcmp(buf,"-l") == 0) {
        /* a local key is directly specified */
        cp = copy_nword(cp, buf, sizeof(buf));
        newuser->authKeyLen = 0;
        ret = ret2;
        if (!snmp_hex_to_binary(&newuser->authKey, &ret,
                                &newuser->authKeyLen, 0, buf)) {
            usm_free_user(newuser);
            return;
        }
        if (ret != newuser->authKeyLen) {
            usm_free_user(newuser);
            return;
        }
    } else {
        newuser->authKeyLen = ret2;
        ret2 = generate_kul(newuser->authProtocol, newuser->authProtocolLen,
                           newuser->engineID, newuser->engineIDLen,
                           userKey, userKeyLen,
                           newuser->authKey, &newuser->authKeyLen);
        if (ret2 != SNMPERR_SUCCESS) {
            usm_free_user(newuser);
            return;
        }
    }

    if (!cp)
        goto add;               /* no privacy type (which is legal) */

    /*
     * READ: Privacy Type
     */
    testcase = 0;
#ifndef NETSNMP_DISABLE_DES
    if (strncmp(cp, "DES", 3) == 0) {
        memcpy(newuser->privProtocol, usmDESPrivProtocol,
               sizeof(usmDESPrivProtocol));
        testcase = 1;
    /* DES uses a 128 bit key, 64 bits of which is a salt */
    privKeyLen = 16;
    }
#endif
#ifdef HAVE_AES
    if (strncmp(cp, "AES128", 6) == 0 ||
               strncmp(cp, "AES", 3) == 0) {
        memcpy(newuser->privProtocol, usmAESPrivProtocol,
               sizeof(usmAESPrivProtocol));
        testcase = 1;
    privKeyLen = 16;
    }
#endif
    if (testcase == 0) {
        usm_free_user(newuser);
        return;
    }

    cp = skip_token(cp);
    /*
     * READ: Encryption Pass Phrase or key
     */
    if (!cp) {
        /*
         * assume the same as the authentication key
         */
        memdup(&newuser->privKey, newuser->authKey, newuser->authKeyLen);
        newuser->privKeyLen = newuser->authKeyLen;
    } else {
        cp = copy_nword(cp, buf, sizeof(buf));

        if (strcmp(buf,"-m") == 0) {
            /* a master key is specified */
            cp = copy_nword(cp, buf, sizeof(buf));
            ret = sizeof(userKey);
            tmpp = userKey;
            userKeyLen = 0;
            if (!snmp_hex_to_binary(&tmpp, &ret, &userKeyLen, 0, buf)) {
                usm_free_user(newuser);
                return;
            }
        } else if (strcmp(buf,"-l") != 0) {
            /* a password is specified */
            userKeyLen = sizeof(userKey);
            ret2 = generate_Ku(newuser->authProtocol, newuser->authProtocolLen,
                              (u_char*) buf, strlen(buf), userKey, &userKeyLen);
            if (ret2 != SNMPERR_SUCCESS) {
                usm_free_user(newuser);
                return;
            }
        }

        /*
         * And turn it into a localized key
         */
        ret2 = sc_get_properlength(newuser->authProtocol,
                                   newuser->authProtocolLen);
        if (ret2 < 0) {
            usm_free_user(newuser);
            return;
        }
        newuser->privKey = (u_char*) malloc(ret2);

        if (strcmp(buf,"-l") == 0) {
            /* a local key is directly specified */
            cp = copy_nword(cp, buf, sizeof(buf));
            ret = ret2;
            newuser->privKeyLen = 0;
            if (!snmp_hex_to_binary(&newuser->privKey, &ret,
                                    &newuser->privKeyLen, 0, buf)) {
                usm_free_user(newuser);
                return;
            }
        } else {
            newuser->privKeyLen = ret2;
            ret2 = generate_kul(newuser->authProtocol, newuser->authProtocolLen,
                               newuser->engineID, newuser->engineIDLen,
                               userKey, userKeyLen,
                               newuser->privKey, &newuser->privKeyLen);
            if (ret2 != SNMPERR_SUCCESS) {
                usm_free_user(newuser);
                return;
            }
        }
    }

    if ((newuser->privKeyLen >= privKeyLen) || (privKeyLen == 0)){
      newuser->privKeyLen = privKeyLen;
    }
    else {
      /* The privKey length is smaller than required by privProtocol */
      usm_free_user(newuser);
      return;
    }

  add:
    usm_add_user(newuser);
}

/*******************************************************************-o-******
 * engineBoots_conf
 *
 * Parameters:
 *    *word
 *    *cptr
 *
 * Line syntax:
 *    engineBoots <num_boots>
 */
void
NetSnmpAgent::engineBoots_conf(const char* word, char* cptr)
{
    engineBoots = atoi(cptr) + 1;
}

/*******************************************************************-o-******
 * engineIDType_conf
 *
 * Parameters:
 *    *word
 *    *cptr
 *
 * Line syntax:
 *    engineIDType <1 or 3>
 *        1 is default for IPv4 engine ID type.  Will automatically
 *            chose between IPv4 & IPv6 if either 1 or 2 is specified.
 *        2 is for IPv6.
 *        3 is hardware (MAC) address, currently supported under Linux
 */
void
NetSnmpAgent::engineIDType_conf(const char* word, char* cptr)
{
    engineIDType = atoi(cptr);
    /*
     * verify valid type selected
     */
    switch (engineIDType) {
    case ENGINEID_TYPE_IPV4:   /* IPv4 */
    case ENGINEID_TYPE_IPV6:   /* IPv6 */
        /*
         * IPV? is always good
         */
        break;
#if defined(IFHWADDRLEN) && defined(SIOCGIFHWADDR)
    case ENGINEID_TYPE_MACADDR:        /* MAC address */
        break;
#endif
    default:
        engineIDType = ENGINEID_TYPE_IPV4;
    }
}

/*******************************************************************-o-******
 * engineIDNic_conf
 *
 * Parameters:
 *    *word
 *    *cptr
 *
 * Line syntax:
 *    engineIDNic <string>
 *        eth0 is default
 */
void
NetSnmpAgent::engineIDNic_conf(const char* word, char* cptr)
{
    /*
     * Make sure they haven't already specified the engineID via the
     * * configuration file
     */
    if (0 == engineIDIsSet)
        /*
         * engineID has NOT been set via configuration file
         */
    {
        /*
         * See if already set if so erase & release it
         */
        if (NULL != engineIDNic) {
            SNMP_FREE(engineIDNic);
        }
        engineIDNic = (u_char*) malloc(strlen(cptr) + 1);
        if (NULL != engineIDNic) {
            strcpy((char*) engineIDNic, cptr);
        }
    }
}

/*******************************************************************-o-******
 * engineID_conf
 *
 * Parameters:
 *    *word
 *    *cptr
 *
 * This function reads a string from the configuration file and uses that
 * string to initialize the engineID.  It's assumed to be human readable.
 */
void
NetSnmpAgent::engineID_conf(const char* word, char* cptr)
{
    setup_engineID(NULL, cptr);
}

void
NetSnmpAgent::version_conf(const char* word, char* cptr)
{
    int valid = 0;
#ifndef NETSNMP_DISABLE_SNMPV1
    if ((strcmp(cptr,  "1") == 0) ||
        (strcmp(cptr, "v1") == 0)) {
        netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SNMPVERSION,
               NETSNMP_DS_SNMP_VERSION_1);       /* bogus value */
        valid = 1;
    }
#endif
#ifndef NETSNMP_DISABLE_SNMPV2C
    if ((strcasecmp(cptr,  "2c") == 0) ||
               (strcasecmp(cptr, "v2c") == 0)) {
        netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SNMPVERSION,
               NETSNMP_DS_SNMP_VERSION_2c);
        valid = 1;
    }
#endif
    if ((strcasecmp(cptr,  "3") == 0) ||
               (strcasecmp(cptr, "v3") == 0)) {
        netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SNMPVERSION,
               NETSNMP_DS_SNMP_VERSION_3);
        valid = 1;
    }
    if (!valid) {
        return;
    }
}

/*
 * oldengineID_conf(const char *, char*):
 *
 * Reads a octet string encoded engineID into the oldEngineID and
 * oldEngineIDLen pointers.
 */
void
NetSnmpAgent::oldengineID_conf(const char* word, char* cptr)
{
    read_config_read_octet_string(cptr, &oldEngineID, &oldEngineIDLength);
}

/*
 * exactEngineID_conf(const char *, char*):
 *
 * Reads a octet string encoded engineID into the engineID and
 * engineIDLen pointers.
 */
void
NetSnmpAgent::exactEngineID_conf(const char* word, char* cptr)
{
    read_config_read_octet_string(cptr, &engineID, &engineIDLength);
    if (engineIDLength > MAX_ENGINEID_LENGTH) {
        engineID[MAX_ENGINEID_LENGTH - 1] = '\0';
        engineIDLength = MAX_ENGINEID_LENGTH;
    }
    engineIDIsSet = 1;
    engineIDType = ENGINEID_TYPE_EXACT;
}


/*
 * merely call
 */
void
NetSnmpAgent::get_enginetime_alarm(unsigned int regnum, void* clientargs)
{
    /* we do this every so (rarely) often just to make sure we watch
       wrapping of the times() output */
    snmpv3_local_snmpEngineTime();
}

/*******************************************************************-o-******
 * init_snmpv3
 *
 * Parameters:
 *    *type    Label for the config file "type" used by calling entity.
 *
 * Set time and engineID.
 * Set parsing functions for config file tokens.
 * Initialize SNMP Crypto API (SCAPI).
 */
void
NetSnmpAgent::init_snmpv3(const char* type)
{
#if SNMP_USE_TIMES
  struct tms dummy;

  /* remember how many ticks per second there are, since times() returns this */

  clockticks = sysconf(_SC_CLK_TCK);

#endif /* SNMP_USE_TIMES */

    if (!type)
        type = "__snmpapp__";

    /*
     * we need to be called back later
     */
    snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                           SNMP_CALLBACK_POST_READ_CONFIG,
                           &NetSnmpAgent::init_snmpv3_post_config, NULL);

    snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                           SNMP_CALLBACK_POST_PREMIB_READ_CONFIG,
                           &NetSnmpAgent::init_snmpv3_post_premib_config, NULL);
    /*
     * we need to be called back later
     */
    snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_STORE_DATA,
        &NetSnmpAgent::snmpv3_store, (void*) strdup(type));

    /*
     * Free stuff at shutdown time
     */
    snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                           SNMP_CALLBACK_SHUTDOWN,
                           &NetSnmpAgent::free_enginetime_on_shutdown, NULL);

    /*
     * initialize submodules
     */
    /*
     * NOTE: this must be after the callbacks are registered above,
     * since they need to be called before the USM callbacks.
     */
    init_secmod();

    /*
     * register all our configuration handlers (ack, there's a lot)
     */

    /*
     * handle engineID setup before everything else which may depend on it
     */
    register_prenetsnmp_mib_handler(type, "engineID",
                                    &NetSnmpAgent::engineID_conf, NULL,
                                    "string");
    register_prenetsnmp_mib_handler(type, "oldEngineID",
                                    &NetSnmpAgent::oldengineID_conf,
                                    NULL, NULL);
    register_prenetsnmp_mib_handler(type, "exactEngineID",
                                    &NetSnmpAgent::exactEngineID_conf,
                                    NULL, NULL);
    register_prenetsnmp_mib_handler(type, "engineIDType",
                                    &NetSnmpAgent::engineIDType_conf, NULL, "num");
    register_prenetsnmp_mib_handler(type, "engineIDNic",
                                    &NetSnmpAgent::engineIDNic_conf,
                                    NULL, "string");
    register_config_handler(type, "engineBoots",
                            &NetSnmpAgent::engineBoots_conf, NULL,
                            NULL);

    /*
     * default store config entries
     */
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defSecurityName",
                   NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SECNAME);
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defContext",
                   NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_CONTEXT);
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defPassphrase",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_PASSPHRASE);
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defAuthPassphrase",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_AUTHPASSPHRASE);
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defPrivPassphrase",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_PRIVPASSPHRASE);
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defAuthMasterKey",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_AUTHMASTERKEY);
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defPrivMasterKey",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_PRIVMASTERKEY);
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defAuthLocalizedKey",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_AUTHLOCALIZEDKEY);
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defPrivLocalizedKey",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_PRIVLOCALIZEDKEY);
    register_config_handler("snmp", "defVersion",
                            &NetSnmpAgent::version_conf, NULL,
                            "1|2c|3");

    register_config_handler("snmp", "defAuthType",
                            &NetSnmpAgent::snmpv3_authtype_conf,
                            NULL, "MD5|SHA");
    register_config_handler("snmp", "defPrivType",
                            &NetSnmpAgent::snmpv3_privtype_conf,
                            NULL,
#ifdef HAVE_AES
                            "DES|AES");
#else
                            "DES (AES support not available)");
#endif
    register_config_handler("snmp", "defSecurityLevel",
                            &NetSnmpAgent::snmpv3_secLevel_conf, NULL,
                            "noAuthNoPriv|authNoPriv|authPriv");
    register_config_handler(type, "userSetAuthPass", &NetSnmpAgent::usm_set_password,
                            NULL, NULL);
    register_config_handler(type, "userSetPrivPass", &NetSnmpAgent::usm_set_password,
                            NULL, NULL);
    register_config_handler(type, "userSetAuthKey", &NetSnmpAgent::usm_set_password, NULL,
                            NULL);
    register_config_handler(type, "userSetPrivKey", &NetSnmpAgent::usm_set_password, NULL,
                            NULL);
    register_config_handler(type, "userSetAuthLocalKey", &NetSnmpAgent::usm_set_password,
                            NULL, NULL);
    register_config_handler(type, "userSetPrivLocalKey", &NetSnmpAgent::usm_set_password,
                            NULL, NULL);
}

/*
 * initializations for SNMPv3 to be called after the configuration files
 * have been read.
 */

int
NetSnmpAgent::init_snmpv3_post_config(int majorid, int minorid, void* serverarg,
                        void* clientarg)
{

    size_t          engineIDLen = 0;
    u_char*         c_engineID;

    c_engineID = snmpv3_generate_engineID(&engineIDLen);

    if (engineIDLen == 0 || !c_engineID) {
        /*
         * Somethine went wrong - help!
         */
        SNMP_FREE(c_engineID);
        return SNMPERR_GENERR;
    }

    /*
     * if our engineID has changed at all, the boots record must be set to 1
     */
    if (engineIDLen != oldEngineIDLength ||
        oldEngineID == NULL || c_engineID == NULL ||
        memcmp(oldEngineID, c_engineID, engineIDLen) != 0) {
        engineBoots = 1;
    }

    /*
     * set our local engineTime in the LCD timing cache
     */
    set_enginetime(c_engineID, engineIDLen,
                   snmpv3_local_snmpEngineBoots(),
                   snmpv3_local_snmpEngineTime(), TRUE);

    SNMP_FREE(c_engineID);
    return SNMPERR_SUCCESS;
}

int
NetSnmpAgent::init_snmpv3_post_premib_config(int majorid, int minorid, void* serverarg,
                               void* clientarg)
{
    if (!engineIDIsSet)
        setup_engineID(NULL, NULL);

    return SNMPERR_SUCCESS;
}

/*******************************************************************-o-******
 * store_snmpv3
 *
 * Parameters:
 *    *type
 */
int
NetSnmpAgent::snmpv3_store(int majorID, int minorID, void* serverarg, void* clientarg)
{
    char            line[SNMP_MAXBUF_SMALL];
    u_char          c_engineID[SNMP_MAXBUF_SMALL];
    int             engineIDLen;
    const char*     type = (const char*) clientarg;

    if (type == NULL)           /* should never happen, since the arg is ours */
        type = "unknown";

    sprintf(line, "engineBoots %ld", engineBoots);
    read_config_store(type, line);

    engineIDLen = snmpv3_get_engineID(c_engineID, SNMP_MAXBUF_SMALL);

    if (engineIDLen) {
        /*
         * store the engineID used for this run
         */
        sprintf(line, "oldEngineID ");
        read_config_save_octet_string(line + strlen(line), c_engineID,
                                      engineIDLen);
        read_config_store(type, line);
    }
    return SNMPERR_SUCCESS;
}                               /* snmpv3_store() */

u_long
NetSnmpAgent::snmpv3_local_snmpEngineBoots(void)
{
    return engineBoots;
}


/*******************************************************************-o-******
 * snmpv3_get_engineID
 *
 * Parameters:
 *    *buf
 *     buflen
 *
 * Returns:
 *    Length of engineID    On Success
 *    SNMPERR_GENERR        Otherwise.
 *
 *
 * Store engineID in buf; return the length.
 *
 */
size_t
NetSnmpAgent::snmpv3_get_engineID(u_char*  buf, size_t buflen)
{
    /*
     * Sanity check.
     */
    if (!buf || (buflen < engineIDLength)) {
        return 0;
    }

    memcpy(buf, engineID, engineIDLength);
    return engineIDLength;

}                               /* end snmpv3_get_engineID() */

/*******************************************************************-o-******
 * snmpv3_clone_engineID
 *
 * Parameters:
 *    **dest
 *       *dest_len
 *       src
 *     srclen
 *
 * Returns:
 *    Length of engineID    On Success
 *    0                Otherwise.
 *
 *
 * Clones engineID, creates memory
 *
 */
int
snmpv3_clone_engineID(u_char**  dest, size_t*  destlen, u_char*  src,
                      size_t srclen)
{
    if (!dest || !destlen)
        return 0;

    if (*dest) {
        SNMP_FREE(*dest);
        *dest = NULL;
    }
    *destlen = 0;

    if (srclen && src) {
        *dest = (u_char*) malloc(srclen);
        if (*dest == NULL)
            return 0;
        memmove(*dest, src, srclen);
        *destlen = srclen;
    }
    return *destlen;
}                               /* end snmpv3_clone_engineID() */


/*******************************************************************-o-******
 * snmpv3_generate_engineID
 *
 * Parameters:
 *    *length
 *
 * Returns:
 *    Pointer to copy of engineID    On Success.
 *    NULL                If malloc() or snmpv3_get_engineID()
 *                        fail.
 *
 * Generates a malloced copy of our engineID.
 *
 * 'length' is set to the length of engineID  -OR-  < 0 on failure.
 */
u_char*
NetSnmpAgent::snmpv3_generate_engineID(size_t*  length)
{
    u_char*         newID;
    newID = (u_char*) malloc(engineIDLength);

    if (newID) {
        *length = snmpv3_get_engineID(newID, engineIDLength);
    }

    if (*length == 0) {
        SNMP_FREE(newID);
        newID = NULL;
    }

    return newID;

}                               /* end snmpv3_generate_engineID() */

struct timeval convert_2_timeval(clocktype nanosec)
{
    struct timeval time;
    time.tv_sec = nanosec / (long) pow(10.0, 9.0);
    long left_sec = nanosec - time.tv_sec * (long) pow(10.0, 9.0);
    time.tv_usec = left_sec / (long) pow(10.0, 6.0);
    return time;
}

/*
 * snmpv3_local_snmpEngineTime(): return the number of seconds since the
 * snmpv3 engine last incremented engine_boots
 */
u_long
NetSnmpAgent::snmpv3_local_snmpEngineTime(void)
{
    struct timeval  now;
    now = convert_2_timeval(this->node->getNodeTime());
    return calculate_sectime_diff(&now, &snmpv3starttime);
}



/*
 * Code only for Linux systems
 */
#if defined(IFHWADDRLEN) && defined(SIOCGIFHWADDR)
static int
getHwAddress(const char* networkDevice, /* e.g. "eth0", "eth1" */
             char* addressOut)
{                               /* return address. Len=IFHWADDRLEN */
    /*
     * getHwAddress(...)
     * *
     * *  This function will return a Network Interfaces Card's Hardware
     * *  address (aka MAC address).
     * *
     * *  Input Parameter(s):
     * *      networkDevice - a null terminated string with the name of a network
     * *                      device.  Examples: eth0, eth1, etc...
     * *
     * *  Output Parameter(s):
     * *      addressOut -    This is the binary value of the hardware address.
     * *                      This value is NOT converted into a hexadecimal string.
     * *                      The caller must pre-allocate for a return value of
     * *                      length IFHWADDRLEN
     * *
     * *  Return value:   This function will return zero (0) for success.  If
     * *                  an error occurred the function will return -1.
     * *
     * *  Caveats:    This has only been tested on Ethernet networking cards.
     */
    int             sock;       /* our socket */
    struct ifreq    request;    /* struct which will have HW address */

    if ((NULL == networkDevice) || (NULL == addressOut)) {
        return -1;
    }
    /*
     * In order to find out the hardware (MAC) address of our system under
     * * Linux we must do the following:
     * * 1.  Create a socket
     * * 2.  Do an ioctl(...) call with the SIOCGIFHWADDRLEN operation.
     */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }
    /*
     * erase the request block
     */
    memset(&request, 0, sizeof(request));
    /*
     * copy the name of the net device we want to find the HW address for
     */
    strncpy(request.ifr_name, networkDevice, IFNAMSIZ - 1);
    /*
     * Get the HW address
     */
    if (ioctl(sock, SIOCGIFHWADDR, &request)) {
        close(sock);
        return -1;
    }
    close(sock);
    memcpy(addressOut, request.ifr_hwaddr.sa_data, IFHWADDRLEN);
    return 0;
}
#endif
