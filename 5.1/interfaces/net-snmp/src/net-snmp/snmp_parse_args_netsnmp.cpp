#include "net-snmp-config_netsnmp.h"
#include "types_netsnmp.h"
#include "system_netsnmp.h"
#include "netSnmpAgent.h"
#include "keytools_netsnmp.h"
#include "transform_oids_netsnmp.h"
#include "tools_netsnmp.h"
#include "errno.h"
/*
 * This method does the real work for snmp_parse_args.  It takes an
 * extra argument, proxy, and uses this to decide how to handle the lack of
 * of a community string.
 */
#define BUF_SIZE 512
char*  optarg;
int optind;
int
NetSnmpAgent::snmp_parse_args(int argc,
                char** argv,
                netsnmp_session*  session, const char* localOpts,
                void (NetSnmpAgent::*proc) (int, char* const* , int))
{
    static char*   sensitive[4] = { NULL, NULL, NULL, NULL };
    int             arg=0, sp = 0, zero_sensitive = 1, testcase = 0;
    char*           cp;
    char*           Apsz = NULL;
    char*           Xpsz = NULL;
    char*           Cpsz = NULL;
    char            Opts[BUF_SIZE];
    int             logopt = 0;

    /*
     * initialize session to default values
     */
    snmp_sess_init(session);
    strcpy(Opts, "Y:VhHm:M:O:I:P:D:dv:r:t:c:Z:e:E:n:u:l:x:X:a:A:p:T:-:3:s:S:L:");
    if (localOpts)
        strcat(Opts, localOpts);

    if (strcmp(argv[0], "snmpd-trapsess") == 0 ||
    strcmp(argv[0], "snmpd-proxy")    == 0) {
    /*  Don't worry about zeroing sensitive parameters as they are not
        on the command line anyway (called from internal config-line
        handler).  */
    zero_sensitive = 0;
    }

    /*
     * get the options
     */

    optind = 1;
    while (1/*(arg = getopt(argc, argv, Opts)) != EOF*/) {
        switch (arg) {
        case '-':
            if (strcasecmp(optarg, "help") == 0) {
                return (-1);
            }
            if (strcasecmp(optarg, "version") == 0) {
                return (-2);
            }
            break;

        case 'V':
            return (-2);

        case 'h':
            return (-1);
            break;

        case 'H':
            init_snmp("snmpapp");
            ERROR_ReportWarning("Configuration directives understood:\n");
            return (-2);

        case 'Y':
            break;

#ifndef NETSNMP_DISABLE_MIB_LOADING
        case 'm':
            break;

        case 'M':
            netsnmp_get_mib_directory(); /* prepare the default directories */
            netsnmp_set_mib_directory(optarg);
            break;
#endif /* NETSNMP_DISABLE_MIB_LOADING */

        case 'O':
            if (cp != NULL) {
                ERROR_ReportWarningArgs("Unknown output option passed to -O:"
                                        " %c.\n", *cp);
                return (-1);
            }
            break;

        case 'I':
            if (cp != NULL) {
                ERROR_ReportWarningArgs("Unknown input option passed to -I:"
                                        " %c.\n", *cp);
                return (-1);
            }
            break;

#ifndef NETSNMP_DISABLE_MIB_LOADING
        case 'P':
            if (cp != NULL) {
                ERROR_ReportWarningArgs("Unknown parsing option passed to -P:"
                                        " %c.\n", *cp);
                return (-1);
            }
            break;
#endif /* NETSNMP_DISABLE_MIB_LOADING */

        case 'D':
            break;

        case 'd':
            netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_DUMP_PACKET, 1);
            break;

        case 'v':
            session->version = -1;
#ifndef NETSNMP_DISABLE_SNMPV1
            if (!strcmp(optarg, "1")) {
                session->version = SNMP_VERSION_1;
            }
#endif
#ifndef NETSNMP_DISABLE_SNMPV2C
            if (!strcasecmp(optarg, "2c")) {
                session->version = SNMP_VERSION_2c;
            }
#endif
            if (!strcasecmp(optarg, "3")) {
                session->version = SNMP_VERSION_3;
            }
            if (session->version == -1) {
                ERROR_ReportWarningArgs("Invalid version specified after "
                                        "-v flag: %s\n", optarg);
                return (-1);
            }
            break;

        case 'p':
            ERROR_ReportWarning("Warning: -p option is no longer used - "
                                "specify the remote host as HOST:PORT\n");
            return (-1);
            break;

        case 'T':
            ERROR_ReportWarning("Warning: -T option is no longer "
                                "used - specify the remote host as "
                                "TRANSPORT:HOST\n");
            return (-1);
            break;

        case 't':
            session->timeout = (long)(atof(optarg) * 1000000L);
            if (session->timeout <= 0) {
                ERROR_ReportWarning("Invalid timeout in seconds after -t"
                                    " flag.\n");
                return (-1);
            }
            break;

        case 'r':
            session->retries = atoi(optarg);
            if (session->retries < 0 || !isdigit(optarg[0])) {
                ERROR_ReportWarning("Invalid number of retries after -r"
                                    " flag.\n");
                return (-1);
            }
            break;

        case 'c':
        if (zero_sensitive) {
        if ((sensitive[sp] = strdup(optarg)) != NULL) {
            Cpsz = sensitive[sp];
            memset(optarg, '\0', strlen(optarg));
            sp++;
        } else {
            ERROR_ReportWarning("malloc failure processing -c flag.\n");
            return -1;
        }
        } else {
        Cpsz = optarg;
        }
            break;

        case '3':
        /*  TODO: This needs to zero things too.  */
            if (snmpv3_options(optarg, session, &Apsz, &Xpsz, argc, argv) < 0){
                return (-1);
            }
            break;

        logopt = 1;
            break;

#define SNMPV3_CMD_OPTIONS
#ifdef  SNMPV3_CMD_OPTIONS
        case 'Z':
            errno = 0;
            session->engineBoots = strtoul(optarg, &cp, 10);
            if (errno || cp == optarg) {
                ERROR_ReportWarning("Need engine boots value after -Z "
                                    "flag.\n");
                return (-1);
            }
            if (*cp == ',') {
                char* endptr;
                cp++;
                session->engineTime = strtoul(cp, &endptr, 10);
                if (errno || cp == endptr) {
                    ERROR_ReportWarning("Need engine time after \"-Z "
                                        "engineBoot,\".\n");
                    return (-1);
                }
            }
            /*
             * Handle previous '-Z boot time' syntax
             */
            else if (optind < argc) {
                session->engineTime = strtoul(argv[optind], &cp, 10);
                if (errno || cp == argv[optind]) {
                    ERROR_ReportWarning("Need engine time after \"-Z "
                                        "engineBoot\".\n");
                    return (-1);
                }
            } else {
                ERROR_ReportWarning("Need engine time after \"-Z "
                                    "engineBoot\".\n");
                return (-1);
            }
            break;

        case 'e':{
                size_t ebuf_len = 32, eout_len = 0;
                u_char* ebuf = (u_char*)malloc(ebuf_len);

                if (ebuf == NULL) {
                    ERROR_ReportWarning("malloc failure processing -e "
                                        "flag.\n");
                    return (-1);
                }
                if (!snmp_hex_to_binary
                    (&ebuf, &ebuf_len, &eout_len, 1, optarg)) {
                    ERROR_ReportWarning("Bad engine ID value after -e "
                                        "flag.\n");
                    free(ebuf);
                    return (-1);
                }
                if ((eout_len < 5) || (eout_len > 32)) {
                    ERROR_ReportWarning("Invalid engine ID value after "
                                        "-e flag.\n");
                    free(ebuf);
                    return (-1);
                }
                session->securityEngineID = ebuf;
                session->securityEngineIDLen = eout_len;
                break;
            }

        case 'E':{
                size_t ebuf_len = 32, eout_len = 0;
                u_char* ebuf = (u_char*)malloc(ebuf_len);

                if (ebuf == NULL) {
                    ERROR_ReportWarning("malloc failure processing -E "
                                        "flag.\n");
                    return (-1);
                }
                if (!snmp_hex_to_binary(&ebuf, &ebuf_len,
                    &eout_len, 1, optarg)) {
                    ERROR_ReportWarning("Bad engine ID value after -E "
                                        "flag.\n");
                    free(ebuf);
                    return (-1);
                }
                if ((eout_len < 5) || (eout_len > 32)) {
                    ERROR_ReportWarning("Invalid engine ID value after "
                                        "-E flag.\n");
                    free(ebuf);
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
        if (zero_sensitive) {
        if ((sensitive[sp] = strdup(optarg)) != NULL) {
            session->securityName = sensitive[sp];
            session->securityNameLen = strlen(sensitive[sp]);
            memset(optarg, '\0', strlen(optarg));
            sp++;
        } else {
            ERROR_ReportWarning("malloc failure processing -u flag.\n");
            return -1;
        }
        } else {
        session->securityName = optarg;
        session->securityNameLen = strlen(optarg);
        }
            break;

        case 'l':
            if (!strcasecmp(optarg, "noAuthNoPriv") || !strcmp(optarg, "1")
                || !strcasecmp(optarg, "noauth")
                || !strcasecmp(optarg, "nanp")) {
                session->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
            } else if (!strcasecmp(optarg, "authNoPriv")
                       || !strcmp(optarg, "2")
                       || !strcasecmp(optarg, "auth")
                       || !strcasecmp(optarg, "anp")) {
                session->securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
            } else if (!strcasecmp(optarg, "authPriv")
                       || !strcmp(optarg, "3")
                       || !strcasecmp(optarg, "priv")
                       || !strcasecmp(optarg, "ap")) {
                session->securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
            } else {
                ERROR_ReportWarningArgs("Invalid security level specified "
                                        "after -l flag: %s\n", optarg);
                return (-1);
            }

            break;

        case 'a':
#ifndef NETSNMP_DISABLE_MD5
            if (!strcasecmp(optarg, "MD5")) {
                session->securityAuthProto = usmHMACMD5AuthProtocol;
                session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
            } else
#endif
                if (!strcasecmp(optarg, "SHA")) {
                session->securityAuthProto = usmHMACSHA1AuthProtocol;
                session->securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
            } else {
                ERROR_ReportWarningArgs("Invalid authentication protocol "
                                        "specified after -a flag: %s\n",
                                        optarg);
                return (-1);
            }
            break;

        case 'x':
            testcase = 0;
#ifndef NETSNMP_DISABLE_DES
            if (!strcasecmp(optarg, "DES")) {
                testcase = 1;
                session->securityPrivProto = usmDESPrivProtocol;
                session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
            }
#endif
#ifdef HAVE_AES
            if (!strcasecmp(optarg, "AES128") ||
                !strcasecmp(optarg, "AES")) {
                testcase = 1;
                session->securityPrivProto = usmAESPrivProtocol;
                session->securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
            }
#endif
            if (testcase == 0) {
                ERROR_ReportWarningArgs("Invalid privacy protocol specified "
                                        "after -x flag: %s\n", optarg);
                return (-1);
            }
            break;

        case 'A':
        if (zero_sensitive) {
        if ((sensitive[sp] = strdup(optarg)) != NULL) {
            Apsz = sensitive[sp];
            memset(optarg, '\0', strlen(optarg));
            sp++;
        } else {
            ERROR_ReportWarning("malloc failure processing -A flag.\n");
            return -1;
        }
        } else {
        Apsz = optarg;
        }
            break;

        case 'X':
        if (zero_sensitive) {
        if ((sensitive[sp] = strdup(optarg)) != NULL) {
            Xpsz = sensitive[sp];
            memset(optarg, '\0', strlen(optarg));
            sp++;
        } else {
            ERROR_ReportWarning("malloc failure processing -X flag.\n");
            return -1;
        }
        } else {
        Xpsz = optarg;
        }
            break;
#endif                          /* SNMPV3_CMD_OPTIONS */

        case '?':
            return (-1);
            break;

        default:
            break;
        }
    }

    /*
     * read in MIB database and initialize the snmp library
     */
    init_snmp("snmpapp");

    /*
     * session default version
     */
    if (session->version == SNMP_DEFAULT_VERSION) {
        /*
         * run time default version
         */
        session->version = netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,
                          NETSNMP_DS_LIB_SNMPVERSION);

        /*
         * compile time default version
         */
        if (!session->version) {
            switch (NETSNMP_DEFAULT_SNMP_VERSION) {
#ifndef NETSNMP_DISABLE_SNMPV1
            case 1:
                session->version = SNMP_VERSION_1;
                break;
#endif

#ifndef NETSNMP_DISABLE_SNMPV2C
            case 2:
                session->version = SNMP_VERSION_2c;
                break;
#endif

            case 3:
                session->version = SNMP_VERSION_3;
                break;

            default:
                return(-2);
            }
        } else {
#ifndef NETSNMP_DISABLE_SNMPV1
            if (session->version == NETSNMP_DS_SNMP_VERSION_1)  /* bogus value.  version 1 actually = 0 */
                session->version = SNMP_VERSION_1;
#endif
        }
    }

    /*
     * make master key from pass phrases
     */
    if (Apsz) {
        session->securityAuthKeyLen = USM_AUTH_KU_LEN;
        if (session->securityAuthProto == NULL) {
            /*
             * get .conf set default
             */
            const oid*      def =
                get_default_authtype(&session->securityAuthProtoLen);
            session->securityAuthProto =
                (snmp_duplicate_objid(def, session->securityAuthProtoLen));
        }
        if (session->securityAuthProto == NULL) {
#ifndef NETSNMP_DISABLE_MD5
            /*
             * assume MD5
             */
            session->securityAuthProto =
                snmp_duplicate_objid(usmHMACMD5AuthProtocol,
                                     USM_AUTH_PROTO_MD5_LEN);
            session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
#else
            session->securityAuthProto =
                snmp_duplicate_objid(usmHMACSHA1AuthProtocol,
                                     USM_AUTH_PROTO_SHA_LEN);
            session->securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
#endif
        }
        if (generate_Ku((oid*)session->securityAuthProto,
                        session->securityAuthProtoLen,
                        (u_char*)Apsz, strlen(Apsz),
                        session->securityAuthKey,
                        &session->securityAuthKeyLen) != SNMPERR_SUCCESS) {
            ERROR_ReportWarning("Error generating a key (Ku) from the "
                                "supplied authentication pass phrase.\n");
            return (-2);
        }
    }
    if (Xpsz) {
        session->securityPrivKeyLen = USM_PRIV_KU_LEN;
        if (session->securityPrivProto == NULL) {
            /*
             * get .conf set default
             */
            const oid*      def =
                get_default_privtype(&session->securityPrivProtoLen);
            session->securityPrivProto =
                snmp_duplicate_objid(def, session->securityPrivProtoLen);
        }
        if (session->securityPrivProto == NULL) {
            /*
             * assume DES
             */
#ifndef NETSNMP_DISABLE_DES
            session->securityPrivProto =
                snmp_duplicate_objid(usmDESPrivProtocol,
                                     USM_PRIV_PROTO_DES_LEN);
            session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
#else
            session->securityPrivProto =
                snmp_duplicate_objid(usmAESPrivProtocol,
                                     USM_PRIV_PROTO_AES_LEN);
            session->securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
#endif

        }
        if (generate_Ku((oid*)session->securityAuthProto,
                        session->securityAuthProtoLen,
                        (u_char*)Xpsz, strlen(Xpsz),
                        session->securityPrivKey,
                        &session->securityPrivKeyLen) != SNMPERR_SUCCESS) {
            ERROR_ReportWarning("Error generating a key (Ku) from the "
                                "supplied privacy pass phrase. \n");
            return (-2);
        }
    }
    /*
     * get the hostname
     */
    if (optind == argc) {
        ERROR_ReportWarning("No hostname specified.\n");
        return (-1);
    }
    session->peername = argv[optind++]; /* hostname */

#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
    /*
     * If v1 or v2c, check community has been set, either by a -c option above,
     * or via a default token somewhere.
     * If neither, it will be taken from the incoming request PDU.
     */

#if defined(NETSNMP_DISABLE_SNMPV1)
    if (session->version == SNMP_VERSION_2c)
#else
#if defined(NETSNMP_DISABLE_SNMPV2C)
    if (session->version == SNMP_VERSION_1)
#else
    if (session->version == SNMP_VERSION_1 ||
    session->version == SNMP_VERSION_2c)
#endif
#endif
    {
        if (Cpsz == NULL) {
            Cpsz = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                     NETSNMP_DS_LIB_COMMUNITY);
        if (Cpsz == NULL) {
                if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                                           NETSNMP_DS_LIB_IGNORE_NO_COMMUNITY)){
                    session->community = NULL;
                    session->community_len = 0;
                } else {
                    ERROR_ReportWarning("No community name specified.\n");
                    return (-1);
                }
        }
    } else {
            session->community = (unsigned char*)Cpsz;
            session->community_len = strlen(Cpsz);
        }
    }
#endif /* support for community based SNMP */

    return optind;
}
