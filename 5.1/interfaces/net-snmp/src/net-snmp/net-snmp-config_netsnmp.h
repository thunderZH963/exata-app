#ifndef NET_SNMP_CONFIG_H_NETSNMP
#define NET_SNMP_CONFIG_H_NETSNMP

/* include/net-snmp/net-snmp-config.h.in.  Generated from configure.in by autoheader.  */
/* modified by hand with care. */

/* Define to 1 if you have the <winsock.h> header file. */
#define HAVE_WINSOCK_H 1

#define NETSNMP_WIN32ID 13

#define OSTYPE NETSNMP_WIN32ID

/* The assigned enterprise number for sysObjectID. */
#define NETSNMP_SYSTEM_MIB        1,3,6,1,4,1,8072,3,2,OSTYPE

/* The assigned enterprise number for notifications. */
#define NETSNMP_NOTIFICATION_MIB        1,3,6,1,4,1,8072,4

#ifndef NETSNMP_IMPORT
#  define NETSNMP_IMPORT extern
#endif

#define NETSNMP_VERS_DESC   "unknown"             /* overridden at run time */
#define NETSNMP_SYS_NAME    "unknown"             /* overridden at run time */
#define NETSNMP_DEFAULT_SNMP_VERSION 3
/* comment out the second define to turn off functionality for any of
   these: (See README for details) */

/*   proc PROCESSNAME [MAX] [MIN] */
#define NETSNMP_PROCMIBNUM 2

/*   exec/shell NAME COMMAND      */
#define NETSNMP_SHELLMIBNUM 8

/*   swap MIN                     */
#define NETSNMP_MEMMIBNUM 4

/*   disk DISK MINSIZE            */
#define NETSNMP_DISKMIBNUM 9

/*   load 1 5 15                  */
#define NETSNMP_LOADAVEMIBNUM 10

/* which version are you using? This mibloc will tell you */
#define NETSNMP_VERSIONMIBNUM 100

/* Reports errors the agent runs into */
/* (typically its "can't fork, no mem" problems) */
#define NETSNMP_ERRORMIBNUM 101

/* The sub id of EXTENSIBLEMIB returned to queries of
   .iso.org.dod.internet.mgmt.mib-2.system.sysObjectID.0 */
#define NETSNMP_AGENTID 250


/* default system contact */
#define NETSNMP_SYS_CONTACT "unknown"

/* system location */
#define NETSNMP_SYS_LOC "unknown"

/* The original CMU code had this hardcoded as = 1 */
#define NETSNMP_SNMPBLOCK 1       /* Set if snmpgets should block and never timeout */


/*
 * Win32 needs extern for inline function declarations in headers.
 * See MS tech note Q123768:
 *   http://support.microsoft.com/default.aspx?scid=kb;EN-US;123768
 */
#define NETSNMP_INLINE extern inline
#define NETSNMP_STATIC_INLINE static inline
#define NETSNMP_ENABLE_INLINE 1

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void


#define srandom(s) srand(s)

#if defined (WIN32) || defined (mingw32) || defined (cygwin)
#define ENV_SEPARATOR ";"
#define ENV_SEPARATOR_CHAR ';'
#else
#define ENV_SEPARATOR ":"
#define ENV_SEPARATOR_CHAR ':'
#endif

#define NETSNMP_MAX_PERSISTENT_BACKUPS 10

#define INSTALL_BASE c:/usr
/* default location to look for mibs to load using the above tokens
   and/or those in the MIBS envrionment variable*/
#define NETSNMP_DEFAULT_MIBDIRS INSTALL_BASE ## /share/snmp/mibs

#define NETSNMP_DEFAULT_MIBS "IP-MIB;IF-MIB;TCP-MIB;UDP-MIB;HOST-RESOURCES-MIB;SNMPv2-MIB;RFC1213-MIB;NOTIFICATION-LOG-MIB;UCD-SNMP-MIB;UCD-DEMO-MIB;SNMP-TARGET-MIB;NET-SNMP-AGENT-MIB;DISMAN-EVENT-MIB;SNMP-VIEW-BASED-ACM-MIB;SNMP-COMMUNITY-MIB;UCD-DLMOD-MIB;SNMP-FRAMEWORK-MIB;SNMP-MPD-MIB;SNMP-USER-BASED-SM-MIB;SNMP-NOTIFICATION-MIB;SNMPv2-TM"

#define DEBUG_ALWAYS_TOKEN "all"

/* The enterprise number has been assigned by the IANA group.   */
/* Optionally, this may point to the location in the tree your  */
/* company/organization has been allocated.                     */
/* The assigned enterprise number for the NET_SNMP MIB modules. */
#define NETSNMP_ENTERPRISE_OID            8072
#define NETSNMP_ENTERPRISE_MIB            1,3,6,1,4,1,8072
#define NETSNMP_ENTERPRISE_DOT_MIB        1.3.6.1.4.1.8072
#define NETSNMP_ENTERPRISE_DOT_MIB_LENGTH    7

/* The assigned enterprise number for sysObjectID. */
#define NETSNMP_SYSTEM_MIB        1,3,6,1,4,1,8072,3,2,OSTYPE
#define NETSNMP_SYSTEM_DOT_MIB        1.3.6.1.4.1.8072.3.2.OSTYPE
#define NETSNMP_SYSTEM_DOT_MIB_LENGTH    10

/* The assigned enterprise number for notifications. */
#define NETSNMP_NOTIFICATION_MIB        1,3,6,1,4,1,8072,4
#define NETSNMP_NOTIFICATION_DOT_MIB        1.3.6.1.4.1.8072.4
#define NETSNMP_NOTIFICATION_DOT_MIB_LENGTH    8

/* this is the location of the net-snmp mib tree.  It shouldn't be
   changed, as the places it is used are expected to be constant
   values or are directly tied to the UCD-SNMP-MIB. */
#define NETSNMP_OID             8072
#define NETSNMP_MIB             1,3,6,1,4,1,8072
#define NETSNMP_DOT_MIB         1.3.6.1.4.1.8072
#define NETSNMP_DOT_MIB_LENGTH  7

#if defined (WIN32)
typedef unsigned short mode_t;
typedef unsigned __int32 uint32_t;
typedef int int32_t;
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
typedef unsigned __int64 uintmax_t;
typedef __int64 intmax_t;
typedef unsigned short   uint16_t;
#endif

#endif                          /* NET_SNMP_CONFIG_H_NETSNMP */
