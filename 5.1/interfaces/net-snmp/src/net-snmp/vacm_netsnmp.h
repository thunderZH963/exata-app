/*
 * vacm.h
 *
 * SNMPv3 View-based Access Control Model
 */

#ifndef VACM_H_NETSNMP
#define VACM_H_NETSNMP


#include "types_netsnmp.h"

#define VACM_SUCCESS       0
#define VACM_NOSECNAME     1
#define VACM_NOGROUP       2
#define VACM_NOACCESS      3
#define VACM_NOVIEW        4
#define VACM_NOTINVIEW     5
#define VACM_NOSUCHCONTEXT 6
#define VACM_SUBTREE_UNKNOWN 7

#define SECURITYMODEL    1
#define SECURITYNAME    2
#define SECURITYGROUP    3
#define SECURITYSTORAGE    4
#define SECURITYSTATUS    5

#define ACCESSPREFIX    1
#define ACCESSMODEL    2
#define ACCESSLEVEL    3
#define ACCESSMATCH    4
#define ACCESSREAD    5
#define ACCESSWRITE    6
#define ACCESSNOTIFY    7
#define ACCESSSTORAGE    8
#define ACCESSSTATUS    9

#define VACMVIEWSPINLOCK 1
#define VIEWNAME    2
#define VIEWSUBTREE    3
#define VIEWMASK    4
#define VIEWTYPE    5
#define VIEWSTORAGE    6
#define VIEWSTATUS    7

#define VACM_MAX_STRING 32
#define VACMSTRINGLEN   34      /* VACM_MAX_STRING + 2 */

    struct vacm_groupEntry {
        int             securityModel;
        char            securityName[VACMSTRINGLEN];
        char            groupName[VACMSTRINGLEN];
        int             storageType;
        int             status;

        u_long          bitMask;
        struct vacm_groupEntry* reserved;
        struct vacm_groupEntry* next;
    };

#define CONTEXT_MATCH_EXACT  1
#define CONTEXT_MATCH_PREFIX 2

/* VIEW ENUMS ---------------------------------------- */

/* SNMPD usage: get/set/send-notification views */
#define VACM_VIEW_READ     0
#define VACM_VIEW_WRITE    1
#define VACM_VIEW_NOTIFY   2

/* SNMPTRAPD usage: log execute and net-access (forward) usage */
#define VACM_VIEW_LOG      3
#define VACM_VIEW_EXECUTE  4
#define VACM_VIEW_NET      5

/* VIEW BIT MASK VALUES-------------------------------- */

/* SNMPD usage: get/set/send-notification views */
#define VACM_VIEW_READ_BIT      (1 << VACM_VIEW_READ)
#define VACM_VIEW_WRITE_BIT     (1 << VACM_VIEW_WRITE)
#define VACM_VIEW_NOTIFY_BIT    (1 << VACM_VIEW_NOTIFY)

/* SNMPTRAPD usage: log execute and net-access (forward) usage */
#define VACM_VIEW_LOG_BIT      (1 << VACM_VIEW_LOG)
#define VACM_VIEW_EXECUTE_BIT  (1 << VACM_VIEW_EXECUTE)
#define VACM_VIEW_NET_BIT      (1 << VACM_VIEW_NET)

#define VACM_VIEW_NO_BITS      0

/* Maximum number of views in the view array */
#define VACM_MAX_VIEWS     8

#define VACM_VIEW_ENUM_NAME "vacmviews"

    void init_vacm(void);

    struct vacm_accessEntry {
        char            groupName[VACMSTRINGLEN];
        char            contextPrefix[VACMSTRINGLEN];
        int             securityModel;
        int             securityLevel;
        int             contextMatch;
        char            views[VACM_MAX_VIEWS][VACMSTRINGLEN];
        int             storageType;
        int             status;

        u_long          bitMask;
        struct vacm_accessEntry* reserved;
        struct vacm_accessEntry* next;
    };

    struct vacm_viewEntry {
        char            viewName[VACMSTRINGLEN];
        oid             viewSubtree[MAX_OID_LEN];
        size_t          viewSubtreeLen;
        u_char          viewMask[VACMSTRINGLEN];
        size_t          viewMaskLen;
        int             viewType;
        int             viewStorageType;
        int             viewStatus;

        u_long          bitMask;

        struct vacm_viewEntry* reserved;
        struct vacm_viewEntry* next;
    };

    void            vacm_destroyViewEntry(const char* , oid* , size_t);
    void            vacm_destroyAllViewEntries(void);

#define VACM_MODE_FIND                0
#define VACM_MODE_IGNORE_MASK         1
#define VACM_MODE_CHECK_SUBTREE       2

    /*
     * Returns a pointer to the viewEntry with the
     * same viewName and viewSubtree
     * Returns NULL if that entry does not exist.
     */

    /*int vacm_checkSubtree(const char *, oid *, size_t);*/

    /*
     * Initialized the scan routines so that they will begin at the
     * beginning of the list of viewEntries.
     *
     */


    /*struct vacm_viewEntry *vacm_scanViewNext(void);*/
    /*
     * Returns a pointer to the next viewEntry.
     * These entries are returned in no particular order,
     * but if N entries exist, N calls to view_scanNext() will
     * return all N entries once.
     * Returns NULL if all entries have been returned.
     * view_scanInit() starts the scan over.
     */

    /*struct vacm_viewEntry *vacm_createViewEntry(const char *, oid *,
                                                size_t);*/
    /*
     * Creates a viewEntry with the given index
     * and returns a pointer to it.
     * The status of this entry is created as invalid.
     */

    void            vacm_destroySecurityEntry(const char*);
    struct vacm_securityEntry* vacm_createSecurityEntry(const char*);
    struct vacm_securityEntry* vacm_getSecurityEntry(const char*);
    void            vacm_scanSecurityInit(void);
    struct vacm_securityEntry* vacm_scanSecurityEntry(void);

    void            vacm_save_view(struct vacm_viewEntry* view,
                                   const char* token, const char* type);
    void            vacm_save_access(struct vacm_accessEntry* access_entry,
                                     const char* token, const char* type);
    void            vacm_save_auth_access(struct vacm_accessEntry* access_entry,
                                     const char* token, const char* type, int authtype);
    void            vacm_save_group(struct vacm_groupEntry* group_entry,
                                    const char* token, const char* type);

    void            vacm_parse_config_group(const char* token, char* line);

    struct vacm_viewEntry* netsnmp_view_get(struct vacm_viewEntry* head,
                                            const char* viewName,
                                            oid * viewSubtree,
                                            size_t viewSubtreeLen, int mode);


#endif                          /* VACM_H_NETSNMP */
