/*
 * snmpusm_netsnmp.h
 *
 * Header file for USM support.
 */

#ifndef SNMPUSM_H_NETSNMP
#define SNMPUSM_H_NETSNMP

#define WILDCARDSTRING "*"

    /*
     * General.
     */
#define USM_MAX_ID_LENGTH        1024    /* In bytes. */
#define USM_MAX_SALT_LENGTH        128     /* In BITS. */
#define USM_DES_SALT_LENGTH        64      /* In BITS. */
#define USM_AES_SALT_LENGTH        128     /* In BITS. */
#define USM_MAX_KEYEDHASH_LENGTH    128     /* In BITS. */

#define USM_TIME_WINDOW            150
#define USM_MD5_AND_SHA_AUTH_LEN        12      /* bytes */
#define USM_MAX_AUTHSIZE                USM_MD5_AND_SHA_AUTH_LEN

#define USM_SEC_MODEL_NUMBER            3

    int usm_set_aes_iv(u_char*  iv,
                   size_t*  iv_length,
                   u_int net_boots,
                   u_int net_time,
                   u_char*  salt);



    /*
     * Structures.
     */
    struct usmStateReference {
        char*           usr_name;
        size_t          usr_name_length;
        u_char*         usr_engine_id;
        size_t          usr_engine_id_length;
        oid*            usr_auth_protocol;
        size_t          usr_auth_protocol_length;
        u_char*         usr_auth_key;
        size_t          usr_auth_key_length;
        oid*            usr_priv_protocol;
        size_t          usr_priv_protocol_length;
        u_char*         usr_priv_key;
        size_t          usr_priv_key_length;
        u_int           usr_sec_level;
    };


    /*
     * struct usmUser: a structure to represent a given user in a list
     */
    /*
     * Note: Any changes made to this structure need to be reflected in
     * the following functions:
     */

struct usmUser;
struct usmUser {
    u_char*         engineID;
    size_t          engineIDLen;
    char*           name;
    char*           secName;
    oid*            cloneFrom;
    size_t          cloneFromLen;
    oid*            authProtocol;
    size_t          authProtocolLen;
    u_char*         authKey;
    size_t          authKeyLen;
    oid*            privProtocol;
    size_t          privProtocolLen;
    u_char*         privKey;
    size_t          privKeyLen;
    u_char*         userPublicString;
    size_t          userPublicStringLen;
    int             userStatus;
    int             userStorageType;
    /* these are actually DH*  pointers but only if openssl is avail. */
    void*           usmDHUserAuthKeyChange;
    void*           usmDHUserPrivKeyChange;
    struct usmUser* next;
    struct usmUser* prev;
};

    int             usm_check_secLevel(int level, struct usmUser* user);

    struct usmUser* usm_get_user_from_list(u_char*  engineID,
                                           size_t engineIDLen, char* name,
                                           struct usmUser* userList,
                                           int use_default);
    struct usmUser* usm_add_user(struct usmUser* user);
    struct usmUser* usm_add_user_to_list(struct usmUser* user,
                                         struct usmUser* userList);
struct usmUser* usm_free_user(struct usmUser* user);
    struct usmUser* usm_create_user(void);
    struct usmUser* usm_remove_user_from_list(struct usmUser* user,
                                              struct usmUser** userList);
    void            usm_save_users(const char* token, const char* type);
    void            usm_save_users_from_list(struct usmUser* user,
                                             const char* token,
                                             const char* type);
    void            usm_save_user(struct usmUser* user, const char* token,
                                  const char* type);
     void            usm_set_user_password(struct usmUser* user,
                                          const char* token, char* line);

#endif                          /* SNMPUSM_H */
