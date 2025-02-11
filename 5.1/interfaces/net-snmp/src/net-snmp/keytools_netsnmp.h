/*
 * keytools_netsnmp.h
 */

#ifndef _KEYTOOLS_H_NETSNMP
#define _KEYTOOLS_H_NETSNMP
#ifdef __cplusplus
extern          "C" {
#endif

#include "types_netsnmp.h"

#define USM_LENGTH_EXPANDED_PASSPHRASE    (1024 * 1024)   /* 1Meg. */

#define USM_LENGTH_KU_HASHBLOCK        64      /* In bytes. */

#define USM_LENGTH_P_MIN        8       /* In characters. */
    /*
     * Recommended practice given in <draft-ietf-snmpv3-usm-v2-02.txt>,
     * * Section 11.2 "Defining Users".  Move into cmdline app argument
     * * parsing, and out of the internal routine?  XXX
     */

    /*
     * Prototypes.h
     */
    int             generate_Ku(const oid*  hashtype, u_int hashtype_len,
                                u_char*  P, size_t pplen,
                                u_char*  Ku, size_t*  kulen);

    int             generate_kul(const oid*  hashtype, u_int hashtype_len,
                                 u_char*  engineID, size_t engineID_len,
                                 u_char*  Ku, size_t ku_len,
                                 u_char*  Kul, size_t*  kul_len);

    int             decode_keychange(const oid*  hashtype,
                                     u_int hashtype_len, u_char*  oldkey,
                                     size_t oldkey_len, u_char*  kcstring,
                                     size_t kcstring_len, u_char*  newkey,
                                     size_t*  newkey_len);


    /*
     * All functions devolve to the following block if we can't do cryptography
     */
#define    _KEYTOOLS_NOT_AVAILABLE            \
{                        \
    return SNMPERR_KT_NOT_AVAILABLE;    \
}

#ifdef __cplusplus
}
#endif
#endif                          /* _KEYTOOLS_H */
