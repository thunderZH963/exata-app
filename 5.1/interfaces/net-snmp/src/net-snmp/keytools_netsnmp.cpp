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

/*
 * keytools.c
 */

#include "types_netsnmp.h"
#include "keytools_netsnmp.h"
#include<openssl/evp.h>
#include "snmp_api_netsnmp.h"
#include <openssl/hmac.h>

#include "scapi_netsnmp.h"
#include "keytools_netsnmp.h"
#include "tools_netsnmp.h"
#include "transform_oids_netsnmp.h"
#include "node.h"

/*******************************************************************-o-******
 * generate_Ku
 *
 * Parameters:
 *    *hashtype    MIB OID for the transform type for hashing.
 *     hashtype_len    Length of OID value.
 *    *P        Pre-allocated bytes of passpharase.
 *     pplen        Length of passphrase.
 *    *Ku        Buffer to contain Ku.
 *    *kulen        Length of Ku buffer.
 *
 * Returns:
 *    SNMPERR_SUCCESS            Success.
 *    SNMPERR_GENERR            All errors.
 *
 *
 * Convert a passphrase into a master user key, Ku, according to the
 * algorithm given in RFC 2274 concerning the SNMPv3 User Security Model (USM)
 * as follows:
 *
 * Expand the passphrase to fill the passphrase buffer space, if necessary,
 * concatenation as many duplicates as possible of P to itself.  If P is
 * larger than the buffer space, truncate it to fit.
 *
 * Then hash the result with the given hashtype transform.  Return
 * the result as Ku.
 *
 * If successful, kulen contains the size of the hash written to Ku.
 *
 * NOTE  Passphrases less than USM_LENGTH_P_MIN characters in length
 *     cause an error to be returned.
 *     (Punt this check to the cmdline apps?  XXX)
 */
int
generate_Ku(const oid*  hashtype, u_int hashtype_len,
            u_char*  P, size_t pplen, u_char*  Ku, size_t*  kulen)
{
    int             rval = SNMPERR_SUCCESS,
        nbytes = USM_LENGTH_EXPANDED_PASSPHRASE;

    u_int           i, pindex = 0;

    u_char          buf[USM_LENGTH_KU_HASHBLOCK], *bufp;

    EVP_MD_CTX*     ctx = (EVP_MD_CTX*)malloc(sizeof(EVP_MD_CTX));
    unsigned int    tmp_len;

    /*
     * Sanity check.
     */
    if (!hashtype || !P || !Ku || !kulen || (*kulen <= 0)
        || (hashtype_len != USM_LENGTH_OID_TRANSFORM)) {
    }

    if (pplen < USM_LENGTH_P_MIN) {
        snmp_set_detail("The supplied password length is too short.");
    }


    /*
     * Setup for the transform type.
     */
    if (ISTRANSFORM(hashtype, HMACMD5Auth))
        EVP_DigestInit(ctx, EVP_md5());
    else
        if (ISTRANSFORM(hashtype, HMACSHA1Auth))
        EVP_DigestInit(ctx, EVP_sha1());
    else {
        free(ctx);
        return (SNMPERR_GENERR);
    }

    while (nbytes > 0) {
        bufp = buf;
        for (i = 0; i < USM_LENGTH_KU_HASHBLOCK; i++) {
            *bufp++ = P[pindex++ % pplen];
        }
        EVP_DigestUpdate(ctx, buf, USM_LENGTH_KU_HASHBLOCK);
        nbytes -= USM_LENGTH_KU_HASHBLOCK;
    }

    tmp_len = *kulen;
    EVP_DigestFinal(ctx, (unsigned char*) Ku, &tmp_len);
    *kulen = tmp_len;
    /*
     * what about free()
     */
    memset(buf, 0, sizeof(buf));
    free(ctx);
    return rval;

}                               /* end generate_Ku() */

/*******************************************************************-o-******
 * generate_kul
 *
 * Parameters:
 *    *hashtype
 *     hashtype_len
 *    *engineID
 *     engineID_len
 *    *Ku        Master key for a given user.
 *     ku_len        Length of Ku in bytes.
 *    *Kul        Localized key for a given user at engineID.
 *    *kul_len    Length of Kul buffer (IN); Length of Kul key (OUT).
 *
 * Returns:
 *    SNMPERR_SUCCESS            Success.
 *    SNMPERR_GENERR            All errors.
 *
 *
 * Ku MUST be the proper length (currently fixed) for the given hashtype.
 *
 * Upon successful return, Kul contains the localized form of Ku at
 * engineID, and the length of the key is stored in kul_len.
 *
 * The localized key method is defined in RFC2274, Sections 2.6 and A.2, and
 * originally documented in:
 *      U. Blumenthal, N. C. Hien, B. Wijnen,
 *         "Key Derivation for Network Management Applications",
 *    IEEE Network Magazine, April/May issue, 1997.
 *
 *
 * ASSUMES  SNMP_MAXBUF >= sizeof(Ku + engineID + Ku).
 *
 * NOTE  Localized keys for privacy transforms are generated via
 *     the authentication transform held by the same usmUser.
 *
 * XXX    An engineID of any length is accepted, even if larger than
 *    what is spec'ed for the textual convention.
 */
int
generate_kul(const oid*  hashtype, u_int hashtype_len,
             u_char*  engineID, size_t engineID_len,
             u_char*  Ku, size_t ku_len,
             u_char*  Kul, size_t*  kul_len)
{
    int             rval = SNMPERR_SUCCESS;
    u_int           nbytes = 0;
    size_t          properlength;
    int             iproperlength;

    u_char          buf[SNMP_MAXBUF];
    /*
     * Sanity check.
     */
    if (!hashtype || !engineID || !Ku || !Kul || !kul_len
        || (engineID_len <= 0) || (ku_len <= 0) || (*kul_len <= 0)
        || (hashtype_len != USM_LENGTH_OID_TRANSFORM)) {
        QUITFUN(SNMPERR_GENERR, generate_kul_quit);
    }


    iproperlength = sc_get_properlength(hashtype, hashtype_len);
    if (iproperlength == SNMPERR_GENERR)
        QUITFUN(SNMPERR_GENERR, generate_kul_quit);

    properlength = (size_t) iproperlength;

    if ((*kul_len < properlength) || (ku_len < properlength)) {
        QUITFUN(SNMPERR_GENERR, generate_kul_quit);
    }

    /*
     * Concatenate Ku and engineID properly, then hash the result.
     * Store it in Kul.
     */
    nbytes = 0;
    memcpy(buf, Ku, properlength);
    nbytes += properlength;
    memcpy(buf + nbytes, engineID, engineID_len);
    nbytes += engineID_len;
    memcpy(buf + nbytes, Ku, properlength);
    nbytes += properlength;

    rval = sc_hash(hashtype, hashtype_len, buf, nbytes, Kul, kul_len);

    QUITFUN(rval, generate_kul_quit);


  generate_kul_quit:
    return rval;

}                               /* end generate_kul() */

/*******************************************************************-o-******
 * decode_keychange
 *
 * Parameters:
 *    *hashtype    MIB OID of the hash transform to use.
 *     hashtype_len    Length of the hash transform MIB OID.
 *    *oldkey        Old key that is used to encode the new key.
 *     oldkey_len    Length of oldkey in bytes.
 *    *kcstring    Encoded KeyString buffer containing the new key.
 *     kcstring_len    Length of kcstring in bytes.
 *    *newkey        Buffer to hold the extracted new key.
 *    *newkey_len    Length of newkey in bytes.
 *
 * Returns:
 *    SNMPERR_SUCCESS            Success.
 *    SNMPERR_GENERR            All errors.
 *
 *
 * Decodes a string of bits encoded according to the KeyChange TC described
 * in RFC 2274, Section 5.  The new key is extracted from *kcstring with
 * the aid of the old key.
 *
 * Upon successful return, *newkey_len contains the length of the new key.
 *
 *
 * ASSUMES    Old key is exactly 1/2 the length of the KeyChange buffer,
 *        although this length may be less than the hash transform
 *        output.  Thus the new key length will be equal to the old
 *        key length.
 */
/*
 * XXX:  if the newkey is not long enough, it should be freed and remalloced
 */
int
decode_keychange(const oid*  hashtype, u_int hashtype_len,
                 u_char*  oldkey, size_t oldkey_len,
                 u_char*  kcstring, size_t kcstring_len,
                 u_char*  newkey, size_t*  newkey_len)
{
    int             rval = SNMPERR_SUCCESS;
    size_t          properlength = 0;
    int             iproperlength = 0;
    u_int           nbytes = 0;

    u_char*         bufp, tmp_buf[SNMP_MAXBUF];
    size_t          tmp_buf_len = SNMP_MAXBUF;
    u_char*         tmpbuf = NULL;



    /*
     * Sanity check.
     */
    if (!hashtype || !oldkey || !kcstring || !newkey || !newkey_len
        || (oldkey_len <= 0) || (kcstring_len <= 0) || (*newkey_len <= 0)
        || (hashtype_len != USM_LENGTH_OID_TRANSFORM)) {
        QUITFUN(SNMPERR_GENERR, decode_keychange_quit);
    }


    /*
     * Setup for the transform type.
     */
    iproperlength = sc_get_properlength(hashtype, hashtype_len);
    if (iproperlength == SNMPERR_GENERR)
        QUITFUN(SNMPERR_GENERR, decode_keychange_quit);

    properlength = (size_t) iproperlength;

    if (((oldkey_len * 2) != kcstring_len) || (*newkey_len < oldkey_len)) {
        QUITFUN(SNMPERR_GENERR, decode_keychange_quit);
    }

    properlength = oldkey_len;
    *newkey_len = properlength;

    /*
     * Use the old key and the given KeyChange TC string to recover
     * the new key:
     *      . Hash (oldkey | random_bytes) (into newkey),
     *      . XOR hash and encoded (second) half of kcstring (into newkey).
     */
    tmpbuf = (u_char*) malloc(properlength * 2);
    if (tmpbuf) {
        memcpy(tmpbuf, oldkey, properlength);
        memcpy(tmpbuf + properlength, kcstring, properlength);

        rval = sc_hash(hashtype, hashtype_len, tmpbuf, properlength * 2,
                       tmp_buf, &tmp_buf_len);
        QUITFUN(rval, decode_keychange_quit);

        memcpy(newkey, tmp_buf, properlength);
        bufp = kcstring + properlength;
        nbytes = 0;
        while ((nbytes++) < properlength) {
            *newkey++ ^= *bufp++;
        }
    }

  decode_keychange_quit:
    if (rval != SNMPERR_SUCCESS) {
        memset(newkey, 0, properlength);
    }
    memset(tmp_buf, 0, SNMP_MAXBUF);
    if (tmpbuf != NULL)
        SNMP_FREE(tmpbuf);

    return rval;

}                               /* end decode_keychange() */
