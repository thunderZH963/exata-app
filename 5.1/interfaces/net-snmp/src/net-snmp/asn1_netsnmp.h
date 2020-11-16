    /*
     * Definitions for Abstract Syntax Notation One, ASN.1
     * As defined in ISO/IS 8824 and ISO/IS 8825
     *
     *
     */
/***********************************************************
    Copyright 1988, 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

#ifndef ASN1_H_NETSNMP
#define ASN1_H_NETSNMP

#include <stdio.h>
#ifndef u_char
typedef unsigned char u_char;
#endif
#ifndef u_long
typedef unsigned long u_long ;
#endif
#ifndef u_int
typedef unsigned int u_int ;
#endif
#ifndef u_short
typedef unsigned short u_short ;
#endif
#ifndef oid
typedef u_int oid;
#endif

#ifndef MAX_SUBID               /* temporary - duplicate definition protection */
#define MAX_SUBID   0xFFFFFFFF
#endif

#define OID_LENGTH(x)  (sizeof(x)/sizeof(oid))
#define ASN_PRIV_INCL_RANGE (ASN_PRIVATE | 2)
#define ASN_PRIV_EXCL_RANGE (ASN_PRIVATE | 3)
#define ASN_PRIV_DELEGATED  (ASN_PRIVATE | 5)
#define ASN_PRIV_IMPLIED_OCTET_STR  (ASN_PRIVATE | ASN_OCTET_STR)       /* 4 */
#define ASN_PRIV_IMPLIED_OBJECT_ID  (ASN_PRIVATE | ASN_OBJECT_ID)       /* 6 */
#define ASN_PRIV_RETRY      (ASN_PRIVATE | 7)   /* 199 */
#define IS_DELEGATED(x)   ((x) == ASN_PRIV_DELEGATED)

#ifndef ASN_TYPES
#define ASN_TYPES
#define ASN_BOOLEAN        ((u_char)0x01)
#define ASN_INTEGER        ((u_char)0x02)
#define ASN_BIT_STR        ((u_char)0x03)
#define ASN_OCTET_STR        ((u_char)0x04)
#define ASN_NULL        ((u_char)0x05)
#define ASN_OBJECT_ID        ((u_char)0x06)
#define ASN_SEQUENCE        ((u_char)0x10)
#define ASN_SET            ((u_char)0x11)
#define ASN_UNIVERSAL        ((u_char)0x00)
#define ASN_APPLICATION     ((u_char)0x40)
#define ASN_CONTEXT        ((u_char)0x80)
#define ASN_PRIVATE        ((u_char)0xC0)
#define ASN_PRIMITIVE        ((u_char)0x00)
#define ASN_CONSTRUCTOR        ((u_char)0x20)
#define ASN_LONG_LEN        (0x80)
#define ASN_EXTENSION_ID    (0x1F)
#define ASN_BIT8        (0x80)

#endif

#define ASN_PRIV_INCL_RANGE (ASN_PRIVATE | 2)
#define ASN_PRIV_EXCL_RANGE (ASN_PRIVATE | 3)
#define ASN_PRIV_DELEGATED  (ASN_PRIVATE | 5)
#define ASN_PRIV_IMPLIED_OCTET_STR  (ASN_PRIVATE | ASN_OCTET_STR)       /* 4 */
#define ASN_PRIV_IMPLIED_OBJECT_ID  (ASN_PRIVATE | ASN_OBJECT_ID)       /* 6 */
#define ASN_PRIV_RETRY      (ASN_PRIVATE | 7)   /* 199 */
#define IS_DELEGATED(x)   ((x) == ASN_PRIV_DELEGATED)

#define IS_EXTENSION_ID(byte)    (((byte) & ASN_EXTENSION_ID) == ASN_EXTENSION_ID)

    typedef struct counter64 integer64;
    typedef struct counter64 unsigned64;

    /*
     * The BER inside an OPAQUE is an context specific with a value of 48 (0x30)
     * plus the "normal" tag. For a Counter64, the tag is 0x46 (i.e., an
     * applications specific tag with value 6). So the value for a 64 bit
     * counter is 0x46 + 0x30, or 0x76 (118 base 10). However, values
     * greater than 30 can not be encoded in one octet. So the first octet
     * has the class, in this case context specific (ASN_CONTEXT), and
     * the special value (i.e., 31) to indicate that the real value follows
     * in one or more octets. The high order bit of each following octet
     * indicates if the value is encoded in additional octets. A high order
     * bit of zero, indicates the last. For this "hack", only one octet
     * will be used for the value.
     */

    /*
     * first octet of the tag
     */
#define ASN_OPAQUE_TAG1 (ASN_CONTEXT | ASN_EXTENSION_ID)
    /*
     * base value for the second octet of the tag - the
     * second octet was the value for the tag
     */
#define ASN_OPAQUE_TAG2 ((u_char)0x30)

#define ASN_OPAQUE_TAG2U ((u_char)0x2f) /* second octet of tag for union */

    /*
     * All the ASN.1 types for SNMP "should have been" defined in this file,
     * but they were not. (They are defined in snmp_impl.h)  Thus, the tag for
     * Opaque and Counter64 is defined, again, here with a different names.
     */
#define ASN_APP_OPAQUE (ASN_APPLICATION | 4)
#define ASN_APP_COUNTER64 (ASN_APPLICATION | 6)
#define ASN_APP_FLOAT (ASN_APPLICATION | 8)
#define ASN_APP_DOUBLE (ASN_APPLICATION | 9)
#define ASN_APP_I64 (ASN_APPLICATION | 10)
#define ASN_APP_U64 (ASN_APPLICATION | 11)
#define ASN_APP_UNION (ASN_PRIVATE | 1) /* or ASN_PRIV_UNION ? */

    /*
     * value for Counter64
     */
#define ASN_OPAQUE_COUNTER64 (ASN_OPAQUE_TAG2 + ASN_APP_COUNTER64)
    /*
     * max size of BER encoding of Counter64
     */
#define ASN_OPAQUE_COUNTER64_MX_BER_LEN 12

    /*
     * value for Float
     */
#define ASN_OPAQUE_FLOAT (ASN_OPAQUE_TAG2 + ASN_APP_FLOAT)
    /*
     * size of BER encoding of Float
     */
#define ASN_OPAQUE_FLOAT_BER_LEN 7

    /*
     * value for Double
     */
#define ASN_OPAQUE_DOUBLE (ASN_OPAQUE_TAG2 + ASN_APP_DOUBLE)
    /*
     * size of BER encoding of Double
     */
#define ASN_OPAQUE_DOUBLE_BER_LEN 11

    /*
     * value for Integer64
     */
#define ASN_OPAQUE_I64 (ASN_OPAQUE_TAG2 + ASN_APP_I64)
    /*
     * max size of BER encoding of Integer64
     */
#define ASN_OPAQUE_I64_MX_BER_LEN 11

    /*
     * value for Unsigned64
     */
#define ASN_OPAQUE_U64 (ASN_OPAQUE_TAG2 + ASN_APP_U64)
    /*
     * max size of BER encoding of Unsigned64
     */
#define ASN_OPAQUE_U64_MX_BER_LEN 12


    struct counter64 {
        unsigned long high;
        unsigned long low;
    };

    int             asn_check_packet(u_char* , size_t);
    u_char*         asn_parse_int(u_char* , size_t* , u_char* , long* ,
                                  size_t);
    u_char*         asn_build_int(u_char* , size_t* , u_char, const long* ,
                                  size_t);
    u_char*         asn_parse_unsigned_int(u_char* , size_t* , u_char* ,
                                           u_long* , size_t);
    u_char*         asn_build_unsigned_int(u_char* , size_t* , u_char,
                                           const u_long* , size_t);
    u_char*         asn_parse_string(u_char* , size_t* , u_char* ,
                                     u_char* , size_t*);
    u_char*         asn_parse_header(u_char* , size_t* , u_char*);
    u_char*         asn_parse_sequence(u_char* , size_t* , u_char* , u_char expected_type,      /* must be this type */
                                       const char* estr);       /* error message prefix */
    u_char*         asn_build_header(u_char* , size_t* , u_char, size_t);
    u_char*         asn_build_sequence(u_char* , size_t* , u_char, size_t);
    u_char*         asn_parse_length(u_char* , u_long*);
    u_char*         asn_build_length(u_char* , size_t* , size_t);
    u_char*         asn_parse_objid(u_char* , size_t* , u_char* , oid* ,
                                    size_t*);
    u_char*         asn_build_objid(u_char* , size_t* , u_char, oid* ,
                                    size_t);
    u_char*         asn_parse_null(u_char* , size_t* , u_char*);
    u_char*         asn_build_null(u_char* , size_t* , u_char);
    u_char*         asn_parse_bitstring(u_char* , size_t* , u_char* ,
                                        u_char* , size_t*);
    u_char*         asn_build_bitstring(u_char* , size_t* , u_char,
                                        const u_char* , size_t);
    u_char*         asn_parse_unsigned_int64(u_char* , size_t* , u_char* ,
                                             struct counter64* , size_t);
    u_char*         asn_build_unsigned_int64(u_char* , size_t* , u_char,
                                             const struct counter64* , size_t);
    u_char*         asn_parse_signed_int64(u_char* , size_t* , u_char* ,
                                           struct counter64* , size_t);
    u_char*         asn_build_signed_int64(u_char* , size_t* , u_char,
                                           const struct counter64* , size_t);
    u_char*         asn_build_float(u_char* , size_t* , u_char, const float* ,
                                    size_t);
    u_char*         asn_parse_float(u_char* , size_t* , u_char* , float* ,
                                    size_t);
    u_char*         asn_build_double(u_char* , size_t* , u_char, const double* ,
                                     size_t);
    u_char*         asn_parse_double(u_char* , size_t* , u_char* ,
                                     double* , size_t);
int             asn_realloc_rbuild_int(u_char**  pkt, size_t*  pkt_len,
                                           size_t*  offset,
                                           int allow_realloc, u_char type,
                                           const long* data, size_t data_size);
int             asn_realloc_rbuild_sequence(u_char**  pkt,
                                                size_t*  pkt_len,
                                                size_t*  offset,
                                                int allow_realloc,
                                                u_char type,
                                                size_t data_size);
int             asn_realloc_rbuild_header(u_char**  pkt,
                                              size_t*  pkt_len,
                                              size_t*  offset,
                                              int allow_realloc,
                                              u_char type,
                                              size_t data_size);
int             asn_realloc(u_char** , size_t*);

#endif /* ASN1_H_NETSNMP */

