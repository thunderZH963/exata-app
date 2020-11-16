// Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.
//                          600 Corporate Pointe
//                          Suite 1200
//                          Culver City, CA 90230
//                          info@scalable-networks.com
//
// This source code is licensed, not sold, and is subject to a written
// license agreement.  Among other things, no portion of this source
// code may be copied, transmitted, disclosed, displayed, distributed,
// translated, used as the basis for a derivative work, or used, in
// whole or in part, for any program or purpose other than its intended
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "crypto.h"

#include "qualnet_error.h"

/**
 * FUNCTION: high/low_to_hex
 * PURPOSE: Auxiliary function that converts between a character
 *          and its hexadecimal value (occupies 2 chararacters then)
 *
 * PARAMETERS: in: input char
 *
 * RESULT: the higher 4-bit or the lower 4-bit of the input
 *         (in hexadecimal format)
 */
static unsigned char high_to_hex(unsigned char in)
{
    register unsigned char ch = (in>>4) & 0xf;
    if (ch > 9)
        return ch - 10 + 'A';
    else
        return ch + '0';
}
static unsigned char low_to_hex(unsigned char in)
{
    register unsigned char ch = in & 0xf;
    if (ch > 9)
        return ch - 10 + 'A';
    else
        return ch + '0';
}

/**
 * FUNCTION: hex_to_val
 * PURPOSE: Auxiliary function that converts between a character
 *          and its hexadecimal value (occupies 2 chararacters then)
 *
 * PARAMETERS: in: input hexadecimal value (e.g., 'C', '3', 'f')
 *
 * RESULT: -1: something wrong; otherwise the char
 */
int hex_to_val(unsigned char in)
{
    if ((in >= '0') && (in <= '9'))
        return in - '0';
    if ((in >= 'A') && (in <= 'F'))
        return in - 'A' + 10;
    if ((in >= 'a') && (in <= 'f'))
        return in - 'a' + 10;
    return -1;
}

/**
 * FUNCTION: bitstream_to_hexstr
 * PURPOSE: Convert arbitrary bitstream with `leng' bytes to its hexadecimal
 *          string representation.  E.g., a value 0xFF to string "FF"
 *
 * PARAMETERS: hexstr: the output placeholder
 *             bitstream: the input
 *             leng: the length of the input
 * ASSUMPTION: Must pre-allocate `hexstring' to be 2*leng + 1 bytes
 */
void
bitstream_to_hexstr(unsigned char *hexstr,
                    const unsigned char *bitstream,
                    size_t leng)
{
    size_t i, j;

    for (i = 0,j = 0; i < leng; i++)
    {
        hexstr[j++] = high_to_hex(bitstream[i]);
        hexstr[j++] = low_to_hex(bitstream[i]);
    }
    hexstr[j] = '\0';
}

/**
 * FUNCTION: bitstream_to_hexstr
 * PURPOSE: Reverse routine of bitstream_to_hexstr.
 *          Convert hexadecimal string back to bitstream.
 *          E.g.,  string "FF" back to a value 0xFF
 *
 * PARAMETERS: bitstream: the output placeholder
 *             leng: the length of the input
 *             hexstr: the input
 * ASSUMPTION: hexstr can represent negative.  However, bitstream can't.
 *      Therefore, please be sure the incoming hexstr is never negative.
 *
 *       In addition, if leng is not 0, this one implements alignment
 *       to add prefix 0's if 'hexstr' is not long enough.
 */
int
hexstr_to_bitstream(byte *bitstream,
                    size_t leng,
                    const byte *hexstr)
{
    int cursor = 0, j, k = (int)strlen((char *)hexstr), diff;

    if (leng != 0)
    {
        for (diff = (int)(leng - (k+1)/2); diff > 0; diff--)
        {
            // add prefix 0's
            bitstream[cursor++] = 0;
        }
    }
    if (k % 2 == 1)
    {
        bitstream[cursor++] = (byte) hex_to_val(hexstr[0]);
        j = 1;
    }
    else
        j = 0;

    for (; j!=k; j+=2)
        bitstream[cursor++] =
        (byte) ((hex_to_val(hexstr[j]) << 4) + hex_to_val(hexstr[j+1]));

    return cursor;
}


/*-----------------------------------------------------------------
** Dummy functions
-----------------------------------------------------------------*/
#define JUST_LINK_MPI_AND_CIPHER
#ifdef JUST_LINK_MPI_AND_CIPHER
extern "C" {

void
wipememory(byte *ptr, int len)
{}

static void
out_of_core(size_t n, int secure)
{
    ERROR_ReportErrorArgs("out of crypto memory while allocating %u bytes\n",
                          (unsigned)n );
}

void *
xmalloc( size_t n )
{
    char *p;

    /* mallocing zero bytes is undefined by ISO-C, so we better make
       sure that it won't happen */
    if (!n)
      n = 1;
    p = (char *)malloc( n );
    if (!(p))
    {
        out_of_core(n,0);
    }
    return p;
}

void *
xmalloc_secure( size_t n )
{
    return xmalloc(n);
}

void *
xmalloc_clear( size_t n )
{
    void *p;
    p = xmalloc( n );
    memset(p, 0, n );
    return p;
}

void *
xcalloc (size_t n, size_t m)
{
  size_t nbytes;

  nbytes = n * m;
  if (m && nbytes / m != n)
    out_of_core (nbytes, 0);
  return xmalloc_clear (nbytes);
}

void *
xmalloc_secure_clear( size_t n)
{
    return xmalloc_clear(n);
}

void *
xrealloc( void *a, size_t n )
{
    void *b;

    b = realloc( a, n );
    if (!(b))
    {
        out_of_core(n,0);
    }
    return b;
}

void
xfree( void *a )
{
    free(a);
}

size_t
m_size( const void *a )
{
    const byte *p = (byte *)a;
    size_t n;

    n  = ((byte*)p)[-4];
    n |= ((byte*)p)[-3] << 8;
    n |= ((byte*)p)[-2] << 16;
    return n;
}

char *
xstrdup( const char *a )
{
    size_t n = strlen(a);
    char *p = (char *)xmalloc(n+1);
    strcpy(p, a);
    return p;
}

void
m_check( const void *a )
{}

int
m_is_secure( const void *p )
{
    return 0;
}

void
tty_printf()
{}

int
make_timestamp()
{
    return 1;
}

FILE *
log_stream()
{
    return stderr;
}

int
ascii_toupper (int c)
{
    if (c >= 'a' && c <= 'z')
        c &= ~0x20;
    return c;
}

int
ascii_tolower (int c)
{
    if (c >= 'A' && c <= 'Z')
        c |= 0x20;
    return c;
}

int
ascii_strcasecmp (const char *a, const char *b)
{
  const unsigned char *p1 = (const unsigned char *)a;
  const unsigned char *p2 = (const unsigned char *)b;
  unsigned char c1, c2;

  if (p1 == p2)
    return 0;

  do
    {
      c1 = (unsigned char) ascii_tolower (*p1);
      c2 = (unsigned char) ascii_tolower (*p2);

      if (c1 == '\0')
        break;

      ++p1;
      ++p2;
    }
  while (c1 == c2);

  return c1 - c2;
}

} /* extern "C" */
#endif /* JUST_LINK_MPI_AND_CIPHER */
