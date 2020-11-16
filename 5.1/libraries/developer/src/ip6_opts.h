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

#ifndef IPV6_OPTIONS_H
#define IPV6_OPTIONS_H

#include "api.h"

// N.B. The option processing is not used for this version.
// Kept for future use.

struct optionListTag
{
    unsigned int headerType;
    unsigned int headerSize;
    unsigned int optionNextHeader;
    char* optionPointer;
    struct optionListTag* nextOption;
};

struct opt6_any_struct      /* common option header */
{
    unsigned char o6any_ext;  /* extension type */
    unsigned char o6any_len;  /* length */
};

struct headerInfoTag
{
    unsigned char nextHeader;
    unsigned char headerLength;
};

typedef struct optionListTag optionList;
typedef struct opt6_any_struct opt6_any;
typedef struct headerInfoTag headerInfo;

optionList* ip6SaveOption(
    Message* msg,
    optionList** option);

optionList* ip6deleteOption(
    Message* msg,
    optionList** option,
    int which);

optionList*
ip6insertOption(
    Message* msg,
    optionList** option,
    int whichType);

optionList*
ip6CopyOption(
    Message* msg,
    optionList** option);

optionList* Ipv6OptionAlloc(int size);

//----------------------------------------------------------------------//

#endif
