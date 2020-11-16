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
/*********************************************************************
 *
 * AUTHORIZATION TO USE AND DISTRIBUTE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that:
 *
 * (1) source code distributions retain this paragraph in its entirety,
 *
 * (2) distributions including binary code include this paragraph in
 *     its entirety in the documentation or other materials provided
 *     with the distribution, and
 *
 * (3) all advertising materials mentioning features or use of this
 *     software display the following acknowledgment:
 *
 *      "This product includes software written and developed
 *       by Brian Adamson and Joe Macker of the Naval Research
 *       Laboratory (NRL)."
 *
 *  The name of NRL, the name(s) of NRL  employee(s), or any entity
 *  of the United States Government may not be used to endorse or
 *  promote  products derived from this software, nor does the
 *  inclusion of the NRL written and developed software  directly or
 *  indirectly suggest NRL or United States  Government endorsement
 *  of this product.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 ********************************************************************/

#include<string.h>
#include "qualnet_error.h"
#include "mapping.h"
#include "network.h"
#include "if_loopback.h"
#include "mdpProtoDefs.h"
#include "mdpProtoAddress.h"


// /**
// CONSTANT    :: IP_MIN_MULTICAST_ADDRESS  : 0xE0000000
// DESCRIPTION :: Used to determine whether an IP address is multicast.
// **/
#define IP_MIN_MULTICAST_ADDRESS_MDP 0xE0000000    // 224.0.0.0

// /**
// CONSTANT    :: IP_MAX_MULTICAST_ADDRESS  : 0xEFFFFFFF
// DESCRIPTION :: Used to determine whether an IP address is multicast.
// **/
#define IP_MAX_MULTICAST_ADDRESS_MDP 0xEFFFFFFF    // 239.255.255.255


MdpProtoAddress::MdpProtoAddress()
{
    memset(&addr, 0, sizeof(Address));
    addr.networkType = NETWORK_INVALID;
    length = 0;
    port = 0;
}



void MdpProtoAddress::Reset(int theType)
{

    memset(&addr, 0, sizeof(Address));

    switch (theType)
    {
        case NETWORK_IPV4:
            {
                addr.networkType = NETWORK_IPV4;
                length = 4;
                break;
            }
        case NETWORK_IPV6:
            {
                addr.networkType = NETWORK_IPV6;
                length  = 16;
                break;
            }
        default:
            // invalid address
            ERROR_Assert(FALSE,
                "MdpProtoAddress::Reset() Invalid address type!\n");
    }
    PortSet(0);
}  // end MdpProtoAddress::Reset();


BOOL MdpProtoAddress::IsMulticast() const
{
    switch (addr.networkType)
    {
        case NETWORK_IPV4:
            {
                if (addr.interfaceAddr.ipv4 >= IP_MIN_MULTICAST_ADDRESS_MDP
                  && addr.interfaceAddr.ipv4 <= IP_MAX_MULTICAST_ADDRESS_MDP)
                {
                    return TRUE;
                }
                return FALSE;
           }
        case NETWORK_IPV6:
           {
                if (addr.interfaceAddr.ipv6.s6_addr8[0] == 0xff)
                {
                    return TRUE;
                }
                return FALSE;
           }
        default:
              ERROR_Assert(FALSE, " MdpProtoAddress::IsMulticast() \
                                  Wrong network type \n");
              return FALSE;
    }
}  // end IsMulticast()



BOOL MdpProtoAddress::IsSiteLocal() const
{
    if (addr.networkType == NETWORK_IPV6
        && addr.interfaceAddr.ipv6.s6_addr8[0] == 0xfe
        && addr.interfaceAddr.ipv6.s6_addr8[1] == 0xc0)
    {
        return TRUE;
    }
    else
    {
        ERROR_Assert(FALSE, " MdpProtoAddress::IsSiteLocal() \
                            Called for wrong network type \n");
    }
    return FALSE;
}  // end MdpProtoAddress::IsSiteLocal()


BOOL MdpProtoAddress::IsLinkLocal() const
{
    if (addr.networkType == NETWORK_IPV6
        && addr.interfaceAddr.ipv6.s6_addr8[0] == 0xfe
        && addr.interfaceAddr.ipv6.s6_addr8[1] == 0x80)
    {
        return TRUE;
    }
    else
    {
        ERROR_Assert(FALSE, " MdpProtoAddress::IsLinkLocal() \
                            Called for wrong network type \n");
        return FALSE;
    }
}  // end MdpProtoAddress::IsLinkLocal()



const char* MdpProtoAddress::GetRawHostAddress() const
{
    switch (addr.networkType)
    {
        case NETWORK_IPV4:
            {
                return ((char*)&((Address*)&addr)->interfaceAddr.ipv4);
            }
        case NETWORK_IPV6:
            {
                return ((char*)&((Address*)&addr)->interfaceAddr.ipv6);
            }
        default:
            ERROR_Assert(FALSE, " MdpProtoAddress::GetRawHostAddress() \
                                  Wrong network type \n");
            return FALSE;
            //return NULL;
    }
}  // end MdpProtoAddress::GetRawHostAddress()


BOOL MdpProtoAddress::SetRawHostAddress(int          theType,
                                     const char*  buffer,
                                     UInt8        buflen)
{
    UInt16 thePort = GetPort();
    switch (theType)
    {
        case NETWORK_IPV4:
            {
                if (buflen > 4) return FALSE;
                addr.networkType = NETWORK_IPV4;
                length = 4;
                memset(&addr.interfaceAddr.ipv4, 0, 4);
                memcpy(&addr.interfaceAddr.ipv4, buffer, buflen);
                break;
            }
        case NETWORK_IPV6:
            {
                if (buflen > 16) return FALSE;
                addr.networkType = NETWORK_IPV6;
                length = 16;
                memset(&addr.interfaceAddr.ipv6, 0, 16);
                memcpy(&addr.interfaceAddr.ipv6, buffer, buflen);
                break;
            }
        default:
            ERROR_Assert(FALSE, " MdpProtoAddress::SetRawHostAddress() \
                                  Wrong network type \n");
            //return NULL;
    }
    PortSet(thePort);
    return TRUE;
}  // end MdpProtoAddress::SetRawHostAddress()



UInt16 MdpProtoAddress::GetPort() const
{
    if (port == 0)
    {
        ERROR_ReportWarning("Port 0 is an invalid port \n");
        return 0;
    }
    else
        return port;
}  // end MdpProtoAddress::GetPort()


BOOL MdpProtoAddress::HostIsEqual(MdpProtoAddress& theAddr)
{
    char errStr[MAX_STRING_LENGTH];
    if (!IsValid() && !theAddr.IsValid())
    {
        sprintf(errStr,"MdpProtoAddress::HostIsEqual(): Addresses are matched"
                       " but having invalid netwrok type \n");
        ERROR_ReportWarning(errStr);
        return TRUE;
    }

    if (addr.networkType == theAddr.addr.networkType)
    {
        return Address_IsSameAddress(&addr, &theAddr.addr);
    }
    else
    {
        sprintf(errStr,"MdpProtoAddress::HostIsEqual(): Addresses are "
                       " having different netwrok type \n");
        ERROR_Assert(FALSE, errStr);
        return FALSE;
    }
}  // end MdpProtoAddress::HostIsEqual()
