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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "app_util.h"
#include "app_dns.h"
#include "partition.h"
#include "network_ip.h"
#include "mapping.h"
#include "transport_tcp.h"
#include "ipv6.h"
#include "app_trafficSender.h"
#include "app_dhcp.h"

#define DEBUG 0


//--------------------------------------------------------------------------
// FUNCTION     :: DnsHeaderSetQr
// LAYER        :: Application Layer
// PURPOSE      :: Sets Qr bit in DNS header
// PARAMETERS   :: DnsHeader - stores DNS Header
//                 dnsqr - DNS Qr bit
// RETURN       :: NONE
//--------------------------------------------------------------------------
static void DnsHeaderSetQr(UInt16* dnsHeader, BOOL dnsqr)
{
    short x = (short)dnsqr;

    // masks dnsqr within boundry range
    x = x & maskShort(16, 16);

    // clears the first bit of DnsHeader
    *dnsHeader = *dnsHeader & (~(maskShort(1, 1)));

    // Setting the value of x at first position in DnsHeader
    *dnsHeader = *dnsHeader | LshiftShort(x, 1);
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsHeaderSetOpcode
// LAYER        :: Application Layer
// PURPOSE      :: Sets opcode in DNS header
// PARAMETERS   :: DnsHeader - stores DNS Header
//                 opcode - opcode
// RETURN       :: NONE
//--------------------------------------------------------------------------
static void DnsHeaderSetOpcode(UInt16* dnsHeader, short opcode)
{
    // masks opcode within boundry range
    opcode = opcode & maskShort(13, 16);

    // clears 2-5 bits
    *dnsHeader = *dnsHeader & (~(maskShort(2, 5)));

    // setting the value of opcode in DnsHeader
    *dnsHeader = *dnsHeader | LshiftShort(opcode, 5);
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsHeaderSetUpdReserved
// LAYER        :: Application Layer
// PURPOSE      :: Sets Z bit in DNS header in update msg
// PARAMETERS   :: DnsHeader - stores DNS Header
//                 reserved
// RETURN       :: NONE
//--------------------------------------------------------------------------
static void DnsHeaderSetUpdReserved(UInt16* dnsHeader, short reserved)
{
    // masks reserved within boundry range
    reserved = reserved & maskShort(10, 16);

    // clears 6-12 bits
    *dnsHeader = *dnsHeader & (~(maskShort(6, 12)));

    // setting the value of reserved in DnsHeader
    *dnsHeader = *dnsHeader | LshiftShort(reserved, 12);
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsHeaderSetReserved
// LAYER        :: Application Layer
// PURPOSE      :: Sets Z bit in DNS header in query msg
// PARAMETERS   :: DnsHeader - stores DNS header
//                 reserved
// RETURN       :: NONE
//--------------------------------------------------------------------------
static void DnsHeaderSetReserved(UInt16* dnsHeader, short reserved)
{
    // masks reserved within boundry range
    reserved = reserved & maskShort(14, 16);

    // clears 10-12 bits
    *dnsHeader = *dnsHeader & (~(maskShort(10, 12)));

    // setting the value of reserved in DnsHeader
    *dnsHeader = *dnsHeader | LshiftShort(reserved, 12);
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsHeaderSetRcode
// LAYER        :: Application Layer
// PURPOSE      :: Sets Rcode in DNS header
// PARAMETERS   :: DnsHeader - stores DNS Header
//                 rcode
// RETURN       :: NONE
//--------------------------------------------------------------------------
static void DnsHeaderSetRcode(UInt16* dnsHeader, short rcode)
{
    // masks rcode within boundry range
    rcode = rcode & maskShort(13, 16);

    // clears 13-16 bits
    *dnsHeader = *dnsHeader & (~(maskShort(13, 16)));

    // setting the value of rcode in DnsHeader
    *dnsHeader = *dnsHeader | rcode;
}

//--------------------------------------------------------------------------
// FUNCTION     :: DnsHeaderGetRcode
// LAYER        :: Application Layer
// PURPOSE      :: Gets Rcode in DNS header
// PARAMETERS   :: DnsHeader - stores DNS Header
// RETURN       :: rcode
//--------------------------------------------------------------------------

static UInt16 DnsHeaderGetRcode(UInt16 dnsHeader)
{
    UInt16 rcode = dnsHeader;

    // clears 13-16 bits
    rcode = rcode & maskShort(13, 16);

    return rcode;
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsHeaderSetAA
// LAYER        :: Application Layer
// PURPOSE      :: Sets AA bit in DNS header
// PARAMETERS   :: DnsHeader - stores DNS Header
//                 dnsaa
// RETURN       :: NONE
//--------------------------------------------------------------------------
static void DnsHeaderSetAA(UInt16* dnsHeader, BOOL dnsaa)
{
    UInt16 x = (UInt16)dnsaa;

    // masks dnsqr within boundry range
    x = x & maskShort(16, 16);

    // clears the sixth bit of DnsHeader
    *dnsHeader = *dnsHeader & (~(maskShort(6, 6)));

    // Setting the value of x at sixth position in DnsHeader
    *dnsHeader = *dnsHeader | LshiftShort(x, 6);
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsHeaderSetTC
// LAYER        :: Application Layer
// PURPOSE      :: Sets TC bit in DNS header
// PARAMETERS   :: DnsHeader - stores DNS Header
//              :: dnstc
// RETURN       :: NONE
//--------------------------------------------------------------------------
static void DnsHeaderSetTC(UInt16* dnsHeader, BOOL dnstc)
{
    UInt16 x = (UInt16)dnstc;

    // masks dnstc within boundry range
    x = x & maskShort(16, 16);

    // clears the 7th bit of DnsHeader
    *dnsHeader = *dnsHeader & (~(maskShort(7, 7)));

    // Setting the value of x at 7th position in DnsHeader
    *dnsHeader = *dnsHeader | LshiftShort(x, 7);
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsHeaderSetRD
// LAYER        :: Application Layer
// PURPOSE      :: Sets RD bit in DNS header
// PARAMETERS   :: DnsHeader - stores DNS Header
//              :: dnsrd
// RETURN       :: NONE
//--------------------------------------------------------------------------
static void DnsHeaderSetRD(UInt16* dnsHeader, BOOL dnsrd)
{
    UInt16 x = (UInt16)dnsrd;

    // masks dnsrd within boundry range
    x = x & maskShort(16, 16);

    // clears the 8th bit of DnsHeader
    *dnsHeader = *dnsHeader & (~(maskShort(8, 8)));

    // Setting the value of x at 8th position in DnsHeader
    *dnsHeader = *dnsHeader | LshiftShort(x, 8);
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsHeaderSetRA
// LAYER        :: Application Layer
// PURPOSE      :: Sets RA bit in DNS header
// PARAMETERS   :: DnsHeader - stores DNS Header
//              :: dnsra
// RETURN       :: NONE
//--------------------------------------------------------------------------
static void DnsHeaderSetRA(UInt16* dnsHeader, BOOL dnsra)
{
    UInt16 x = (UInt16)dnsra;

    // masks dnsra within boundry range
    x = x & maskShort(16, 16);

    // clears the 9th bit of DnsHeader
    *dnsHeader = *dnsHeader & (~(maskShort(9, 9)));

    // Setting the value of x at 9th position in DnsHeader
    *dnsHeader = *dnsHeader | LshiftShort(x, 9);
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsHeaderGetQr
// LAYER        :: Application Layer
// PURPOSE      :: Gets Qr bit from DNS header
// PARAMETERS   :: DnsHeader - stores DNS Header
// RETURN       :: BOOL
//--------------------------------------------------------------------------
static BOOL DnsHeaderGetQr(UInt16 dnsHeader)
{
    UInt16 qr_set = dnsHeader;

    // clears all bits except first bit
    qr_set = qr_set & maskShort(1, 1);

    // right shifts 15 bits so that last bit contains the value of qr_set
    qr_set = RshiftShort(qr_set, 1);

    return (BOOL) qr_set;
}
#if 0
// These functions have not been currently used but kept
// here for completeness

// /**
// FUNCTION    :: DnsHeaderGetAA
// LAYER       :: Application Layer
// PURPOSE     :: Gets AA bit from DNS header
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + domain : char*: the domain name
// RETURN       : Int32 : No of dots
// **/

static BOOL DnsHeaderGetAA(UInt16 dnsHeader)
{
    UInt16 aa_set = dnsHeader;

    // clears all bits except sixth bit
    aa_set = aa_set & maskShort(6, 6);

    // right shifts 10 bits so that last bit contains the value of aa_set
    aa_set = RshiftShort(aa_set, 6);

    return (BOOL) aa_set;
}


static UInt16 DnsHeaderGetOpcode(UInt16 dnsHeader)
{
    UInt16 opcode = dnsHeader;

    // clears 2-5 bits
    opcode = opcode & maskShort(2, 5);

    // right shifts 11 bits so that last 4 bits contain the value of
    // opcode
    opcode = RshiftShort(opcode, 5);

    return opcode;
}

static UInt16 DnsHeaderGetUpdReserved(UInt16 dnsHeader)
{
    UInt16 reserved = dnsHeader;

    // clears 6-12 bits
    reserved = reserved & maskShort(6, 12);

    // right shifts 4 bits so that last 7 bits contain the value of
    // reserved
    reserved = RshiftShort(reserved, 12);

    return reserved;
}

static UInt16 DnsHeaderGetReserved(UInt16 dnsHeader)
{
    UInt16 reserved = dnsHeader;

    // clears 10-12 bits
    reserved = reserved & maskShort(10, 12);

    // right shifts 4 bits so that last 3 bits contain the value of
    // reserved
    reserved = RshiftShort(reserved, 12);

    return reserved;
}

static UInt16 DnsHeaderGetRcode(UInt16 dnsHeader)
{
    UInt16 rcode = dnsHeader;

    // clears 13-16 bits
    rcode = rcode & maskShort(13, 16);

    return rcode;
}

static BOOL DnsHeaderGetTC(UInt16 dnsHeader)
{
    UInt16 tc_set = dnsHeader;

    // clears all bits except 7th bit
    tc_set = tc_set & maskShort(7, 7);

    // right shifts 9 bits so that last bit contains the value of tc_set
    tc_set = RshiftShort(tc_set, 7);

    return (BOOL) tc_set;
}

static BOOL DnsHeaderGetRD(UInt16 dnsHeader)
{
    UInt16 rd_set = dnsHeader;

    // clears all bits except 8th bit
    rd_set = rd_set & maskShort(8, 8);

    // right shifts 8 bits so that last bit contains the value of rd_set
    rd_set = RshiftShort(rd_set, 8);

    return (BOOL) rd_set;
}

static BOOL DnsHeaderGetRA(UInt16 dnsHeader)
{
    UInt16 ra_set = dnsHeader;

    // clears all bits except 9th bit
    ra_set = ra_set & maskShort(9, 9);

    // right shifts 9 bits so that last bit contains the value of ra_set
    ra_set = RshiftShort(ra_set, 9);

    return (BOOL) ra_set;
}

#endif


//--------------------------------------------------------------------------
// FUNCTION     :: DotCount
// LAYER        :: Application Layer
// PURPOSE      :: To count the "." operator in the query URL
// PARAMETERS   :: Node* - Pointer to node.
//                 const char* - the domain name
// RETURN       : Int32 - No of dots
//--------------------------------------------------------------------------
Int32 DotCount(const char* domain)
{
    Int32 noOfDot = 0;
    char tempChar = '0';

    while (*domain != '\0')
    {
        if (*domain == '.')
        {
            noOfDot++;
        }
        tempChar = *domain;
        domain++;
    }
    return noOfDot;
}


//--------------------------------------------------------------------------
// FUNCTION     :: showdata
// LAYER        :: Application Layer
// PURPOSE      :: for Debugging Purpose
//                (Show all the RR Record for all Nodes)
// PARAMETERS   :: PartitionData*  : Partion Data Ptr
// RETURN       :: void
//--------------------------------------------------------------------------
void showdata(PartitionData* partitionData)
{
    Node* node = partitionData->firstNode;

    while (node != NULL)
    {
        struct DnsData* dnsData = NULL;
        struct DnsServerData* dnsServerData = NULL;

        dnsData = (struct DnsData*)node->appData.dnsData;

        if (dnsData!=NULL)
        {
            dnsServerData = dnsData->server;

            DnsRrRecordList :: iterator item;

            item = dnsData->server->rrList->begin();

            // check for matching destIP
            printf("*************************************");
            printf("\nAfter Dns ZoneList Initialization\n");
            printf("*************************************\n");
            printf("For Node: %d the following RR records\n",
                node->nodeId);
            while (item != dnsData->server->rrList->end())
            {
                struct DnsRrRecord* rrItem = (struct DnsRrRecord*)*item;

                printf("\tAssociated Domain Name: %s\n",
                    rrItem->associatedDomainName);

                item++;
            }
            printf("\n");
        }
        node = node->nextNodeData;
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: ADDR_IsUrl
// LAYER        :: Application Layer
// PURPOSE      :: Check for a string if is it a URL address
// PARAMETERS   :: const char* - Destination String
// RETURN       :: BOOL - TRUE if its is URL otherwise FALSE
//--------------------------------------------------------------------------
BOOL ADDR_IsUrl(const char* destString)
{
    // Check for the character : in the string for an IPv6 Address
    if (strchr(destString, ':'))
    {
        return FALSE;
    }

    while (*destString != '\0')
    {
        if ((*destString >= ASCII_VALUE_OF_CAPS_A &&
            *destString <= ASCII_VALUE_OF_CAPS_Z) ||
            (*destString >= ASCII_VALUE_OF_SMALL_A &&
            *destString <= ASCII_VALUE_OF_SMALL_Z))
        {
            return TRUE;
        }
        destString++;
    }
    return FALSE;
}

//--------------------------------------------------------------------------
// NAME        : AppDnsConcatenatePeriodIfNotPresent.
// PURPOSE     : Used to concatenate a period to domain names, application
//               urls and urls specified in hosts file if it is not explicitly
//               specified
// PARAMETERS:
// + destString : std::string*     : destination string
// RETURN       :
// void         : NULL
//--------------------------------------------------------------------------

void AppDnsConcatenatePeriodIfNotPresent(std::string* destString)
{
    Int32 urlLength = destString->length();
    if ((*destString)[urlLength - 1] != '.')
    {
        destString->push_back('.');
    }
    if (destString->length() >= DNS_NAME_LENGTH)
    {
        // This condition should never occur.
        ERROR_ReportErrorArgs(
            "The total length of the domain name exceeds %d",
            DNS_NAME_LENGTH - 1);
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsCreateNewRrRecord
// LAYER        :: Application Layer
// PURPOSE      :: Create New RR with all fields
// PARAMETERS   :: rrRecord* - RR Record Pointer
//                 domainOrUrlNameString* - the domain Name for the RR
//                 rrType - RR Type
//                 rrClass - RR class
//                 ttl - TTL value for the RR
//                 rdLength - Resource data Length
//                 associatedIpAddr : Corresponding IP address for this RR
// RETURN       :: NONE
//--------------------------------------------------------------------------
void DnsCreateNewRrRecord(
                      struct DnsRrRecord* rrRecord,
                      const char* domainOrUrlNameString,
                      enum RrType rrType,
                      enum RrClass rrClass,
                      clocktype ttl,
                      UInt32 rdLength,
                      Address* associatedIpAddr)
{
    strcpy(rrRecord->associatedDomainName, domainOrUrlNameString);
    rrRecord->rrType = rrType;
    rrRecord->rrClass = rrClass;
    rrRecord->ttl = ttl;
    rrRecord->rdLength = rdLength;
    memcpy(&(rrRecord->associatedIpAddr), associatedIpAddr, sizeof(Address));
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsReadTreeConfigParameter
// LAYER        :: Application Layer
// PURPOSE      :: Read DNS hierarchy information from .dnsspace file
// PARAMETERS   :: node - Pointer to node.
//                 dnsData - Pointer to DnsData Structure
//                 treeStructureInput - DNS Tree Configuration Information
//                 nodeInput - pointer to nodeInput structure
// RETURN       :: None
//--------------------------------------------------------------------------
void DnsReadTreeConfigParameter(
                           Node* node,
                           struct DnsData* dnsData,
                           const NodeInput* treeStructureInput,
                           const NodeInput* nodeInput)
{
    Int32 lineCount = 0;
    Int32 lineCount1 = 0;
    Int32 numInputs = 0;
    char nodeAddress[MAX_STRING_LENGTH] = "";
    char parentNodeAddress[MAX_STRING_LENGTH] = "";
    char tempnodeAddress[MAX_STRING_LENGTH] = "";
    char tempparentNodeAddress[MAX_STRING_LENGTH] = "";
    //Int32 levelCount;
    UInt32 level = 0;
    UInt32 zoneNo = 0;
    char label[DNS_NAME_LENGTH] = "";
    char zoneMasterOrSlave[8] = "";
    UInt32 tempLevel = 0;
    char tmpLabel[DNS_NAME_LENGTH] = "";
    char tempzoneMasterOrSlave[8] = "";
    UInt32 tempZoneNo = 0;
    BOOL val = FALSE;
    BOOL wasFoundDnsTreeInformation = FALSE;
    BOOL rrRecordFound = FALSE;
    char timeAddedStr[MAX_STRING_LENGTH] = "";
    char tempTimeAddedStr[MAX_STRING_LENGTH] = "";
    list<struct ZonePrimaryServerInfo*>* zonePrimaryServerList;
    struct ZonePrimaryServerInfo* zonePrimaryServerInfo;

    BOOL rootAddressFlag = FALSE;
    rootAddressFlag = FALSE;
    rrRecordFound = FALSE;

    const char* dot = DOT_SEPARATOR;
    const char* rootLabel = ROOT_LABEL;
    BOOL isNodeId = FALSE;
    Address dest_addr;
    memset(&dest_addr, 0, sizeof(Address));
    char buf[MAX_STRING_LENGTH] = "";
    BOOL retVal = FALSE;
    BOOL isParentValidServer = FALSE;

    struct DnsServerData* dnsServerData = dnsData->server;
    struct DnsTreeInfo* dnsTreeInfo = dnsData->server->dnsTreeInfo;

    struct ZoneData* zoneData = dnsData->zoneData;

    if (treeStructureInput->numLines)
    {
        dnsServerData->rrList = new DnsRrRecordList;
        zoneData->data = new ZoneDataList;
        zoneData->retryQueue = new RetryQueueList;
        zoneData->notifyRcvd = new NotifyReceivedList;
        zonePrimaryServerList = new list<struct ZonePrimaryServerInfo*>;
    }
    else
    {
        ERROR_ReportErrorArgs(
            "Node %d:DNS Tree Config File is empty\n",
            node->nodeId);
    }

    if (DEBUG)
    {
        printf("For partition %d\n\n", node->partitionId);
    }
    for (lineCount = 0;
        lineCount < treeStructureInput->numLines;
        lineCount++)
    {
        const char* currentLine =
            treeStructureInput->inputStrings[lineCount];
        zonePrimaryServerInfo = (struct ZonePrimaryServerInfo*)
                            MEM_malloc(sizeof(struct ZonePrimaryServerInfo));
        zonePrimaryServerInfo->zoneId = 0;
        zonePrimaryServerInfo->exists = FALSE;

        numInputs = sscanf(currentLine,
                           "%s %u %s %s %u %s %s",
                            nodeAddress,
                            &level,
                            parentNodeAddress,
                            label,
                            &zoneNo,
                            zoneMasterOrSlave,
                            timeAddedStr);

        if (numInputs < 7)
        {
            Int32 num_inputs = sscanf(
                                currentLine,
                                "%s %s %s",
                                label,
                                timeAddedStr,
                                nodeAddress);
            if (num_inputs == 3)
            {
                continue;
            }

            ERROR_ReportErrorArgs("The format in the file should be:\n"
                " <nodeIpaddress>\n <level>\n <parent nodeIpaddress>\n"
                " <label>\n <zone no.>\n <Zone Master or Slave>\n"
                " <Time at which node is added as a server>\n"
                " Please configure the labels according to the"
                " RFC standards.\n");

        }
        IO_ParseNodeIdHostOrNetworkAddress(
                nodeAddress,
                &dest_addr,
                &isNodeId);
        if (isNodeId)
        {
            ERROR_ReportErrorArgs("The nodeIpaddress: %s is not"
                "a valid IP Address\n", nodeAddress);

        }
        IO_ParseNodeIdHostOrNetworkAddress(
                parentNodeAddress,
                &dest_addr,
                &isNodeId);
        if (isNodeId && strcmp(label, "/"))
        {
            ERROR_ReportErrorArgs("The parent nodeIpaddress: %s is not"
                "a valid IP Address\n", parentNodeAddress);

        }
        if (!strcmp(label, "/") && (level != 0))
        {
            ERROR_ReportErrorArgs(
                "Root label(/) is reserved for root only\n");
        }
        if (zoneNo == 0)
        {
            if (strcmp(label, "/"))
            {
                ERROR_ReportErrorArgs("Zone 0 can only be used for root\n");
            }
        }
        if (DEBUG)
        {
            printf("Reading node id %s, parent node %s, level %d "
                    "for outer loop\n",
                    nodeAddress,
                    parentNodeAddress,
                    level);
        }

        NodeAddress nodeId = 0;
        NodeAddress parentNodeId = 0;
        Address destAddr;
        memset(&destAddr, 0, sizeof(Address));
        clocktype timeAdded = TIME_ConvertToClock(timeAddedStr);

        if (DEBUG)
        {
            printf("timeAdded = %u\n", (UInt32)timeAdded);
        }
        IO_AppParseDestString(node, NULL, nodeAddress, &nodeId, &destAddr);
        if (nodeId != 0)
        {
            if (DEBUG)
            {
                printf("Src is a valid ip\n");
            }
            nodeId = MAPPING_GetNodeIdFromInterfaceAddress(node, destAddr);
            if (DEBUG)
            {
                printf("Src node id %d\n", nodeId);
            }
        }
        else
        {
            ERROR_ReportErrorArgs("Node can be ip address only\n");
        }

        if (parentNodeAddress[0] != '0' || (strlen(parentNodeAddress) >= 2))
        {
            IO_AppParseDestString(node,
                                  NULL,
                                  parentNodeAddress,
                                  &parentNodeId,
                                  &destAddr);
        }
        else
        {
            parentNodeId = 0;
        }
        if (parentNodeId != 0)
        {
            if (DEBUG)
            {
                printf("Parent is a valid ip\n");
            }
            parentNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                node,
                                destAddr);
            if (DEBUG)
            {
                printf("Parent node id %d\n", parentNodeId);
            }
        }
        else if (strcmp(parentNodeAddress, "0"))
        {
            ERROR_ReportErrorArgs("Parent Node can be ip address only\n");
        }
        // Validate parent node
        if ((node->nodeId == nodeId) && strcmp(label, "/"))
        {
            isParentValidServer = FALSE;
            IO_ReadBool(parentNodeId,
                      ANY_ADDRESS,
                      nodeInput,
                      "DNS-ENABLED",
                      &retVal,
                      &val);

            if (retVal == TRUE)
            {
                if (val)
                {
                   IO_ReadBool(parentNodeId,
                                 ANY_ADDRESS,
                                 nodeInput,
                                 "DNS-SERVER",
                                 &retVal,
                                 &val);
                    if (retVal == TRUE)
                    {
                        if (val)
                        {
                            isParentValidServer = TRUE;
                        }
                    }
                }
            }
            if (!isParentValidServer)
            {
                ERROR_ReportErrorArgs(
                    "Parent Node %d is not a valid DNS server\n",
                    parentNodeId);
            }
        }

        if (strcmp(zoneMasterOrSlave, "P") &&
            strcmp(zoneMasterOrSlave, "S") &&
            strcmp(zoneMasterOrSlave, "NS"))
        {
            ERROR_ReportErrorArgs(
                "Entry should be P for Primary"
                " Master Zone Server or S for Slave Server"
                " NS for Name Server");
        }

        zonePrimaryServerInfo->zoneId = zoneNo;
        if (strcmp(zoneMasterOrSlave, "P") == 0)
        {
            struct ZonePrimaryServerInfo* zonePrimaryServerInfoTmp = NULL;
            zonePrimaryServerInfo->exists = TRUE;
            list<struct ZonePrimaryServerInfo*> :: iterator lstItem;
            if (zonePrimaryServerList->size() == 0)
            {
                zonePrimaryServerList->push_back(zonePrimaryServerInfo);
            }
            else
            {
                lstItem = zonePrimaryServerList->begin();
                while (lstItem != zonePrimaryServerList->end())
                {
                    zonePrimaryServerInfoTmp =
                            (struct ZonePrimaryServerInfo*)*lstItem;
                    if ((zonePrimaryServerInfoTmp->zoneId == zoneNo) &&
                            zonePrimaryServerInfoTmp->exists)
                    {
                        ERROR_ReportErrorArgs("There can exist only one "\
                            "Primary DNS for zone %d \n", zoneNo);
                    }
                    lstItem++;
                }
                zonePrimaryServerList->push_back(zonePrimaryServerInfo);
            }
        }
        else
        {
            MEM_free(zonePrimaryServerInfo);
            zonePrimaryServerInfo = NULL;
        }

        if (node->nodeId != nodeId)
        {
            if (DEBUG)
            {
                printf("Contributing node->nodeId %d not equal to "
                        "nodeId %d\n", node->nodeId, nodeId);
            }
            continue;
        }
        else
        {
            char serverDomain[DNS_NAME_LENGTH] = {0};
            wasFoundDnsTreeInformation = TRUE;
            dnsTreeInfo->zoneId = zoneNo;
            dnsTreeInfo->level = level;
            if (strcmp(zoneMasterOrSlave, "S"))
            {
                if (strcmp(label, rootLabel))
                {
                    strcpy(dnsTreeInfo->domainName, label);
                    strcat(dnsTreeInfo->domainName, dot);
                }
                else
                {
                    strcpy(dnsTreeInfo->domainName, dot);
                }
            }

            char domain[DNS_NAME_LENGTH]= {0};
            AppDnsComputeDomainName(
                                node,
                                label,
                                dnsTreeInfo->zoneId,
                                dnsTreeInfo->level,
                                treeStructureInput,
                                parentNodeId,
                                domain);
            if (!strcmp(zoneMasterOrSlave, "S"))
            {
                dnsData->inSrole = TRUE;
                dnsData->secondaryTimeAdded = timeAdded;
                strcpy(dnsData->secondryDomain, label);
                strcat(dnsData->secondryDomain, dot);
                strcat(dnsData->secondryDomain, domain);
            }
            else if (strlen(domain))
            {
                strcat(dnsTreeInfo->domainName, domain);
            }
            if (DEBUG)
            {
                if (!strcmp(zoneMasterOrSlave, "S"))
                {
                    printf("\n\nthe domain name of node %d is %s\n",
                        node->nodeId, dnsData->secondryDomain);
                }
                else
                {
                    printf("\n\nthe domain name of node %d is %s\n",
                        node->nodeId, dnsTreeInfo->domainName);
                }
            }

            if (timeAdded == 0)
            {
                dnsTreeInfo->parentId = parentNodeId;
            }
            if (strcmp(zoneMasterOrSlave, "S"))
            {
                dnsTreeInfo->timeAdded = timeAdded;
            }
            enum DnsServerRole role;
            Address node_addr;
            Address parent_addr;
            NodeAddress tempNodeId = 0;
            memset(&node_addr, 0, sizeof(Address));
            memset(&parent_addr, 0, sizeof(Address));
            if (!strcmp(zoneMasterOrSlave, "P"))
            {
                role = Primary;
                zoneData->isMasterOrSlave = TRUE;
                memcpy(&serverDomain,
                    dnsTreeInfo->domainName,
                    sizeof(serverDomain));
            }
            else if (!strcmp(zoneMasterOrSlave, "S"))
            {
                role = Secondary;
                zoneData->isMasterOrSlave = FALSE;
                memcpy(&serverDomain,
                    dnsData->secondryDomain,
                    sizeof(serverDomain));
            }
            else if (!strcmp(zoneMasterOrSlave, "NS"))
            {
                role = NameServer;
                zoneData->isMasterOrSlave = FALSE;
                memcpy(&serverDomain,
                    dnsTreeInfo->domainName,
                    sizeof(serverDomain));
            }
            IO_AppParseDestString(
                node,
                NULL,
                nodeAddress,
                &tempNodeId,
                &node_addr);

            if (!strcmp(zoneMasterOrSlave, "S"))
            {
                AppToUdpSend* info = NULL;
                Message* msg = NULL;
                IO_AppParseDestString(
                    node,
                    NULL,
                    parentNodeAddress,
                    &tempNodeId,
                    &parent_addr);
                enum DnsMessageType dnsMsgType = DNS_ADD_SERVER;
                msg = MESSAGE_Alloc(
                            node,
                            TRANSPORT_LAYER,
                            TransportProtocol_UDP,
                            MSG_TRANSPORT_FromAppSend);

                MESSAGE_PacketAlloc(
                        node,
                        msg,
                        sizeof(Address)+ sizeof(enum DnsMessageType) +
                            DNS_NAME_LENGTH,
                        TRACE_DNS);
                memcpy(
                    MESSAGE_ReturnPacket(msg),
                    (char*)(&dnsMsgType),
                    sizeof(enum DnsMessageType));
                memcpy(
                    MESSAGE_ReturnPacket(msg) + sizeof(enum DnsMessageType),
                    (char*)(&node_addr),
                    sizeof(Address));
                memcpy(
                    MESSAGE_ReturnPacket(msg) + sizeof(enum DnsMessageType)+
                       sizeof(Address),
                    (char*)(dnsData->secondryDomain),
                    DNS_NAME_LENGTH);
                MESSAGE_InfoAlloc(node, msg, sizeof(AppToUdpSend));
                info = (AppToUdpSend*) MESSAGE_ReturnInfo(msg);
                memset(info, 0, sizeof(AppToUdpSend));
                info->sourceAddr = node_addr;
                info->sourcePort = (short)APP_DNS_CLIENT;
                memcpy(&(info->destAddr), &parent_addr, sizeof(Address));
                info->destPort = (short) APP_DNS_SERVER;
                info->priority = APP_DEFAULT_TOS;
                dnsData->addServer = msg;
            }
            else if (timeAdded != 0)
            {
                Message* timerMsg = MESSAGE_Alloc(
                                        node,
                                        APP_LAYER,
                                        APP_DNS_SERVER,
                                        MSG_APP_DNS_SERVER_INIT);

                MESSAGE_PacketAlloc(
                node,
                timerMsg,
                sizeof(Address) + sizeof(label) + sizeof(enum DnsServerRole),
                TRACE_DNS);
                memcpy(
                    MESSAGE_ReturnPacket(timerMsg),
                    (char*)(&node_addr),
                    sizeof(Address));
                memcpy(
                    MESSAGE_ReturnPacket(timerMsg) + sizeof(Address),
                    (char*)(serverDomain),
                    sizeof(serverDomain));
                memcpy(
                    MESSAGE_ReturnPacket(timerMsg) + sizeof(Address) +
                    sizeof(label),
                    (char*)(&role),
                    sizeof(role));
                MESSAGE_Send(node, timerMsg, timeAdded);
            }
        }

        // the code followed by this line will be executed
        // once only for the above for loop

        for (lineCount1 = 0;
              lineCount1 < treeStructureInput->numLines;
              lineCount1++)
        {
            const char* tempCurrentLine =
                treeStructureInput->inputStrings[lineCount1];

            numInputs = sscanf(tempCurrentLine,
                            "%s %u %s %s %u %s %s",
                            tempnodeAddress,
                            &tempLevel,
                            tempparentNodeAddress,
                            tmpLabel,
                            &tempZoneNo,
                            tempzoneMasterOrSlave,
                            tempTimeAddedStr);
            if ((numInputs < 7))
            {
                continue;
            }
            char tempLabel[DNS_NAME_LENGTH]= {0};
            strcpy(tempLabel, tmpLabel);
            Address node_addr;
            Address parent_node_addr;
            NodeAddress tempNodeId = 0;
            NodeAddress tempparentNodeId = 0;
            clocktype tempTimeAdded = TIME_ConvertToClock(tempTimeAddedStr);
            memset(&parent_node_addr, 0, sizeof(Address));
            memset(&node_addr, 0, sizeof(Address));
            IO_AppParseDestString(
                node,
                NULL,
                tempnodeAddress,
                &tempNodeId,
                &node_addr);

            if (tempNodeId != 0)
            {
                // source address and source port generation
                NetworkProtocolType protocol_type = INVALID_NETWORK_TYPE;

                protocol_type = NetworkIpGetNetworkProtocolType(node,
                                        node->nodeId);
                if (DEBUG)
                {
                    printf("Src is a valid ip\n");
                }
                tempNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                node,
                                node_addr);
                if (DEBUG)
                {
                    printf("Src node id %d\n", tempNodeId);
                }
                if (!strcmp(nodeAddress, tempnodeAddress))
                {
                    char errStr[MAX_STRING_LENGTH];
                    if (!strcmp(zoneMasterOrSlave, "P") &&
                        !strcmp(tempzoneMasterOrSlave, "S"))
                    {
                        ERROR_ReportErrorArgs(errStr, "NOT SUPPORTED:"
                            "Primary DNS Server(%d) can not be configured"
                            "Secondary of a Zone\n", tempNodeId);
                    }
                    else if ((!strcmp(zoneMasterOrSlave, "S") &&
                             !strcmp(tempzoneMasterOrSlave, "S")) &&
                             (zoneNo != tempZoneNo))
                    {
                        ERROR_ReportErrorArgs("NOT SUPPORTED: DNS "
                            "Server(%d) can not be configured as "
                            "Secondary\n of multiple Zones\n", tempNodeId);
                    }
                }
            }
            else
            {
                ERROR_ReportErrorArgs("Node can be ip address only\n");
            }

            if (tempparentNodeAddress[0] != '0' ||
                (strlen(tempparentNodeAddress) >= 2))
            {
                IO_AppParseDestString(
                    node,
                    NULL,
                    tempparentNodeAddress,
                    &tempparentNodeId,
                    &parent_node_addr);
            }
            else
            {
                tempparentNodeId = 0;
            }

            if (tempparentNodeId != 0)
            {
                if (DEBUG)
                {
                    printf("Parent is a valid ip\n");
                }
                tempparentNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                        node,
                                        parent_node_addr);
                if (DEBUG)
                {
                    printf("Parent node id %d\n", tempparentNodeId);
                }
            }
            else if (strcmp(tempparentNodeAddress, "0"))
            {
                ERROR_ReportErrorArgs(
                    "Parent Node can be ip address only\n");
            }

            if (DEBUG)
            {
                // List Insert for Nodes those are in same Zone No.
                printf("node %d, parent of tempnode %d is %d\n",
                        node->nodeId,
                        tempNodeId,
                        tempparentNodeId);
            }
            if ((dnsTreeInfo->parentId == tempNodeId ) &&
                !dnsData->zoneData->isMasterOrSlave &&
                !dnsData->inSrole)
            {
                if ((UInt32)dnsTreeInfo->zoneId != tempZoneNo)
                {
                    ERROR_ReportErrorArgs("Node %d can not have its parent"
                        "%d in diffrent zone\n",
                            nodeId,
                            tempNodeId);
                }
            }
            if ((UInt32)dnsTreeInfo->zoneId == tempZoneNo)
            {
                if (DEBUG)
                {
                    printf("zone init during serverinit for node %d\n",
                           node->nodeId);
                }
                // if the node is Master Server for this Zone
                // Insert the Slave Server's Address for the same Zone
                if ((dnsData->zoneData->isMasterOrSlave == TRUE &&
                   !strcmp(tempzoneMasterOrSlave, "S")))
                {
                    if (DEBUG)
                    {
                        printf("inserted in zone data for node %d\n",
                               node->nodeId);
                    }
                    data* tempData = NULL;
                    //NodeAddress tempNodeId = 0;

                    tempData = (data*)MEM_malloc(sizeof(data));
                    memset(tempData, 0, sizeof(data));

                    memcpy(&(tempData->zoneServerAddress),
                            &node_addr,
                            sizeof(Address));
                    memcpy(&tempData->timeAdded,
                            &tempTimeAdded,
                            sizeof(tempTimeAdded));

                    memset(label, 0, DNS_NAME_LENGTH);

                    memcpy(tempData->tempLabel,
                            dnsTreeInfo->domainName,
                            sizeof(tempData->tempLabel));
                    tempData->isZoneMaster = FALSE;
                    if (DEBUG)
                    {
                        printf("--------------------------------------\n");
                        printf("Contents of Zone data for node id %d: \n",
                                 node->nodeId );
                        printf("Label: %s\n", tempData->tempLabel);
                        printf("--------------------------------------\n");
                    }
                    dnsData->zoneData->data->push_back(tempData);
                }
                if ((dnsData->zoneData->isMasterOrSlave == TRUE &&
                   !strcmp(tempzoneMasterOrSlave, "NS")) &&
                   (tempTimeAdded == 0))
                {
                    data* tempData = NULL;
                    char domain[DNS_NAME_LENGTH] = {0};
                    tempData = (data*)MEM_malloc(sizeof(data));

                    memcpy(&tempData->zoneServerAddress,
                            &node_addr,
                            sizeof(Address));

                    AppDnsComputeDomainName(node,
                        tempLabel,
                        tempZoneNo,
                        tempLevel,
                        treeStructureInput,
                        tempparentNodeId,
                        domain);

                    char label[DNS_NAME_LENGTH];
                    memcpy(label, tempLabel, sizeof(tempLabel));
                    if (strcmp(label, rootLabel) &&
                        (dnsTreeInfo->parentId != tempNodeId))
                    {
                        strcat(label, dot);
                        strcat(label, domain);
                    }
                    memcpy(tempData->tempLabel, label, sizeof(label));
                    dnsData->nameServerList->push_back(tempData);

                    if (node->nodeId != tempparentNodeId)
                    {
                        struct DnsRrRecord* rrRecord =
                        (struct DnsRrRecord*)MEM_malloc
                        (sizeof(struct DnsRrRecord));
                        memset(rrRecord, 0, sizeof(struct DnsRrRecord));

                        DnsCreateNewRrRecord(rrRecord,
                            tempData->tempLabel,
                            NS,
                            IN,
                            dnsData->cacheRefreshTime,
                            sizeof(Address),
                            &tempData->zoneServerAddress);

                        dnsServerData->rrList->push_back(rrRecord);
                    }
                }
                // if the node is Slave Server for this Zone
                // Insert the Master Server's Address for the same Zone
                if ((dnsData->zoneData->isMasterOrSlave == FALSE) &&
                    !strcmp(tempzoneMasterOrSlave, "P") &&
                    strcmp(zoneMasterOrSlave, "NS"))
                {
                    if ((tempLevel != level) ||
                        (tempZoneNo != zoneNo) ||
                        strcmp(tempLabel, label) ||
                        (parentNodeId != tempparentNodeId))
                    {
                        ERROR_ReportErrorArgs(
                            "Node %d is not a valid Secondary"
                            " Server of Zone %d\n",
                            node->nodeId,
                            zoneNo);
                    }
                    if (DEBUG)
                    {
                        printf("secondary inserted in zone data for node"
                               " %d\n",
                               node->nodeId);
                    }

                    data* tempData = (data*)MEM_malloc(sizeof(data));

                    memcpy(&tempData->zoneServerAddress,
                           &node_addr,
                           sizeof(Address));

                    char label[DNS_NAME_LENGTH] = "";
                    memcpy(label, tempLabel, sizeof(tempLabel));
                    if (strcmp(label, rootLabel) &&
                        (dnsTreeInfo->parentId != tempNodeId))
                    {
                        strcat(label, dot);
                        strcat(label, dnsTreeInfo->domainName);
                    }
                    memcpy(tempData->tempLabel, label, sizeof(label));
                    tempData->isZoneMaster = TRUE;
                    if (DEBUG)
                    {
                        printf("--------------------------------------\n");
                        printf("Contents of Zone data for node id %d: \n",
                               node->nodeId );
                        printf("Label: %s\n", tempData->tempLabel);
                    }
                    dnsData->zoneData->data->push_back(tempData);
                }
                else if ((dnsData->zoneData->isMasterOrSlave == TRUE) &&
                         !strcmp(tempzoneMasterOrSlave, "P") &&
                         strcmp(dnsTreeInfo->domainName, dot) &&
                         strcmp(zoneMasterOrSlave, "NS"))
                {
                    // create and add SOA type RR for each Primary zone
                    // server
                    struct DnsRrRecord* SOArrRecord =
                    (struct DnsRrRecord*)MEM_malloc
                    (sizeof(struct DnsRrRecord));
                    memset(SOArrRecord, 0, sizeof(struct DnsRrRecord));

                    DnsCreateNewRrRecord(
                        SOArrRecord,
                        dnsTreeInfo->domainName,
                        SOA,
                        IN,
                        dnsData->cacheRefreshTime,
                        sizeof(node_addr),
                        &node_addr);

                    dnsServerData->rrList->push_back(SOArrRecord);
                }
            }
            if ((node->nodeId == tempNodeId) &&
                !strcmp(zoneMasterOrSlave, "NS") &&
                !strcmp(tempzoneMasterOrSlave, "S"))
            {
                if (tempTimeAdded < dnsTreeInfo->timeAdded)
                {
                    ERROR_ReportErrorArgs("DNS Server %d can't be added as "
                            "Secondary before adding it as Nameserver\n",
                            node->nodeId);
                }
            }

            if (((node->nodeId == tempparentNodeId) ||
                (!rootAddressFlag )) &&
                strcmp(zoneMasterOrSlave, "S"))
            {
                Address tempAddress;
                char domain[DNS_NAME_LENGTH] = {0};
                BOOL firstTime = TRUE;
                memcpy(&tempAddress, &node_addr, sizeof(Address));
                Int32 recCount = 1;
                if ((tempTimeAdded < dnsTreeInfo->timeAdded) &&
                    (rootAddressFlag))
                {
                    ERROR_ReportErrorArgs("DNS Server %d can't be added"
                            " before its Parent Server %d\n",
                            tempNodeId,
                            node->nodeId);
                }
                if (!strcmp(tempLabel, rootLabel))
                {
                    strcpy(tempLabel, dot);
                    rootAddressFlag = TRUE;
                }
                else if (tempLevel != 1)
                {
                    AppDnsComputeDomainName(node,
                                        tempLabel,
                                        tempZoneNo,
                                        tempLevel,
                                        treeStructureInput,
                                        tempparentNodeId,
                                        domain);
                    if (!strcmp(tempzoneMasterOrSlave, "S"))
                    {
                        strcat(tempLabel, dot);
                        strcat(tempLabel, domain);
                    }
                    else if (strlen(domain))
                    {
                        strcat(tempLabel, dot);
                        strcat(tempLabel, domain);
                    }
                }
                else if (tempLevel == 1)
                {
                    strcat(tempLabel, dot);
                }

                while (recCount)
                {
                    recCount--;
                    struct DnsRrRecord* rrRecord =
                    (struct DnsRrRecord*)MEM_malloc
                    (sizeof(struct DnsRrRecord));
                    memset(rrRecord, 0, sizeof(struct DnsRrRecord));
                    // Create a RR Record for a new record
                    // and insert it to the RR record List
                    if (DEBUG)
                    {
                            printf("in DnsReadTreeConfigParameter creating"
                                " new rr\n");
                    }
                    if ((tempTimeAdded == 0) &&
                        strcmp(tempzoneMasterOrSlave, "S"))
                    {
                        DnsCreateNewRrRecord(
                            rrRecord,
                            tempLabel,
                            NS,
                            IN,
                            dnsData->cacheRefreshTime,
                            sizeof(tempAddress),
                            &tempAddress);
                    }
                    else if ((strcmp(zoneMasterOrSlave, "P") ||
                            !strcmp(label, rootLabel)) &&
                            strcmp(tempzoneMasterOrSlave, "S"))
                    {
                        Address tmpParentAddress;
                        memset(&tmpParentAddress, 0, sizeof(Address));
                        IO_ParseNodeIdHostOrNetworkAddress(
                            nodeAddress, &tmpParentAddress, &isNodeId);
                        AppDnsAddServerRRToParent(
                            node,
                            tempLabel,
                            tempAddress,
                            tmpParentAddress);
                            //tempTimeAdded);
                    }
                    DnsRrRecordList :: iterator tmpItem;
                    tmpItem = dnsServerData->rrList->begin();
                    while (tmpItem != dnsServerData->rrList->end())
                    {
                        struct DnsRrRecord* rrItemTmp = NULL;
                        rrItemTmp = (struct DnsRrRecord*)*tmpItem;
                        if (!strcmp(rrItemTmp->associatedDomainName,
                                   rrRecord->associatedDomainName) &&
                           (rrItemTmp->associatedIpAddr.networkType
                               == rrRecord->associatedIpAddr.networkType) &&
                           strcmp(tempzoneMasterOrSlave, "S"))
                        {
                             ERROR_ReportErrorArgs(
                                 "NodeId %d: Multiple"
                                 "nameservers with identical domain name"
                                 " (%s) can not exist on same level\n",
                                node->nodeId,
                                rrRecord->associatedDomainName);
                        }
                        tmpItem++;
                    }
                    if ((tempTimeAdded == 0) &&
                        strcmp(tempzoneMasterOrSlave, "S"))
                    {
                        dnsServerData->rrList->push_back(rrRecord);
                    }

                    if (firstTime)
                    {
                        firstTime = FALSE;
                        for (Int32 lineNum = 0;
                            lineNum < treeStructureInput->numLines;
                            lineNum++)
                        {
                            char secLabel[MAX_STRING_LENGTH] = "";
                            BOOL rootEntry = FALSE;
                            char secAddressTypStr[MAX_STRING_LENGTH] = "";
                            char secNodeAddress[MAX_STRING_LENGTH] = "";
                            const char* tempCurrentLine =
                                treeStructureInput->inputStrings[lineNum];

                            Int32 countInputs = sscanf(tempCurrentLine,
                                                "%s %s %s",
                                                secLabel,
                                                secAddressTypStr,
                                                secNodeAddress);
                            if (countInputs < 3)
                            {
                                continue;
                            }
                            if (!strcmp(secLabel, rootLabel) &&
                                strcmp(label, rootLabel) &&
                                !strcmp(tmpLabel, secLabel))
                            {
                                rootEntry = TRUE;
                            }
                            strcat(secLabel, dot);
                            if (dnsTreeInfo->level >= 1)
                            {
                                strcat(secLabel, dnsTreeInfo->domainName);
                            }
                            if (!strcmp(tempLabel, secLabel) ||
                                rootEntry )
                            {
                                if ((!strcmp(secAddressTypStr, "AAAA")) ||
                                    (!strcmp(secAddressTypStr, "A")))
                                {
                                    Address localAddr;
                                    IO_AppParseDestString(node,
                                        NULL,
                                        secNodeAddress,
                                        &tempNodeId,
                                        &localAddr);
                                    memcpy(&tempAddress,
                                        &localAddr,
                                        sizeof(Address));
                                    recCount++;
                                    break;
                                }
                                else
                                {
                                    ERROR_ReportErrorArgs(
                                        "NodeId %d: Invalid RR type(%s) \n",
                                        node->nodeId,
                                        secAddressTypStr);
                                }
                            }
                        }
                    }
                }
            }   // end of if
        } // end of For
    } // end of for
    if (zonePrimaryServerList)
    {
        list<struct ZonePrimaryServerInfo*> :: iterator lstItem;
        lstItem = zonePrimaryServerList->begin();
        while (lstItem != zonePrimaryServerList->end())
        {
            struct ZonePrimaryServerInfo* item =
                (struct ZonePrimaryServerInfo*)(*lstItem);
            lstItem++;
            MEM_free(item);
            item = NULL;
        }
        delete(zonePrimaryServerList);
        zonePrimaryServerList = NULL;
    }
    if (DEBUG)
    {
        DnsRrRecordList :: iterator item;
        item = dnsData->server->rrList->begin();

        // check for matching destIP
        printf("For Node: %d the following RR records\n", node->nodeId);
        while (item != dnsData->server->rrList->end())
        {
            struct DnsRrRecord* rrItem = (struct DnsRrRecord*)*item;

            printf("\tAssociated Domain Name: %s\n",
                rrItem->associatedDomainName);

            item++;
        }
        printf("\n");
    }

    if (!wasFoundDnsTreeInformation)
    {
        ERROR_ReportErrorArgs(
                "DNS Server Information is not available "
                "in .dnsspace for Node: %u",
                node->nodeId);
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsAddServerToTree
// LAYER        :: Application Layer
// PURPOSE      :: Add new server info to zone master
// PARAMETERS   :: node - Pointer to node.
//                 treeStructureInput - DNS Tree information of node
//                 newServerLabel
//                 size
//                 recordPtr
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsAddServerToTree(Node* node,
                      Address* zoneServerAddress,
                      char* newServerLabel,
                      UInt32 size,
                      char* recordPtr)
{

    // if the node is Master Server for this Zone
    // Insert the Slave Server's Address for the same Zone

    if (DEBUG)
    {
        printf("inserted in zone data for node %d\n",
               node->nodeId);
    }
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
    struct DnsTreeInfo* dnsTreeInfo = dnsData->server->dnsTreeInfo;
    struct DnsServerData* dnsServerData = dnsData->server;
    char* tmpRecordPtr = NULL;
    UInt32 recordCount = 0;
    // Increment the zone fresh count as newer data has arrived.
    dnsData->zoneData->zoneFreshCount++;
    Address tempAddress;
    char tempLabel[DNS_NAME_LENGTH] = "";
    struct DnsRrRecord* rrRecord =
        (struct DnsRrRecord*)MEM_malloc(sizeof(struct DnsRrRecord));
    memset(rrRecord, 0, sizeof(struct DnsRrRecord));
    memset(&tempAddress, 0, sizeof(Address));
    memcpy(tempLabel, newServerLabel, sizeof(tempLabel));
    memcpy(&tempAddress, zoneServerAddress, sizeof(Address));
    // Create a RR Record for a new record
    // and insert it to the RR record List
    if (DEBUG)
    {
        printf("Node %u: in AddServerToTree adding new NS rr(%s)\n",
            node->nodeId, tempLabel);
    }
    DnsCreateNewRrRecord(rrRecord,
        tempLabel,
        NS,
        IN,
        dnsData->cacheRefreshTime,
        sizeof(tempAddress),
        &tempAddress);

    dnsServerData->rrList->push_back(rrRecord);
    // Search registered host for this new server and also add
    tmpRecordPtr = recordPtr;
    for (recordCount = 0; recordCount < size; recordCount++)
    {
        BOOL recordExist = FALSE;
        BOOL isSecondaryToZone = FALSE;
        struct DnsRrRecord* tmpRecord =
                (struct DnsRrRecord*)MEM_malloc(sizeof(struct DnsRrRecord));
        memcpy(tmpRecord, tmpRecordPtr, sizeof(struct DnsRrRecord));

        DnsRrRecordList :: iterator item = dnsServerData->rrList->begin();
        while (item != dnsServerData->rrList->end())
        {
            struct DnsRrRecord* rrRecord = (struct DnsRrRecord*)*item;
            if (!strcmp(tmpRecord->associatedDomainName,
                        rrRecord->associatedDomainName) &&
                !MAPPING_CompareAddress(tmpRecord->associatedIpAddr,
                                        rrRecord->associatedIpAddr))
            {
                recordExist = TRUE;
                break;
            }
            item++;
        }
        ZoneDataList :: iterator zItem = dnsData->zoneData->data->begin();
        while (zItem != dnsData->zoneData->data->end())
        {
            data* tmpData = (data*)*zItem;
            if (!MAPPING_CompareAddress(tmpData->zoneServerAddress,
                tmpRecord->associatedIpAddr))
            {
                isSecondaryToZone = TRUE;
            }
            zItem++;
        }

        tmpRecordPtr += sizeof(struct DnsRrRecord);
        if (tmpRecord->rrType == NS &&  !recordExist && isSecondaryToZone)
            // put a check so that only its zone NS record is inserted
            // use Nameservrlist to check the NS
        {
            tmpRecord->ttl = dnsData->cacheRefreshTime;
            dnsServerData->rrList->push_back(tmpRecord);
        }
        else
        {
            if (tmpRecord)
            {
                MEM_free(tmpRecord);
                tmpRecord = NULL;
            }
        }
    }
    MEM_free(recordPtr);
    recordPtr = NULL;
    if (DEBUG)
    {
        DnsRrRecordList :: iterator item;
        item = dnsData->server->rrList->begin();

        // check for matching destIP
        printf("\nIn function AddServer Tree For Node: %d "
        "the following RR records\n", node->nodeId);

        while (item != dnsData->server->rrList->end())
        {
            struct DnsRrRecord* rrItem = (struct DnsRrRecord*)*item;

            printf("\tAssociated Domain Name: %s\n",
                    rrItem->associatedDomainName);

            item++;
        }
        printf("\n");
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsCreateAndAddRR
// LAYER        :: Application Layer
// PURPOSE      :: Creates a new RR and adds it in the RRlist of that node
// PARAMETERS   :: node - Pointer to node.
//                 outputNodeAddress
//                 nodeInput
// RETURN       :: None
//--------------------------------------------------------------------------
void DnsCreateAndAddRR(Node* node,
                  struct DnsData* dnsData,
                  Address outputNodeAddress,
                  const NodeInput* nodeInput,
                  const char* tempLabel,
                  const char* interfaceAddressString)
{
    BOOL  retVal = FALSE;
    struct DnsServerData* dnsServerData = dnsData->server;
    char* hostname = NULL;
    char tempDomainName[2 * DNS_NAME_LENGTH] = "";
    enum RrType record_type = A;

    NodeAddress tempIpAddress = MAPPING_GetNodeIdFromInterfaceAddress(
                                        node,
                                        outputNodeAddress);

    struct DnsRrRecord* rrRecord =
        (struct DnsRrRecord*)MEM_malloc(sizeof(struct DnsRrRecord));
    memset(rrRecord, 0, sizeof(struct DnsRrRecord));
    hostname = (char*)MEM_malloc(sizeof(char) * MAX_STRING_LENGTH);
    sprintf(hostname, "host%d", tempIpAddress);

    IO_ReadString(tempIpAddress,
                  ANY_ADDRESS,
                  nodeInput,
                  "HOSTNAME",
                  &retVal,
                  hostname);
    if (DEBUG)
    {
        printf("\nhostname for node %d is %s\n", tempIpAddress, hostname);
    }

    strcpy(tempDomainName, hostname);
    strcat(tempDomainName, DOT_SEPARATOR);
    if (!strcmp(tempLabel, DOT_SEPARATOR))
    {
        ERROR_ReportErrorArgs("Hosts can't be registered directly "
            "with root(/) node\n");
    }
    strcat(tempDomainName, tempLabel);

    if (DNS_NAME_LENGTH < strlen(tempDomainName))
    {
        ERROR_ReportErrorArgs("The total length of the domain name"
                " exceeds 255");
    }
    if (MAPPING_GetNetworkType(interfaceAddressString) == NETWORK_IPV6)
    {
        record_type = AAAA;
    }
    else
    {
        record_type = A;
    }
    DnsCreateNewRrRecord(rrRecord,
                          tempDomainName,
                          record_type,
                          IN,
                          dnsData->cacheRefreshTime,
                          sizeof(Address),
                          &outputNodeAddress);

    dnsServerData->rrList->push_back(rrRecord);

    if (DEBUG)
    {
        printf(" Node %d with domainname %s is registered under Node %d\n",
                tempIpAddress, tempDomainName, node->nodeId);
    }
    MEM_free(hostname);
    hostname = NULL;
    return;
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsReadDomainNameFile
// LAYER        :: Application Layer
// PURPOSE      :: Read Domain Name and it's associated interface
//                information from .dnsspace file
// PARAMETERS   :: node - Pointer to node.
//                 dnsData - Pointer to DnsData Structure
//                 nodeInput - pointer to node input structure
//                 domainNameInput - Domain Name Configuration
//                                      Information
// RETURN       :: None
//--------------------------------------------------------------------------
void DnsReadDomainNameFile(Node* node,
                      struct DnsData* dnsData,
                      const NodeInput* nodeInput,
                      const NodeInput* domainNameInput)
{
    Int32 lineCount = 0;
    std::string interfaceAddressString;
    std::string domainName;
    BOOL isNodeId = FALSE;
    Address outputNodeAddress;
    Int32 numInputs = 0;

    struct DnsServerData* dnsServerData = dnsData->server;

    struct DnsTreeInfo* dnsTreeInfo = dnsData->server->dnsTreeInfo;
    Address ipAddress;

    if (domainNameInput->numLines == 0)
    {
        ERROR_ReportErrorArgs(
            "Node %d:The DNS register file is empty\n",
            node->nodeId);
    }
    // Read the domain Name File
    for (lineCount = 0;
        lineCount < domainNameInput->numLines;
        lineCount++)
    {
        std::stringstream currentLine(domainNameInput->inputStrings[lineCount]);
        currentLine >> interfaceAddressString;
        currentLine >> domainName;

        if (domainName.size() == 0)
        {
            ERROR_ReportErrorArgs("Incorrect format is used in DNS Names"
                                  " File in line: %s\n"
                                  "It should be [Interface IP Address | "
                                  "Subnet-Addr] <Domain Name>",
                                  domainNameInput->inputStrings[lineCount]);
        }

        AppDnsConcatenatePeriodIfNotPresent(&domainName);

        NodeAddress nodeId = 0;
        memset(&outputNodeAddress, 0, sizeof(Address));

        NetworkType networkType =
                MAPPING_GetNetworkType(interfaceAddressString.c_str());
        memset(&ipAddress, 0, sizeof(Address));
        if (networkType == NETWORK_IPV4)
        {
            Int32 numHostBits = 0;
            ipAddress.networkType = NETWORK_IPV4;

            IO_ParseNodeIdHostOrNetworkAddress(
                interfaceAddressString.c_str(),
                &ipAddress.interfaceAddr.ipv4,
                &numHostBits,
                &isNodeId);

            if (numHostBits != 0)
            {
                // Find the pointer to the partition map
                // For all the subnets in the scenario, Get the Subnet List.
                // For all the members in the Subnet List
                // Extract the interface index and Address.
                // Find the subnet mask of this Adress.
                // Using the subnet mask, find the subnet address
                // If this subnet address is equal to the Subnet address
                // given in file then it means that this address lies
                // in the subnet

                Int32 countNumSubnets = 0;
                Int32 countNumMembers = 0;
                Int32 interfaceIndex = 0;
                NodeId nodeId = 0;
                NodeAddress subnetmask = 0;
                NodeAddress subnetAddress = 0;

                PartitionData* partitionData = node->partitionData;
                PartitionSubnetData* subnetData = &partitionData->subnetData;
                for (countNumSubnets = 0;
                    countNumSubnets < subnetData->numSubnets;
                    countNumSubnets++)
                {
                    PartitionSubnetList subnetList =
                         subnetData->subnetList[countNumSubnets];

                    for (countNumMembers = 0;
                        countNumMembers < subnetList.numMembers;
                        countNumMembers++)
                    {
                        nodeId =
                            subnetList.memberList[countNumMembers].nodeId;

                        interfaceIndex =
                            subnetList.memberList[countNumMembers].
                            interfaceIndex;

                        NodeAddress nodeAddress =
                            subnetList.memberList[countNumMembers].address.
                                                    interfaceAddr.ipv4;

                        subnetmask = MAPPING_GetSubnetMaskForInterface(node,
                                        nodeId, interfaceIndex);
                        subnetAddress = nodeAddress & subnetmask;

                        if (subnetAddress == ipAddress.interfaceAddr.ipv4)
                        {
                            outputNodeAddress =
                            subnetList.memberList[countNumMembers].address;
                            // check the domain name of the Node with the
                            // domain Name specified in the .register file
                            // if matched then the corresponding interface
                            // IP address will be registered under this node

                            if (!strcmp(dnsTreeInfo->domainName,
                                domainName.c_str()))
                            {
                                DnsCreateAndAddRR(
                                    node,
                                    dnsData,
                                    outputNodeAddress,
                                    nodeInput,
                                    domainName.c_str(),
                                    interfaceAddressString.c_str());
                            }// end

                            if (dnsData->zoneData->isMasterOrSlave == TRUE)
                            {
                                data* tempData = NULL;
                                ZoneDataList :: iterator item;

                                Int32 size = dnsData->zoneData->data->size();
                                if (size != 0)
                                {
                                    item = dnsData->zoneData->data->begin();
                                    tempData = (data*)*item;
                                }
                                while ((size != 0) && tempData &&
                                   (item != dnsData->zoneData->data->end()))
                                {
                                    // check the domain name of the slave
                                    // with the domain Name specified in the
                                    // .register file if matched then the
                                    // corresponding interface IP address
                                    //  will be registered under this node

                                    if (!strcmp(tempData->tempLabel,
                                                domainName.c_str()))
                                    {
                                        DnsCreateAndAddRR(
                                             node,
                                             dnsData,
                                             outputNodeAddress,
                                             nodeInput,
                                             domainName.c_str(),
                                             interfaceAddressString.
                                                c_str());
                                    }// end
                                    size--;
                                    if (size!=0)
                                    {
                                        item++;
                                        tempData = (data*)*item;
                                    }
                                }
                            }
                         }
                         else
                         {
                             break; // continue with next subnets
                         }
                    }
                }
                continue; // No need to execute the rest of the code
            }
            else
            {
                if (DEBUG)
                {
                    printf("Num host bits is zero\n");
                }
                IO_AppParseDestString(node,
                                      NULL,
                                      interfaceAddressString.c_str(),
                                      &nodeId,
                                      &outputNodeAddress);
            }
        }
        else if (networkType == NETWORK_IPV6)
        {
            UInt32 numHostBits = 0;
            BOOL isIpAddr = FALSE;
            NodeId isNodeId = 0;
            ipAddress.networkType = NETWORK_IPV6;

            IO_ParseNodeIdHostOrNetworkAddress(
                interfaceAddressString.c_str(),
                &ipAddress.interfaceAddr.ipv6,
                &isIpAddr,
                &isNodeId,
                &numHostBits);

            if (numHostBits != 128)
            {
                // Find the pointer to the partition map
                // For all the subnets in the scenario, Get the Subnet List.
                // For all the members in the Subnet List
                // Extract the interface index and Address.
                // Find the subnet mask of this Adress.
                // Using the subnet mask, find the subnet address
                // If this subnet address is equal to the Subnet address
                // given in file then it means that this address lies
                // in the subnet

                Int32 countNumSubnets = 0;
                Int32 countNumMembers = 0;
                Address subnetAddress;

                PartitionData* partitionData = node->partitionData;
                PartitionSubnetData* subnetData = &partitionData->subnetData;
                for (countNumSubnets = 0;
                    countNumSubnets < subnetData->numSubnets;
                    countNumSubnets++)
                {
                    PartitionSubnetList subnetList =
                         subnetData->subnetList[countNumSubnets];

                    for (countNumMembers = 0;
                        countNumMembers < subnetList.numMembers;
                        countNumMembers++)
                    {
                        memset(&subnetAddress, 0, sizeof(Address));
                        subnetAddress.networkType = NETWORK_IPV6;
                        MAPPING_GetSubnetAddressFromInterfaceAddress(node,
                             &subnetList.memberList[countNumMembers].address.
                             interfaceAddr.ipv6,
                             &subnetAddress.interfaceAddr.ipv6);

                        if (!MAPPING_CompareAddress(subnetAddress,
                                                    ipAddress))
                        {
                            outputNodeAddress =
                             subnetList.memberList[countNumMembers].address;
                            // check the domain name of the Node with the
                            // domain Name specified in the .register file
                            // if matched then the corresponding interface
                            // IP address will be registered under this node

                            if (!strcmp(dnsTreeInfo->domainName,
                                domainName.c_str()))
                            {
                                DnsCreateAndAddRR(
                                    node,
                                    dnsData,
                                    outputNodeAddress,
                                    nodeInput,
                                    domainName.c_str(),
                                    interfaceAddressString.c_str());
                            }// end

                            if (dnsData->zoneData->isMasterOrSlave == TRUE)
                            {
                                data* tempData = NULL;
                                ZoneDataList :: iterator item;

                                Int32 size = dnsData->zoneData->data->size();
                                if (size != 0)
                                {
                                    item = dnsData->zoneData->data->begin();
                                    tempData = (data*)*item;
                                }
                                while ((size != 0) && tempData &&
                                       (item !=
                                            dnsData->zoneData->data->end()))
                                {
                                    // check the domain name of the slave
                                    // with the domain Name specified in the
                                    // .register file if matched then the
                                    // corresponding interface IP address
                                    //  will be registered under this node

                                    if (!strcmp(tempData->tempLabel,
                                                domainName.c_str()))
                                    {
                                        DnsCreateAndAddRR(
                                            node,
                                            dnsData,
                                            outputNodeAddress,
                                            nodeInput,
                                            domainName.c_str(),
                                            interfaceAddressString.
                                                    c_str());
                                    }// end
                                    size--;
                                    if (size != 0)
                                    {
                                        item++;
                                        tempData = (data*)*item;
                                    }
                                }
                            }
                         }
                         else
                         {
                             break; // continue with next subnets
                         }
                    }
                }
                continue; // No need to execute the rest of the code
            }
            else
            {
                if (DEBUG)
                {
                printf("Num host bits is zero\n");
                }
                IO_AppParseDestString(node,
                                      NULL,
                                      interfaceAddressString.c_str(),
                                      &nodeId,
                                      &outputNodeAddress);
            }
        }

        if (nodeId == 0)
        {
            ERROR_ReportErrorArgs("In Line No %d of .dnsregister"
                "file String mentioned is not a valid IP address\n",
                lineCount + 1);
        }

        // check the domain name of the Node with the
        // domain Name specified in the .register file
        // if matched then the corresponding interface IP address
        //  will be registered under this node

        if (!strcmp(dnsTreeInfo->domainName, domainName.c_str()))
        {
            DnsCreateAndAddRR(node,
                              dnsData,
                              outputNodeAddress,
                              nodeInput,
                              domainName.c_str(),
                              interfaceAddressString.c_str());
        }// end
    }

    if (DEBUG)
    {
        DnsRrRecordList :: iterator item;

        item = dnsData->server->rrList->begin();

        // check for matching destIP
        printf("\n********************************************************");
        printf("\n***************After Domain Name Registration***********");
        printf("\n******************************************************\n");
        printf("For Node: %d the following RR records\n", node->nodeId);
        while (item != dnsData->server->rrList->end())
        {
            struct DnsRrRecord* rrItem = (struct DnsRrRecord*)*item;
            if (rrItem->rrType == SOA)
            {
                printf("\tAssociated Domain Name: %s(SOA)\n",
                       rrItem->associatedDomainName);
            }
            else
            {
            printf("\tAssociated Domain Name: %s\n",
                   rrItem->associatedDomainName);
            }
            item++;
        }

        printf("\n");
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsReadCacheTimeOutInterval
// LAYER        :: Application Layer
// PURPOSE      :: Read the cache time out interval
// PARAMETERS   :: node - Pointer to node.
//                 buf - Buffer containing the Refresh time Value
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsReadCacheTimeOutInterval(Node* node, char* buf)
{
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;

    if (dnsData == NULL)
    {
        printf("This Node is neither a DNS Server nor a DNS Client \n");
        return;
    }

    dnsData->cacheRefreshTime = TIME_ConvertToClock(buf);

    // Now Send Cache Refresh Timers.
    Message* msg = MESSAGE_Alloc(node,
                    APP_LAYER,
                    APP_DNS_CLIENT,
                    MSG_APP_DnsCacheRefresh);

    MESSAGE_Send(node, msg, dnsData->cacheRefreshTime);
}


//--------------------------------------------------------------------------
// FUNCTION     :: ExtractDomainNameForThisDomainServer
// LAYER        :: Application Layer
// PURPOSE      :: Extract Domain Name For This Domain Name Server
// PARAMETERS   :: node - Pointer to node.
//                 url - the URL string
//                 levelDifference - level deiffrence between the query
//                                      URL and domain Name String
//                 domainName - the domain Name
//                 serverLevel - the level of server (i.e. 0 for Root)
// RETURN       :: NONE
//--------------------------------------------------------------------------
void ExtractDomainNameForThisDomainServer(Node* node,
                                     char* url,
                                     Int32 levelDifference,
                                     char* domainName,
                                     Int32 serverLevel)
{
    Int32 dotCount = 0;
    dotCount = 0;
    BOOL flag = FALSE;
    const char* dotOperator = ".";

    node = NULL; // To suppress compiler warning
    if (DEBUG)
    {
        printf("In ExtractDomainNameForThisDomainServer "
               "level diff %d\n", levelDifference);
    }
    if (serverLevel == 0)
    {
        strcpy(domainName, dotOperator);
    }
    else
    {
        while (*url != '\0')
        {
            if (!flag)
            {
                if (*url == '.')
                {
                    dotCount++;
                }

                url++;

                if (dotCount == levelDifference)
                {
                    flag = TRUE;
                }
            }
            else
            {
                *domainName = *url;
                domainName++;
                url++;
            }
        }
        *domainName = '\0';
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: ExtractLabelForThisDomainServer
// LAYER        :: Application Layer
// PURPOSE      :: Extract Label ForThis Domain Name Server
// PARAMETERS   :: node - Node* : Pointer to node.
//                 domainName - the domain Name
//                 levelDifference - level deiffrence between the query
//                                   URL and domain Name String
//                 label - The reqiured label for this server
// RETURN       :: NONE
//--------------------------------------------------------------------------
void ExtractLabelForThisDomainServer(Node* node,
                                char* domainName,
                                Int32 levelDifference,
                                char* label)
{
    Int32 dotCount = 0;

    dotCount = 0;
    node = NULL; // To suppress compiler warning
    if (levelDifference == 1)
    {
        while (*domainName != '.')
        {
            *label = *domainName;
            label++;
            domainName++;
        }
        *label = '\0';
    }
    else
    {
        while (*domainName != '\0')
        {
            if (*domainName == '.')
            {
                dotCount++;
            }
            domainName++;

            if (dotCount == levelDifference - 1 )
            {
                break;
            }
        }
        while (*domainName != '.')
        {
            *label = *domainName;
            label++;
            domainName++;
        }
        *label = '\0';
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsResolveNameFromLocalCache
// LAYER        :: Application Layer
// PURPOSE      :: Search the Cache for the query URL
// PARAMETERS   :: node - Pointer to node.
//                 serverUrl - std::string* : server URL
//  `              resolvedAddr  - Resolved Address for the query URL
//                 cacheFound - if Cache Found then TRUE otherwise FALSE
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsResolveNameFromLocalCache(Node* node,
                                std::string serverUrl,
                                Address* resolvedAddr,
                                BOOL* cacheFound)
{
    CacheRecordList :: iterator item;
    struct CacheRecord* cacheItem = NULL;
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
    char remoteAddrStr[MAX_STRING_LENGTH];
    // Validate and then Search this List
    if ((!dnsData->cache) || (dnsData->cache->size() == 0))
    {
        *cacheFound = FALSE;
        if (DEBUG)
        {
            printf("In AppDnsResolveNameFromLocalCache no "
                   "cache found\n");
        }
        return ;
    }

    if (DEBUG)
    {
        printf("Node %u local cache has size %d \n",
            node->nodeId, (Int32) dnsData->cache->size());
    }

    // Otherwise seach associated list
    item = dnsData->cache->begin();

    while (item != dnsData->cache->end())
    {
        cacheItem = (struct CacheRecord*)*item;

        if (cacheItem->urlNameString->compare(serverUrl)== 0
            && (cacheItem->deleted == FALSE))
        {
            IO_ConvertIpAddressToString(&cacheItem->associatedIpAddr,
                                        remoteAddrStr);
            if (DEBUG)
            {
                printf("Node %u local cache found addr %s \n",
                    node->nodeId,
                    remoteAddrStr);
            }

            // Check the entry if it is already expired or older
            // then cache refresh time.
            if ((cacheItem->cacheEntryTime == (clocktype)0) || (clocktype )
                 (node->getNodeTime() - cacheItem->cacheEntryTime) <
                  dnsData->cacheRefreshTime )
            {
                *cacheFound = TRUE;
                memcpy(resolvedAddr, &(cacheItem->associatedIpAddr),
                       sizeof(Address));
                dnsData->stat.numOfDnsNameResolvedFromCache++;
                if (DEBUG)
                {
                    printf("node %d %s found in cache\n", node->nodeId,
                        cacheItem->urlNameString->c_str());
                }
                return;
            }
            else
            {
                if (DEBUG)
                {
                    printf("AppDnsResolveNameFromLocalCache Marking deleted"
                        " for cache item %s in node %d\n", serverUrl.c_str(),
                         node->nodeId);
                }
                cacheItem->deleted = TRUE;
                return;
            }
        }
        item++;
    }
}

//--------------------------------------------------------------------------
// FUNCTION     :: DnsZoneClientSendPacket
// LAYER        :: Application Layer
// PURPOSE      :: Send the next item.
// PARAMETERS   :: node - Pointer to node.
//                 clientPtr - pointer to the
//                              Zone Transfer client data structure.
//                 end  - End of session
// RETURN       : None
//--------------------------------------------------------------------------
void DnsZoneClientSendPacket(Node* node,
                        struct DnsServerZoneTransferClient* clientPtr,
                        BOOL end)
{
    end = 0; // to suppress compiler warning
    // Update the time when the first packet is sent
    if (clientPtr->lastItemSent ==0)
    {
        clientPtr->sessionStart = node->getNodeTime();
        clientPtr->sessionFinish = node->getNodeTime();
    }

    DnsRrRecordList :: iterator rrList;
    struct DnsData* dnsData = NULL;
    DnsRrRecordList :: iterator rrRecord;
    Int32 rrCount = 0;
    dnsData = (struct DnsData*)node->appData.dnsData;
    rrList = dnsData->server->rrList->begin();

    rrRecord = dnsData->server->rrList->begin();

    char* packetToSend = NULL;
    char* tempPtr = NULL;
    UInt32 zoneFreshCount = dnsData->zoneData->zoneFreshCount;
    struct DnsZoneTransferPacket* dnsZoneReplyPacket;
    dnsZoneReplyPacket = (struct DnsZoneTransferPacket*)clientPtr->dataSentPtr;

    packetToSend = (char*)MEM_malloc(dnsData->server->rrList->size()
                            *sizeof(struct DnsRrRecord)
                            + sizeof(struct DnsZoneTransferPacket)
                            + sizeof(zoneFreshCount));

    tempPtr = (char*)packetToSend;

    memcpy(tempPtr,
        &zoneFreshCount,
        sizeof(zoneFreshCount));
    tempPtr += sizeof(zoneFreshCount);

    dnsZoneReplyPacket->dnsHeader.dns_id = 0;
    // 1 for response
    DnsHeaderSetQr(&dnsZoneReplyPacket->dnsHeader.dns_hdr, 1);

    // 5 for update message
    DnsHeaderSetOpcode(&dnsZoneReplyPacket->dnsHeader.dns_hdr, 5);

    DnsHeaderSetUpdReserved(&dnsZoneReplyPacket->dnsHeader.dns_hdr, 0);

    // No error condition
    DnsHeaderSetRcode(&dnsZoneReplyPacket->dnsHeader.dns_hdr, 0);

    dnsZoneReplyPacket->dnsHeader.zoCount = 0;
    dnsZoneReplyPacket->dnsHeader.prCount = 0; // prerequisite section RRs
    dnsZoneReplyPacket->dnsHeader.upCount =
        (UInt16)dnsData->server->rrList->size();
    dnsZoneReplyPacket->dnsHeader.adCount = 0;

    memcpy(tempPtr,
        (struct DnsZoneTransferPacket*)dnsZoneReplyPacket,
        sizeof(struct DnsZoneTransferPacket));

    tempPtr += sizeof(struct DnsZoneTransferPacket);

    for (; rrRecord != dnsData->server->rrList->end(); rrRecord++)
    {
            memcpy(tempPtr, *rrRecord,
                    sizeof(struct DnsRrRecord));
            tempPtr += sizeof(struct DnsRrRecord);
    }

    if (dnsZoneReplyPacket !=NULL)
    {
        MEM_free(dnsZoneReplyPacket);
        dnsZoneReplyPacket = NULL;
    }
    clientPtr->dataSentPtr = NULL;
    //APP_TcpSendData(
    //    node,
    //    clientPtr->connectionId,
    //    (char*)packetToSend,
    //    (dnsData->server->rrList->size() * sizeof(DnsRrRecord)
    //        + sizeof(struct DnsZoneTransferPacket)
    //        + sizeof(zoneFreshCount)),
    //    TRACE_DNS);
    Message *msg = APP_TcpCreateMessage(
                        node,
                        clientPtr->connectionId,
                        TRACE_DNS);

    APP_AddPayload(
        node,
        msg,
        packetToSend,
        (dnsData->server->rrList->size() * sizeof(struct DnsRrRecord)
            + sizeof(struct DnsZoneTransferPacket)
            + sizeof(zoneFreshCount)));

    APP_TcpSend(node, msg);
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsZoneClientSendNextItem
// LAYER        :: Application Layer
// PURPOSE      :: Send the next item.
// PARAMETERS   :: node - Pointer to node.
//                 clientPtr - pointer to the
//                              Zone Transfer client data structure.
// RETURN       : None
//--------------------------------------------------------------------------
void DnsZoneClientSendNextItem(Node* node,
                          struct DnsServerZoneTransferClient* clientPtr)
{
    if (DEBUG)
    {
        printf("DNS Client: Node %u has %u items left to send\n",
            node->nodeId, clientPtr->itemsToSend);
    }

    if (((clientPtr->itemsToSend > 1) &&
        (node->getNodeTime() < clientPtr->endTime)) ||
        ((clientPtr->itemsToSend == 0) &&
        (node->getNodeTime() < clientPtr->endTime)) ||
        ((clientPtr->itemsToSend > 1) && (clientPtr->endTime == 0)) ||
       ((clientPtr->itemsToSend == 0) && (clientPtr->endTime == 0)))
    {
        if (DEBUG)
        {
            printf("DNS Client: Sending data \n");
        }
        DnsZoneClientSendPacket(node, clientPtr, FALSE);

        if (clientPtr->itemsToSend > 0)
        {
            clientPtr->itemsToSend--;
        }
    }
    else
    {
        if (((clientPtr->itemsToSend == 1) &&
            (node->getNodeTime() < clientPtr->endTime)) ||
            ((clientPtr->itemsToSend == 1) && (clientPtr->endTime == 0)))
        {
            DnsZoneClientSendPacket(node, clientPtr, TRUE);
        }

        clientPtr->sessionIsClosed = TRUE;
        clientPtr->sessionFinish = node->getNodeTime();

        if (DEBUG)
        {
            printf("Zone Transfer Client: Node %d closing connection %d\n",
                node->nodeId, clientPtr->connectionId);
        }

        APP_TcpCloseConnection(
            node,
            clientPtr->connectionId);
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsZoneClientNewDnsZoneClient
// LAYER        :: Application Layer
// PURPOSE      :: New Zone Transfer Client creation
// PARAMETERS   :: node - Pointer to node.
//                 clientAddr - Zone Transfer Client Address
//                 serverAddr - Zone Transfer Server Address
//                 itemsToSend - Item to send
//                 itemSize - Size of Item
//                 endTime - End time
//                 tos - Tos Type
// RETURN       :: struct DnsServerZoneTransferClient*  :  the pointer to the
//                 created Zone transfer client data structure, NULL if no
//                 data structure allocated.
//--------------------------------------------------------------------------
struct DnsServerZoneTransferClient* // inline //
AppDnsZoneClientNewDnsZoneClient(Node* node,
                                 Address clientAddr,
                                 Address serverAddr,
                                 Int32 itemsToSend,
                                 Int32 itemSize,
                                 clocktype endTime,
                                 TosType tos)
{
    struct DnsServerZoneTransferClient* zoneTransferClient =
        (struct DnsServerZoneTransferClient*)
        MEM_malloc(sizeof(struct DnsServerZoneTransferClient));

    memset(zoneTransferClient, 0, sizeof(struct DnsServerZoneTransferClient));

    // fill in connection id, etc.

    zoneTransferClient->connectionId = -1;
    zoneTransferClient->localAddr = clientAddr;
    zoneTransferClient->remoteAddr = serverAddr;

    zoneTransferClient->itemsToSend = itemsToSend;
    zoneTransferClient->itemSize = itemSize;
    zoneTransferClient->endTime = endTime;
    zoneTransferClient->uniqueId = node->appData.uniqueId++;

    zoneTransferClient->numBytesSent = 0;
    zoneTransferClient->lastItemSent = 0;
    zoneTransferClient->tos = tos;

    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;

    dnsData->zoneTransferClientData->push_back(zoneTransferClient);

    return zoneTransferClient;
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsZoneServerNewDnsZoneServer
// LAYER        :: Application Layer
// PURPOSE      :: New Zone Transfer Server creation
// PARAMETERS   :: node - Pointer to node.
//                 openResult - Result of the open request.
// RETURN       :: struct DnsServerZoneTransferServer*  :  the pointer to the
//                 created Zone Transfer Serverdata structure, NULL if no
//                 data structure allocated.
//--------------------------------------------------------------------------
struct DnsServerZoneTransferServer* AppDnsZoneServerNewDnsZoneServer(
            Node* node,
            TransportToAppOpenResult* openResult)
{
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
    if (!dnsData->zoneTransferServerData)
    {
        dnsData->zoneTransferServerData = new ServerZoneTransferDataList;
    }
    struct DnsServerZoneTransferServer* zoneTransferServer =
        (struct DnsServerZoneTransferServer*)
                MEM_malloc(sizeof(struct DnsServerZoneTransferServer));

    // fill in connection id, etc.
    zoneTransferServer->connectionId = openResult->connectionId;
    zoneTransferServer->localAddr = openResult->localAddr;
    zoneTransferServer->remoteAddr = openResult->remoteAddr;
    zoneTransferServer->sessionStart = 0;
    zoneTransferServer->sessionFinish = 0;
    zoneTransferServer->sessionIsClosed = FALSE;
    zoneTransferServer->numBytesRecvd = 0;
    zoneTransferServer->lastItemRecvd = 0;

    dnsData->zoneTransferServerData->push_back(zoneTransferServer);

    return zoneTransferServer;
}

//--------------------------------------------------------------------------
// FUNCTION     :: DnsZoneClientGetDnsZoneClientWithUniqueId
// LAYER        :: Application Layer
// PURPOSE      :: search for a Zone Transfer client data structure.
// PARAMETERS   :: node - Pointer to node.
//                 uniqueId -  uniqueId of the Zone Transfer client.
// RETURN       :: struct DnsServerZoneTransferClient*:   the pointer to the
//                 Zone Transfer client data structure,
//                 NULL if nothing found
//--------------------------------------------------------------------------
struct DnsServerZoneTransferClient* DnsZoneClientGetDnsZoneClientWithUniqueId(
            Node* node,
            Int32 uniqueId)
{
    struct DnsData* dnsData = NULL;
    dnsData = (struct DnsData*)node->appData.dnsData;
    ClientZoneTransferDataList :: iterator zoneClientData;
    BOOL clientFound = FALSE;

    zoneClientData = dnsData->zoneTransferClientData->begin();

    struct DnsServerZoneTransferClient* zoneTransferClient = NULL;
    struct DnsServerZoneTransferClient* tempZoneTransferClient = NULL;

    while (zoneClientData != dnsData->zoneTransferClientData->end())
    {
        zoneTransferClient = (struct DnsServerZoneTransferClient*)*zoneClientData;

        if (zoneTransferClient->uniqueId == uniqueId)
        {
            clientFound = TRUE;
            tempZoneTransferClient = zoneTransferClient;
            break;

        }
        zoneClientData++;
    }

    if (clientFound == TRUE)
    {
        return zoneTransferClient;
    }
    else
    {
        return NULL;
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsZoneClientGetDnsZoneClient
// LAYER        :: Application Layer
// PURPOSE      :: search for a Zone Transfer Server data structure.
// PARAMETERS   :: node - Pointer to node.
//                 connId - connection ID of the Zone Transfer client.
// RETURN       :: struct DnsServerZoneTransferClient* :   the pointer to the
//                 Zone Transfer client data structure,
//                 NULL if nothing found
//--------------------------------------------------------------------------
struct DnsServerZoneTransferClient* DnsZoneClientGetDnsZoneClient(
            Node* node,
            Int32 connId)
{

    struct DnsData* dnsData = NULL;
    dnsData = (struct DnsData*)node->appData.dnsData;
    ClientZoneTransferDataList :: iterator zoneClientData;
    BOOL clientFound = FALSE;

    zoneClientData = dnsData->zoneTransferClientData->begin();

    struct DnsServerZoneTransferClient* zoneTransferClient = NULL;
    struct DnsServerZoneTransferClient* tempZoneTransferClient = NULL;

    while (zoneClientData != dnsData->zoneTransferClientData->end())
    {
        zoneTransferClient =
            (struct DnsServerZoneTransferClient*)*zoneClientData;

        if (zoneTransferClient->connectionId == connId)
        {
            clientFound = TRUE;
            tempZoneTransferClient = zoneTransferClient;
            break;
        }

        zoneClientData++;
    }

    if (clientFound == TRUE)
    {
        return zoneTransferClient;
    }
    else
    {
        return NULL;
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsZoneClientUpdateDnsZoneClient
// LAYER        :: Application Layer
// PURPOSE      :: update existing Zone Transferclient data structure
//                 by including connection id.
// PARAMETERS   :: node - Pointer to node.
//                 openResult - Result of the open request.
// RETURN       :: struct DnsServerZoneTransferClient*: the pointer to the
//                 created Zone Transfer client data structure, NULL if
//                 no data structure allocated.
//--------------------------------------------------------------------------
struct DnsServerZoneTransferClient* DnsZoneClientUpdateDnsZoneClient(
            Node* node,
            TransportToAppOpenResult* openResult)
{
    struct DnsData* dnsData = NULL;
    dnsData = (struct DnsData*)node->appData.dnsData;
    ClientZoneTransferDataList :: iterator zoneClientData;

    zoneClientData = dnsData->zoneTransferClientData->begin();

    struct DnsServerZoneTransferClient* zoneTransferClient = NULL;

    while (zoneClientData != dnsData->zoneTransferClientData->end())
    {
        zoneTransferClient =
            (struct DnsServerZoneTransferClient*)*zoneClientData;

        if (zoneTransferClient->uniqueId == openResult->uniqueId)
        {
            break;
        }

        zoneClientData++;
    }

    // fill in connection id, etc.

    zoneTransferClient->connectionId = openResult->connectionId;
    zoneTransferClient->localAddr = openResult->localAddr;
    zoneTransferClient->remoteAddr = openResult->remoteAddr;
    zoneTransferClient->sessionStart = 0;
    zoneTransferClient->sessionFinish = 0;
    zoneTransferClient->sessionIsClosed = FALSE;

    return zoneTransferClient;
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsZoneTransferServerGetDnsZoneServer
// LAYER        :: Application Layer
// PURPOSE      :: Send the next item.
// PARAMETERS   :: node - Pointer to node.
//                 connId - Connection Id
//                          Zone Transfer client data structure.
// RETURN       :: struct DnsServerZoneTransferServer* - Pointer to Zone
//                          Transfer Server Structure
//--------------------------------------------------------------------------

struct DnsServerZoneTransferServer* DnsZoneTransferServerGetDnsZoneServer(
            Node* node,
            Int32 connId)
{
    struct DnsData* dnsData = NULL;
    dnsData = (struct DnsData*)node->appData.dnsData;
    struct DnsServerZoneTransferServer* zoneTransferServer = NULL;

    ServerZoneTransferDataList :: iterator lstItem;
    lstItem = dnsData->zoneTransferServerData->begin();
    while (lstItem != dnsData->zoneTransferServerData->end())
    {
        zoneTransferServer = (struct DnsServerZoneTransferServer*)*lstItem;
        if (zoneTransferServer->connectionId == connId)
        {
            return zoneTransferServer;
        }
        lstItem++;
    }
    return NULL;
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsServerQueryProcessing
// LAYER        :: Application Layer
// PURPOSE      :: Dns Server Query Packet Processing
// PARAMETERS   :: node - Pointer to node.
//                 dnsQueryPacket - Dns Query Packet Pointer
//                 answerRrs - Answer Rr records Pointer
//                 nameServerRrs - Name Server Rr records Pointer
//                 additionalRrs - Additional Rr records Pointer
//                 anCount - Answer Rr records count
//                 nsCount - Name Server Rr records count
//                 arCount - Additional Rr records count
//                 isAuthoritiveAnswer - Authorirative abswer Found
// RETURN       :: BOOL - TRUE if answer found otherwise No
//--------------------------------------------------------------------------
BOOL AppDnsServerQueryProcessing(
                            Node* node,
                            struct DnsQueryPacket* dnsQueryPacket,
                            struct DnsRrRecord* answerRrs,
                            struct DnsRrRecord* nameServerRrs,
                            struct DnsRrRecord* additionalRrs,
                            UInt16* anCount,
                            UInt16* nsCount,
                            UInt16* arCount,
                            BOOL* isAuthoritiveAnswer,
                            BOOL  isprimary)
{
    char serverDomain[DNS_NAME_LENGTH] = "";
    /*char queryUrl[DNS_NAME_LENGTH] = "";*/
    std::string queryUrl;
    char queryDomain[DNS_NAME_LENGTH] = "";
    //char tmpQueryDomain[DNS_NAME_LENGTH];
    char queryLabel[DNS_NAME_LENGTH] = "";
    Int32 counter = 0;
    struct DnsRrRecord* tempAnRecord = NULL;
    struct DnsRrRecord* tempNsRecord = NULL;
    struct DnsRrRecord* tempArRecord = NULL;
    DnsRrRecordList :: iterator rrList;
    BOOL domainMatched = FALSE;
    BOOL resolvingSecondary = FALSE;
    Int32 levelDifference = 0;
    DnsRrRecordList :: iterator rrRecord;
    NetworkType networkType = NETWORK_INVALID;

    struct DnsData* dnsData = NULL;

    BOOL answerFound = FALSE;

    *arCount = *arCount;
    dnsData = (struct DnsData*)node->appData.dnsData;
    if (dnsQueryPacket->dnsQuestion.dnsQType == A)
    {
        networkType = NETWORK_IPV4;
    }
    else if (dnsQueryPacket->dnsQuestion.dnsQType == AAAA)
    {
        networkType = NETWORK_IPV6;
    }
    if (!dnsData)
    {
        ERROR_ReportErrorArgs("Node %d is not a DNS Server", node->nodeId);
    }
    memset(queryDomain, 0, DNS_NAME_LENGTH);
    memset(queryLabel, 0, DNS_NAME_LENGTH);
    // Domain Name of the server
    strcpy(serverDomain, dnsData->server->dnsTreeInfo->domainName);

    // The Query Url
    queryUrl.assign(dnsQueryPacket->dnsQuestion.dnsQname);

    rrList = dnsData->server->rrList->begin();

    tempAnRecord = answerRrs;
    tempNsRecord = nameServerRrs;
    tempArRecord = additionalRrs;

    if (queryUrl.find(serverDomain) != string::npos)
    {
        domainMatched = TRUE;
        levelDifference = DotCount(queryUrl.c_str()) -
                              DotCount(serverDomain);
    }

    if (dnsData->inSrole &&
        dnsData->isSecondaryActivated &&
        queryUrl.find(dnsData->secondryDomain) != string::npos)
    {
        if (domainMatched)
        {
            Int32 levelDiff = DotCount(queryUrl.c_str()) -
                DotCount(dnsData->secondryDomain);
           if (levelDiff < levelDifference)
           {
                resolvingSecondary = TRUE;
                levelDifference = levelDiff;
           }
        }
        else
        {
            domainMatched = TRUE;
            resolvingSecondary = TRUE;
            levelDifference = DotCount(queryUrl.c_str()) -
                             DotCount(dnsData->secondryDomain);
        }
    }
    if (!strcmp(serverDomain, "."))
    {
        levelDifference++;
    }
    answerFound = FALSE;
    if (domainMatched)
    {
        if (dnsQueryPacket->dnsQuestion.dnsQType == NS)
        {
            rrRecord = dnsData->server->rrList->begin();
            for (counter = 1;
                counter <= dnsData->server->rrList->size();
                counter++)
            {
                struct DnsRrRecord* rrItem = (struct DnsRrRecord*)*rrRecord;
                if (rrItem->rrType == NS &&
                    strcmp(rrItem->associatedDomainName, "."))
                {
                    (*anCount)++;
                    memcpy(tempAnRecord, rrItem, sizeof(struct DnsRrRecord));
                    tempAnRecord++;
                }
                rrRecord++;
            }
            answerFound = TRUE;
            *isAuthoritiveAnswer = TRUE;
        }
        if (dnsQueryPacket->dnsQuestion.dnsQType == SOA &&
            !answerFound)
        {
            BOOL isSecondaryToDomain = FALSE;
            data* tempData = NULL;
            NameServerList :: iterator item =
                dnsData->nameServerList->begin();
            while (item != dnsData->nameServerList->end())
            {
                tempData = (data*)*item;
                if (!queryUrl.compare(tempData->tempLabel))
                {
                    isSecondaryToDomain = TRUE;
                    break;
                }
                item++;
            }
            if (isSecondaryToDomain || (levelDifference == 0) &&
                dnsData->zoneData->isMasterOrSlave)
            {
                DnsRrRecordList :: iterator rrRecordList;
                rrRecordList = dnsData->server->rrList->begin();
                (*anCount)++;
                while (rrRecordList != dnsData->server->rrList->end())
                {
                    struct DnsRrRecord* rrItemTmp =
                        (struct DnsRrRecord*)*rrRecordList;
                    if (rrItemTmp->rrType == SOA)
                    {
                        memcpy(tempAnRecord,
                               rrItemTmp,
                               sizeof(struct DnsRrRecord));
                        tempAnRecord++;
                        answerFound = TRUE;
                        *isAuthoritiveAnswer = TRUE;
                        break;
                    }
                    rrRecordList++;
                }
            }
        }

        if (levelDifference == 1 &&
            !answerFound &&
            (dnsQueryPacket->dnsQuestion.dnsQType != SOA))
        {
            if (!dnsData->server->rrList->size())
            {
                ERROR_ReportErrorArgs("DNS Server %d don't have any "
                    "valid RR records",
                    node->nodeId);
            }

            rrRecord = dnsData->server->rrList->begin();
            while ((rrRecord != dnsData->server->rrList->end()) &&
                    !answerFound)
            {
                struct DnsRrRecord* rrItem = (struct DnsRrRecord*)*rrRecord;

                // if the querylabel and the rrRecord label matched
                if (!strcmp(rrItem->associatedDomainName, queryUrl.c_str()))
                {
                    switch(rrItem->rrType)
                    {
                        case A:
                        {
                            if (dnsQueryPacket->dnsQuestion.dnsQType == AAAA)
                            {
                                rrRecord++;
                                continue;
                            }
                            (*anCount)++;
                            memcpy(tempAnRecord,
                                   rrItem,
                                   sizeof(struct DnsRrRecord));
                            tempAnRecord++;
                            break;
                        }
                        case AAAA:
                        {
                            if (dnsQueryPacket->dnsQuestion.dnsQType == A)
                            {
                                rrRecord++;
                                continue;
                            }
                            (*anCount)++;
                            memcpy(tempAnRecord,
                                   rrItem,
                                   sizeof(struct DnsRrRecord));
                            tempAnRecord++;
                            break;
                        }
                        default:
                        {
                            ERROR_ReportErrorArgs(" Invalid Rr Type");
                        }
                    }

                    answerFound = TRUE;
                    *isAuthoritiveAnswer = TRUE;
                    break;
                }
                rrRecord++;
            }
        }
        else if (!answerFound && levelDifference)
        {
            char tmpQueryUrl[DNS_NAME_LENGTH] = "";
            const char* ptr = queryUrl.c_str();
            for (Int32 i = 0; i < levelDifference-1; i++)
            {
                while (!(*ptr == '.'))
                {
                    ptr++;
                }
                ptr++;
            }
            strcpy(tmpQueryUrl, ptr);
            rrRecord = dnsData->server->rrList->begin();
            while (rrRecord != dnsData->server->rrList->end())
            {
                struct DnsRrRecord* rrItem = (struct DnsRrRecord*)*rrRecord;

                // if the querylabel and the rrRecord label matched
                if (!strcmp(rrItem->associatedDomainName, tmpQueryUrl) &&
                    (rrItem->rrType == NS) &&
                    (rrItem->associatedIpAddr.networkType == networkType))
                {
                    (*nsCount)++;
                    memcpy(tempNsRecord,
                           rrItem,
                           sizeof(struct DnsRrRecord));
                    tempNsRecord++;

                    answerFound = TRUE;
                    *isAuthoritiveAnswer = TRUE;
                    if (*nsCount >= MAX_NS_RR_RECORD_NO)
                    {
                        char errStr[MAX_STRING_LENGTH];
                        sprintf(errStr, "DNS Server %d can return upto 20"
                            " NS RR records at a time so dropping others",
                            node->nodeId);
                        ERROR_ReportWarning(errStr);
                            break;
                    }
                }
                rrRecord++;
            }
        }
    }

    // if this is primaryDNS SErver and answer still not found,
    //  this Server will send the root address to the DNS Client

    if ((isprimary || ((dnsQueryPacket->dnsQuestion.dnsQType == SOA) &&
        levelDifference == 0) || (!domainMatched))
        &&(!answerFound))
    {
        rrRecord = dnsData->server->rrList->begin();

        for (counter = 1;
             counter <= dnsData->server->rrList->size();
             counter++)
        {
            struct DnsRrRecord* rrItem = (struct DnsRrRecord*)*rrRecord;
            // search the RR record that contains the root
            // label i.e. "."

            if (!strcmp(rrItem->associatedDomainName, DOT_SEPARATOR))
            {
                if (((dnsQueryPacket->dnsQuestion.dnsQType == AAAA) &&
                    rrItem->associatedIpAddr.networkType != NETWORK_IPV6) ||
                    ((dnsQueryPacket->dnsQuestion.dnsQType == A) &&
                    rrItem->associatedIpAddr.networkType != NETWORK_IPV4))
                {
                    rrRecord++;
                    continue;
                }
                (*nsCount)++;
                memcpy(tempNsRecord, rrItem, sizeof(struct DnsRrRecord));
                tempNsRecord++;

                answerFound = TRUE;
                *isAuthoritiveAnswer = TRUE;
                break;
            }
            rrRecord++;
        }
    }

    // if the answer is not found yet. search the cache
    // if the query URL is there

    if (!answerFound)
    {
        Address resolvedAddress;

        BOOL cacheFound = FALSE;
        memset(&resolvedAddress, 0, sizeof(Address));
        AppDnsResolveNameFromLocalCache(node,
            queryUrl,
            &resolvedAddress,
            &cacheFound);

        if (cacheFound == TRUE)
        {
            struct DnsRrRecord* rrRecord = (struct DnsRrRecord*)
                MEM_malloc(sizeof(struct DnsRrRecord));

            DnsCreateNewRrRecord (rrRecord,
                queryUrl.c_str(),
                A,
                IN,
                dnsData->cacheRefreshTime,
                sizeof(resolvedAddress),
                &resolvedAddress);

            (*anCount)++;
            memcpy(tempAnRecord, rrRecord, sizeof(struct DnsRrRecord));
            tempAnRecord++;

            answerFound = TRUE;
        }
    }
    return answerFound;
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsSelectDnsServerForQuery
// LAYER        :: Application Layer
// PURPOSE      :: Dns Finalization
// PARAMETERS   :: node - Node Ptr
//                 destString - destinationString
// RETURN       :: None
//--------------------------------------------------------------------------
void DnsSelectDnsServerForQuery(
                           Node* node,
                           char* destString,
                           Address* sourceAddr)
{
    BOOL clientInformationFoundForThisInterface = FALSE;
    Int32 interfaceIndex = 0;
    struct DnsData* dnsData = NULL;
    DnsClientDataList :: iterator item;
    struct ClientResolveState* clientResolveState = NULL;

    if (sourceAddr->networkType == NETWORK_IPV4)
    {
        Int32 interface_index = 0;
        interface_index = GetDefaultInterfaceIndex(node, NETWORK_IPV4);
        NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
        if (!ip->interfaceInfo[interface_index]->isDhcpEnabled)
        {
            interfaceIndex = NetworkIpGetInterfaceIndexFromAddress(
                                node,
                                sourceAddr->interfaceAddr.ipv4);
        }
        else
        {
            interfaceIndex = interface_index;
        }
    }
    else
    {
        Int32 interface_index = 0;
        interface_index = GetDefaultInterfaceIndex(node, NETWORK_IPV6);
        NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
        if (!ip->interfaceInfo[interface_index]->isDhcpEnabled)
        {
            interfaceIndex = Ipv6GetInterfaceIndexFromAddress(
                             node,
                                &sourceAddr->interfaceAddr.ipv6);
        }
        else
        {
            interfaceIndex = interface_index;
        }
    }

    dnsData = (struct DnsData*)node->appData.dnsData;

    if (!dnsData)
    {
        ERROR_ReportErrorArgs("DNS is not enabled: %d", node->nodeId);
    }
    clientInformationFoundForThisInterface = FALSE;

    // If DNS is not already allocated
    if (dnsData->clientData == NULL)
    {
        ERROR_ReportErrorArgs("No DNS Client Information" \
            "is configured for Node Id: %d",
            node->nodeId);
    }

    item = dnsData->clientData->begin();

    while (item != dnsData->clientData->end())
    {
        struct DnsClientData* dnsClientData = (struct DnsClientData*)*item;

        if (dnsClientData->interfaceNo == interfaceIndex ||
            dnsClientData->interfaceNo == ALL_INTERFACE)
        {
            struct ClientResolveState* clientresolve = NULL;
            ClientResolveStateList :: iterator tempItem =
                                dnsData->clientResolveState->begin();
            while (tempItem != dnsData->clientResolveState->end())
            {
                if (!(*tempItem)->queryUrl->compare(destString))
                {
                    clientresolve = (struct ClientResolveState*)*tempItem;
                }
            }
            if (clientresolve != NULL)
            {
                return;
            }
            clientResolveState =
                (struct ClientResolveState*)
                MEM_malloc(sizeof(struct ClientResolveState));

            memset(clientResolveState,0,
               sizeof(clientResolveState));

            clientResolveState->queryUrl = new std::string();
            clientResolveState->queryUrl->assign(destString);

            clientResolveState->primaryDNS = dnsClientData->primaryDNS;
            clientResolveState->secondaryDNS = dnsClientData->secondaryDNS;
            clientInformationFoundForThisInterface = TRUE;
            break;
        }
        item++;
    }

    if (clientInformationFoundForThisInterface == TRUE)
    {
        dnsData->clientResolveState->push_back(clientResolveState);
    }
    else
    {
        ERROR_ReportErrorArgs("No DNS Client Information"
            "is configured for Interface No:%d of Node Id: %d",
            interfaceIndex,
            node->nodeId);
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsInformApplication
// LAYER        :: Application Layer
// PURPOSE      :: DNS Inform Requesting Application
// PARAMETERS   :: node - Pointer to node.
//                 resolvedUrl - Resolved URL
//                 destAddr - Destination Address
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsInformApplication(
                        Node* node,
                        const char* resolvedUrl,
                        Address* destAddr)
{
    DnsAppReqItemList :: iterator item;
    struct DnsAppReqListItem* appItem = NULL;
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
    DnsAppReqItemList :: iterator deleteItem;
    UInt16 appSourcePort;
    AppType tmpAppType;
    struct DnsQueryPacket* dnsQueryPacket = NULL;
    dnsQueryPacket =
        (struct DnsQueryPacket*)MEM_malloc(sizeof(struct DnsQueryPacket));
    memset(dnsQueryPacket, 0, sizeof(struct DnsQueryPacket));

    MEM_free(dnsQueryPacket);
    dnsQueryPacket = NULL;
    // check the AppReqList for matching serverUrl
    item = dnsData->appReqList->begin();

    // check for matching URL
    while (item != dnsData->appReqList->end())
    {
        appItem = *item;

        if (DEBUG)
        {
            printf("In AppDnsInformApplication stored serverurl"
                " %s, resolvedUrl %s\n",
                appItem->serverUrl->c_str(), resolvedUrl);
        }
        if ((appItem->serverUrl->compare(resolvedUrl) == 0) &&
            ((destAddr->networkType == appItem->queryNetworktype) ||
            (appItem->queryNetworktype == NETWORK_INVALID)))
        {
            // Inform that application
            struct AppDnsInfoTimer* timer = NULL;
            Message* timerMsg = MESSAGE_Alloc(node,
                                    APP_LAYER,
                                    APP_TRAFFIC_SENDER,
                                    MSG_APP_DnsInformResolvedAddr);

            MESSAGE_InfoAlloc(node, timerMsg, sizeof(struct AppDnsInfoTimer));

            timer = (struct AppDnsInfoTimer*)MESSAGE_ReturnInfo(timerMsg);

            timer->sourcePort = appItem->sourcePort;
            timer->uniqueId = appItem->uniqueId;
            timer->tcpMode = appItem->tcpMode;
            timer->interfaceId = appItem->interfaceId;
            memcpy(&timer->addr, destAddr, sizeof(Address));

            // VOIP-DNS Changes
            timer->serverUrl = new std::string();
            timer->serverUrl->assign(resolvedUrl);
            // VOIP-DNS Changes Over

            // In case DNS address is resolved instantly i.e,
            // from cache no need to update it
            if (node->getNodeTime()- (appItem->resolveStartTime))
            {
                dnsData->stat.avgDelayForSuccessfullAddressResolution =
                    node->getNodeTime() - (appItem->resolveStartTime);
            }
            if (DEBUG)
            {
                char buf[MAX_STRING_LENGTH] = "";
                TIME_PrintClockInSecond(node->getNodeTime(), buf);
                printf("DNS client Informing the App at %sS\n", buf);
            }

            MESSAGE_Send(node, timerMsg, 0);
            // Delete that item from the list
            appSourcePort = appItem->sourcePort;
            tmpAppType = appItem->appType;
            deleteItem = item;
            item++;
            if (appItem->interfaceList)
            {
                if (appItem->interfaceList->size())
                {
                    // delete the interface list
                    AppReqInterfaceList::iterator appReqIntListIt =
                                appItem->interfaceList->begin();
                    while (appReqIntListIt != appItem->interfaceList->end())
                    {
                        Int16* listItem1 = (Int16*)*appReqIntListIt;
                        appReqIntListIt++;
                        MEM_free(listItem1);
                        listItem1 = NULL;
                    }
                    delete(appItem->interfaceList);
                    appItem->interfaceList = NULL;
                }
            }
            delete (appItem->serverUrl);
            MEM_free(appItem);
            appItem = NULL;
            dnsData->appReqList->remove(*deleteItem);
            // check for duplicate entries
            DnsAppReqItemList :: iterator tmpItem;
            struct DnsAppReqListItem* tmpAppItem = NULL;
            tmpItem = dnsData->appReqList->begin();
            while (tmpItem != dnsData->appReqList->end())
            {
                tmpAppItem = (struct DnsAppReqListItem*)*tmpItem;
                if ((tmpAppItem->serverUrl->compare(resolvedUrl) == 0) &&
                    (destAddr->networkType == tmpAppItem->queryNetworktype)
                    && (tmpAppItem->sourcePort == appSourcePort)
                    && (tmpAppType == tmpAppItem->appType))
                {
                    deleteItem = tmpItem;
                    tmpItem++;
                    if (tmpAppItem->interfaceList)
                    {
                        if (tmpAppItem->interfaceList->size())
                        {
                            AppReqInterfaceList ::
                                iterator appReqIntListIt =
                                        tmpAppItem->interfaceList->begin();
                            while (appReqIntListIt !=
                                        tmpAppItem->interfaceList->end())
                            {
                                Int16* listItem1 = (Int16*)*appReqIntListIt;
                                appReqIntListIt++;
                                MEM_free(listItem1);
                                listItem1 = NULL;
                            }
                        }
                        delete(tmpAppItem->interfaceList);
                        tmpAppItem->interfaceList = NULL;
                    }
                    // free item

                    dnsData->appReqList->remove(*deleteItem);
                    delete ((*deleteItem)->serverUrl);
                    MEM_free(*deleteItem);
                    *deleteItem = NULL;
                    item = dnsData->appReqList->begin();
                }
                else
                {
                    tmpItem++;
                }
            }
        }
        else{
            item++;
        }
    }   // end of List searching
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsStartResolvingDomainName
// LAYER        :: Application Layer
// PURPOSE      :: DNS Start resolving domain Name to IP address
// PARAMETERS   :: node - Pointer to node.
//                 queryDomainName - Queried domain NAme
//                 type - Application Type
//                 sourceAddress - Source Adrress
//                 sourcePort - Source Port
//                 uniqueId - Unique Id for TCP type application
//                 dnsClientData - dns client data
//                 appItemRec - application item record
//                 tcpMode - TRUE is TRCP based application
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsStartResolvingDomainName(
                               Node* node,
                               const char* queryDomainName,
                               AppType type,
                               Address sourceAddress,
                               UInt16 sourcePort,
                               Int32 uniqueId,
                               struct DnsClientData* dnsClientData,
                               struct DnsAppReqListItem* appItemRec,
                               BOOL tcpMode)
{
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
    NetworkType queryNetworktype = appItemRec->queryNetworktype;
    Address remoteAddress, remoteAddressSec;
    Address compatibleSrcAddr1, compatibleSrcAddr2;
    memset(&remoteAddress, 0, sizeof(Address));
    memset(&remoteAddressSec, 0, sizeof(Address));
    memset(&compatibleSrcAddr1, 0, sizeof(Address));
    memset(&compatibleSrcAddr2, 0, sizeof(Address));

    if (strlen(queryDomainName) >= DNS_NAME_LENGTH)
    {
        // This condition should never occur.
        ERROR_ReportErrorArgs(
            "Node %d: The total length of the domain name exceeds %d",
            node->nodeId,
            DNS_NAME_LENGTH - 1);
    }

    char qDomainName[DNS_NAME_LENGTH] = "";
    memcpy(qDomainName, queryDomainName, strlen(queryDomainName));
    if (DEBUG)
    {
        printf("In AppDnsStartResolvingDomainName resolve %s\n",
                                    qDomainName);
    }

    if (!dnsClientData)
    {
        if (DEBUG)
        {
            printf("returning as dns server is/are not valid\n");
        }
        return;
    }

    if ((dnsClientData->primaryDNS.networkType == NETWORK_INVALID)&&
      (dnsClientData->secondaryDNS.networkType == NETWORK_INVALID) &&
      (dnsClientData->ipv6PrimaryDNS.networkType == NETWORK_INVALID)&&
      (dnsClientData->ipv6SecondaryDNS.networkType == NETWORK_INVALID))
    {
        // No need to send Query
        dnsData->stat.numOfDnsNameUnresolved++;
        if (DEBUG)
        {
            printf("returning as dns server is/are not valid\n");
        }
        return;
    }

    struct DnsQueryPacket* dnsQueryPacket = NULL;
    NetworkProtocolType sourcetype =
        NetworkIpGetNetworkProtocolType(node,
                                        node->nodeId);
    dnsQueryPacket =
        (struct DnsQueryPacket*)MEM_malloc(sizeof(struct DnsQueryPacket));

    memset(dnsQueryPacket, 0, sizeof(struct DnsQueryPacket));

    memcpy(dnsQueryPacket->dnsQuestion.dnsQname,
        qDomainName, DNS_NAME_LENGTH);

    dnsQueryPacket->dnsQuestion.dnsQClass = IN ;
    if (queryNetworktype == NETWORK_INVALID)
    {
        if ((sourcetype == IPV4_ONLY) &&
            (dnsClientData->primaryDNS.networkType == NETWORK_IPV4))
        {
            compatibleSrcAddr1.networkType = NETWORK_IPV4;
            compatibleSrcAddr1.interfaceAddr.ipv4 =
                GetDefaultIPv4InterfaceAddress(node);

            remoteAddress.networkType = NETWORK_IPV4;
            remoteAddress.interfaceAddr.ipv4 =
                        dnsClientData->primaryDNS.interfaceAddr.ipv4;

            dnsQueryPacket->dnsQuestion.dnsQType = A;
            appItemRec->queryNetworktype = NETWORK_IPV4;
        }
        else if (((sourcetype == IPV6_ONLY) ||
            (sourcetype == DUAL_IP)) &&
            (dnsClientData->ipv6PrimaryDNS.networkType == NETWORK_IPV6))
        {
            compatibleSrcAddr1.networkType = NETWORK_IPV6;

            Ipv6GetGlobalAggrAddress(node,
                        GetDefaultInterfaceIndex(node, NETWORK_IPV6),
                        &compatibleSrcAddr1.interfaceAddr.ipv6);

            remoteAddress.networkType = NETWORK_IPV6;
            remoteAddress.interfaceAddr.ipv6 =
                        dnsClientData->ipv6PrimaryDNS.interfaceAddr.ipv6;

            dnsQueryPacket->dnsQuestion.dnsQType = AAAA;
            appItemRec->queryNetworktype = NETWORK_IPV6;
            appItemRec->AAAASend = TRUE;
        }
        else if ((sourcetype == DUAL_IP) &&
            (dnsClientData->primaryDNS.networkType == NETWORK_IPV4))
        {
            compatibleSrcAddr1.networkType = NETWORK_IPV4;
            compatibleSrcAddr1.interfaceAddr.ipv4 =
                GetDefaultIPv4InterfaceAddress(node);

            remoteAddress.networkType = NETWORK_IPV4;
            remoteAddress.interfaceAddr.ipv4 =
                        dnsClientData->primaryDNS.interfaceAddr.ipv4;

            dnsQueryPacket->dnsQuestion.dnsQType = A;
            appItemRec->queryNetworktype = NETWORK_IPV4;
            appItemRec->AAAASend = TRUE;
        }
        else
        {
            ERROR_ReportErrorArgs("\nIncompatible Src and Dest address"
                "type");
        }
    }
    else
    {
        if ((queryNetworktype == NETWORK_IPV4) &&
            (dnsClientData->primaryDNS.networkType == NETWORK_IPV4))
        {
            compatibleSrcAddr1.networkType = NETWORK_IPV4;
            compatibleSrcAddr1.interfaceAddr.ipv4 =
                GetDefaultIPv4InterfaceAddress(node);

            remoteAddress.networkType = NETWORK_IPV4;
            remoteAddress.interfaceAddr.ipv4 =
                        dnsClientData->primaryDNS.interfaceAddr.ipv4;

            dnsQueryPacket->dnsQuestion.dnsQType = A;
        }
        else if ((queryNetworktype == NETWORK_IPV6) &&
            (dnsClientData->ipv6PrimaryDNS.networkType == NETWORK_IPV6))
        {
            compatibleSrcAddr1.networkType = NETWORK_IPV6;

            Ipv6GetGlobalAggrAddress(node,
                        GetDefaultInterfaceIndex(node, NETWORK_IPV6),
                        &compatibleSrcAddr1.interfaceAddr.ipv6);

            remoteAddress.networkType = NETWORK_IPV6;
            remoteAddress.interfaceAddr.ipv6 =
                            dnsClientData->ipv6PrimaryDNS.interfaceAddr.ipv6;

            dnsQueryPacket->dnsQuestion.dnsQType = AAAA;
            appItemRec->AAAASend = TRUE;
            appItemRec->ASend = TRUE;
        }
        else
        {
            ERROR_ReportErrorArgs("\nIncompatible Src and Dest address "
                "type");
        }
    }

    if ((dnsClientData->secondaryDNS.networkType != NETWORK_INVALID) ||
        (dnsClientData->ipv6SecondaryDNS.networkType != NETWORK_INVALID))
    {
        if (queryNetworktype == NETWORK_INVALID)
        {
            if ((sourcetype == IPV4_ONLY) &&
                (dnsClientData->secondaryDNS.networkType == NETWORK_IPV4))
            {
                compatibleSrcAddr2.networkType = NETWORK_IPV4;
                compatibleSrcAddr2.interfaceAddr.ipv4 =
                    GetDefaultIPv4InterfaceAddress(node);

                remoteAddressSec.networkType = NETWORK_IPV4;
                remoteAddressSec.interfaceAddr.ipv4 =
                            dnsClientData->secondaryDNS.interfaceAddr.ipv4;

                dnsQueryPacket->dnsQuestion.dnsQType = A;
            }
            else if (((sourcetype == IPV6_ONLY) ||
                    (sourcetype == DUAL_IP)) &&
                    (dnsClientData->ipv6SecondaryDNS.networkType ==
                        NETWORK_IPV6))
            {
                compatibleSrcAddr2.networkType = NETWORK_IPV6;

                Ipv6GetGlobalAggrAddress(node,
                            GetDefaultInterfaceIndex(node, NETWORK_IPV6),
                            &compatibleSrcAddr2.interfaceAddr.ipv6);

                remoteAddressSec.networkType = NETWORK_IPV6;
                remoteAddressSec.interfaceAddr.ipv6 =
                            dnsClientData->ipv6SecondaryDNS.
                                interfaceAddr.ipv6;

                dnsQueryPacket->dnsQuestion.dnsQType = AAAA;
                appItemRec->AAAASend = TRUE;
            }
            else if ((sourcetype == DUAL_IP) &&
                (dnsClientData->secondaryDNS.networkType == NETWORK_IPV4))
            {
                compatibleSrcAddr2.networkType = NETWORK_IPV4;
                compatibleSrcAddr2.interfaceAddr.ipv4 =
                    GetDefaultIPv4InterfaceAddress(node);

                remoteAddressSec.networkType = NETWORK_IPV4;
                remoteAddressSec.interfaceAddr.ipv4 =
                            dnsClientData->secondaryDNS.interfaceAddr.ipv4;

                dnsQueryPacket->dnsQuestion.dnsQType = A;
                appItemRec->AAAASend = TRUE;
            }
            else
            {
                ERROR_ReportErrorArgs(
                    "\nIncompatible Src and Dest address type");
            }
        }
        else
        {
            if ((queryNetworktype == NETWORK_IPV4) &&
                (dnsClientData->secondaryDNS.networkType == NETWORK_IPV4))
            {
                compatibleSrcAddr2.networkType = NETWORK_IPV4;
                compatibleSrcAddr2.interfaceAddr.ipv4 =
                    GetDefaultIPv4InterfaceAddress(node);

                remoteAddressSec.networkType = NETWORK_IPV4;
                remoteAddressSec.interfaceAddr.ipv4 =
                            dnsClientData->secondaryDNS.interfaceAddr.ipv4;

                dnsQueryPacket->dnsQuestion.dnsQType = A;
            }
            else if ((queryNetworktype == NETWORK_IPV6) &&
                    (dnsClientData->ipv6SecondaryDNS.networkType ==
                        NETWORK_IPV6))
            {
                compatibleSrcAddr2.networkType = NETWORK_IPV6;

                Ipv6GetGlobalAggrAddress(node,
                            GetDefaultInterfaceIndex(node, NETWORK_IPV6),
                            &compatibleSrcAddr2.interfaceAddr.ipv6);

                remoteAddressSec.networkType = NETWORK_IPV6;
                remoteAddressSec.interfaceAddr.ipv6 =
                                dnsClientData->ipv6SecondaryDNS.
                                interfaceAddr.ipv6;

                dnsQueryPacket->dnsQuestion.dnsQType = AAAA;
                appItemRec->AAAASend = TRUE;
                appItemRec->ASend = TRUE;
            }
            else
            {
                ERROR_ReportErrorArgs(
                    "\nIncompatible Src and Dest address type");
            }
        }
    }

    char remoteAddrStr[MAX_STRING_LENGTH] = "";
    char remoteAddrStrSec[MAX_STRING_LENGTH] = "";
    if (remoteAddress.networkType != NETWORK_INVALID)
    {
        IO_ConvertIpAddressToString(&remoteAddress, remoteAddrStr);
    }
    if (remoteAddressSec.networkType != NETWORK_INVALID)
    {
        IO_ConvertIpAddressToString(&remoteAddressSec, remoteAddrStrSec);
    }
    if (DEBUG)
    {
        if (remoteAddress.networkType != NETWORK_INVALID)
        {
            printf("Node %d is going to send the query packet" \
                   "to its PDNS %s \n",
                   node->nodeId, remoteAddrStr);
        }
        if (remoteAddressSec.networkType != NETWORK_INVALID)
        {
            printf("Node %d is going to send the query packet" \
                   "to its SEC DNS %s \n",
                   node->nodeId, remoteAddrStrSec);
        }
    }

    // Check validity of remote Address
    if ((remoteAddress.networkType == NETWORK_IPV4 &&
         remoteAddress.interfaceAddr.ipv4 == 0) ||
         (remoteAddress.networkType == NETWORK_INVALID))
    {
        // No need to send Query
        dnsData->stat.numOfDnsNameUnresolved++;
        if (DEBUG)
        {
            printf("returning as dns server is not valid\n");
        }
        return;
    }

    dnsQueryPacket->dnsHeader.dns_id = 1;
     // query message (message type)
    DnsHeaderSetQr(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // standary query
    DnsHeaderSetOpcode(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // valid from responses
    DnsHeaderSetAA(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // truncated or not
    DnsHeaderSetTC(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // recursion desired
    DnsHeaderSetRD(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // recursion available
    DnsHeaderSetRA(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // for future use
    DnsHeaderSetReserved(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // response code
    DnsHeaderSetRcode(&dnsQueryPacket->dnsHeader.dns_hdr, 0);

    if (DEBUG)
    {
        char remoteAddrStr[MAX_STRING_LENGTH] = "";
        char sourceAddrStr[MAX_STRING_LENGTH] = "";
        char remoteAddrStrSec[MAX_STRING_LENGTH] = "";
        IO_ConvertIpAddressToString(&remoteAddress, remoteAddrStr);
        IO_ConvertIpAddressToString(&sourceAddress, sourceAddrStr);
        printf("send pkt from %s to %s \n", sourceAddrStr, remoteAddrStr);
        if (remoteAddressSec.networkType != NETWORK_INVALID)
        {
            IO_ConvertIpAddressToString(&remoteAddressSec, remoteAddrStrSec);
            printf("send pkt from %s to %s \n", sourceAddrStr,
                                                remoteAddrStrSec);
        }
    }

    enum DnsMessageType dnsMsgType;

    dnsMsgType = DNS_QUERY;

    Message* msg = NULL;
    AppToUdpSend* info = NULL;
    BOOL isprimary = TRUE;
    msg = MESSAGE_Alloc(
            node,
            TRANSPORT_LAYER,
            TransportProtocol_UDP,
            MSG_TRANSPORT_FromAppSend);

    MESSAGE_PacketAlloc(
        node,
        msg,
        sizeof(Address) +
        sizeof(enum DnsMessageType) +
        sizeof(BOOL) +
        sizeof(struct DnsQueryPacket),
        TRACE_DNS);

    memcpy(MESSAGE_ReturnPacket(msg),
          (char*)(&dnsMsgType),
          sizeof(enum DnsMessageType));

    memcpy(MESSAGE_ReturnPacket(msg) +
           sizeof(enum DnsMessageType),
           (char*)dnsQueryPacket,
           sizeof(struct DnsQueryPacket));

    memcpy(MESSAGE_ReturnPacket(msg) +
           sizeof(enum DnsMessageType) +
           sizeof(struct DnsQueryPacket),
           (char*)(&sourceAddress),
           sizeof(Address));

    memcpy(MESSAGE_ReturnPacket(msg) +
           sizeof(enum DnsMessageType) +
           sizeof(struct DnsQueryPacket) +
           sizeof(Address),
           (char*)(&isprimary),
           sizeof(BOOL));
    // Duplicating for retransmission
    Message* dupMsg = MESSAGE_Duplicate (node, msg);
    MESSAGE_InfoAlloc(
        node,
        msg,
        sizeof(AppToUdpSend));

    info = (AppToUdpSend*) MESSAGE_ReturnInfo(msg);
    memset(info, 0, sizeof(AppToUdpSend));

    info->sourceAddr = compatibleSrcAddr1;

    info->sourcePort = sourcePort;

    info->destAddr = remoteAddress;

    info->destPort = (short) APP_DNS_SERVER;
    info->priority = APP_DEFAULT_TOS;
    info->outgoingInterface = ANY_INTERFACE;

    MESSAGE_Send(node, msg, 0);
    dnsData->stat.numOfDnsQuerySent++;
    if (remoteAddressSec.networkType != NETWORK_INVALID)
    {
        Message* msgSec = MESSAGE_Duplicate (node, msg);
        AppToUdpSend* infoSec = (AppToUdpSend*) MESSAGE_ReturnInfo(msgSec);
        memset(infoSec, 0, sizeof(AppToUdpSend));

        infoSec->sourceAddr = compatibleSrcAddr2;
        infoSec->sourcePort = sourcePort;
        infoSec->destAddr = remoteAddressSec;
        infoSec->destPort = (short) APP_DNS_SERVER;
        infoSec->priority = APP_DEFAULT_TOS;
        infoSec->outgoingInterface = ANY_INTERFACE;
        MESSAGE_Send(node, msgSec, 0);
        dnsData->stat.numOfDnsQuerySent++;
    }

    MESSAGE_SetLayer(dupMsg, APP_LAYER, APP_TRAFFIC_SENDER);
    MESSAGE_SetEvent(dupMsg, MSG_APP_TimerDnsSendPacket);
    MESSAGE_InfoAlloc(node, dupMsg, sizeof(AppDnsInfoTimer));

    AppDnsInfoTimer* timer = (AppDnsInfoTimer*) MESSAGE_ReturnInfo(dupMsg);
    timer->type = type;
    timer->serverUrl = new std::string();
    timer->serverUrl->assign(qDomainName);
    timer->sourcePort = sourcePort,
    timer->addr = sourceAddress;
    timer->tcpMode = tcpMode;
    timer->uniqueId = uniqueId;

    MESSAGE_Send(node, dupMsg, TIMEOUT_INTERVAL_OF_DNS_QUERY_REPLY);
    MEM_free(dnsQueryPacket);
    dnsQueryPacket = NULL;
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsHandleResolveUrlProcess
// LAYER        :: Application Layer
// PURPOSE      :: Handle resolve URL Process
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsHandleResolveUrlProcess(Node* node, Message* msg)
{
    struct AppDnsInfoTimer* timer = NULL;
    Address resolvedAddr;
    BOOL cacheFound = FALSE;
    bool isFoundInAddressCache = false;
    BOOL queryIsInProgress = FALSE;
    Int16 interfaceId = 0;
    struct DnsAppReqListItem* appItemTmp = NULL;
    struct DnsAppReqListItem* lstItemToDelete = NULL;
    struct DnsAppReqListItem* appItemRec = NULL;
    timer = (struct AppDnsInfoTimer*)MESSAGE_ReturnInfo(msg);
    interfaceId = timer->interfaceId;
    NetworkProtocolType sourcetype = NetworkIpGetNetworkProtocolType(node,
                                        node->nodeId);
    if (timer->addr.networkType == NETWORK_IPV4)
    {
        timer->addr.interfaceAddr.ipv4 = NetworkIpGetInterfaceAddress(
                                                    node,
                                                    timer->interfaceId);
    }
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
    if (!dnsData)
    {
        ERROR_ReportErrorArgs("The Node: %d has no dnsdata", node->nodeId);
    }

    if (DEBUG)
    {
        printf("in AppDnsHandleResolveUrlProcess node %d "
               "trying to resolve from cache\n", node->nodeId);
    }
    memset(&resolvedAddr, 0, sizeof(Address));

    // First check traffic sender local address cache
    resolvedAddr = node->appData.appTrafficSender->
                    lookupUrlInAddressCache(*(timer->serverUrl));
    if (resolvedAddr.networkType != NETWORK_INVALID)
    {
        isFoundInAddressCache = true;
    }
    else
    {
        // Not found in traffic sender cache, Now check DNS cache
        AppDnsResolveNameFromLocalCache(node,
                *(timer->serverUrl), &resolvedAddr, &cacheFound);
    }

    // Insert this item in DNS request list

    struct DnsAppReqListItem* appItem =
    (struct DnsAppReqListItem*)MEM_malloc(sizeof(struct DnsAppReqListItem));
    memset(appItem, 0, sizeof(struct DnsAppReqListItem));

    /*memcpy(appItem->serverUrl, timer->serverUrl, DNS_NAME_LENGTH);*/
    appItem->serverUrl = new std::string();
    appItem->serverUrl->assign(*timer->serverUrl);

    appItem->sourcePort = timer->sourcePort;
    appItem->appType = timer->type;
    appItem->uniqueId = timer->uniqueId;
    appItem->tcpMode = timer->tcpMode;
    appItem->resolveStartTime = node->getNodeTime();
    appItem->addr = timer->addr;
    appItem->retryCount = 0;
    appItem->interfaceId = timer->interfaceId;
    if (timer->sourceNetworktype == NETWORK_IPV6)
    {
        appItem->AAAASend = TRUE;
        appItem->ASend = TRUE;
    }
    else if (timer->sourceNetworktype == NETWORK_IPV4)
    {
        appItem->AAAASend = FALSE;
        appItem->ASend = FALSE;
    }
    else if (sourcetype == IPV6_ONLY || sourcetype == DUAL_IP)
    {
        appItem->AAAASend = TRUE;
        appItem->ASend = FALSE;
    }
    else
    {
        appItem->AAAASend = FALSE;
        appItem->ASend = FALSE;
    }
    appItem->queryNetworktype = timer->sourceNetworktype;
    appItem->interfaceList = new AppReqInterfaceList;
    Int16* interfaceIndex = (Int16*)MEM_malloc(sizeof(Int16));
    *interfaceIndex = timer->interfaceId;
    appItem->interfaceList->push_back(interfaceIndex);
    Int16 i;
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (i != timer->interfaceId)
        {
            interfaceIndex = (Int16*)MEM_malloc(sizeof(Int16));
            *interfaceIndex = i;
            appItem->interfaceList->push_back(interfaceIndex);
        }
    }
    appItemRec = appItem;
    DnsAppReqItemList :: iterator lstItem;
    lstItem = dnsData->appReqList->begin();
    BOOL isAppItemExist = FALSE;
    while (lstItem != dnsData->appReqList->end())
    {
        appItemTmp = (struct DnsAppReqListItem*)*lstItem;

        if ((appItemTmp->serverUrl->compare(*appItem->serverUrl) == 0) &&
            (appItem->sourcePort == appItemTmp->sourcePort) &&
            (appItem->appType == appItemTmp->appType) &&
            appItem->queryNetworktype == appItemTmp->queryNetworktype)
        {
            isAppItemExist = TRUE;
            appItemRec = appItemTmp;
            lstItemToDelete = (struct DnsAppReqListItem*)*lstItem;
            appItemTmp->retryCount++;
            break;
        }
        lstItem++;
    }
    if (!isAppItemExist)
    {
        lstItem = dnsData->appReqList->begin();
        while (lstItem != dnsData->appReqList->end())
        {
            appItemTmp = (struct DnsAppReqListItem*)*lstItem;

            if ((appItemTmp->serverUrl->compare(*appItem->serverUrl) == 0) &&
                appItemTmp->queryNetworktype == appItem->queryNetworktype)
            {
                 isAppItemExist = TRUE;
                 //short* appId = (short*)MEM_malloc(sizeof(short));
                 //*appId = appItem->sourcePort;
                 queryIsInProgress = TRUE;
                 lstItemToDelete = (struct DnsAppReqListItem*)*lstItem;
                 appItemRec = appItemTmp;
                 //MEM_free(appId);
                 break;
            }
            lstItem++;
        }
        dnsData->appReqList->push_back(appItem);
    }
    else
    {
        if (appItem->interfaceList)
        {
            if (appItem->interfaceList->size())
            {
                AppReqInterfaceList::iterator appReqIntListIt =
                                appItem->interfaceList->begin();
                while (appReqIntListIt != appItem->interfaceList->end())
                {
                    Int16* listItem1 = (Int16*)*appReqIntListIt;
                    appReqIntListIt++;
                    MEM_free(listItem1);
                    listItem1 = NULL;
                }
                delete(appItem->interfaceList);
                appItem->interfaceList = NULL;
            }
        }
        delete (appItem->serverUrl);
        MEM_free(appItem);
        appItem = NULL;
    }
    NodeAddress nodeId = 0;
    Address destAddr;

    if (!timer->serverUrl->compare("localhost.")||
        !timer->serverUrl->compare("localhost"))
    {
        if ((sourcetype == IPV4_ONLY) || (sourcetype == DUAL_IP))
        {
            IO_AppParseDestString(node, NULL, "127.0.0.1", &nodeId, &destAddr);
            resolvedAddr = destAddr;
            cacheFound = TRUE;
        }
        else if (sourcetype == IPV6_ONLY)
        {
            IO_AppParseDestString(node, NULL, "::1", &nodeId, &destAddr);
            resolvedAddr = destAddr;
            cacheFound = TRUE;
        }
    }
    if (cacheFound || isFoundInAddressCache)
    {
        // Inform Respective Application
        if (DEBUG)
        {
            printf("Node %d invoking AppDnsInformApplication "
                " from cache\n", node->nodeId);
        }
        AppDnsInformApplication(node,
            timer->serverUrl->c_str(),
            &resolvedAddr);
    }
    else
    {
        // Ask for DNS service
        if (!queryIsInProgress)
        {
            if (!appItemRec->interfaceList->size())
            {
                return;
            }
            Int16 tmpInterfaceId = **(appItemRec->interfaceList->begin());
            DnsClientDataList :: iterator tmpItem;
            struct DnsClientData* tmpDnsClientData = NULL;
            tmpItem = dnsData->clientData->begin();
            while (tmpItem != dnsData->clientData->end())
            {
                tmpDnsClientData = (struct DnsClientData*)*tmpItem;
                if (tmpDnsClientData->interfaceNo == tmpInterfaceId)
                {
                    break;
                }
                tmpItem++;
            }
            if (appItemRec->retryCount >= MAX_COUNT_OF_DNS_QUERY_RETRIES)
            {
                if (appItemRec->interfaceList->size())
                {
                    // free item
                    dnsData->stat.numOfDnsNameUnresolved++;
                    Int16* temp = appItemRec->interfaceList->front();
                    appItemRec->interfaceList->
                    remove(appItemRec->interfaceList->front());
                    MEM_free(temp);
                }
                appItemRec->retryCount = 0;
            }
            if (!appItemRec->interfaceList->size())
            {
                if (DEBUG)
                {
                    printf("Node %d:Maximum retry limit for resolving\n"
                        "URL %s has been reached.\n",
                        node->nodeId, timer->serverUrl->c_str());
                }
                if (dnsData->appReqList)
                {
                    if (lstItemToDelete->interfaceList)
                    {
                        if (lstItemToDelete->interfaceList->size())
                        {
                            AppReqInterfaceList ::
                                iterator appReqIntListIt =
                                    lstItemToDelete->interfaceList->begin();
                            while (appReqIntListIt !=
                                    lstItemToDelete->interfaceList->end())
                            {
                                Int16* listItem1 = (Int16*)*appReqIntListIt;
                                appReqIntListIt++;
                                MEM_free(listItem1);
                                listItem1 = NULL;

                            }
                        }
                        delete(lstItemToDelete->interfaceList);
                        lstItemToDelete->interfaceList = NULL;
                    }
                    // free item

                    dnsData->appReqList->remove(lstItemToDelete);
                    delete (lstItemToDelete->serverUrl);
                    MEM_free(lstItemToDelete);
                    lstItemToDelete = NULL;
                }
                return;
            }
            interfaceId = **(appItemRec->interfaceList->begin());

            DnsClientDataList :: iterator item;
            struct DnsClientData* dnsClientData = NULL;
            item = dnsData->clientData->begin();
            while (item != dnsData->clientData->end())
            {
                dnsClientData = (struct DnsClientData*)*item;
                if (dnsClientData->interfaceNo == interfaceId)
                {
                    if ((tmpInterfaceId != interfaceId) &&
                        tmpDnsClientData &&
                        !memcmp(&tmpDnsClientData->primaryDNS,
                        &dnsClientData->primaryDNS, sizeof(Address)) &&
                        !memcmp(&tmpDnsClientData->secondaryDNS,
                        &dnsClientData->secondaryDNS, sizeof(Address)))
                    {
                        item = dnsData->clientData->begin();
                        if (!appItemRec->interfaceList->size())
                        {
                            break;
                        }
                        // free item
                        Int16* temp = appItemRec->interfaceList->front();
                        appItemRec->interfaceList->
                            remove(appItemRec->interfaceList->front());
                        MEM_free(temp);
                        if (!appItemRec->interfaceList->size())
                        {
                            break;
                        }
                        interfaceId = *(appItemRec->interfaceList->front());
                        appItemRec->retryCount = 0;
                        continue;
                    }
                    break;
                }
                item++;
                if (item == dnsData->clientData->end())
                {
                    item = dnsData->clientData->begin();
                    if (!appItemRec->interfaceList->size())
                    {
                        break;
                    }
                    // free item
                    Int16* temp = appItemRec->interfaceList->front();
                    appItemRec->interfaceList->
                            remove(appItemRec->interfaceList->front());
                    MEM_free(temp);
                    if (!appItemRec->interfaceList->size())
                    {
                        break;
                    }
                    interfaceId = *(appItemRec->interfaceList->front());
                    appItemRec->retryCount = 0;
                }
            }
            AppDnsStartResolvingDomainName(node,
                timer->serverUrl->c_str(),
                timer->type,
                timer->addr,
                timer->sourcePort,
                timer->uniqueId,
                dnsClientData,
                appItemRec,
                timer->tcpMode);
        }
    }
    delete(timer->serverUrl);
    MESSAGE_Free(node, msg);
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsRetryResolveNameserver
// LAYER        :: Application Layer
// PURPOSE      :: Handle resolve nameserve Process
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: void - None
//--------------------------------------------------------------------------
void AppDnsRetryResolveNameserver(Node* node, Message* msg)
{
    DnsClientDataList :: iterator item;
    AppToUdpSend* info = NULL;
    struct DnsClientData* dnsClientData = NULL;
    struct DnsData* dnsData = NULL;
    Address secDnsAddress;
    dnsData = (struct DnsData*)node->appData.dnsData;
    info = (AppToUdpSend*) MESSAGE_ReturnInfo(msg);
    memset(&secDnsAddress, 0, sizeof(Address));
    item = dnsData->clientData->begin();
    while (item != dnsData->clientData->end())
    {
        dnsClientData = (struct DnsClientData*)*item;

        if ((dnsClientData->interfaceNo == info->outgoingInterface) ||
            (dnsClientData->interfaceNo == ALL_INTERFACE))
        {
            memcpy(&secDnsAddress,
                &dnsClientData->secondaryDNS,
                sizeof(Address));
            if (dnsClientData->isNameserverResolved ||
                dnsClientData->nextMessage == NULL)
            {
                MESSAGE_Free(node, msg);
                return;
            }
            break;
        }
        item++;
    }
    if (dnsClientData->retryCount >= MAX_COUNT_OF_DNS_QUERY_RETRIES)
    {
        if (DEBUG)
        {
            printf("Maximum retry limit for resolving Primary Name server "
                "for node %d[%d] is reached\n",
                node->nodeId, info->outgoingInterface);
        }
        if (dnsClientData->nextMessage)
        {
            MESSAGE_Free(node, dnsClientData->nextMessage);
            dnsClientData->nextMessage = NULL;
        }
        MESSAGE_Free(node, msg);
        return;
    }
    Message* dupMsg = MESSAGE_Duplicate (node, dnsClientData->nextMessage);
    MESSAGE_Send(node, dnsClientData->nextMessage, 0);
    dnsClientData->rootQueriedCount = 0;
    if (DEBUG)
    {
        char remoteAddrStr[MAX_STRING_LENGTH] = "";
        AppToUdpSend* info = (AppToUdpSend*)MESSAGE_ReturnInfo(dupMsg);
        IO_ConvertIpAddressToString(&info->destAddr, remoteAddrStr);
        printf("In AppDnsRetryResolveNameserver: Node %d"
               " sending SOA query to its PDNS %s\n",
               node->nodeId,
               remoteAddrStr);
    }
    dnsData->stat.numOfDnsSOAQuerySent++;
    if (secDnsAddress.networkType != NETWORK_INVALID)
    {
        Message* secDupMsg = MESSAGE_Duplicate (node, dupMsg);
        AppToUdpSend* info = (AppToUdpSend*)MESSAGE_ReturnInfo(secDupMsg);
        memcpy(&info->destAddr, &secDnsAddress, sizeof(Address));
        MESSAGE_Send(node, secDupMsg, 0);
        dnsData->stat.numOfDnsSOAQuerySent++;
        if (DEBUG)
        {
            char remoteAddrStr[MAX_STRING_LENGTH] = "";
            IO_ConvertIpAddressToString(&secDnsAddress, remoteAddrStr);
            printf("In AppDnsRetryResolveNameserver: Node %d"
                   " sending SOA query to its SDNS %s\n",
                   node->nodeId,
                   remoteAddrStr);
        }
    }
    dnsClientData->nextMessage = dupMsg;

    AppToUdpSend* timer = NULL;
    Message* timerMsg = MESSAGE_Alloc(node,
                            APP_LAYER,
                            APP_DNS_CLIENT,
                            MSG_APP_DnsRetryResolveNameServer);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppToUdpSend));
    timer = (AppToUdpSend*)MESSAGE_ReturnInfo(timerMsg);
    timer->outgoingInterface = info->outgoingInterface;
    MESSAGE_Send(node,
                timerMsg,
                TIMEOUT_INTERVAL_OF_DNS_QUERY_REPLY);
    dnsClientData->retryCount++;
    MESSAGE_Free(node, msg);
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsUpdateNotSucceeded
// LAYER        :: Application Layer
// PURPOSE      :: Handle DNS update Process
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsUpdateNotSucceeded(Node* node, Message* msg)
{
    DnsClientDataList ::iterator item;
    AppToUdpSend* info = NULL;
    struct DnsClientData* dnsClientData = NULL;
    struct DnsData* dnsData = NULL;
    dnsData = (struct DnsData*)node->appData.dnsData;
    info = (AppToUdpSend*) MESSAGE_ReturnInfo(msg);

    item = dnsData->clientData->begin();
    while (item != dnsData->clientData->end())
    {
        dnsClientData = (struct DnsClientData*)*item;
        if ((dnsClientData->interfaceNo == info->outgoingInterface) ||
            (dnsClientData->interfaceNo == ALL_INTERFACE))
        {
            if (dnsClientData->isUpdateSuccessful ||
                dnsClientData->nextMessage == NULL)
            {
                MESSAGE_Free(node, msg);
                return;
            }
            break;
        }
        item++;
    }
    if (dnsClientData->retryCount >= MAX_COUNT_OF_DNS_QUERY_RETRIES)
    {
        if (DEBUG)
        {
            printf("Maximum retry limit for resolving Primary Name server "
                "for node %d[%d] is reached\n",
                node->nodeId, info->outgoingInterface);
        }
        if (dnsClientData->nextMessage)
        {
            MESSAGE_Free(node, dnsClientData->nextMessage);
            dnsClientData->nextMessage = NULL;
        }
        MESSAGE_Free(node, msg);
        return;
    }
    Message* dupMsg = MESSAGE_Duplicate (node,
                                    dnsClientData->nextMessage);
    if (DEBUG)
    {
        char remoteAddrStr[MAX_STRING_LENGTH] = "";
        AppToUdpSend* info = NULL;
        info = (AppToUdpSend*)MESSAGE_ReturnInfo(dupMsg);
        IO_ConvertIpAddressToString(&info->destAddr, remoteAddrStr);
        printf("In AppDnsUpdateNotSucceeded: NODE %d"
               " SENDING UPDATE TO ITS PRIMARY NAME SERVER %s\n",
               node->nodeId,
               remoteAddrStr);
    }
    MESSAGE_Send(node, dnsClientData->nextMessage, 0);
    dnsClientData->nextMessage = dupMsg;

    AppToUdpSend* timer = NULL;
    Message* timerMsg = MESSAGE_Alloc(node,
                            APP_LAYER,
                            APP_DNS_CLIENT,
                            MSG_APP_DnsUpdateNotSucceeded);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppToUdpSend));
    timer = (AppToUdpSend*)MESSAGE_ReturnInfo(timerMsg);
    timer->outgoingInterface = info->outgoingInterface;
    MESSAGE_Send(node,
                timerMsg,
                TIMEOUT_INTERVAL_OF_DNS_QUERY_REPLY);
    dnsClientData->retryCount++;
    MESSAGE_Free(node, msg);
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsCreateAndSendQuery
// LAYER        :: Application Layer
// PURPOSE      :: Handle resolve URL Process
// PARAMETERS   :: node - Pointer to node.
//                 isPrimary,
//                 dnsQuestion,
//                 dns_id,
//                 sourceAddress,
//                 sourcePort,
//                 destAddress
//                 qtype
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsCreateAndSendQuery(
                         Node* node,
                         BOOL isPrimary,
                         struct DnsQuestion* dnsQuestion,
                         UInt16 dns_id,
                         Address sourceAddress,
                         UInt16 sourcePort,
                         Address destAddress,
                         enum RrType  qtype)
{
    // check source address state; if in invalid address state then do not
    // send query packet
    if (sourceAddress.networkType == NETWORK_INVALID)
    {
        // address is not valid do not send a query
        return;
    }

    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;

    struct DnsQueryPacket* dnsQueryPacket = (struct DnsQueryPacket*)
                                        MEM_malloc (sizeof(struct DnsQueryPacket));

    memset(dnsQueryPacket, 0, sizeof(struct DnsQueryPacket));

    dnsQueryPacket->dnsQuestion.dnsQType = qtype;

    memcpy(dnsQueryPacket->dnsQuestion.dnsQname,
        dnsQuestion->dnsQname, DNS_NAME_LENGTH);

    dnsQueryPacket->dnsQuestion.dnsQClass = IN ;

    dnsQueryPacket->dnsHeader.dns_id = dns_id;

     // query message (message type)
    DnsHeaderSetQr(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // standary query
    DnsHeaderSetOpcode(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // valid from responses
    DnsHeaderSetAA(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // truncated or not
    DnsHeaderSetTC(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // recursion desired
    DnsHeaderSetRD(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // recursion available
    DnsHeaderSetRA(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // for future use
    DnsHeaderSetReserved(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // response code
    DnsHeaderSetRcode(&dnsQueryPacket->dnsHeader.dns_hdr, 0);

    Message* msg = NULL;
    AppToUdpSend* info = NULL;

    enum DnsMessageType dnsMsgType = DNS_QUERY;
    msg = MESSAGE_Alloc(
            node,
            TRANSPORT_LAYER,
            TransportProtocol_UDP,
            MSG_TRANSPORT_FromAppSend);

    MESSAGE_PacketAlloc(
        node,
        msg,
        sizeof(Address) + sizeof(enum DnsMessageType) +
        sizeof(struct DnsQueryPacket) + sizeof(BOOL),
        TRACE_DNS);

    memcpy(MESSAGE_ReturnPacket(msg),
           (char*)(&dnsMsgType),
           sizeof(enum DnsMessageType));

    memcpy(MESSAGE_ReturnPacket(msg) + sizeof(enum DnsMessageType),
           (char*)dnsQueryPacket,
           sizeof(struct DnsQueryPacket));

    memcpy(MESSAGE_ReturnPacket(msg) + sizeof(enum DnsMessageType) +
                 sizeof(struct DnsQueryPacket),
           (char*)(&sourceAddress),
           sizeof(Address));

    memcpy(MESSAGE_ReturnPacket(msg) + sizeof(enum DnsMessageType) +
                sizeof(struct DnsQueryPacket) + sizeof(Address),
           (char*)(&isPrimary),
           sizeof(BOOL));

    MESSAGE_InfoAlloc(node, msg, sizeof(AppToUdpSend));

    info = (AppToUdpSend*) MESSAGE_ReturnInfo(msg);
    memset(info, 0, sizeof(AppToUdpSend));
    info->sourceAddr = sourceAddress;

    info->sourcePort = sourcePort;

    info->destAddr = destAddress;
    info->destPort = (short) APP_DNS_SERVER;
    info->priority = APP_DEFAULT_TOS;
    info->outgoingInterface = ANY_INTERFACE;

    MESSAGE_Send(node, msg, 0);

    if ((dnsQueryPacket->dnsQuestion.dnsQType == A) ||
        (dnsQueryPacket->dnsQuestion.dnsQType == AAAA))
    {
        dnsData->stat.numOfDnsQuerySent++;
    }
    else if ((dnsQueryPacket->dnsQuestion.dnsQType == SOA))
    {
        dnsData->stat.numOfDnsSOAQuerySent++;
    }
    else if ((dnsQueryPacket->dnsQuestion.dnsQType == NS))
    {
        dnsData->stat.numOfDnsNSQuerySent++;
    }

    MEM_free(dnsQueryPacket);
    dnsQueryPacket = NULL;
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsFindOldCacheEntry
// LAYER        :: Application Layer
// PURPOSE      :: Finds an olds existing cache entry
// PARAMETERS   :: node - Pointer to node.
//                 cache,
//                 answerUrl,
//                 cacheItem,
//                 incrementstats,
//                 queryType
// RETURN       :: Bool
//--------------------------------------------------------------------------
static BOOL AppDnsFindOldCacheEntry(CacheRecordList* cache,
                                    std::string answerUrl,
                                    struct CacheRecord** cacheItem,
                                    BOOL* incrementstats,
                                    NetworkType queryType)
{
    // No cache is present
    if (!cache)
    {
        cacheItem = NULL;
        return FALSE;
    }

    CacheRecordList :: iterator item;
    item = cache->begin();
    struct CacheRecord* tempcacheItem = NULL;
    // check for matching destIP
    while (item != cache->end())
    {
        tempcacheItem = (struct CacheRecord*)*item;

        if ((tempcacheItem->urlNameString->compare(answerUrl) == 0) &&
            (tempcacheItem->associatedIpAddr.networkType == queryType))
        {
            if (tempcacheItem->deleted == TRUE)
            {
                *incrementstats = TRUE;
            }
            else
            {
                *incrementstats = FALSE;
            }
            *cacheItem = tempcacheItem;
            return TRUE;
        }
        item++;
    }

    *cacheItem = NULL;
    return FALSE;
}

//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsHandleMsgFromTransport
// LAYER        :: Application Layer
// PURPOSE      :: Diffrent Type of Message served by DNS Client
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsHandleMsgFromTransport(Node* node, Message* msg)
{
    struct DnsData* dnsData = NULL;
    char serverDomain[DNS_NAME_LENGTH] = "";
    //char answerUrl[DNS_NAME_LENGTH] = "";
    std::string answerUrl;
    struct DnsQueryPacket* dnsReplyPacket = NULL;
    struct DnsCommonHeader* dnsHeader = NULL;
    struct DnsQuestion* dnsQuestion = NULL;
    Int32 count = 0;

    struct DnsRrRecord* answerRrs = NULL;
    struct DnsRrRecord* nameServerRrs = NULL;
    struct DnsRrRecord* additionalRrs = NULL;

    Address destAddress;
    Address sourceAddress;

    // VOIP-DNS Changes
    UInt16 sourcePort = 0;
    // VOIP-DNS Changes Over

    dnsData = (struct DnsData*)node->appData.dnsData;
    if (!dnsData)
    {
        // Not a valid DNS msg for this node so free it and return.
        MESSAGE_Free(node, msg);
        return;
    }
    memset(&destAddress, 0, sizeof(Address));
    memset(&sourceAddress, 0, sizeof(Address));
    dnsHeader = (struct DnsCommonHeader*)
                MEM_malloc(sizeof(struct DnsCommonHeader));
    dnsQuestion = (struct DnsQuestion*)
                    MEM_malloc(sizeof(struct DnsQuestion));
    dnsReplyPacket =
        (struct DnsQueryPacket*)MEM_malloc(sizeof(struct DnsQueryPacket));

    struct DnsRrRecord* tempAnRrRecord = NULL;
    struct DnsRrRecord* tempNsRrRecord = NULL;

    if (DEBUG)
    {
        char buf[MAX_STRING_LENGTH] = "";
        TIME_PrintClockInSecond(node->getNodeTime(), buf);
        printf("in AppDnsHandleMsgFromTransport DNS client"
               " node %d at %sS\n", node->nodeId, buf);
    }
    memcpy(dnsReplyPacket,
        MESSAGE_ReturnPacket(msg),
        (sizeof(struct DnsQueryPacket)));

    char* dnsPacketPtr = MESSAGE_ReturnPacket(msg) +
                         sizeof(struct DnsQueryPacket)+ sizeof(BOOL);


    memcpy(dnsHeader,
           &(dnsReplyPacket->dnsHeader),
           sizeof(struct DnsCommonHeader));

    memcpy(dnsQuestion,
           &(dnsReplyPacket->dnsQuestion),
           sizeof(struct DnsQuestion));

    if (dnsHeader->anCount == 0 &&
        dnsHeader->nsCount == 0 &&
        dnsHeader->arCount == 0 &&
        dnsQuestion->dnsQType == SOA)
    {
        DnsClientDataList :: iterator item;
        item = dnsData->clientData->begin();
        struct DnsClientData* dnsClientData = NULL;
        while (item != dnsData->clientData->end())
        {
            dnsClientData = (struct DnsClientData*)*item;

            if ((dnsClientData->interfaceNo == dnsHeader->dns_id) ||
                (dnsClientData->interfaceNo == ALL_INTERFACE))
            {
                UInt16 rcode = DnsHeaderGetRcode(dnsHeader->dns_hdr);
                if (dnsClientData->isNameserverResolved &&
                    (rcode == NOERROR))
                {
                    if (DEBUG)
                    {
                        printf(
                            "ACK RECEIVED: DNS UPDATE(%d->%d) SUCCEEDED\n",
                            node->nodeId,
                            msg->originatingNodeId);
                    }
                    if (dnsClientData->nextMessage)
                    {
                        MESSAGE_Free(node, dnsClientData->nextMessage);
                    }
                    dnsClientData->nextMessage = NULL;
                    dnsClientData->isUpdateSuccessful = TRUE;
                    memset(&dnsClientData->resolvedNameServer,
                           0,
                           sizeof(Address));
                    if (dnsClientData->oldIpAddress.networkType
                                    == NETWORK_IPV4)
                    {
                        sourceAddress.networkType = NETWORK_IPV4;
                        sourceAddress.interfaceAddr.ipv4 =
                                    NetworkIpGetInterfaceAddress(
                                        node,
                                        dnsClientData->interfaceNo);
                    }
                    if (dnsClientData->nameServerList != NULL)
                    {
                        if (dnsClientData->nameServerList->size())
                        {
                            ServerList :: iterator serverListIt =
                                dnsClientData->nameServerList->begin();
                            while (serverListIt !=
                                   dnsClientData->nameServerList->end())
                            {
                                Address* listItem1 =
                                            (Address*)*serverListIt;
                                serverListIt++;
                                MEM_free(listItem1);
                                listItem1 = NULL;
                            }
                        }
                        delete(dnsClientData->nameServerList);
                        dnsClientData->nameServerList = NULL;
                    }
                    memcpy(&dnsClientData->oldIpAddress,
                           &sourceAddress,
                           sizeof(Address));
                }
                else if (rcode == NOTAUTH)
                {
                    if (DEBUG)
                    {
                        printf("ACK RECEIVED: DNS UPDATE(%d->%d) FAILED\n",
                               node->nodeId,
                               msg->originatingNodeId);
                    }
                    if (dnsClientData->nameServerList &&
                        dnsClientData->nameServerList->size())
                    {
                        memcpy(&dnsClientData->resolvedNameServer,
                               *(dnsClientData->nameServerList->begin()),
                               sizeof(Address));
                        // free item
                        Address* temp =
                            dnsClientData->nameServerList->front();
                        dnsClientData->nameServerList->
                            remove(dnsClientData->nameServerList->front());
                        MEM_free(temp);

                        Message* dupMsg = MESSAGE_Duplicate(
                                            node,
                                            dnsClientData->nextMessage);
                        AppToUdpSend* info;
                        info = (AppToUdpSend*)MESSAGE_ReturnInfo(dupMsg);
                        info->destAddr = dnsClientData->resolvedNameServer;
                        MESSAGE_Send(node, dupMsg, 0);
                        info = (AppToUdpSend*)MESSAGE_ReturnInfo(
                                                dnsClientData->nextMessage);
                        info->destAddr = dnsClientData->resolvedNameServer;
                    }
                    else if (!dnsClientData->receivedNsQueryResult)
                    {
                        if (dnsClientData->resolvedNameServer.networkType
                                                          == NETWORK_IPV4)
                        {
                            sourceAddress.networkType = NETWORK_IPV4;
                            sourceAddress.interfaceAddr.ipv4 =
                                        NetworkIpGetInterfaceAddress(
                                        node,
                                        dnsClientData->interfaceNo);
                        }
                        if (DEBUG)
                        {
                            printf("Node %d doing NS query\n",
                                node->nodeId);
                        }
                        AppDnsCreateAndSendQuery(
                            node,
                            FALSE,
                            dnsQuestion,
                            dnsHeader->dns_id,
                            sourceAddress,
                            (short)APP_DNS_CLIENT,
                            dnsClientData->resolvedNameServer,
                            NS);
                    }
                }
                MESSAGE_Free(node, msg);
                MEM_free(dnsHeader);
                MEM_free(dnsQuestion);
                MEM_free(dnsReplyPacket);
                return;
            }
            item++;
        }
    }
    if ((dnsQuestion->dnsQType == A) ||
        (dnsQuestion->dnsQType == AAAA))
    {
        dnsData->stat.numOfDnsReplyRecv++;
    }
    else if ((dnsQuestion->dnsQType == SOA))
    {
        dnsData->stat.numOfDnsSOAReplyRecv++;
    }
    else if ((dnsQuestion->dnsQType == NS))
    {
        dnsData->stat.numOfDnsNSReplyRecv++;
    }

    // check various count field
    if (dnsHeader->anCount > 0)
    {
        answerRrs = (struct DnsRrRecord*)
            MEM_malloc(dnsHeader->anCount * sizeof(struct DnsRrRecord));
        if (DEBUG)
        {
            printf("coping answers\n");
        }
        memcpy(
            answerRrs,
            dnsPacketPtr,
            dnsHeader->anCount * sizeof(struct DnsRrRecord));
        dnsPacketPtr += dnsHeader->anCount * sizeof(struct DnsRrRecord);
    }
    if (dnsHeader->nsCount > 0)
    {
        nameServerRrs = (struct DnsRrRecord*) MEM_malloc(
                            dnsHeader->nsCount*
                            sizeof(struct DnsRrRecord));
        if (DEBUG)
        {
            printf("coping nameservers\n");
        }
        memcpy(
            nameServerRrs,
            dnsPacketPtr,
            dnsHeader->nsCount * sizeof(struct DnsRrRecord));
        dnsPacketPtr += dnsHeader->nsCount * sizeof(struct DnsRrRecord);
    }
    if (dnsHeader->arCount > 0)
    {
        additionalRrs = (struct DnsRrRecord*)
            MEM_malloc(dnsHeader->arCount*
            sizeof(struct DnsRrRecord));
        if (DEBUG)
        {
            printf("coping addiotional rrs\n");
        }
        memcpy(additionalRrs,
            dnsPacketPtr,
            dnsHeader->arCount*sizeof(struct DnsRrRecord));
        dnsPacketPtr += dnsHeader->arCount * sizeof(struct DnsRrRecord);
    }

    memcpy(serverDomain,
        dnsPacketPtr,
        DNS_NAME_LENGTH);

    dnsPacketPtr += DNS_NAME_LENGTH;

   // VOIP-DNS Changes
    memcpy(&sourcePort,
        dnsPacketPtr,
        sizeof(UInt16));
   // VOIP-DNS Changes Over

    if (DEBUG)
    {
        char buf[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(node->getNodeTime(), buf);
        printf("In AppDnsHandleMsgFromTransport: Received port as "
               "%d at %sS\n", sourcePort, buf);
    }

    // check validity of DNS packet
    if (DnsHeaderGetQr(dnsHeader->dns_hdr) != 1)
    {
        ERROR_ReportErrorArgs("\nThis in not a valid type of DNS message");
    }

    // check if the answer rrRecords have some
    // answers to the query URL

    if (dnsHeader->anCount > 0)
    {
        tempAnRrRecord = (struct DnsRrRecord*)answerRrs;
        for (count = 1; count <= dnsHeader->anCount; count++)
        {
            if (DEBUG)
            {
                printf("Node %d in ANS orig dname %s, Ansdname %s\n",
                       node->nodeId, dnsQuestion->dnsQname,
                       tempAnRrRecord->associatedDomainName);
            }
            struct CacheRecord* cacheItem = NULL;
            BOOL incrementstats = TRUE;
            if ((strstr(dnsQuestion->dnsQname,
                tempAnRrRecord->associatedDomainName) &&
                dnsQuestion->dnsQType == SOA) ||
                (dnsQuestion->dnsQType == NS))
            {
                enum DnsMessageType msgType = DNS_UPDATE;
                Message* dnsMsg = NULL;
                AppToUdpSend* info = NULL;
                UInt32 zoneFreshCount = 0;
                struct DnsZoneTransferPacket dnsZonePacket;
                Address sourceAddress;
                Address oldSourceAddress;
                DnsClientDataList :: iterator item;
                struct DnsClientData* dnsClientData = NULL;
                struct DnsRrRecord rrRecord;
                memset(&rrRecord, 0, sizeof(struct DnsRrRecord));
                Int32 interfaceId = dnsHeader->dns_id;

                NetworkProtocolType protocol_type = INVALID_NETWORK_TYPE;

                memset(&sourceAddress, 0, sizeof(Address));

                memset(&dnsZonePacket, 0, sizeof(struct DnsZoneTransferPacket));

                dnsZonePacket.dnsZone.dnsZoneType = SOA;
                dnsZonePacket.dnsZone.dnsZoneClass = IN;

                dnsZonePacket.dnsHeader.dns_id = dnsHeader->dns_id; // 0;

                 // query message (message type)
                DnsHeaderSetQr(&dnsZonePacket.dnsHeader.dns_hdr, 0);
                 // standary query
                DnsHeaderSetOpcode(&dnsZonePacket.dnsHeader.dns_hdr, 5);
                 // for future use
                DnsHeaderSetUpdReserved(&dnsZonePacket.dnsHeader.dns_hdr, 0);
                 // response code
                DnsHeaderSetRcode(&dnsZonePacket.dnsHeader.dns_hdr, 0);

                dnsZonePacket.dnsHeader.zoCount = 0;

                // prerequisite section RRs
                dnsZonePacket.dnsHeader.prCount = 0;

                // Update section RRs
                dnsZonePacket.dnsHeader.upCount = 1;

                // Additional section RRs
                dnsZonePacket.dnsHeader.adCount = 0;

                protocol_type = NetworkIpGetNetworkProtocolType(node,
                                              node->nodeId);
                Address destAddr = tempAnRrRecord->associatedIpAddr;
                if ((destAddr.networkType == NETWORK_IPV6) &&
                    ((protocol_type == IPV6_ONLY) ||
                    (protocol_type == DUAL_IP)))
                {
                    sourceAddress.networkType = NETWORK_IPV6;
                    Ipv6GetGlobalAggrAddress(node,
                                    interfaceId,
                                    &sourceAddress.interfaceAddr.ipv6);
                }
                else if ((destAddr.networkType == NETWORK_IPV4) &&
                    ((protocol_type == IPV4_ONLY) ||
                    (protocol_type == DUAL_IP)))
                {
                    sourceAddress.networkType = NETWORK_IPV4;
                    sourceAddress.interfaceAddr.ipv4 =
                            NetworkIpGetInterfaceAddress(node, interfaceId);
                }
                else
                {
                    continue;
                }

                item = dnsData->clientData->begin();
                while (item != dnsData->clientData->end())
                {
                    dnsClientData = (struct DnsClientData*)*item;

                    if (( dnsClientData->interfaceNo == interfaceId )||
                        ( dnsClientData->interfaceNo == ALL_INTERFACE))
                    {
                        char* domainName = strstr(dnsClientData->fqdn, ".");
                        strcpy(dnsZonePacket.dnsZone.dnsZonename,
                                domainName + 1);
                        // check whether Name server is already resolved
                        if ((dnsClientData->isNameserverResolved &&
                            (dnsQuestion->dnsQType != NS)) ||
                            dnsClientData->isUpdateSuccessful)
                        {
                            MESSAGE_Free(node, msg);
                            if (dnsHeader->anCount > 0)
                            {
                                MEM_free(answerRrs);
                            }
                            if (dnsHeader->nsCount > 0)
                            {
                                MEM_free(nameServerRrs);
                            }
                            if (dnsHeader->arCount > 0)
                            {
                                MEM_free(additionalRrs);
                            }
                            MEM_free(dnsHeader);
                            MEM_free(dnsQuestion);
                            MEM_free(dnsReplyPacket);
                            return;
                        }
                        oldSourceAddress = dnsClientData->oldIpAddress;
                        memcpy(&dnsClientData->resolvedNameServer,
                                &destAddr,
                                sizeof(Address));
                        // free next message
                        if (dnsClientData->nextMessage)
                        {
                            MESSAGE_Free(node, dnsClientData->nextMessage);
                        }
                        dnsClientData->nextMessage = NULL;
                        dnsClientData->retryCount = 0;// reset the count
                        dnsClientData->isNameserverResolved = TRUE;
                        memcpy(&rrRecord.associatedDomainName,
                                dnsClientData->fqdn,
                                strlen(dnsClientData->fqdn));
                        if (dnsHeader->anCount > 0 &&
                            (dnsQuestion->dnsQType == NS))
                        {
                            dnsClientData->receivedNsQueryResult = TRUE;
                        }
                        if (dnsHeader->anCount > 1 &&
                            (dnsQuestion->dnsQType == NS))
                        {
                            dnsClientData->nameServerList = new ServerList;
                            Address* ipaddr = NULL;
                            struct DnsRrRecord* anRrRecord = NULL;
                            anRrRecord = (struct DnsRrRecord*)answerRrs;
                            for (Int32 i = 2; i <= dnsHeader->anCount; i++)
                            {
                                anRrRecord++;
                                ipaddr = (Address*)
                                            MEM_malloc(sizeof(Address));
                                memcpy(ipaddr,
                                        &anRrRecord->associatedIpAddr,
                                        sizeof(Address));
                                dnsClientData->nameServerList->
                                                push_back(ipaddr);
                            }
                        }
                        break;
                    }
                    item++;
                }
                rrRecord.associatedIpAddr = sourceAddress;
                rrRecord.rdLength = sizeof(rrRecord.associatedIpAddr);
                rrRecord.rrClass = IN;

                if (sourceAddress.networkType == NETWORK_IPV4)
                {
                    rrRecord.rrType = A;
                }
                else
                {
                    rrRecord.rrType = AAAA;
                }
                rrRecord.ttl = dnsData->cacheRefreshTime;

                zoneFreshCount = 0;

                dnsMsg = MESSAGE_Alloc(node,
                                      TRANSPORT_LAYER,
                                      TransportProtocol_UDP,
                                      MSG_TRANSPORT_FromAppSend);

                MESSAGE_PacketAlloc(node,
                                    dnsMsg,
                                    sizeof(Address)+
                                    sizeof(enum DnsMessageType) +
                                    sizeof(zoneFreshCount) +
                                    sizeof(struct DnsZoneTransferPacket)+
                                    sizeof(struct DnsRrRecord),
                                    TRACE_DNS);

                memset(MESSAGE_ReturnPacket(dnsMsg), 0, sizeof(Address)+
                                            sizeof(enum DnsMessageType) +
                                            sizeof(zoneFreshCount) +
                                            sizeof(struct DnsZoneTransferPacket)+
                                            sizeof(struct DnsRrRecord));

                memcpy(MESSAGE_ReturnPacket(dnsMsg),
                        &msgType,
                        sizeof(enum DnsMessageType));

                memcpy(MESSAGE_ReturnPacket(dnsMsg) +
                        sizeof(enum DnsMessageType),
                        &zoneFreshCount,  sizeof(zoneFreshCount));

                memcpy(MESSAGE_ReturnPacket(dnsMsg) +
                        sizeof(enum DnsMessageType) + sizeof(zoneFreshCount),
                        &dnsZonePacket,
                        sizeof(struct DnsZoneTransferPacket));

                memcpy(MESSAGE_ReturnPacket(dnsMsg) +
                            sizeof(enum DnsMessageType) +
                            sizeof(struct DnsZoneTransferPacket) +
                            sizeof(zoneFreshCount),
                       &oldSourceAddress,
                       sizeof(Address));

                memcpy(MESSAGE_ReturnPacket(dnsMsg) +
                            sizeof(enum DnsMessageType) +
                            sizeof(struct DnsZoneTransferPacket) +
                            sizeof(zoneFreshCount)+
                            sizeof(Address),
                        &rrRecord,
                        sizeof(struct DnsRrRecord));

                MESSAGE_InfoAlloc(node,
                                  dnsMsg,
                                  sizeof(AppToUdpSend));

                info = (AppToUdpSend*) MESSAGE_ReturnInfo(dnsMsg);
                memset(info, 0, sizeof(AppToUdpSend));
                info->sourceAddr = sourceAddress;

                info->sourcePort = (short)APP_DNS_CLIENT;

                memcpy(&(info->destAddr), &destAddr, sizeof(Address));

                info->destPort = (short) APP_DNS_SERVER;
                info->priority = APP_DEFAULT_TOS;
                info->outgoingInterface = interfaceId;
                if (DEBUG)
                {
                    char remoteAddrStr[MAX_STRING_LENGTH];
                    if (destAddr.networkType != NETWORK_INVALID)
                    {
                        IO_ConvertIpAddressToString(&destAddr,
                                                    remoteAddrStr);
                    }
                    printf("\n NODE %d SENDING UPDATE TO ITS PRIMARY"
                          " NAME SERVER %s\n", node->nodeId, remoteAddrStr);
                }

                Message* dupMsg = MESSAGE_Duplicate (node, dnsMsg);

                dnsData->stat.numOfDnsUpdateRequestsSent++;
                MESSAGE_Send(node, dnsMsg, 0);
                MESSAGE_Free(node, msg);

                if (dnsClientData)
                {
                    dnsClientData->nextMessage = dupMsg;
                }
                else
                {
                    ERROR_ReportErrorArgs("Wrong message received on Node "
                        " %d due to invalid configuration and this might be "
                        "due to either assignment of IP address of any DNS"
                        " server to a DHCP clent or DNS clent configuration"
                        " is missing on this node \n",
                        node->nodeId);
                }

                AppToUdpSend* timer = NULL;
                Message* timerMsg = MESSAGE_Alloc(node,
                                        APP_LAYER,
                                        APP_DNS_CLIENT,
                                        MSG_APP_DnsUpdateNotSucceeded);

                MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppToUdpSend));
                timer = (AppToUdpSend*)MESSAGE_ReturnInfo(timerMsg);
                timer->outgoingInterface = info->outgoingInterface;
                MESSAGE_Send(node,
                            timerMsg,
                            TIMEOUT_INTERVAL_OF_DNS_QUERY_REPLY);
                dnsClientData->retryCount++;

                if (dnsHeader->anCount > 0)
                {
                    MEM_free(answerRrs);
                }

                if (dnsHeader->nsCount > 0)
                {
                    MEM_free(nameServerRrs);
                }

                if (dnsHeader->arCount > 0)
                {
                    MEM_free(additionalRrs);
                }

                MEM_free(dnsHeader);
                MEM_free(dnsQuestion);
                MEM_free(dnsReplyPacket);
                return;
            }

            if (!strcmp(dnsQuestion->dnsQname,
                tempAnRrRecord->associatedDomainName))
            {
                // First check the old expired entry if found update it.
                /*memcpy(answerUrl,
                        tempAnRrRecord->associatedDomainName,
                        DNS_NAME_LENGTH);*/
                answerUrl.assign(tempAnRrRecord->associatedDomainName);

                if (AppDnsFindOldCacheEntry(
                            dnsData->cache,
                            answerUrl, &cacheItem,
                            &incrementstats,
                            tempAnRrRecord->associatedIpAddr.networkType))
                {
                    cacheItem->associatedIpAddr =
                           tempAnRrRecord->associatedIpAddr;
                    cacheItem->deleted = FALSE;
                    cacheItem->cacheEntryTime = node->getNodeTime();
                    if (DEBUG)
                    {
                        printf("updated the cache\n");
                    }

                }
                else
                {
                    // No old entry exists so add a new entry in cache.
                    cacheItem =
                        (struct CacheRecord*)
                        MEM_malloc(sizeof(struct CacheRecord));
                    memset(cacheItem, 0, sizeof(struct CacheRecord));
                    if (DEBUG)
                    {
                        printf("\ncreate the cache\n");
                    }
                    cacheItem->urlNameString = new std::string();
                    cacheItem->urlNameString->assign(
                                    tempAnRrRecord->associatedDomainName);


                    cacheItem->associatedIpAddr =
                        tempAnRrRecord->associatedIpAddr;
                    cacheItem->deleted = FALSE;
                    cacheItem->cacheEntryTime = node->getNodeTime();

                    dnsData->cache->push_back(cacheItem);
                }

                if (incrementstats)
                {
                    DnsAppReqItemList::iterator item;
                    struct DnsAppReqListItem* appItem = NULL;
                    item = dnsData->appReqList->begin();

                    // check for matching URL
                    while (item != dnsData->appReqList->end())
                    {
                        Int32 compareResult = 0;
                        bool isSameNetworkType = false;
                        bool isInvalidNetworkType = false;
                        appItem = *item;
                        compareResult = appItem->serverUrl->compare(
                            tempAnRrRecord->associatedDomainName);
                        isSameNetworkType = tempAnRrRecord->
                            associatedIpAddr.networkType ==
                            appItem->queryNetworktype;
                        isInvalidNetworkType =
                            appItem->queryNetworktype == NETWORK_INVALID;
                        if ((compareResult == 0) &&
                            (isSameNetworkType || isInvalidNetworkType))
                        {
                            dnsData->stat.numOfDnsNameResolved++;
                            break;
                        }
                        item++;
                    }
                }

                if (DEBUG)
                {
                    printf("Node %d informs application\n", node->nodeId);
                }

                AppDnsInformApplication(
                    node,
                    tempAnRrRecord->associatedDomainName,
                    &(tempAnRrRecord->associatedIpAddr));

                MESSAGE_Free(node, msg);

                if (dnsHeader->anCount > 0)
                {
                    MEM_free(answerRrs);
                }

                if (dnsHeader->nsCount > 0)
                {
                    MEM_free(nameServerRrs);
                }

                if (dnsHeader->arCount > 0)
                {
                    MEM_free(additionalRrs);
                }

                MEM_free(dnsHeader);
                MEM_free(dnsQuestion);
                MEM_free(dnsReplyPacket);
                return;
            }
            tempAnRrRecord++;
        }
    }

    if (dnsHeader->nsCount > 0)
    {
        tempNsRrRecord = (struct DnsRrRecord*)nameServerRrs;
        memset(&sourceAddress, 0, sizeof(Address));

        for (count = 1; count <= dnsHeader->nsCount; count++)
        {
            BOOL doNoquery = FALSE;
            // Concatination of hostName and domain name
            // to form the answer URL

            answerUrl.assign(tempNsRrRecord->associatedDomainName);
            if (DEBUG)
            {
                printf("Node %d in NS orig dname %s, Ansdname %s\n",
                         node->nodeId, dnsQuestion->dnsQname,
                         tempNsRrRecord->associatedDomainName);
            }
            if (!answerUrl.compare(".") &&
                dnsQuestion->dnsQType == SOA)
            {
                Int32 interfaceId = dnsHeader->dns_id;
                struct DnsClientData* dnsClientData = NULL;
                DnsClientDataList :: iterator item;
                item = dnsData->clientData->begin();
                while (item != dnsData->clientData->end())
                {
                    dnsClientData = (struct DnsClientData*)*item;
                    if (dnsClientData->interfaceNo == interfaceId )
                    {
                        if (dnsClientData->rootQueriedCount == 2)
                        {
                            doNoquery = TRUE;
                            break;
                        }
                        dnsClientData->rootQueriedCount++;
                    }
                    item++;
                }
            }
            if (doNoquery)
            {
                continue;
            }
            // if the answerUrl matched with the Dns Question Name
            if (!answerUrl.compare(dnsQuestion->dnsQname)
                && dnsQuestion->dnsQType !=SOA)
            {
                // enter this answer into the cache so that
                // it can be used as future reference.

                struct CacheRecord* cacheItem = NULL;
                BOOL incrementstats = TRUE;

                // First check the old expired entry if found update it.
                if (AppDnsFindOldCacheEntry(
                            dnsData->cache,
                            answerUrl,
                            &cacheItem,
                            &incrementstats,
                            tempNsRrRecord->associatedIpAddr.networkType))
                {
                    cacheItem->associatedIpAddr =
                               tempNsRrRecord->associatedIpAddr;
                    cacheItem->deleted = FALSE;
                    cacheItem->cacheEntryTime = node->getNodeTime();
                    if (DEBUG)
                    {
                        printf("updated the cache\n");
                    }

                }
                else
                {
                    // No old entry exists so add a new entry in cache.
                    cacheItem =
                        (struct CacheRecord*)
                        MEM_malloc(sizeof(struct CacheRecord));
                    memset(cacheItem, 0, sizeof(struct CacheRecord));
                    if (DEBUG)
                    {
                        printf("\ncreate the cache\n");
                    }
                    cacheItem->urlNameString = new std::string();
                    cacheItem->urlNameString->assign(answerUrl);

                    cacheItem->associatedIpAddr =
                        tempNsRrRecord->associatedIpAddr;
                    cacheItem->deleted = FALSE;
                    cacheItem->cacheEntryTime = node->getNodeTime();

                    if (dnsData->cache)
                    {
                        dnsData->cache->push_back(cacheItem);
                    }
                }

                // inform the application that the
                // query has been resolved
                if (incrementstats)
                {
                    DnsAppReqItemList::iterator item;
                    struct DnsAppReqListItem* appItem = NULL;
                    item = dnsData->appReqList->begin();

                    // check for matching URL
                    while (item != dnsData->appReqList->end())
                    {
                        Int32 compareResult = 0;
                        bool isSameNetworkType = false;
                        bool isInvalidNetworkType = false;
                        appItem = *item;
                        compareResult = appItem->serverUrl->compare(
                            tempAnRrRecord->associatedDomainName);
                        isSameNetworkType = tempAnRrRecord->
                            associatedIpAddr.networkType ==
                            appItem->queryNetworktype;
                        isInvalidNetworkType =
                            appItem->queryNetworktype == NETWORK_INVALID;

                        if ((compareResult == 0) &&
                            (isSameNetworkType || isInvalidNetworkType))
                        {
                            dnsData->stat.numOfDnsNameResolved++;
                            break;
                        }
                        item++;
                    }
                }
                if (DEBUG)
                {
                    printf("Node %d invoking AppDnsInformApplication"
                            " from NS\n", node->nodeId);
                }

                AppDnsInformApplication(node,
                        answerUrl.c_str(),
                        &(tempNsRrRecord->associatedIpAddr));

                MESSAGE_Free(node, msg);

                if (dnsHeader->anCount > 0)
                {
                    MEM_free(answerRrs);
                }

                if (dnsHeader->nsCount > 0)
                {
                    MEM_free(nameServerRrs);
                }

                if (dnsHeader->arCount > 0)
                {
                    MEM_free(additionalRrs);
                }

                MEM_free(dnsHeader);
                MEM_free(dnsQuestion);
                MEM_free(dnsReplyPacket);
                return;
            }
            else
            {
                // send another query packet to
                // the reference ip address
                destAddress = tempNsRrRecord->associatedIpAddr;
            }
            enum RrType  qtype = R_INVALID;
            NetworkProtocolType protocol_type = INVALID_NETWORK_TYPE;
            protocol_type = NetworkIpGetNetworkProtocolType(
                                node,
                                node->nodeId);
            if (destAddress.networkType == NETWORK_IPV4)
            {
                if ((protocol_type == IPV4_ONLY) ||
                        (protocol_type == DUAL_IP))
                {
                    sourceAddress.networkType = NETWORK_IPV4;
                    sourceAddress.interfaceAddr.ipv4 =
                                    NetworkIpGetInterfaceAddress(node, 0);
                    qtype = A;
                }
                else
                {
                    ERROR_ReportErrorArgs(
                                "\nIncompatible Src and Dest address type");
                }
            }
            else if (destAddress.networkType == NETWORK_IPV6)
            {
                if ((protocol_type == IPV6_ONLY) ||
                    (protocol_type == DUAL_IP))
                {
                    sourceAddress.networkType = NETWORK_IPV6;
                    Ipv6GetGlobalAggrAddress(
                        node,
                        0,
                        &sourceAddress.interfaceAddr.ipv6);
                    qtype = AAAA;
                }
                else
                {
                    ERROR_ReportErrorArgs(
                                "\nIncompatible Src and Dest address type");
                }
            }
            if (DEBUG)
            {
                char srcAddrStr[MAX_STRING_LENGTH] = "";
                char dstAddrStr[MAX_STRING_LENGTH] = "";
                char buf[MAX_STRING_LENGTH] = "";
                TIME_PrintClockInSecond(node->getNodeTime(), buf);
                IO_ConvertIpAddressToString(&destAddress, dstAddrStr);
                IO_ConvertIpAddressToString(&sourceAddress, srcAddrStr);
                printf("DNS client %d %s Sending new query to the next"
                       " server %s at %sS\n",
                       node->nodeId,
                       srcAddrStr,
                       dstAddrStr,
                       buf);
            }
            if (((destAddress.networkType == NETWORK_IPV4) &&
               (sourceAddress.networkType == NETWORK_IPV6)) ||
               ((destAddress.networkType == NETWORK_IPV6) &&
               (sourceAddress.networkType == NETWORK_IPV4)))
            {
                char dstAddrStr[MAX_STRING_LENGTH] = "";
                IO_ConvertIpAddressToString(&destAddress, dstAddrStr);
                ERROR_ReportErrorArgs(
                    "Node type %d and Dns server %s type does not match."
                    "Cannot send query\n",
                    node->nodeId,
                    dstAddrStr);
            }
            BOOL isprimary = FALSE;
            if (dnsQuestion->dnsQType == SOA)
            {
                qtype = SOA;
            }
            AppDnsCreateAndSendQuery(
                node,
                isprimary,
                dnsQuestion,
                dnsHeader->dns_id,
                sourceAddress,
                sourcePort,
                destAddress,
                qtype);
            tempNsRrRecord++;
        } // end of for
    } // end of dnsHeader->nsCount check

    if (dnsHeader->arCount > 0)
    {
        printf(" Node %u has arCount %d \n",
            node->nodeId, dnsHeader->arCount);
    }

    if (dnsHeader->anCount == 0 &&
        dnsHeader->nsCount == 0 &&
        dnsHeader->arCount == 0)
    {
        NetworkProtocolType sourcetype =
            NetworkIpGetNetworkProtocolType(node, node->nodeId);

        struct DnsAppReqListItem* appItem = NULL;
        DnsAppReqItemList :: iterator lstItem;
        lstItem = dnsData->appReqList->begin();
        BOOL isAppItemExist = FALSE;
        while (lstItem != dnsData->appReqList->end())
        {
            appItem = (struct DnsAppReqListItem*)*lstItem;
            if ((appItem->serverUrl->compare(dnsQuestion->dnsQname) == 0) &&
                (appItem->sourcePort == sourcePort))
            {
                isAppItemExist = TRUE;
                if ((appItem->queryNetworktype == NETWORK_IPV6) &&
                    ( appItem->AAAASend == TRUE) &&
                    (appItem->ASend == TRUE))
                {
                    char errStr[MAX_STRING_LENGTH];
                    sprintf(errStr,
                            "Could not resolve url %s",
                            dnsQuestion->dnsQname);
                    ERROR_ReportWarning(errStr);
                }
                break;
            }
            lstItem++;
        }

        if ((sourcetype == DUAL_IP) &&
            (isAppItemExist && appItem->AAAASend == TRUE))
        {
            if ((isAppItemExist && appItem->ASend == FALSE) &&
                dnsQuestion->dnsQType == AAAA)
            {
                NodeAddress tempNodeId = 0;
                appItem->ASend = TRUE;
                appItem->queryNetworktype = NETWORK_IPV4;
                AppToUdpSend* info = NULL;
                info = (AppToUdpSend*) MESSAGE_ReturnInfo(msg);
                destAddress = info->sourceAddr;
                if (destAddress.networkType == NETWORK_IPV4)
                {
                    sourceAddress.networkType = NETWORK_IPV4;
                    sourceAddress.interfaceAddr.ipv4 =
                            NetworkIpGetInterfaceAddress(node, 0);
                }
                else if (destAddress.networkType == NETWORK_IPV6)
                {
                    sourceAddress.networkType = NETWORK_IPV6;
                    Ipv6GetGlobalAggrAddress(
                        node,
                        0,
                        &sourceAddress.interfaceAddr.ipv6);
                }

                if (DEBUG)
                {
                    char srcAddrStr[MAX_STRING_LENGTH] = "";
                    char dstAddrStr[MAX_STRING_LENGTH] = "";
                    char buf[MAX_STRING_LENGTH] = "";
                    TIME_PrintClockInSecond(node->getNodeTime(), buf);
                    IO_ConvertIpAddressToString(&destAddress, dstAddrStr);
                    IO_ConvertIpAddressToString(&sourceAddress, srcAddrStr);
                    printf("DNS client %d %s Sending new query to the next"
                        " server %s at %sS\n",
                        node->nodeId,
                        srcAddrStr,
                        dstAddrStr,
                        buf);
                }
                if (((destAddress.networkType == NETWORK_IPV4) &&
                    (sourceAddress.networkType == NETWORK_IPV6)) ||
                    ((destAddress.networkType == NETWORK_IPV6) &&
                    (sourceAddress.networkType == NETWORK_IPV4)))
                {
                   char errStr[MAX_STRING_LENGTH] = "";
                   sprintf(errStr,
                       "Node type %d and Dns server %d type does not match."
                       "Cannot send query\n",
                       node->nodeId,
                       tempNodeId);
                   ERROR_ReportWarning(errStr);
                }

                BOOL isprimary = FALSE;
                memcpy(&isprimary,
                       MESSAGE_ReturnPacket(msg) + sizeof(struct DnsQueryPacket),
                       sizeof(BOOL));

                AppDnsCreateAndSendQuery(node,
                    isprimary,
                    dnsQuestion,
                    dnsHeader->dns_id,
                    sourceAddress,
                    sourcePort,
                    destAddress,
                    A);
            }
            else if (dnsQuestion->dnsQType == A)
            {
                char errStr[MAX_STRING_LENGTH] = "";
                sprintf(errStr,
                        "Could not resolve url %s",
                        dnsQuestion->dnsQname);
                ERROR_ReportWarning(errStr);
            }
        }
        else
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr,
                    "Could not resolve url %s",
                    dnsQuestion->dnsQname);
            ERROR_ReportWarning(errStr);
        }
    }

    MESSAGE_Free(node, msg);

    if (dnsHeader->anCount > 0)
    {
        MEM_free(answerRrs);
    }

    if (dnsHeader->nsCount > 0)
    {
        MEM_free(nameServerRrs);
    }

    if (dnsHeader->arCount > 0)
    {
        MEM_free(additionalRrs);
    }
    MEM_free(dnsHeader);
    MEM_free(dnsQuestion);
    MEM_free(dnsReplyPacket);
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsRefreshCache
// LAYER        :: Application Layer
// PURPOSE      :: Set the cache refresh timer
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: None
//--------------------------------------------------------------------------
static void AppDnsRefreshCache(Node* node, Message* msg)
{
    CacheRecordList :: iterator item;
    struct CacheRecord* cacheItem = NULL;
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
    if (DEBUG)
    {
        printf("\n**In AppDnsRefreshCache \n");
    }
    // Otherwise seach associated list
    if (!dnsData->cache)
    {
        // reschedule refresh timer
        if (DEBUG)
        {
            printf("\nIn AppDnsRefreshCache reschedule refresh timer\n");
        }
        MESSAGE_Send(node, msg, dnsData->cacheRefreshTime);
        if (DEBUG)
        {
            printf("\n**Out AppDnsRefreshCache \n");
        }
        return;
    }

    item = dnsData->cache->begin();

    // Delete mark all the entrires which has expired....!
    while (item != dnsData->cache->end())
    {
        cacheItem = (struct CacheRecord*)*item;

        // Check the entry if it is already expired or older
        // then cache refresh time.

        if ((clocktype)(node->getNodeTime() - cacheItem->cacheEntryTime) >=
              dnsData->cacheRefreshTime)
        {
            if (cacheItem->deleted == FALSE)
            {
                // delete the cache entry:
                if (DEBUG)
                {
                    printf("AppDnsRefreshCache Marking deleted for cache "
                        "item %s in node %d\n",
                        cacheItem->urlNameString->c_str(),
                        node->nodeId);
                }
                cacheItem->deleted = TRUE;
                if (DEBUG)
                {
                    char buf[MAX_STRING_LENGTH] = "";
                    TIME_PrintClockInSecond(cacheItem->cacheEntryTime, buf);
                    printf("node %d %s Deleting DNS Cache entry\n",
                        node->nodeId, buf);
                }
            }
        }
        item++;
    }
    MESSAGE_Send(node, msg, dnsData->cacheRefreshTime);
    if (DEBUG)
    {
        printf("\nOut AppDnsRefreshCache \n");
    }
}



//--------------------------------------------------------------------------
// FUNCTION     :: AppLayerDnsClient
// LAYER        :: Application Layer
// PURPOSE      :: Diffrent Type of Message served by DNS Client
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: None
//--------------------------------------------------------------------------
void AppLayerDnsClient(Node* node, Message* msg)
{
    switch (msg->eventType)
    {
        case MSG_APP_DnsStartResolveUrl:
        {
            AppDnsHandleResolveUrlProcess(node, msg);
            break;
        }
        case MSG_APP_FromTransport:
        {
            AppDnsHandleMsgFromTransport(node, msg);
            break;
        }
        case MSG_APP_DnsCacheRefresh :
        {
            AppDnsRefreshCache(node, msg);
            break;
        }
        case MSG_APP_DnsRetryResolveNameServer:
        {
            AppDnsRetryResolveNameserver(node, msg);
            break;
        }
        case MSG_APP_DnsUpdateNotSucceeded:
        {
            AppDnsUpdateNotSucceeded(node, msg);
            break;
        }
        default:
            break;
    }// end of switch-case
}

//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsSendNotifyToSlaves
// LAYER        :: Application Layer
// PURPOSE      :: Diffrent Type of Message served by DNS Client
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsSendNotifyToSlaves(Node* node)
{
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;

    struct ZoneData* zoneData = dnsData->zoneData;
    data* tempData = NULL;
    ZoneDataList :: iterator item;
    struct DnsTreeInfo* dnsTreeInfo = dnsData->server->dnsTreeInfo;
    clocktype addTime = 0;
    clocktype lastZoneTransferTime = dnsData->lastZoneTransferTime;

    Int32 size = zoneData->data->size();
    item = zoneData->data->begin();

    while (size != 0)
    {
        tempData = (data*)*item;
        clocktype time = node->getNodeTime() / SECOND;
        if (time < (tempData->timeAdded / SECOND))
        {
            item++;
            size--;
            continue;
        }
        if (tempData->timeAdded != 0 &&
            (time == (tempData->timeAdded/SECOND)))
        {
            item++;
            size--;
            continue;
        }
        if ((node->getNodeTime() - lastZoneTransferTime) <=0 &&
            lastZoneTransferTime)
        {
            return;
        }
        if (lastZoneTransferTime &&
            ((node->getNodeTime() - lastZoneTransferTime) <
                                DEFAULT_MIN_ZONE_TRANSFER_INTERVAL))
        {
            addTime = (DEFAULT_MIN_ZONE_TRANSFER_INTERVAL -
                node->getNodeTime()) + lastZoneTransferTime;
            dnsData->lastZoneTransferTime = node->getNodeTime() + addTime;
        }
        else if (!lastZoneTransferTime)
        {
            dnsData->lastZoneTransferTime = node->getNodeTime();
        }
        Message* notifyMsg = NULL;
        AppToUdpSend* info = NULL;
        enum DnsMessageType msgType;
        msgType = DNS_NOTIFY;
        struct DnsQueryPacket* dnsNotifyPacket = NULL;

        dnsNotifyPacket =
            (struct DnsQueryPacket*)MEM_malloc(sizeof(struct DnsQueryPacket));

        memset(dnsNotifyPacket, 0, sizeof(struct DnsQueryPacket));

        memcpy(dnsNotifyPacket->dnsQuestion.dnsQname,
            dnsTreeInfo->domainName, DNS_NAME_LENGTH);

        dnsNotifyPacket->dnsQuestion.dnsQClass = IN ;
        dnsNotifyPacket->dnsQuestion.dnsQType = SOA;
        dnsNotifyPacket->dnsHeader.dns_id = 1;

         // query message (message type)
        DnsHeaderSetQr(&dnsNotifyPacket->dnsHeader.dns_hdr, 0);
         // standary query
        DnsHeaderSetOpcode(&dnsNotifyPacket->dnsHeader.dns_hdr, 4);
         // valid from responses
        DnsHeaderSetAA(&dnsNotifyPacket->dnsHeader.dns_hdr, 0);
         // truncated or not
        DnsHeaderSetTC(&dnsNotifyPacket->dnsHeader.dns_hdr, 0);
         // recursion desired
        DnsHeaderSetRD(&dnsNotifyPacket->dnsHeader.dns_hdr, 0);
         // recursion available
        DnsHeaderSetRA(&dnsNotifyPacket->dnsHeader.dns_hdr, 0);
         // for future use
        DnsHeaderSetReserved(&dnsNotifyPacket->dnsHeader.dns_hdr, 0);
         // response code
        DnsHeaderSetRcode(&dnsNotifyPacket->dnsHeader.dns_hdr, 0);

        Address sourceAddress;

        memset(&sourceAddress, 0, sizeof(Address));

        NetworkProtocolType protocol_type = INVALID_NETWORK_TYPE;

        protocol_type =
            NetworkIpGetNetworkProtocolType(node, node->nodeId);

        if ((protocol_type == IPV6_ONLY) || (protocol_type == DUAL_IP))
        {
             sourceAddress.networkType = NETWORK_IPV6;
             Ipv6GetGlobalAggrAddress(node,
                             0,
                             &sourceAddress.interfaceAddr.ipv6);
        }
        else if (protocol_type == IPV4_ONLY)
        {
             sourceAddress.networkType = NETWORK_IPV4;
             sourceAddress.interfaceAddr.ipv4 =
                             NetworkIpGetInterfaceAddress(node, 0);
        }

        notifyMsg = MESSAGE_Alloc(
            node,
            TRANSPORT_LAYER,
            TransportProtocol_UDP,
            MSG_TRANSPORT_FromAppSend);

        MESSAGE_PacketAlloc(node,
                notifyMsg,
                sizeof(enum DnsMessageType)+ sizeof(struct DnsQueryPacket),
                TRACE_DNS);

        memcpy(MESSAGE_ReturnPacket(notifyMsg),
               &msgType,
               sizeof(enum DnsMessageType));

        memcpy(MESSAGE_ReturnPacket(notifyMsg) + sizeof(enum DnsMessageType),
              (char*)(dnsNotifyPacket),
              sizeof(struct DnsQueryPacket));

        MESSAGE_InfoAlloc(node,
            notifyMsg,
            sizeof(AppToUdpSend));

        info = (AppToUdpSend*) MESSAGE_ReturnInfo(notifyMsg);
        memset(info, 0, sizeof(AppToUdpSend));
        info->sourceAddr = sourceAddress;

        info->sourcePort = node->appData.nextPortNum++;

        info->destAddr = tempData->zoneServerAddress;

        info->destPort = (short) APP_DNS_SERVER;
        info->priority = APP_DEFAULT_TOS;
        info->outgoingInterface = ANY_INTERFACE;

        MESSAGE_Send(node, notifyMsg, addTime);

        dnsData->stat.numOfDnsNotifySent++;
        item++;
        size--;

        // Create an entry in the RetryQueue
        struct RetryQueueData* tempRetryData =
            (struct RetryQueueData*)MEM_malloc(sizeof(struct RetryQueueData));
        memset(tempRetryData, 0, sizeof(struct RetryQueueData));

        memcpy(&(tempRetryData->zoneServerAddress),
                &(tempData->zoneServerAddress),
                sizeof(Address));
        tempRetryData->countRetrySent= 1;
        memcpy(&(tempRetryData->dnsNotifyPacket),
                dnsNotifyPacket,
                sizeof(struct DnsQueryPacket));

        dnsData->zoneData->retryQueue->push_back(tempRetryData);

        // Also start the NOTIFY_REFRESH_TIMER (60 Sec)

        Message* timerMsg = MESSAGE_Alloc(node,
                                    APP_LAYER,
                                    APP_DNS_SERVER,
                                    MSG_APP_DNS_NOTIFY_REFRESH_TIMER);
        MESSAGE_PacketAlloc(node,
                timerMsg,
                sizeof(Address)+
                sizeof(AppToUdpSend),
                TRACE_DNS);

        memcpy(MESSAGE_ReturnPacket(timerMsg),
               &(tempData->zoneServerAddress),
               sizeof(Address));

        memcpy(MESSAGE_ReturnPacket(timerMsg) +
               sizeof(Address),
               info,
               sizeof(AppToUdpSend));

        MESSAGE_Send(node, timerMsg, (NOTIFY_REFRESH_INTERVAL + addTime));
    } // end of while
}


//--------------------------------------------------------------------------
// FUNCTION     :: DNSProcessUpdateMessageFromServers
// LAYER        :: Application Layer
// PURPOSE      :: Diffrent Type of Message processing by DNS Server
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: None
//--------------------------------------------------------------------------
static void DNSProcessUpdateMessageFromServers(Node* node, Message* msg)
{
    char newServerLabel[DNS_NAME_LENGTH] = "";
    Address newServerAddr;
    struct DnsZoneTransferPacket* dnsZoneReplyPacket = NULL;
    UInt32 zoneRefreshCount = 0;
    UInt32 recordSize = 0;
    char* recordPtr = NULL;
    enum DnsMessageType msgType;
    if (DEBUG)
    {
        printf(" Node %u in DNSProcessUpdateMessageFromServers \n",
               node->nodeId);
    }
    memcpy(&msgType,
        MESSAGE_ReturnPacket(msg), (sizeof(enum DnsMessageType)));

    char* dnsPacketPtr = MESSAGE_ReturnPacket(msg) +
                        sizeof(enum DnsMessageType);

    dnsZoneReplyPacket = (struct DnsZoneTransferPacket*)
                                MEM_malloc(sizeof(struct DnsZoneTransferPacket));

    memcpy(&zoneRefreshCount, dnsPacketPtr, sizeof(zoneRefreshCount));
    dnsPacketPtr += sizeof(zoneRefreshCount);

    memcpy(dnsZoneReplyPacket, dnsPacketPtr,
           (sizeof(struct DnsZoneTransferPacket)));
    dnsPacketPtr += sizeof(struct DnsZoneTransferPacket);

    memcpy(&newServerAddr, dnsPacketPtr, (sizeof(Address)));

    dnsPacketPtr += sizeof(Address);

    memcpy(newServerLabel, dnsPacketPtr,
              sizeof(newServerLabel));
    dnsPacketPtr += sizeof(newServerLabel);
    memcpy(&recordSize, dnsPacketPtr,
          sizeof(UInt32));
    dnsPacketPtr += sizeof(UInt32);
    recordPtr = (char*)MEM_malloc(recordSize * sizeof(struct DnsRrRecord));
    memcpy(recordPtr, dnsPacketPtr,
          recordSize * sizeof(struct DnsRrRecord));
    clocktype time = node->getNodeTime()/SECOND;
    AppDnsAddServerToTree(node,
                    &newServerAddr,
                    newServerLabel,
                    recordSize,
                    recordPtr);

    // Since Zone Changes have occurred, the Zone Master will notify the
    // slaves of the Zone of the RR changes.

    // For each of the Zone Slaves (Notify List) from data structure ZoneData
    //     1)create an DNS NOTIFY message.
    //     2)send the message on UDP.
    //
    clocktype zoneRefreshTime = (ZONE_REFRESH_INTERVAL/SECOND);
    if (time % zoneRefreshTime)
    {
        AppDnsSendNotifyToSlaves(node);
    }
}

//--------------------------------------------------------------------------
// FUNCTION     :: DNSProcessUpdateMessageFromDnsHost
// LAYER        :: Application Layer
// PURPOSE      :: Diffrent Type of Message processing by DNS Server
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: None
//--------------------------------------------------------------------------
static void DNSProcessUpdateMessageFromDnsHost(Node* node,
                                               Message* msg,
                                               Address oldIpAddress)
{
    enum DnsMessageType msgType;
    struct DnsZoneTransferPacket* dnsZoneReplyPacket = NULL;
    Address destAddress;
    struct DnsRrRecord dnsRrRecord;
    UInt32 zoneRefreshCount = 0;
    DnsRrRecordList :: iterator rrList;
    DnsRrRecordList :: iterator rrRecord;
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;

    BOOL isUpdateSuccessful = FALSE;
    char serverDomain[DNS_NAME_LENGTH] = "";
    AppToUdpSend* oldInfo = NULL;
    oldInfo = (AppToUdpSend*) MESSAGE_ReturnInfo(msg);
    if (!dnsData)
    {
        ERROR_ReportErrorArgs("Node %d is not a DNS Server", node->nodeId);
    }

    if (dnsData->server == NULL)
    {
       ERROR_ReportErrorArgs("Update Message received on non-server node");
    }
    strcpy(serverDomain,
           dnsData->server->dnsTreeInfo->domainName);
    memset(&destAddress, 0, sizeof(Address));
    memcpy( &msgType, MESSAGE_ReturnPacket(msg),
            (sizeof(enum DnsMessageType)));

    char* dnsPacketPtr = MESSAGE_ReturnPacket(msg) +
                        sizeof(enum DnsMessageType);

    dnsZoneReplyPacket = (struct DnsZoneTransferPacket*)
                                MEM_malloc(sizeof(struct DnsZoneTransferPacket));

    memcpy(&zoneRefreshCount, dnsPacketPtr, sizeof(zoneRefreshCount));
    dnsPacketPtr += sizeof(zoneRefreshCount);

    memcpy(dnsZoneReplyPacket, dnsPacketPtr,
           (sizeof(struct DnsZoneTransferPacket)));
    dnsPacketPtr += sizeof(struct DnsZoneTransferPacket);

    memcpy(&destAddress, dnsPacketPtr, (sizeof(Address)));
    dnsPacketPtr += sizeof(Address);

    memcpy(&dnsRrRecord, dnsPacketPtr, (sizeof(struct DnsRrRecord)));

    // Increment the zone fresh count as newer data has arrived.
    dnsData->zoneData->zoneFreshCount++;

    rrList = dnsData->server->rrList->begin();
    rrRecord = dnsData->server->rrList->begin();

    if (rrList == dnsData->server->rrList->end())
    {
        ERROR_ReportErrorArgs("Node %d don't have any" \
            "authoritative information",
            node->nodeId);
    }
    struct DnsRrRecord* rrItemSoa = NULL;
    while (rrRecord != dnsData->server->rrList->end())
    {
        struct DnsRrRecord* rrItem = NULL;
        rrItem = (struct DnsRrRecord*)*rrRecord;
        if (rrItem->rrType == SOA)
        {
            rrItemSoa = rrItem;
            break;
        }
        rrRecord++;
    }

    if ((rrItemSoa &&!strcmp(rrItemSoa->associatedDomainName,
        dnsZoneReplyPacket->dnsZone.dnsZonename)) ||
        !strcmp(serverDomain,
        dnsZoneReplyPacket->dnsZone.dnsZonename))
    {
        rrRecord = dnsData->server->rrList->begin();
        // Update the IP address.
        while (rrRecord != dnsData->server->rrList->end())
        {
            struct DnsRrRecord* rrItem = (DnsRrRecord*)*rrRecord;

            if (strcmp(rrItem->associatedDomainName,
                dnsRrRecord.associatedDomainName) == 0 &&
                rrItem->rdLength == dnsRrRecord.rdLength &&
                rrItem->rrClass == dnsRrRecord.rrClass &&
                    rrItem->rrType == dnsRrRecord.rrType &&
                   !MAPPING_CompareAddress(rrItem->associatedIpAddr,
                   oldIpAddress))
            {
                memcpy(&rrItem->associatedIpAddr,
                    &dnsRrRecord.associatedIpAddr,
                    sizeof(Address));
                isUpdateSuccessful = TRUE;
                break;
            }
            rrRecord++;
        }
    }

    // Since Zone Changes have occurred, the Zone Master will notify the
    // slaves of the Zone of the RR changes.

    // For each of the Zone Slaves (Notify List) from data structure ZoneData
    //     1)create an DNS NOTIFY message.
    //     2)send the message on UDP.
    //
    if (isUpdateSuccessful &&
        dnsData->zoneData->isMasterOrSlave)
    {
        AppDnsSendNotifyToSlaves(node);
    }

    struct DnsZoneTransferPacket dnsZonePacket;

    memset(&dnsZonePacket, 0, sizeof(struct DnsZoneTransferPacket));
    strcpy(dnsZonePacket.dnsZone.dnsZonename,
        dnsZoneReplyPacket->dnsZone.dnsZonename);
    dnsZonePacket.dnsZone.dnsZoneType = SOA;
    dnsZonePacket.dnsZone.dnsZoneClass = IN;

    dnsZonePacket.dnsHeader.dns_id = dnsZoneReplyPacket->dnsHeader.dns_id;

     // query message (message type)
    DnsHeaderSetQr(&dnsZonePacket.dnsHeader.dns_hdr, 0);
     // standary query
    DnsHeaderSetOpcode(&dnsZonePacket.dnsHeader.dns_hdr, 0);
     // for future use
    DnsHeaderSetUpdReserved(&dnsZonePacket.dnsHeader.dns_hdr, 0);
    if (isUpdateSuccessful)
    {
        // response code
        DnsHeaderSetRcode(&dnsZonePacket.dnsHeader.dns_hdr, NOERROR);
        if (DEBUG)
        {
            printf("DNS UPDATE %d->%d IS SUCCESSFUL \n",
                msg->originatingNodeId, node->nodeId);
        }
    }
    else
    {
        DnsHeaderSetRcode(&dnsZonePacket.dnsHeader.dns_hdr, NOTAUTH);
        if (DEBUG)
        {
            printf("DNS UPDATE %d->%d IS FAILED \n",
                msg->originatingNodeId, node->nodeId);
        }
    }

    dnsZonePacket.dnsHeader.zoCount = 0;

    // prerequisite section RRs
    dnsZonePacket.dnsHeader.prCount = 0;

    // Update section RRs
    dnsZonePacket.dnsHeader.upCount = 0;

    // Additional section RRs
    dnsZonePacket.dnsHeader.adCount = 0;

    Message* dnsMsg = NULL;
    dnsMsg = MESSAGE_Alloc(node,
                          TRANSPORT_LAYER,
                          TransportProtocol_UDP,
                          MSG_TRANSPORT_FromAppSend);

    MESSAGE_PacketAlloc(node,
                        dnsMsg,
                        sizeof(struct DnsZoneTransferPacket),
                        TRACE_DNS);

    memset(MESSAGE_ReturnPacket(dnsMsg), 0, sizeof(struct DnsZoneTransferPacket));


    memcpy(MESSAGE_ReturnPacket(dnsMsg),
             &dnsZonePacket,
             sizeof(struct DnsZoneTransferPacket));

    MESSAGE_InfoAlloc(node,
                      dnsMsg,
                      sizeof(AppToUdpSend));

    AppToUdpSend* info = (AppToUdpSend*) MESSAGE_ReturnInfo(dnsMsg);
    memset(info, 0, sizeof(AppToUdpSend));
    info->sourceAddr = oldInfo->destAddr;

    info->sourcePort = (short) APP_DNS_SERVER;

    memcpy(&(info->destAddr),&dnsRrRecord.associatedIpAddr, sizeof(Address));

    info->destPort = (short)APP_DNS_CLIENT;
    info->priority = APP_DEFAULT_TOS;
    info->outgoingInterface = ANY_INTERFACE;
    MESSAGE_Send(node, dnsMsg, 0);
    MESSAGE_Free(node, msg);
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppLayerDnsServer
// LAYER        :: Application Layer
// PURPOSE      :: Diffrent Type of Message processing by DNS Server
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: None
//--------------------------------------------------------------------------
void AppLayerDnsServer(Node* node, Message* msg)
{
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;

    if ((dnsData == NULL) || (dnsData->server == NULL))
    {
         // I am not a server so
         if (DEBUG)
         {
             printf("Node %d is not a valid DNS server\n", node->nodeId);
         }
         return;
    }

    switch (msg->eventType)
    {
        case MSG_APP_FromTransport:
        {
            enum DnsMessageType msgType;
            memcpy(&msgType,
                MESSAGE_ReturnPacket(msg),
                (sizeof(enum DnsMessageType)));

            char* dnsPacketPtr = MESSAGE_ReturnPacket(msg) +
                                 sizeof(enum DnsMessageType);

            UdpToAppRecv* dnsPacketInfo =
                (UdpToAppRecv*) MESSAGE_ReturnInfo(msg);

            short remote_prt = dnsPacketInfo->sourcePort;
            if (DEBUG)
            {
                printf("Node %d:In AppLayerDnsServer, The Remote port"
                        " is %d\n", node->nodeId, remote_prt);
            }

            if (msgType == DNS_UPDATE)
            {
                DnsRrRecordList :: iterator rrList;
                struct DnsData* dnsData = NULL;
                UInt32 slaveZoneRefreshCount;
                BOOL free_msg = TRUE;
                if (DEBUG)
                {
                    printf("Node %d: RECEIVED DNS_UPDATE MESSAGE\n",
                            node->nodeId);
                }
                dnsData = (struct DnsData*)node->appData.dnsData;
                dnsData->stat.numOfDnsUpdateRequestsReceived++;
                rrList = dnsData->server->rrList->begin();

                struct DnsZoneTransferPacket* dnsZoneReplyPacket = NULL;
                Address destAddress;
                memset(&destAddress, 0, sizeof(Address));
                dnsZoneReplyPacket = (struct DnsZoneTransferPacket*)
                                MEM_malloc(sizeof(struct DnsZoneTransferPacket));

                memset(dnsZoneReplyPacket, 0, sizeof(struct DnsZoneTransferPacket));

                memcpy(&slaveZoneRefreshCount,
                    dnsPacketPtr,
                    sizeof(slaveZoneRefreshCount));

                dnsPacketPtr += sizeof(slaveZoneRefreshCount);

                memcpy(dnsZoneReplyPacket,
                    dnsPacketPtr,
                    (sizeof(struct DnsZoneTransferPacket)));

                dnsPacketPtr += sizeof(struct DnsZoneTransferPacket);

                memcpy(&destAddress,
                    dnsPacketPtr,
                    (sizeof(Address)));

                if (dnsZoneReplyPacket->dnsHeader.upCount == 1)
                {
                    // This means that zone is being modified as a result of
                    // the Ipaddress getting modified ofa DNS host.
                    if (DEBUG)
                    {
                        printf("Node %d: PROCESSING DHCP UPDATE\n",
                            node->nodeId);
                    }
                    DNSProcessUpdateMessageFromDnsHost(node,
                                                        msg,
                                                        destAddress);
                }
                else if (dnsZoneReplyPacket->dnsHeader.upCount == 2)
                {
                    // This means that zone is being modified as a result of
                    // addition of a new server at runtime
                    if (DEBUG)
                    {
                        printf("Node %d: PROCESSING DNS UPDATE FROM "
                            "SERVER\n", node->nodeId);
                    }
                    DNSProcessUpdateMessageFromServers(node, msg);
                }
                else if ((dnsData->zoneData->zoneFreshCount >
                    slaveZoneRefreshCount))
                {
                    Address clientAddr;
                    memset(&clientAddr, 0, sizeof(Address));

                    // this is a slave for this zone
                    if (dnsData->zoneData->isMasterOrSlave == TRUE)
                    {
                        // source address and source port generation
                        if (DEBUG)
                        {
                            printf("Node %d: DNS UPDATE REQUEST RECEIVED"
                                " FROM SECONDARY SERVER\n", node->nodeId);
                        }
                        NetworkProtocolType protocol_type =
                              INVALID_NETWORK_TYPE;
                        protocol_type =
                            NetworkIpGetNetworkProtocolType(node,
                                                msg->originatingNodeId);
                        if (protocol_type == IPV6_ONLY)
                        {
                            clientAddr.networkType = NETWORK_IPV6;
                            Ipv6GetGlobalAggrAddress(node,
                                0,
                                &clientAddr.interfaceAddr.ipv6);
                        }
                        else if (protocol_type == IPV4_ONLY)
                        {
                            clientAddr.networkType = NETWORK_IPV4;
                            clientAddr.interfaceAddr.ipv4 =
                                      NetworkIpGetInterfaceAddress(node, 0);
                        }
                        else if (protocol_type == DUAL_IP)
                        {
                            if (destAddress.networkType == NETWORK_IPV4)
                            {
                                clientAddr.networkType = NETWORK_IPV4;
                                clientAddr.interfaceAddr.ipv4 =
                                      NetworkIpGetInterfaceAddress(node, 0);
                            }
                            else
                            {
                                clientAddr.networkType = NETWORK_IPV6;
                                Ipv6GetGlobalAggrAddress(node,
                                    0,
                                    &clientAddr.interfaceAddr.ipv6);
                            }
                        }
                    }
                    else
                    {
                        ERROR_ReportErrorArgs("The Node: %d is not a MASTER"
                         "DNS Server for this zone to get this timer event",
                            node->nodeId);
                    }

                    if (DEBUG)
                    {
                        printf("Slave node : %d Start TCP open process\n",
                            node->nodeId);
                    }

                    // client initialization

                    struct DnsServerZoneTransferClient* clientPtr = NULL;

                    clientPtr = AppDnsZoneClientNewDnsZoneClient(
                        node, clientAddr, destAddress,
                        1,// itemsToSend
                        (dnsData->server->rrList->size() *
                            sizeof(struct DnsRrRecord)) +
                            sizeof(struct DnsZoneTransferPacket),// itemSize,
                         0,// endTime,
                         0);// (TosType) tos);

                    // end of client initialization
                    free_msg = FALSE;
                    clientPtr->dataSentPtr = (void*)dnsZoneReplyPacket;
                    dnsData->stat.numOfDnsUpdateSent++;

                    APP_TcpOpenConnection(
                        node,
                        APP_DNS_SERVER,
                        clientAddr,
                        (short)node->appData.nextPortNum++,
                        destAddress,
                        (short) APP_DNS_SERVER,
                        clientPtr->uniqueId,
                        0,
                        APP_DEFAULT_TOS);
                }
                else
                {
                    if (DEBUG)
                    {
                        printf("Node %d: SECONDARY DNS SERVER IS "
                            "UP TO DATE\n", node->nodeId);
                    }
                }
                if (free_msg)
                {
                    MEM_free(dnsZoneReplyPacket);
                }
            }

            else if (msgType == DNS_QUERY)
            {
                struct DnsQueryPacket dnsQueryPacket;
                struct DnsQueryPacket* dnsReplyPacket = NULL;
                char serverDomain[DNS_NAME_LENGTH] = "";
                BOOL answerFound = FALSE;
                BOOL isAuthoritiveAnswer = FALSE;
                Address sourceAddress;
                Int16 sourcePort;
                UInt16 anCount;
                UInt16 nsCount;
                UInt16 arCount;
                struct DnsRrRecord* answerRrs = NULL;
                struct DnsRrRecord* nameServerRrs = NULL;
                struct DnsRrRecord* additionalRrs = NULL;
                BOOL flag = FALSE;
                UInt32 packetSize;
                Address destAddress;

                if (DEBUG)
                {
                    char buf[MAX_STRING_LENGTH];
                    TIME_PrintClockInSecond(node->getNodeTime(), buf);
                    printf("AppLayerDnsServer: Node %d got query pkt "
                           "at %sS\n", node->nodeId, buf);
                }
                dnsData->stat.numOfDnsQueryRecv++;
                memset(&sourceAddress, 0, sizeof(Address));
                memset(&destAddress, 0, sizeof(Address));
                // memory allocation for answer's, name server's and
                // additional RR records
                answerRrs = (struct DnsRrRecord*)MEM_malloc(
                            MAX_RR_RECORD_NO * sizeof(struct DnsRrRecord));

                nameServerRrs = (struct DnsRrRecord*)
                                    MEM_malloc(MAX_NS_RR_RECORD_NO *
                                        sizeof(struct DnsRrRecord));

                additionalRrs = (struct DnsRrRecord*)MEM_malloc(
                            MAX_RR_RECORD_NO * sizeof(struct DnsRrRecord));

                // source address and source port generation

                NetworkProtocolType protocol_type = INVALID_NETWORK_TYPE;

                protocol_type =
                    NetworkIpGetNetworkProtocolType(node,
                                                    node->nodeId);

                if (protocol_type == IPV6_ONLY)
                {
                    sourceAddress.networkType = NETWORK_IPV6;
                    Ipv6GetGlobalAggrAddress(
                                node,
                                0,
                                &sourceAddress.interfaceAddr.ipv6);
                }
                else if (protocol_type == IPV4_ONLY)
                {
                    sourceAddress.networkType = NETWORK_IPV4;
                    sourceAddress.interfaceAddr.ipv4 =
                                      NetworkIpGetInterfaceAddress(node, 0);
                }
                else if (protocol_type == DUAL_IP)
                {
                    // Search through first IPv6 address
                    if (destAddress.networkType == NETWORK_IPV4)
                    {
                        sourceAddress.networkType = NETWORK_IPV4;
                        sourceAddress.interfaceAddr.ipv4 =
                                      NetworkIpGetInterfaceAddress(node, 0);
                    }
                    else
                    {
                        sourceAddress.networkType = NETWORK_IPV6;
                        Ipv6GetGlobalAggrAddress(node,
                                    0,
                                    &sourceAddress.interfaceAddr.ipv6);
                    }
                }

                sourcePort = node->appData.nextPortNum++;
                char srcAddrStr[MAX_STRING_LENGTH] = "";
                IO_ConvertIpAddressToString(&sourceAddress, srcAddrStr);

                if (DEBUG)
                {
                    char buf[MAX_STRING_LENGTH] = "";
                    TIME_PrintClockInSecond(node->getNodeTime(), buf);
                    printf("AppLayerDnsServer: Node %d %s is making reply"
                        " packet at %sS\n", node->nodeId, srcAddrStr, buf);
                }
                // memory allocation for the reply packet

                dnsReplyPacket =
                    (struct DnsQueryPacket*)MEM_malloc(sizeof(struct DnsQueryPacket));

                memset(dnsReplyPacket, 0, sizeof(struct DnsQueryPacket));

                // extract the query packet
                memcpy(&dnsQueryPacket,
                       dnsPacketPtr,
                       sizeof(struct DnsQueryPacket));

                dnsPacketPtr += sizeof(struct DnsQueryPacket);

                // extract source address from the packet to which
                // the reply packet is to be sent
                memcpy(&destAddress,
                       dnsPacketPtr,
                       sizeof(Address));
                dnsPacketPtr += sizeof(Address);

                // extract whether this is a primary DNS server or not
                BOOL isprimary = FALSE;
                memcpy(&isprimary,
                       dnsPacketPtr,
                       sizeof(BOOL));

                // check the packet type is query or not
                if (DnsHeaderGetQr(dnsQueryPacket.dnsHeader.dns_hdr) != 0)
                {
                    ERROR_ReportErrorArgs(
                        "This is an Invalid Message Type");
                }

                anCount = 0;
                nsCount = 0;
                arCount = 0;

                strcpy(serverDomain,
                       dnsData->server->dnsTreeInfo->domainName);
                if (DEBUG)
                {
                    char buf[MAX_STRING_LENGTH] = "";
                    TIME_PrintClockInSecond(node->getNodeTime(), buf);
                    printf("DNS server %s node %d starting "
                        "AppDnsServerQueryProcessing at %sS\n",
                        serverDomain, node->nodeId, buf);
                }
                answerFound = AppDnsServerQueryProcessing(
                                    node,
                                    &dnsQueryPacket,
                                    answerRrs,
                                    nameServerRrs,
                                    additionalRrs,
                                    &anCount,
                                    &nsCount,
                                    &arCount,
                                    &isAuthoritiveAnswer,
                                    isprimary);

                if (DEBUG)
                {
                    char buf[MAX_STRING_LENGTH] = "";
                    TIME_PrintClockInSecond(node->getNodeTime(), buf);
                    printf("DNS server %s node %d ending "
                        "AppDnsServerQueryProcessing at %sS\n",
                        serverDomain, node->nodeId, buf);
                }
                // copy the question part fron the query
                // packet to the reply packet.

                memcpy(&(dnsReplyPacket->dnsQuestion),
                       &(dnsQueryPacket.dnsQuestion),
                       sizeof(struct DnsQuestion));

                // setting diffrent parameters of common
                // header section of Dns Reply Packet
                dnsReplyPacket->dnsHeader.dns_id =
                                dnsQueryPacket.dnsHeader.dns_id;

                 // query message (message type)
                DnsHeaderSetQr(&dnsReplyPacket->dnsHeader.dns_hdr, 1);
                 // standary query
                DnsHeaderSetOpcode(&dnsReplyPacket->dnsHeader.dns_hdr, 0);
                 // valid from responses
                DnsHeaderSetAA(&dnsReplyPacket->dnsHeader.dns_hdr,
                               isAuthoritiveAnswer);
                 // truncated or not
                DnsHeaderSetTC(&dnsReplyPacket->dnsHeader.dns_hdr, 0);
                 // recursion desired
                DnsHeaderSetRD(&dnsReplyPacket->dnsHeader.dns_hdr, 0);
                 // recursion available
                DnsHeaderSetRA(&dnsReplyPacket->dnsHeader.dns_hdr, 0);
                 // for future use
                DnsHeaderSetReserved(&dnsReplyPacket->dnsHeader.dns_hdr,
                                    0);
                 // response code
                if (anCount == 0 && arCount == 0 && nsCount == 0)
                {
                    DnsHeaderSetRcode(&dnsReplyPacket->dnsHeader.dns_hdr,
                                        NXDOMAIN);
                }
                else
                {
                    DnsHeaderSetRcode(&dnsReplyPacket->dnsHeader.dns_hdr,
                                        NOERROR);
                }
                // no of query Url
                dnsReplyPacket->dnsHeader.qdCount =
                        dnsQueryPacket.dnsHeader.qdCount;
                // no of answer RR record
                dnsReplyPacket->dnsHeader.anCount = anCount;
                 // no of Name Server's(authoritative)RR record
                dnsReplyPacket->dnsHeader.nsCount = nsCount;
                // no of Additional RR Record
                dnsReplyPacket->dnsHeader.arCount = arCount;

                // packetsize intialization
                packetSize = 0;

                Message* tempMsg = NULL;
                AppToUdpSend* info = NULL;

                // temporary message allocation
                tempMsg = MESSAGE_Alloc(node,
                                        TRANSPORT_LAYER,
                                        TransportProtocol_UDP,
                                        MSG_TRANSPORT_FromAppSend);


                // Calculate the packet size appropriately
                UInt32 hdrSize = sizeof(struct DnsQueryPacket);
                hdrSize += sizeof(BOOL);
                if (DEBUG)
                {
                    printf("hdrSize %u\n", hdrSize);
                    printf("%u %u %u %u %u\n",
                            (Int32)sizeof(enum RrClass),
                            (Int32)sizeof(enum RrType),
                            (Int32)sizeof(clocktype),
                            (Int32)sizeof(UInt32),
                            (Int32)sizeof(Address));
                }
                if (anCount>0)
                {
                    hdrSize += anCount *  sizeof(struct DnsRrRecord);
                    if (DEBUG)
                    {
                        printf("anCount sizeof(struct DnsRrRecord)"
                               " hdrSize %u %u %u\n",
                               anCount,
                               (Int32)sizeof(struct DnsRrRecord),
                               hdrSize);
                    }
                }

                if (nsCount>0)
                {
                    hdrSize += nsCount * sizeof(struct DnsRrRecord);
                    if (DEBUG)
                    {
                        printf("nsCount sizeof(struct DnsRrRecord)"
                            " hdrSize %u %u %u %u\n",
                            nsCount,
                            (Int32)sizeof(struct DnsRrRecord),
                            hdrSize,
                            (Int32)sizeof(nameServerRrs->associatedDomainName));
                    }
                }

                if (arCount>0)
                {
                    hdrSize += arCount * sizeof(struct DnsRrRecord);
                    if (DEBUG)
                    {
                        printf("arCount sizeof(struct DnsRrRecord)"
                               " hdrSize %u %u %u\n",
                               arCount,
                               (Int32)sizeof(struct DnsRrRecord),
                               hdrSize);
                    }
                }

                MESSAGE_PacketAlloc(node,
                                    tempMsg,
                                    DNS_NAME_LENGTH +
                                    hdrSize +
                                    sizeof(short),
                                    TRACE_DNS);

                char* hdrPtr = MESSAGE_ReturnPacket(tempMsg);

                memcpy(hdrPtr,
                       (char*)dnsReplyPacket,
                       sizeof(struct DnsQueryPacket));

                hdrPtr += sizeof(struct DnsQueryPacket);

                memcpy(hdrPtr,
                       (char*)(&isprimary),
                       sizeof(BOOL));
                hdrPtr += sizeof(BOOL);

                if (anCount > 0)
                {
                    memcpy(hdrPtr,(char*) answerRrs,
                          anCount * sizeof(struct DnsRrRecord));
                    hdrPtr += anCount * sizeof(struct DnsRrRecord);
                }
                if (nsCount > 0)
                {
                     memcpy(hdrPtr,(char*)nameServerRrs,
                            nsCount * sizeof(struct DnsRrRecord));
                     hdrPtr += nsCount * sizeof(struct DnsRrRecord);
                }
                if (arCount > 0)
                {
                    memcpy(hdrPtr, (char*)additionalRrs,
                           arCount * sizeof(struct DnsRrRecord));
                    hdrPtr += arCount * sizeof(struct DnsRrRecord);
                }
                // Add the server domain
                memcpy(MESSAGE_ReturnPacket(tempMsg) + hdrSize,
                                            (char*)serverDomain,
                                            DNS_NAME_LENGTH);

                // Add the sourceport. This will be used by DNS client to
                //  inform the associated application
                memcpy(MESSAGE_ReturnPacket(tempMsg) + hdrSize +
                       DNS_NAME_LENGTH, (char*)&remote_prt, sizeof(short));

                MESSAGE_InfoAlloc(node,
                                  tempMsg,
                                  sizeof(AppToUdpSend));
                info = (AppToUdpSend *) MESSAGE_ReturnInfo(tempMsg);
                memset(info, 0, sizeof(AppToUdpSend));

               if (destAddress.networkType == NETWORK_IPV4)
               {
                   info->sourceAddr.networkType = NETWORK_IPV4;
                   info->sourceAddr.interfaceAddr.ipv4 =
                                      NetworkIpGetInterfaceAddress(node, 0);
               }
               else
               {
                   info->sourceAddr.networkType = NETWORK_IPV6;
                   Ipv6GetGlobalAggrAddress(node,
                                    0,
                                    &info->sourceAddr.interfaceAddr.ipv6);
               }
                info->destAddr = destAddress;
                info->sourcePort = sourcePort;
                info->destPort = (short) APP_DNS_CLIENT;
                info->priority = APP_DEFAULT_TOS;
                info->outgoingInterface = ANY_INTERFACE;
                if (DEBUG)
                {
                    char buf[MAX_STRING_LENGTH];
                    TIME_PrintClockInSecond(node->getNodeTime(), buf);
                    printf("DNS server %s node %d sending"
                            "msg at %sS with msgsize %u\n",
                            serverDomain,
                            node->nodeId,
                            buf,
                            (Int32)sizeof(hdrSize));
                }

                MESSAGE_Send(node, tempMsg, 0);

                dnsData->stat.numOfDnsReplySent++;

                // Need to free the message;
                MESSAGE_Free(node, msg);

                MEM_free(answerRrs);
                MEM_free(nameServerRrs);
                MEM_free(additionalRrs);
                MEM_free(dnsReplyPacket);

            }// end of else
            else if (msgType == DNS_NOTIFY)
            {
                if (DEBUG)
                {
                    printf(" Node %u : DNS_NOTIFY \n", node->nodeId);
                }

                struct DnsQueryPacket* dnsNotifyPkt = (struct DnsQueryPacket*)dnsPacketPtr;

                if (DnsHeaderGetQr(dnsNotifyPkt->dnsHeader.dns_hdr) == 0)
                {
                    // This means that DNS Notify is received

                    // a.Add its entry in ‘List_Notify_Rxd’ and
                    //  TODO Check if a duplicate entry is already present in
                    //  ‘List_Notify_Rxd’
                    // b.If yes, then set the duplicate flag as 1.
                    // c.If No, then set the duplicate flag as 0.
                    AppToUdpSend tempInfo;

                    memset(&tempInfo, 0, sizeof(AppToUdpSend));
                    memcpy(&tempInfo, MESSAGE_ReturnInfo(msg),
                           sizeof(AppToUdpSend));

                    Address tempAddrVar;
                    memset(&tempAddrVar, 0, sizeof(Address));
                    tempAddrVar = tempInfo.sourceAddr;

                    struct NotifyReceivedData* notifyRcvdData = NULL;
                    struct NotifyReceivedData* notifyRcvdItem = NULL;
                    notifyRcvdData =
                        (struct NotifyReceivedData*)MEM_malloc(
                            sizeof(struct NotifyReceivedData));
                    memset(notifyRcvdData, 0,
                            sizeof(struct NotifyReceivedData));

                    memcpy(&(notifyRcvdData->zoneServerAddress),
                            &tempAddrVar,
                            sizeof(Address));
                    notifyRcvdData->duplicate = FALSE;
                    dnsData->zoneData->notifyRcvd->push_back(notifyRcvdData);

                    // send response back
                    Message* notifyResponseMsg = NULL;
                    AppToUdpSend* info = NULL;
                    enum DnsMessageType msgType = DNS_NOTIFY;
                    struct DnsQueryPacket* dnsNotifyResponsePacket = NULL;

                    dnsNotifyResponsePacket =
                        (struct DnsQueryPacket*)MEM_malloc(sizeof(struct DnsQueryPacket));

                    memset(
                        dnsNotifyResponsePacket, 0, sizeof(struct DnsQueryPacket));
                    memcpy(dnsNotifyResponsePacket, dnsNotifyPkt,
                           sizeof(struct DnsQueryPacket)) ;

                    // notify response message
                    DnsHeaderSetQr(&dnsNotifyResponsePacket->dnsHeader.
                                   dns_hdr, 1);

                    notifyResponseMsg = MESSAGE_Alloc(node,
                                                 TRANSPORT_LAYER,
                                                 TransportProtocol_UDP,
                                                 MSG_TRANSPORT_FromAppSend);
                    MESSAGE_PacketAlloc(node,
                                        notifyResponseMsg,
                                        sizeof(enum DnsMessageType)+
                                        sizeof(struct DnsQueryPacket),
                                        TRACE_DNS);

                    memcpy(MESSAGE_ReturnPacket(notifyResponseMsg),
                           &msgType,
                           sizeof(enum DnsMessageType));

                    memcpy(MESSAGE_ReturnPacket(notifyResponseMsg) +
                           sizeof(enum DnsMessageType),
                           (char*)(dnsNotifyResponsePacket),
                           sizeof(struct DnsQueryPacket));

                    MESSAGE_InfoAlloc(node,
                        notifyResponseMsg,
                        sizeof(AppToUdpSend));

                    info =
                      (AppToUdpSend*) MESSAGE_ReturnInfo(notifyResponseMsg);

                    Address tempAddr;
                    memset(&tempAddr, 0, sizeof(Address));
                    tempAddr = dnsPacketInfo->sourceAddr;
                    info->sourceAddr = tempInfo.destAddr;
                    info->sourcePort = node->appData.nextPortNum++;
                    info->destAddr = tempAddr;

                    info->destPort = (short) APP_DNS_SERVER;
                    info->priority = APP_DEFAULT_TOS;
                    info->outgoingInterface = ANY_INTERFACE;
                    MESSAGE_Send(node, notifyResponseMsg, 0);

                    dnsData->stat.numOfDnsNotifyResponseSent++;

                    Message* timerMsg =
                        MESSAGE_Alloc(node,
                                      APP_LAYER,
                                      APP_DNS_SERVER,
                                      MSG_APP_DNS_ZONE_REFRESH_TIMER);
                    if (dnsData->secZoneRefreshTimerMsg != NULL)
                    {
                        MESSAGE_CancelSelfMsg(node,
                            dnsData->secZoneRefreshTimerMsg);
                    }
                    MESSAGE_Send(node, timerMsg, 0);
                    // Now from notifyRcvd List delete the entry for which
                    // response has been sent
                    notifyRcvdItem = dnsData->zoneData->notifyRcvd->back();
                    // free item
                    dnsData->zoneData->notifyRcvd->remove(notifyRcvdItem);
                    MEM_free(notifyRcvdItem);
                    notifyRcvdItem = NULL;
                    MEM_free(dnsNotifyResponsePacket);
                    dnsNotifyResponsePacket = NULL;
                }
                else
                {
                    // this means that notify response is received
                    if (DEBUG)
                    {
                        printf(" Node %u : DNS_NOTIFY response "
                            "received begin \n", node->nodeId);
                    }
                    AppToUdpSend* info = (AppToUdpSend*)
                                            MESSAGE_ReturnInfo(msg);
                    Address responseFrom = info->sourceAddr;

                    struct DnsData* dnsData =
                        (struct DnsData*)node->appData.dnsData;

                    struct ZoneData* zoneData = dnsData->zoneData;
                    struct RetryQueueData* retryData = NULL;
                    RetryQueueList :: iterator retryItem;
                    Int32 size = zoneData->retryQueue->size();
                    retryItem = zoneData->retryQueue->begin();
                    while (size != 0)
                    {
                        retryData = (struct RetryQueueData*)*retryItem;
                        if (MAPPING_CompareAddress(responseFrom,
                           retryData->zoneServerAddress) == 0)
                        {
                            // free item
                            zoneData->retryQueue->remove(retryData);
                            //MEM_free(retryData);
                            //retryData = NULL;
                            break;
                        }
                        else
                        {
                            retryItem++;
                        }
                        size --;
                    } // end of while

                }
                if (DEBUG)
                {
                    printf(" Node %u : case DNS_NOTIFY end \n",
                           node->nodeId);
                }
            }
            else if (msgType == DNS_ADD_SERVER)
            {
                struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
                struct DnsServerData* dnsServerData = dnsData->server;
                char serverLabel[DNS_NAME_LENGTH] = "";
                Address* serverAddr = NULL;
                struct DnsRrRecord* rrRecord = NULL;
                rrRecord = (struct DnsRrRecord*)
                            MEM_malloc(sizeof(struct DnsRrRecord));
                serverAddr = (Address*) dnsPacketPtr;
                memcpy(serverLabel,
                       dnsPacketPtr + sizeof(Address),
                       sizeof(serverLabel));
                DnsCreateNewRrRecord (rrRecord,
                    serverLabel,
                    NS,
                    IN,
                    dnsData->cacheRefreshTime,
                    sizeof(Address),
                    serverAddr);

                dnsServerData->rrList->push_back(rrRecord);

                if (DEBUG)
                {
                    DnsRrRecordList :: iterator item;
                    item = dnsData->server->rrList->begin();

                    // check for matching destIP
                    printf("\nIn DNS_ADD_SERVER For Node: %d\n"
                        "After Adding Secondary Server domain: %s\n"
                        "Server have the following RR records:\n",
                        node->nodeId, serverLabel);

                    while (item != dnsData->server->rrList->end())
                    {
                        struct DnsRrRecord* rrItem = (DnsRrRecord*)*item;

                        printf("\tAssociated Domain Name: %s\n",
                            rrItem->associatedDomainName);

                        item++;
                    }
                    printf("\n");
                }
                MESSAGE_Free(node, msg);
                if (dnsData->zoneData->isMasterOrSlave)
                {
                    dnsData->zoneData->zoneFreshCount++;
                    AppDnsSendNotifyToSlaves(node);
                }
            }

            break;
        }// end of packet handled from transport layer
        case MSG_APP_DNS_SERVER_INIT:
        {
            if (DEBUG)
            {
                printf(" Node %u : server initialisation begin \n",
                       node->nodeId);
            }

            // take out the label and serveraddress from the packet
            char newServerLabel[DNS_NAME_LENGTH] = "";
            Address* newServerAddr = NULL;
            newServerAddr = (Address*) MESSAGE_ReturnPacket(msg);
            memcpy(newServerLabel,
                   MESSAGE_ReturnPacket(msg)+ sizeof(Address),
                   sizeof(newServerLabel));

            struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
            data* tempData = NULL;
            ZoneDataList :: iterator item;
            Address zoneMasterAddr;
            memset(&zoneMasterAddr, 0, sizeof(Address));
            BOOL zoneMasterfound = FALSE;
            enum DnsServerRole role;
            memcpy(&role,
                   MESSAGE_ReturnPacket(msg)+ sizeof(Address) +
                   sizeof(newServerLabel),
                   sizeof(enum DnsServerRole));

            if (role != Secondary)
            {
                dnsData->server->dnsTreeInfo->timeAdded = 0;
            }

            if (role == NameServer)
            {
                // Find the Primary Master of that Zone that has been updated
                Int32 size = dnsData->zoneData->data->size();
                item = dnsData->zoneData->data->begin();
                if (size != 0)
                {
                    tempData = (data*)*item;
                }
                while (size != 0)
                {
                    if (tempData->isZoneMaster)
                    {
                        zoneMasterfound = TRUE;
                        zoneMasterAddr = tempData->zoneServerAddress;
                        break;
                    }
                    else
                    {
                        item++;
                    }
                    size --;
                } // end of while
                if (zoneMasterfound)
                {
                    Address sourceAddress;
                    memset(&sourceAddress, 0, sizeof(Address));
                    NetworkProtocolType protocol_type = INVALID_NETWORK_TYPE;

                    protocol_type =
                        NetworkIpGetNetworkProtocolType(node,
                                                        node->nodeId);

                    if ((protocol_type == IPV6_ONLY) ||
                        (protocol_type == DUAL_IP))
                    {
                        sourceAddress.networkType = NETWORK_IPV6;
                        Ipv6GetGlobalAggrAddress(node,
                                        0,
                                        &sourceAddress.interfaceAddr.ipv6);
                    }
                    else if (protocol_type == IPV4_ONLY)
                    {
                        sourceAddress.networkType = NETWORK_IPV4;
                        sourceAddress.interfaceAddr.ipv4 =
                                    NetworkIpGetInterfaceAddress(node, 0);
                    }
                    Message* eventMsg = NULL;
                    AppToUdpSend* info = NULL;
                    enum DnsMessageType msgType;
                    msgType = DNS_UPDATE; // Zone has been Modified
                    UInt32 zoneFreshCount;

                    zoneFreshCount = dnsData->zoneData->zoneFreshCount;

                    struct DnsZoneTransferPacket dnsZonePacket;
                    memset(&dnsZonePacket,
                           0,
                           sizeof(struct DnsZoneTransferPacket));

                    dnsZonePacket.dnsHeader.dns_id = 0;
                     // query message (message type)
                    DnsHeaderSetQr(&dnsZonePacket.dnsHeader.dns_hdr, 0);
                     // standary query
                    DnsHeaderSetOpcode(&dnsZonePacket.dnsHeader.dns_hdr, 5);
                     // for future use
                    DnsHeaderSetUpdReserved(&dnsZonePacket.dnsHeader.dns_hdr,
                                            0);
                     // response code
                    DnsHeaderSetRcode(&dnsZonePacket.dnsHeader.dns_hdr, 0);

                    dnsZonePacket.dnsHeader.zoCount = 0;
                    // prerequisite section RRs
                    dnsZonePacket.dnsHeader.prCount = 0;
                    // Update section RRs
                    dnsZonePacket.dnsHeader.upCount = 2;
                    // Additional section RRs
                    dnsZonePacket.dnsHeader.adCount = 0;

                    DnsRrRecordList :: iterator rrRecord =
                        dnsData->server->rrList->begin();
                    UInt32 size = 0;
                    char* tempPtr = NULL;
                    char* tempStartPtr = NULL;
                    size = dnsData->server->rrList->size();
                    tempPtr = (char*)MEM_malloc(
                                size * sizeof(struct DnsRrRecord));
                    tempStartPtr = tempPtr;
                    for (Int32 rrCount = 0; rrCount<size; rrCount++)
                    {
                        memcpy(tempPtr, *rrRecord,
                               sizeof(struct DnsRrRecord));
                        tempPtr += sizeof(struct DnsRrRecord);
                        rrRecord++;
                    }

                    eventMsg = MESSAGE_Alloc(
                        node,
                        TRANSPORT_LAYER,
                        TransportProtocol_UDP,
                        MSG_TRANSPORT_FromAppSend);

                    MESSAGE_PacketAlloc(node,
                            eventMsg,
                            sizeof(enum DnsMessageType) +
                            sizeof(zoneFreshCount)+
                            sizeof(struct DnsZoneTransferPacket)+
                            sizeof(Address) +
                            sizeof(newServerLabel) +
                            sizeof(UInt32) +
                                size * sizeof(struct DnsRrRecord),
                            TRACE_DNS);
                    memset(MESSAGE_ReturnPacket(eventMsg),
                           0,
                           sizeof(Address)+
                                sizeof(enum DnsMessageType) +
                                sizeof(UInt32) +
                                sizeof(struct DnsZoneTransferPacket) +
                                sizeof(newServerLabel));

                    memcpy(MESSAGE_ReturnPacket(eventMsg),
                           &msgType,
                           sizeof(enum DnsMessageType));

                    memcpy(MESSAGE_ReturnPacket(eventMsg) +
                           sizeof(enum DnsMessageType),
                           &zoneFreshCount,
                           sizeof(zoneFreshCount));

                    memcpy(MESSAGE_ReturnPacket(eventMsg) +
                           sizeof(enum DnsMessageType)+
                           sizeof(zoneFreshCount),
                           (char*)&dnsZonePacket,
                           sizeof(struct DnsZoneTransferPacket));

                    memcpy(MESSAGE_ReturnPacket(eventMsg) +
                           sizeof(enum DnsMessageType)+
                           sizeof(UInt32)+
                           sizeof(struct DnsZoneTransferPacket),
                           (char*)(newServerAddr),
                           sizeof(Address));

                    memcpy(MESSAGE_ReturnPacket(eventMsg) +
                               sizeof(enum DnsMessageType)+
                               sizeof(UInt32)+
                               sizeof(struct DnsZoneTransferPacket)+
                               sizeof(Address),
                           (char*)(newServerLabel),
                           sizeof(newServerLabel));

                    memcpy(MESSAGE_ReturnPacket(eventMsg) +
                               sizeof(enum DnsMessageType)+
                               sizeof(UInt32)+
                               sizeof(struct DnsZoneTransferPacket)+
                               sizeof(Address)+
                               sizeof(newServerLabel),
                           &size,
                           sizeof(UInt32));
                    memcpy(MESSAGE_ReturnPacket(eventMsg) +
                               sizeof(enum DnsMessageType)+
                               sizeof(UInt32)+
                               sizeof(struct DnsZoneTransferPacket)+
                               sizeof(Address)+
                               sizeof(newServerLabel)+
                               sizeof(UInt32),
                           (char*)(tempStartPtr),
                           size * sizeof(struct DnsRrRecord));
                    MEM_free(tempStartPtr);
                    MESSAGE_InfoAlloc(node,
                                      eventMsg,
                                      sizeof(AppToUdpSend));

                    info = (AppToUdpSend*) MESSAGE_ReturnInfo(eventMsg);
                    memset(info, 0, sizeof(AppToUdpSend));
                    info->sourceAddr = sourceAddress;

                    info->sourcePort = node->appData.nextPortNum++;

                    info->destAddr = zoneMasterAddr;

                    info->destPort = (short) APP_DNS_SERVER;
                    info->priority = APP_DEFAULT_TOS;
                    info->outgoingInterface = ANY_INTERFACE;

                    MESSAGE_Send(node, eventMsg, 0);
                }
            }
            break;
        }
        case MSG_APP_DNS_ADD_SERVER:
        {
            struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
            BOOL rrExist = FALSE;
            struct DnsServerData* dnsServerData = dnsData->server;
            char serverLabel[DNS_NAME_LENGTH] = "";
            Address* serverAddr = NULL;

            serverAddr = (Address*) MESSAGE_ReturnPacket(msg);
            memcpy(serverLabel,
                   MESSAGE_ReturnPacket(msg)+ sizeof(Address),
                   sizeof(serverLabel));
            if (dnsServerData->rrList->size())
            {
                DnsRrRecordList :: iterator item;
                item = dnsServerData->rrList->begin();
                while (item != dnsServerData->rrList->end())
                {
                    struct DnsRrRecord* rrRecord = (struct DnsRrRecord*)*item;
                    if (!strcmp(rrRecord->associatedDomainName,
                            serverLabel) &&
                        !MAPPING_CompareAddress(rrRecord->associatedIpAddr,
                            *serverAddr))
                    {
                        rrExist = TRUE;
                        break;
                    }
                    item++;
                }
            }
            if (!rrExist)
            {
                struct DnsRrRecord* rrRecord = NULL;
                rrRecord = (struct DnsRrRecord*)
                            MEM_malloc(sizeof(struct DnsRrRecord));
                DnsCreateNewRrRecord(
                    rrRecord,
                    serverLabel,
                    NS,
                    IN,
                    dnsData->cacheRefreshTime,
                    sizeof(Address),
                    serverAddr);

                dnsServerData->rrList->push_back(rrRecord);
            }

            if (DEBUG)
            {
                DnsRrRecordList :: iterator item;
                item = dnsData->server->rrList->begin();
                printf("\nIn MSG_APP_DNS_ADD_SERVER For Node: %d "
                       "adding the RR(%s)\n", node->nodeId, serverLabel);
                // check for matching destIP
                printf("\nAfter addding RR For Node: %d "
                       "the following RR records\n", node->nodeId);

                while (item != dnsData->server->rrList->end())
                {
                    struct DnsRrRecord* rrItem = (struct DnsRrRecord*)*item;

                    printf("\tAssociated Domain Name: %s\n",
                           rrItem->associatedDomainName);

                    item = item++;
                }
                printf("\n");
            }
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_DNS_NOTIFY_REFRESH_TIMER:
        {
            if (DEBUG)
            {
                printf(" Node %u : case NOTIFY_REFRESH_INTERVAL  \n",
                       node->nodeId);
            }
            // Note: When DNS NOTIFY RESPONSE is not received in 60Sec then,
            // DNS NOTIFY message is sent again to slave. This happens for
            // NOTIFY_Count number of times (default value is 5 times).

            Address notifySentToServer;
            memcpy(&notifySentToServer,
                   MESSAGE_ReturnPacket(msg),
                   sizeof(Address));

            AppToUdpSend infoOfPacket;
            AppToUdpSend* info = NULL;
            memcpy(&infoOfPacket,
                   MESSAGE_ReturnPacket(msg) +
                   sizeof(Address),
                   sizeof(AppToUdpSend));

            struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;

            struct ZoneData* zoneData = dnsData->zoneData;
            struct RetryQueueData* retryData = NULL;
            RetryQueueList :: iterator retryItem;

            Int32 size = zoneData->retryQueue->size();
            retryItem = zoneData->retryQueue->begin();
            if (size != 0)
            {
                retryData = (struct RetryQueueData*)*retryItem;
                if (MAPPING_CompareAddress(retryData->zoneServerAddress,
                    notifySentToServer ) == 0)
                {
                    retryData->countRetrySent++;
                    if (retryData->countRetrySent <=
                        MAX_COUNT_OF_NOTIFY_RETRIES_SENT)
                    {
                        Message* notifyMsg = NULL;
                        enum DnsMessageType msgType = DNS_NOTIFY;
                        notifyMsg = MESSAGE_Alloc(
                            node,
                            TRANSPORT_LAYER,
                            TransportProtocol_UDP,
                            MSG_TRANSPORT_FromAppSend);

                        MESSAGE_PacketAlloc(
                            node,
                            notifyMsg,
                            sizeof(enum DnsMessageType)+
                            sizeof(struct DnsQueryPacket),
                            TRACE_DNS);

                        memcpy(MESSAGE_ReturnPacket(notifyMsg),
                               &msgType,
                               sizeof(enum DnsMessageType));

                        memcpy(MESSAGE_ReturnPacket(notifyMsg) +
                               sizeof(enum DnsMessageType),
                               (char*)(&retryData->dnsNotifyPacket),
                               sizeof(struct DnsQueryPacket));

                        MESSAGE_InfoAlloc(node,
                                          notifyMsg,
                                          sizeof(AppToUdpSend));

                        info = (AppToUdpSend*) MESSAGE_ReturnInfo(notifyMsg);
                        memset(info, 0, sizeof(AppToUdpSend));
                        info->sourceAddr = infoOfPacket.sourceAddr;

                        info->sourcePort = node->appData.nextPortNum++;

                        info->destAddr = infoOfPacket.destAddr;

                        info->destPort = (short) APP_DNS_SERVER;
                        info->priority = APP_DEFAULT_TOS;
                        info->outgoingInterface = ANY_INTERFACE;

                        MESSAGE_Send(node, notifyMsg, 0);

                        dnsData->stat.numOfDnsNotifySent++;

                        // Also again start the NOTIFY_REFRESH_TIMER
                        // (default value 60 Sec)
#if 0
                        Message* timerMsg =
                                  MESSAGE_Alloc(node,
                                          APP_LAYER,
                                          APP_DNS_SERVER,
                                          MSG_APP_DNS_NOTIFY_REFRESH_TIMER);
                        MESSAGE_PacketAlloc(node,
                                timerMsg,
                                sizeof(Address)+
                                sizeof(AppToUdpSend),
                                TRACE_DNS);
#endif
                        memcpy(MESSAGE_ReturnPacket(msg),
                               &notifySentToServer,
                               sizeof(Address));

                        memcpy(MESSAGE_ReturnPacket(msg) +
                               sizeof(Address),
                               info,
                               sizeof(AppToUdpSend));

                        MESSAGE_Send(node, msg, NOTIFY_REFRESH_INTERVAL);
                    }
                    else
                    {

                        // delete the entry from retry queue
                        zoneData->retryQueue->remove(*retryItem);
                        // free item
                        // MEM_free(*retryItem);
                        //*retryItem = NULL;
                    }
                }
            }
            break;
        }
        case MSG_APP_DNS_ZONE_REFRESH_TIMER:
        {
            if (DEBUG)
            {
                printf(" Node %u : ttl-timer \n", node->nodeId);
                printf(" Node %u : REQUESTED ZONE UPDATE\n",
                        node->nodeId);
            }
            struct DnsZoneTransferPacket dnsZonePacket;

            struct DnsTreeInfo* dnsTreeInfo = dnsData->server->dnsTreeInfo;
            memset(&dnsZonePacket,
                   0,
                   sizeof(struct DnsZoneTransferPacket));
            strcpy(dnsZonePacket.dnsZone.dnsZonename,
                   dnsTreeInfo->domainName);
            dnsZonePacket.dnsZone.dnsZoneType = SOA;
            dnsZonePacket.dnsZone.dnsZoneClass = IN;
            dnsZonePacket.dnsHeader.dns_id = 0;

             // query message (message type)
            DnsHeaderSetQr(&dnsZonePacket.dnsHeader.dns_hdr, 0);
             // standary query
            DnsHeaderSetOpcode(&dnsZonePacket.dnsHeader.dns_hdr, 5);
             // for future use
            DnsHeaderSetUpdReserved(&dnsZonePacket.dnsHeader.dns_hdr, 0);
             // response code
            DnsHeaderSetRcode(&dnsZonePacket.dnsHeader.dns_hdr, 0);

            dnsZonePacket.dnsHeader.zoCount = 0;
            // prerequisite section RRs
            dnsZonePacket.dnsHeader.prCount = 0;
            // Update section RRs
            dnsZonePacket.dnsHeader.upCount = 0;
            // Additional section RRs
            dnsZonePacket.dnsHeader.adCount = 0;

            Address sourceAddress;
            Address destAddr;
            memset(&sourceAddress, 0, sizeof(Address));
            memset(&destAddr, 0, sizeof(Address));
            data* tempData = *(dnsData->zoneData->data->begin());
            destAddr = tempData->zoneServerAddress;

            NetworkProtocolType protocol_type = INVALID_NETWORK_TYPE;

            protocol_type = NetworkIpGetNetworkProtocolType(node,
                                          node->nodeId);

            if ((destAddr.networkType == NETWORK_IPV6) &&
                ((protocol_type == IPV6_ONLY) ||
                (protocol_type == DUAL_IP)))
            {
                sourceAddress.networkType = NETWORK_IPV6;
                Ipv6GetGlobalAggrAddress(node,
                                0,
                                &sourceAddress.interfaceAddr.ipv6);
            }
            else if ((destAddr.networkType == NETWORK_IPV4) &&
                ((protocol_type == IPV4_ONLY) ||
                (protocol_type == DUAL_IP)))
            {
                sourceAddress.networkType = NETWORK_IPV4;
                sourceAddress.interfaceAddr.ipv4 =
                                NetworkIpGetInterfaceAddress(node, 0);
            }
            else
            {
                ERROR_ReportErrorArgs("\n Src and Destination Address "
                                  "Type Mismatch");
            }

            if (dnsData->zoneData->data->size() != 1)
            {
                ERROR_ReportErrorArgs("The Node: %d has more than one " \
                        "MASTER Zone Server Address or not at all",
                        node->nodeId);
            }

            enum DnsMessageType msgType;
            msgType = DNS_UPDATE;
            Message* dnsMsg = NULL;
            AppToUdpSend* info = NULL;
            UInt32 zoneFreshCount;

            zoneFreshCount = dnsData->zoneData->zoneFreshCount;

            dnsMsg= MESSAGE_Alloc(
                      node,
                      TRANSPORT_LAYER,
                      TransportProtocol_UDP,
                      MSG_TRANSPORT_FromAppSend);

            MESSAGE_PacketAlloc(node,
                                dnsMsg,
                                sizeof(Address)+
                                    sizeof(enum DnsMessageType) +
                                    sizeof(zoneFreshCount) +
                                    sizeof(struct DnsZoneTransferPacket),
                                TRACE_DNS);

            memset(MESSAGE_ReturnPacket(dnsMsg),
                   0,
                   sizeof(Address)+
                        sizeof(enum DnsMessageType) +
                        sizeof(zoneFreshCount) +
                        sizeof(struct DnsZoneTransferPacket));
            memcpy(MESSAGE_ReturnPacket(dnsMsg),
                   &msgType,
                   sizeof(enum DnsMessageType));

            memcpy(MESSAGE_ReturnPacket(dnsMsg) +
                       sizeof(enum DnsMessageType),
                   &zoneFreshCount,
                   sizeof(zoneFreshCount));

            memcpy(MESSAGE_ReturnPacket(dnsMsg) +
                       sizeof(enum DnsMessageType) +
                       sizeof(zoneFreshCount),
                   &dnsZonePacket,
                   sizeof(struct DnsZoneTransferPacket));

            memcpy(MESSAGE_ReturnPacket(dnsMsg) +
                       sizeof(enum DnsMessageType) +
                       sizeof(struct DnsZoneTransferPacket) +
                       sizeof(zoneFreshCount),
                   &sourceAddress,
                   sizeof(Address));
            MESSAGE_InfoAlloc(node,
                              dnsMsg,
                              sizeof(AppToUdpSend));

            info = (AppToUdpSend*) MESSAGE_ReturnInfo(dnsMsg);
            memset(info, 0, sizeof(AppToUdpSend));
            info->sourceAddr = sourceAddress;

            info->sourcePort = (short)APP_DNS_SERVER;

            memcpy(&(info->destAddr), &destAddr, sizeof(Address));

            info->destPort = (short) APP_DNS_SERVER;
            info->priority = APP_DEFAULT_TOS;
            info->outgoingInterface = ANY_INTERFACE;

            dnsData->stat.numOfDnsUpdateRequestsSent++;
            MESSAGE_Send(node, dnsMsg, 0);

            Message* timerMsg = MESSAGE_Alloc(
                                        node,
                                        APP_LAYER,
                                        APP_DNS_SERVER,
                                        MSG_APP_DNS_ZONE_REFRESH_TIMER);
            dnsData->secZoneRefreshTimerMsg = timerMsg;
            MESSAGE_Send(node, timerMsg, ZONE_REFRESH_INTERVAL);

            APP_TcpServerListen(
                        node,
                        APP_DNS_SERVER,
                        sourceAddress,
                        (short) APP_DNS_SERVER);
            break;
        }
        case MSG_APP_FromTransListenResult:
        {
            TransportToAppListenResult* listenResult = NULL;
            listenResult = (TransportToAppListenResult*)
                                MESSAGE_ReturnInfo(msg);

            if (listenResult->connectionId == -1)
            {
                APP_TcpServerListen(
                    node,
                    APP_DNS_SERVER,
                    listenResult->localAddr,
                    (short) APP_DNS_SERVER);

                node->appData.numAppTcpFailure++;
                if (DEBUG)
                {
                    printf(" Node %u : FromTransListenResult : RETRY "
                           "SERVER LISTENING\n", node->nodeId);
                }
            }
            else
            {
                if (DEBUG)
                {
                        printf(" Node %u : FromTransListenResult : STARTED "
                               "LISTENING\n", node->nodeId);
                }
            }
            break;
        }
        case MSG_APP_FromTransOpenResult:
        {
            char buf[MAX_STRING_LENGTH] = "";
            // Client node can now start sending data to server
            ctoa(node->getNodeTime(), buf);

            if (DEBUG)
            {
                printf(" Node %d : FromTransOpenResult : \n", node->nodeId);
            }

            if (dnsData->zoneData->isMasterOrSlave == FALSE)
            {
                TransportToAppOpenResult* openResult = NULL;
                openResult = (TransportToAppOpenResult*)
                                  MESSAGE_ReturnInfo(msg);

                if (openResult->type != TCP_CONN_PASSIVE_OPEN)
                {
                    ERROR_ReportErrorArgs("In DNS openResultType != "
                                       "TCP_CONN_PASSIVE_OPEN \n");
                }

                struct DnsServerZoneTransferServer* serverPtr = NULL;

                serverPtr = AppDnsZoneServerNewDnsZoneServer(node,
                                openResult);

                if (DEBUG)
                {
                    printf("----MSG_APP_FromTransOpenResult--:%u--",
                        node->nodeId);
                    char addrStr[MAX_STRING_LENGTH] = "";
                    IO_ConvertIpAddressToString(&serverPtr->localAddr,
                        addrStr);
                    printf("    localAddr = %s\n", addrStr);
                    IO_ConvertIpAddressToString(&serverPtr->remoteAddr,
                        addrStr);
                    printf("    remoteAddress = %s\n", addrStr);
                }

                if (serverPtr == NULL)
                {
                    ERROR_ReportErrorArgs("Zone Transfer Server: Node %d "
                        "cannot allocate new Zone Transfer server\n",
                           node->nodeId);
                }
                break;
            }
            else // ZONE MASTER
            {
                TransportToAppOpenResult* openResult = NULL;
                struct DnsServerZoneTransferClient* clientPtr = NULL;

                openResult = (TransportToAppOpenResult*)
                             MESSAGE_ReturnInfo(msg);

                if (openResult->type != TCP_CONN_ACTIVE_OPEN)
                {
                    ERROR_ReportErrorArgs("TCP connection not"
                            "TCP_CONN_ACTIVE_OPEN\n");
                }

                clientPtr =
                    DnsZoneClientGetDnsZoneClientWithUniqueId(node,
                    openResult->uniqueId);

                if (DEBUG)
                {
                    printf("----MSG_APP_FromTransOpenResult--:%d--",
                        node->nodeId);
                    printf("Zone Transfer Client: " \
                        "Node %d  got OpenResult\n",
                        node->nodeId);
                    char addrStr[MAX_STRING_LENGTH] = "";
                    IO_ConvertIpAddressToString(&clientPtr->localAddr,
                        addrStr);
                    printf("    localAddr = %s\n", addrStr);
                    IO_ConvertIpAddressToString(&clientPtr->remoteAddr,
                        addrStr);
                    printf("    remoteAddress = %s\n", addrStr);
                }

                if (openResult->connectionId < 0)
                {
                    /* Keep trying until connection is established. */

                    APP_TcpOpenConnection(
                        node,
                        APP_DNS_SERVER,
                        openResult->localAddr,
                        node->appData.nextPortNum++,
                        openResult->remoteAddr,
                        (short)APP_DNS_SERVER,
                        openResult->uniqueId,
                        0,
                        (TosType) clientPtr->tos);

                    if (DEBUG)
                    {
                        printf("Zone Transfer Client: Node %d at %s"
                            "connection failed!  Retrying... \n",
                            node->nodeId, buf);
                    }

                    node->appData.numAppTcpFailure++;
                }
                else
                {
                    clientPtr = DnsZoneClientUpdateDnsZoneClient(node,
                        openResult);

                    if (clientPtr == NULL)
                    {
                        ERROR_ReportErrorArgs("Client pointer NULL");
                    }

                    DnsZoneClientSendNextItem(node, clientPtr);
                }
            }
            break;
        }

        case MSG_APP_FromTransDataReceived:
        {
            // server node receives that data from client
            struct DnsServerZoneTransferServer* serverPtr = NULL;
            BOOL packetFormed = FALSE;
            Int32 packetSize = 0;
            Int32 rrCount = 0;
            char* pktReceived = NULL;
            BOOL packetInTact = FALSE;
            struct TcpConnInfo* tcpTmpConnData = NULL;
            BOOL isItemExist = FALSE;
            struct TcpConnInfo* tcpConnData =
                (struct TcpConnInfo*)MEM_malloc(sizeof(struct TcpConnInfo));
            memset(tcpConnData, 0, sizeof(struct TcpConnInfo));
            tcpConnData->dataRecvd = (TransportToAppDataReceived*)
                        MEM_malloc(sizeof(TransportToAppDataReceived));

            TransportToAppDataReceived* dataRecvd = NULL;
            dataRecvd = (TransportToAppDataReceived*)
                            MESSAGE_ReturnInfo(msg);
            memcpy(tcpConnData->dataRecvd,
                dataRecvd,
                sizeof(TransportToAppDataReceived));
            if (!dnsData->tcpConnDataList->size())
            {
                dnsData->tcpConnDataList->push_back(tcpConnData);
            }
            else
            {
                TcpConnInfoList :: iterator lstItem;
                lstItem = dnsData->tcpConnDataList->begin();
                while (lstItem != dnsData->tcpConnDataList->end())
                {
                    tcpTmpConnData = (struct TcpConnInfo*)*lstItem;
                    if (tcpTmpConnData->dataRecvd->connectionId ==
                                                dataRecvd->connectionId)
                    {
                        isItemExist = TRUE;
                        MEM_free(tcpConnData->dataRecvd);
                        tcpConnData->dataRecvd = NULL;
                        MEM_free(tcpConnData);
                        tcpConnData = NULL;
                        tcpConnData = tcpTmpConnData;
                        break;
                    }
                    lstItem++;
                }
                if (!isItemExist)
                {
                    dnsData->tcpConnDataList->push_back(tcpConnData);
                }
            }

            struct DnsServerData* dnsServerData = dnsData->server;

            if (dnsData->zoneData->isMasterOrSlave == FALSE)
            {
                UInt32 zoneFreshCount = 0;
                struct DnsZoneTransferPacket* dnsZoneReplyPacket = NULL;
                dnsZoneReplyPacket =
                    (struct DnsZoneTransferPacket*)MEM_malloc(
                                    sizeof(struct DnsZoneTransferPacket));
                if (tcpConnData->totalFragment == 0 &&
                        packetFormed == FALSE)
                {
                    memcpy(&zoneFreshCount,
                           (char*)msg->packet,
                           sizeof(zoneFreshCount));
                    memcpy(dnsZoneReplyPacket,
                           (char*)msg->packet + sizeof(zoneFreshCount),
                           (sizeof(struct DnsZoneTransferPacket)));

                    tcpConnData->upCount =
                         dnsZoneReplyPacket->dnsHeader.upCount;

                    memcpy(tcpConnData->dataRecvd,
                           MESSAGE_ReturnInfo(msg),
                           sizeof(TransportToAppDataReceived));
                }

                if (tcpConnData->totalFragment==0 && packetFormed == FALSE &&
                    ((UInt32)MESSAGE_ReturnPacketSize(msg) <
                      (tcpConnData->upCount* sizeof(struct DnsRrRecord)
                     + (sizeof(struct DnsZoneTransferPacket))
                     + (sizeof(zoneFreshCount)))))
                {
                    float totalFrag = 0.0;
                    totalFrag = (((float)(
                                 tcpConnData->upCount *
                                 sizeof(struct DnsRrRecord)
                                   + (sizeof(struct DnsZoneTransferPacket))
                                   + (sizeof(zoneFreshCount))))
                                 /MESSAGE_ReturnPacketSize(msg));

                    tcpConnData->totalFragment = (int)ceil(totalFrag);
                    tcpConnData->packetToSend = (char*)MEM_malloc((
                                           tcpConnData->upCount *
                                           sizeof(struct DnsRrRecord)
                                           + (sizeof(struct DnsZoneTransferPacket))
                                           + (sizeof(zoneFreshCount))));
                    tcpConnData->tempPtr = (char*)tcpConnData->packetToSend;
                }

                if ((UInt32)MESSAGE_ReturnPacketSize(msg) ==
                      (tcpConnData->upCount* sizeof(struct DnsRrRecord)
                          + (sizeof(struct DnsZoneTransferPacket))
                          + (sizeof(zoneFreshCount))))
                {
                    packetInTact = TRUE;
                    tcpConnData->packetToSend = MESSAGE_ReturnPacket(msg);
                }
                if (tcpConnData->totalFragment != 0 && packetFormed == FALSE)
                {
                    memcpy(tcpConnData->tempPtr,
                        (char*)MESSAGE_ReturnPacket(msg),
                    MESSAGE_ReturnPacketSize(msg));

                    tcpConnData->tempPtr += MESSAGE_ReturnPacketSize(msg);
                    tcpConnData->totalFragment--;
                    if (tcpConnData->totalFragment == 0)
                    {
                        packetFormed = TRUE;
                    }
                    else
                    {
                        MEM_free(dnsZoneReplyPacket);
                        break;
                    }
                }

                if (packetFormed == TRUE || packetInTact == TRUE)
                {
                    packetSize = (tcpConnData->upCount*
                                   sizeof(struct DnsRrRecord)
                                   + (sizeof(struct DnsZoneTransferPacket)));
                    pktReceived = (char*)tcpConnData->packetToSend;

                    if (DEBUG)
                    {
                        char buf[MAX_STRING_LENGTH] = "";
                        TIME_PrintClockInSecond(node->getNodeTime(), buf);
                        printf("\nZone Transfer Server:"
                               "Node %d received data %d at %sS\n",
                               node->nodeId, packetSize, buf);
                    }
                    memcpy(&zoneFreshCount,
                           pktReceived,
                           sizeof(zoneFreshCount));
                    pktReceived += (sizeof(zoneFreshCount));

                    memcpy(dnsZoneReplyPacket,
                           pktReceived,
                          (sizeof(struct DnsZoneTransferPacket)));

                    pktReceived += (sizeof(struct DnsZoneTransferPacket));
                    if (DEBUG)
                    {
                        printf("DNS Record Size = %d\n",
                               (Int32)sizeof(struct DnsRrRecord));
                    }

                    char serverDomain[MAX_STRING_LENGTH] = "";
                    strcpy(serverDomain,
                           dnsData->server->dnsTreeInfo->domainName);

                    for (rrCount = 0;
                       rrCount < dnsZoneReplyPacket->dnsHeader.upCount;
                       rrCount++)
                    {
                        struct DnsRrRecord* rrRecord = (struct DnsRrRecord*)
                                    MEM_malloc(sizeof(struct DnsRrRecord));
                        memset(rrRecord, 0, sizeof(struct DnsRrRecord));
                        memcpy(rrRecord,
                               pktReceived,
                              (sizeof(struct DnsRrRecord)));

                        pktReceived += (sizeof(struct DnsRrRecord));
                        DnsRrRecordList :: iterator lst;
                        BOOL addRecord = TRUE;
                        lst = dnsServerData->rrList->begin();
                        while ((lst != dnsServerData->rrList->end()) &&
                                addRecord)
                        {
                            struct DnsRrRecord* tmprrRecord =
                                    (struct DnsRrRecord*)*lst;
                            if (!strcmp(rrRecord->associatedDomainName,
                                tmprrRecord->associatedDomainName) &&
                                !MAPPING_CompareAddress(
                                        rrRecord->associatedIpAddr,
                                        tmprrRecord->associatedIpAddr))
                            {
                                addRecord = FALSE;
                            }
                            lst++;
                        }
                        if (addRecord && rrRecord->rrType == A)
                        {
                            lst = dnsServerData->rrList->begin();
                            while ((lst != dnsServerData->rrList->end()) &&
                                    addRecord)
                            {
                                struct DnsRrRecord* tmprrRecord =
                                    (struct DnsRrRecord*)*lst;
                                if (!strcmp(
                                    rrRecord->associatedDomainName,
                                    tmprrRecord->associatedDomainName) &&
                                    tmprrRecord->rrType == A)
                                {
                                    tmprrRecord->associatedIpAddr =
                                            rrRecord->associatedIpAddr;
                                    addRecord = FALSE;
                                }
                                lst++;
                            }
                        }
                        if (addRecord && (rrRecord->rrType != R_INVALID) &&
                            rrRecord->rrType != SOA)
                        {
                            dnsServerData->rrList->push_back(rrRecord);
                        }
                        else
                        {
                            MEM_free(rrRecord);
                        }
                    }
                    if (DEBUG)
                    {
                        DnsRrRecordList :: iterator item;
                        item = dnsServerData->rrList->begin();

                        // check for matching destIP
                        printf("*************************************");
                        printf("\nAfter Dns ZoneList Updation\n");
                        printf("*************************************\n");
                        printf("For Node: %d the following RR records\n",
                              node->nodeId);
                        while (item != dnsServerData->rrList->end())
                        {
                            struct DnsRrRecord* rrItem =
                                (struct DnsRrRecord*)*item;

                            printf("\tAssociated Domain Name: %s\n",
                               rrItem->associatedDomainName);


                            item++;
                        }
                        printf("\n");
                    }

                    dnsData->zoneData->zoneFreshCount = zoneFreshCount;
                    dnsData->stat.numOfDnsUpdateRecv++;

                    serverPtr = DnsZoneTransferServerGetDnsZoneServer(
                                    node,
                                    tcpConnData->dataRecvd->connectionId);

                    if (serverPtr == NULL)
                    {
                        ERROR_ReportErrorArgs("Zone Transfer Server: Node"
                               "  %d cannot find ftp server\n",
                               node->nodeId);
                    }
                    if (DEBUG)
                    {
                        printf("----MSG_APP_FromTransDataReceived--:%u--",
                               node->nodeId);
                        char addrStr[MAX_STRING_LENGTH] = "";
                        IO_ConvertIpAddressToString(&serverPtr->localAddr,
                             addrStr);
                        printf("    localAddr = %s\n", addrStr);
                        IO_ConvertIpAddressToString(&serverPtr->remoteAddr,
                              addrStr);
                        printf("    remoteAddress = %s\n", addrStr);
                    }
                    if (serverPtr->sessionIsClosed == TRUE)
                    {
                        ERROR_ReportErrorArgs("Zone Transfer Server:Node %d "
                               " ftp server session should not be closed\n",
                               node->nodeId);
                    }

                    if (serverPtr->numBytesRecvd == 0)
                    {
                        serverPtr->sessionStart = node->getNodeTime();
                        serverPtr->sessionFinish = node->getNodeTime();
                    }

                    serverPtr->numBytesRecvd += (clocktype) packetSize;

                    serverPtr->lastItemRecvd = node->getNodeTime();
                    MEM_free(tcpConnData->packetToSend);
                    tcpConnData->packetToSend = NULL;
                }
                MEM_free(dnsZoneReplyPacket);

                isItemExist = FALSE;
                TcpConnInfoList :: iterator lstItem;
                lstItem = dnsData->tcpConnDataList->begin();
                while (lstItem != dnsData->tcpConnDataList->end())
                {
                    tcpTmpConnData = (struct TcpConnInfo*)*lstItem;
                    if (tcpTmpConnData->dataRecvd->connectionId ==
                                    tcpConnData->dataRecvd->connectionId)
                    {
                        isItemExist = TRUE;
                        break;
                    }
                    lstItem++;
                }
                if (isItemExist)
                {
                    if (tcpTmpConnData->dataRecvd)
                    {
                        MEM_free(tcpTmpConnData->dataRecvd);
                        tcpTmpConnData->dataRecvd = NULL;
                    }
                    if (*lstItem)
                    {
                        // free item
                        dnsData->tcpConnDataList->remove(*lstItem);
                        //MEM_free(*lstItem);
                        //*lstItem = NULL;
                    }
                }

                if (!dnsData->isSecondaryActivated)
                {
                    dnsData->isSecondaryActivated = TRUE;
                    if (dnsData->addServer != NULL)
                    {
                        MESSAGE_Send(node, dnsData->addServer,0);
                        dnsData->addServer = NULL;
                    }
                }
            }
            break;
        }
        case MSG_APP_FromTransDataSent:
        {
            // client node can now send next packet to server
            if (dnsData->zoneData->isMasterOrSlave == TRUE)
            {
                TransportToAppDataSent* dataSent = NULL;
                struct DnsServerZoneTransferClient* clientPtr = NULL;

                dataSent = (TransportToAppDataSent*)
                            MESSAGE_ReturnInfo(msg);

                clientPtr = DnsZoneClientGetDnsZoneClient(
                    node, dataSent->connectionId);

                if (DEBUG)
                {
                    printf("----MSG_APP_FromTransDataSent--:%u--",
                        node->nodeId);

                    char addrStr[MAX_STRING_LENGTH] = "";
                    IO_ConvertIpAddressToString(
                        &clientPtr->localAddr,
                        addrStr);
                    printf("    localAddr = %s\n", addrStr);
                    IO_ConvertIpAddressToString(
                        &clientPtr->remoteAddr,
                        addrStr);
                    printf("    remoteAddress = %s\n", addrStr);
                }

                if (clientPtr == NULL)
                {
                    ERROR_ReportErrorArgs("Zone Transfer Client: Node %d "
                        "cannot find ftp client\n",
                               node->nodeId);
                }

                clientPtr->numBytesSent += (clocktype) dataSent->length;
                clientPtr->lastItemSent = node->getNodeTime();

                if (clientPtr->sessionIsClosed != TRUE)
                {
                    DnsZoneClientSendNextItem(node, clientPtr);
                }

                break;
            }
            else
            {
                break;  // for data packet
            }
        }
        case MSG_APP_FromTransCloseResult:
        {
            // Client/Server node receivs close connection information
            struct DnsServerZoneTransferClient* clientPtr = NULL;
            struct DnsServerZoneTransferServer* serverPtr = NULL;

            if (dnsData->zoneData->isMasterOrSlave == TRUE)
            {
                TransportToAppCloseResult* closeResult = NULL;

                closeResult = (TransportToAppCloseResult*)
                                MESSAGE_ReturnInfo(msg);
                clientPtr = DnsZoneClientGetDnsZoneClient(
                                node, closeResult->connectionId);


                if (clientPtr == NULL)
                {
                    ERROR_ReportErrorArgs("Zone Transfer Client:"
                            "Node %d cannot find ftp client\n",
                               node->nodeId);
                }
                if (DEBUG)
                {
                    printf("Zone Transfer Client: "
                           "Node %d got close result\n",
                           node->nodeId);

                    printf("----MSG_APP_FromTransCloseResult--:%u--",
                        node->nodeId);
                    char addrStr[MAX_STRING_LENGTH] = "";
                    IO_ConvertIpAddressToString(&clientPtr->localAddr,
                        addrStr);
                    printf("    localAddr = %s\n", addrStr);
                    IO_ConvertIpAddressToString(&clientPtr->remoteAddr,
                        addrStr);
                    printf("    remoteAddress = %s\n", addrStr);
                }

                if (clientPtr->sessionIsClosed == FALSE)
                {
                    clientPtr->sessionIsClosed = TRUE;
                    clientPtr->sessionFinish = node->getNodeTime();
                }

                break;
            }
            else
            {
                TransportToAppCloseResult* closeResult =
                        (TransportToAppCloseResult*)MESSAGE_ReturnInfo(msg);

                if (DEBUG)
                {
                    printf("Zone Transfer Server: Node %d got close result\n"
                        , node->nodeId);
                }
                serverPtr = DnsZoneTransferServerGetDnsZoneServer(
                                node,
                                closeResult->connectionId);
                if (serverPtr == NULL &&
                    dnsData->zoneTransferServerData->size() == 0)
                {
                    break;
                }

                if (serverPtr == NULL)
                {
                    ERROR_ReportErrorArgs("Zone Transfer Server: Node %d"
                            " cannot find TCP server\n",
                               node->nodeId);
                }

                if (DEBUG)
                {
                    printf("----MSG_APP_FromTransCloseResult--:%d--",
                        node->nodeId);

                    char addrStr[MAX_STRING_LENGTH] = "";

                    IO_ConvertIpAddressToString(&serverPtr->localAddr,
                        addrStr);
                    printf("    localAddr = %s\n", addrStr);
                    IO_ConvertIpAddressToString(&serverPtr->remoteAddr,
                        addrStr);
                    printf("    remoteAddress = %s\n", addrStr);
                }

                if (serverPtr->sessionIsClosed == FALSE)
                {
                    serverPtr->sessionIsClosed = TRUE;
                    serverPtr->sessionFinish = node->getNodeTime();

                    APP_TcpCloseConnection(
                        node,
                        serverPtr->connectionId);
                    ServerZoneTransferDataList :: iterator lstItem =
                        dnsData->zoneTransferServerData->begin();
                    struct DnsServerZoneTransferServer* deleteItem = NULL;
                    struct DnsServerZoneTransferServer* zoneTransferServer;
                    while (lstItem != dnsData->zoneTransferServerData->end())
                    {
                        zoneTransferServer =
                            (struct DnsServerZoneTransferServer*)*lstItem;
                        if (zoneTransferServer->connectionId ==
                                serverPtr->connectionId)
                        {
                            deleteItem =
                                (struct DnsServerZoneTransferServer*)*lstItem;
                            break;
                        }
                        lstItem++;
                    }
                    if (deleteItem)
                    {
                        // free item
                        dnsData->zoneTransferServerData->remove(deleteItem);
                        MEM_free(deleteItem);
                        deleteItem = NULL;
                    }
                }
                break;
            }
        }
        default:
        {
            ERROR_ReportErrorArgs("\n Invalid Message Type");
            break;
        }
    }// end of switch
}
//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsAddServerRRToParent
// LAYER        :: Application Layer
// PURPOSE      :: Adds server RR to parent
// PARAMETERS   :: node - Pointer to node.
//                 serverLabel - server label
//                 serverAddress - server address
//                 parentAddress - parent address
// RETURN       :: None
//--------------------------------------------------------------------------

void AppDnsAddServerRRToParent(Node* node,
                        char* serverLabel,
                        Address serverAddress,
                        Address parentAddress)
{
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
    AppToUdpSend* info = NULL;
    Message* eventMsg = MESSAGE_Alloc(node,
        APP_LAYER,
        APP_DNS_SERVER,
        MSG_APP_DNS_ADD_SERVER);

    MESSAGE_PacketAlloc(node,
        eventMsg,
        sizeof(Address) +
        DNS_NAME_LENGTH,
        TRACE_DNS);
    memcpy(MESSAGE_ReturnPacket(eventMsg),
          (char*)(&serverAddress),
          sizeof(Address));
    memcpy(MESSAGE_ReturnPacket(eventMsg) + sizeof(Address),
            (char*)(serverLabel),
            DNS_NAME_LENGTH);

    MESSAGE_InfoAlloc(node,
                      eventMsg,
                      sizeof(AppToUdpSend));

    info = (AppToUdpSend*) MESSAGE_ReturnInfo(eventMsg);
    memset(info, 0, sizeof(AppToUdpSend));
    info->sourceAddr = serverAddress;
    info->sourcePort = (short)APP_DNS_CLIENT;
    info->destAddr = parentAddress;
    info->destPort = (short) APP_DNS_SERVER;
    info->priority = APP_DEFAULT_TOS;
    dnsData->addServer = eventMsg;
}


//--------------------------------------------------------------------------
// FUNCTION     :: App_DnsRquest
// LAYER        :: Application Layer
// PURPOSE      :: Application request Dns to Resolve Addr
// PARAMETERS   :: node - Partition Data Ptr
//                 type - Application type
//                 uniqueId - Unique ID
//                 tcpMode - tcp mode
//                 localAddr - local address
//                 startTime - start time of application
//                 sourceNetworktype - source network type
// RETURN       :: None
//--------------------------------------------------------------------------

void App_DnsRquest(Node* node,
                   AppType type,
                   UInt16 sourcePort,
                   Int32 uniqueId,
                   BOOL tcpMode,
                   Address* localAddr,
                   std::string serverUrl,
                   clocktype startTime,
                   NetworkType sourceNetworktype)
{
    Message* timerMsg = NULL;
    struct AppDnsInfoTimer* timer = NULL;
    Int16 interfaceId = (Int16)
        MAPPING_GetInterfaceIndexFromInterfaceAddress(node, *localAddr);
    timerMsg = MESSAGE_Alloc(node,
        APP_LAYER,
        APP_DNS_CLIENT,
        MSG_APP_DnsStartResolveUrl);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(struct AppDnsInfoTimer));

    timer = (struct AppDnsInfoTimer*)MESSAGE_ReturnInfo(timerMsg);

    timer->uniqueId = uniqueId;
    timer->sourcePort = sourcePort;
    timer->tcpMode = tcpMode;
    timer->type = type;
    timer->interfaceId = interfaceId;
    timer->sourceNetworktype = sourceNetworktype;
    memcpy(&(timer->addr), localAddr, sizeof(Address));
    AppDnsConcatenatePeriodIfNotPresent(&serverUrl);
    timer->serverUrl = new std::string(serverUrl);
    MESSAGE_Send(node, timerMsg, startTime);
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsZoneListInitialization
// LAYER        :: Application Layer
// PURPOSE      :: Zone List Initialization for MAster of the Zone
// PARAMETERS   :: node - Node Ptr
// RETURN       :: None
//--------------------------------------------------------------------------
void DnsZoneListInitialization(Node* node)
{
    while (node != NULL)
    {
        struct DnsData* dnsData = NULL;
        struct DnsServerData* dnsServerData = NULL;
        if (DEBUG)
        {
            printf("In DnsZoneListInitialization for node %d\n",
                                                 node->nodeId);
        }
        dnsData = (struct DnsData*)node->appData.dnsData;

        if (dnsData == NULL)
        {
            node = node->nextNodeData;
            continue;
        }

        dnsServerData = dnsData->server;
        if (dnsData->dnsServer != TRUE )
        {
            if (DEBUG)
            {
                printf("continuing from DnsZoneListInitialization "
                    "as dnsServer is false\n");
            }
            node = node->nextNodeData;
            continue;
        }
        if (dnsData->zoneData->isMasterOrSlave == TRUE)
        {
            dnsData->zoneData->zoneFreshCount = 1;
            if (dnsData->zoneTransferClientData == NULL)
            {
                dnsData->zoneTransferClientData =
                    new ClientZoneTransferDataList;
            }
        }
        else if (dnsData->inSrole)
        {
            if (DEBUG)
            {
                printf("sending zone refresh timer for node %d as it is "
                "seconadry server\n", node->nodeId);
            }
            dnsData->zoneData->zoneFreshCount = 0;
            Message* timerMsg = MESSAGE_Alloc(node,
                                    APP_LAYER,
                                    APP_DNS_SERVER,
                                    MSG_APP_DNS_ZONE_REFRESH_TIMER);
            dnsData->secZoneRefreshTimerMsg = timerMsg;
            MESSAGE_Send(node, timerMsg, dnsData->secondaryTimeAdded);
        }
        node = node->nextNodeData;
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsHostsFileInit
// LAYER        :: Application Layer
// PURPOSE      :: Initialize Cache from the Hosts file
// PARAMETERS   :: node - Pointer to node.
//                 nodeInput - Configuration Information
// RETURN       :: None
//--------------------------------------------------------------------------

void AppDnsHostsFileInit(
                    Node* node,
                    const NodeInput* nodeInput)
{
    NodeInput hostsFileInput;
    BOOL wasFoundHostsFile = FALSE;
    Int32 lineCount = 0;
    BOOL isNodeId = FALSE;
    Address outputNodeAddress;
    std::string ipAddressString;
    Int32 numInputs = 0;
    std::string url;

    if (DEBUG)
    {
        printf("In AppDnsHostsFileInit for node %d\n", node->nodeId);
    }
    IO_ReadCachedFile(node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "DNS-HOSTS-FILE",
        &wasFoundHostsFile,
        &hostsFileInput);

    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
    memset(&outputNodeAddress, 0 , sizeof(Address));
    // If DNS is not already allocated
    if (dnsData == NULL)
    {
        dnsData = (struct DnsData*)MEM_malloc(sizeof(struct DnsData));
        memset(dnsData, 0, sizeof(struct DnsData));
        dnsData->clientData = new DnsClientDataList;
        dnsData->appReqList = new DnsAppReqItemList;
        dnsData->cache = new CacheRecordList;
        dnsData->clientResolveState = new ClientResolveStateList;
        dnsData->zoneTransferClientData = new ClientZoneTransferDataList;
        dnsData->tcpConnDataList = new TcpConnInfoList;
        dnsData->nameServerList = new NameServerList;
        node->appData.dnsData = (void*)dnsData;
    }

    if (dnsData->cache == NULL)
    {
        dnsData->cache = new CacheRecordList;
    }

    if (wasFoundHostsFile == TRUE)
    {
        for (lineCount = 0;
            lineCount < hostsFileInput.numLines;
            lineCount++)
        {
            std::stringstream currentLine(hostsFileInput.inputStrings[lineCount]);
            currentLine >> url;
            currentLine >> ipAddressString;

            if (ipAddressString.size() == 0)
            {
                ERROR_ReportErrorArgs("Incorrect format is used in DNS Hosts"
                                  " File in line: %s\n"
                                  "It should be <URL> <IP-address>",
                                  hostsFileInput.inputStrings[lineCount]);
            }

            AppDnsConcatenatePeriodIfNotPresent(&url);

            IO_ParseNodeIdHostOrNetworkAddress(
                ipAddressString.c_str(),
                &outputNodeAddress,
                &isNodeId);

            if (isNodeId)
            {
                ERROR_ReportErrorArgs(
                    "Hosts file shouldn't contain any Node Id");
            }

            struct CacheRecord* cacheRecord = NULL;
            cacheRecord = (struct CacheRecord*)
                        MEM_malloc(sizeof(struct CacheRecord));
            memset(cacheRecord, 0, sizeof(struct CacheRecord));
            cacheRecord->urlNameString = new std::string();
            cacheRecord->urlNameString->assign(url);
            cacheRecord->associatedIpAddr = outputNodeAddress;

            // Since simulation clock is not started yet..
            cacheRecord->cacheEntryTime = (clocktype)0;
            cacheRecord->deleted = FALSE;
            dnsData->cache->push_back(cacheRecord);
        }
    }
}


//--------------------------------------------------------------------------
// FUNCTION       :: DNSHostSendAddressChangeUpdateToServer
// PURPOSE        :: Handles any change in the interface address
// PARAMETERS     :: node - Pointer to Node structure
//                   interfaceIndex - interface index
//                   networkType - type of network protocol
//                   dnsClientData - Client DNS Data
// RETURN         :: NULL
//--------------------------------------------------------------------------
static void DNSHostSendAddressChangeUpdateToServer(
    Node* node,
    Int32 interfaceIndex,
    NetworkType networkType,
    struct DnsClientData* dnsClientData)
{
    struct DnsData* dnsData =(struct DnsData*)node->appData.dnsData;
    networkType = NETWORK_INVALID;// to supress the warnings
    Address sourceAddress;
    BOOL isPrimary = TRUE;
    NetworkProtocolType protocol_type = INVALID_NETWORK_TYPE;
    Int32 interfaceId = interfaceIndex;
    protocol_type = NetworkIpGetNetworkProtocolType(node,
                              node->nodeId);
    dnsClientData->rootQueriedCount = 0;
    dnsClientData->retryCount = 0;    // reset the count
    dnsClientData->isUpdateSuccessful = FALSE;
    dnsClientData->isNameserverResolved = FALSE;
    dnsClientData->receivedNsQueryResult = FALSE;
    if (dnsClientData->interfaceNo == ALL_INTERFACE)
    {
        interfaceId = DEFAULT_INTERFACE;
    }
    if ((protocol_type == IPV6_ONLY) || (protocol_type == DUAL_IP))
    {
        sourceAddress.networkType = NETWORK_IPV6;
        Ipv6GetGlobalAggrAddress(node,
                        interfaceId,
                        &sourceAddress.interfaceAddr.ipv6);
    }
    else if (protocol_type == IPV4_ONLY)
    {
        sourceAddress.networkType = NETWORK_IPV4;
        sourceAddress.interfaceAddr.ipv4 =
                            NetworkIpGetInterfaceAddress(node, interfaceId);
    }

    struct DnsQueryPacket* dnsQueryPacket = NULL;

    dnsQueryPacket = (struct DnsQueryPacket*)
                        MEM_malloc (sizeof(struct DnsQueryPacket));

    memset(dnsQueryPacket, 0, sizeof(struct DnsQueryPacket));
    dnsQueryPacket->dnsQuestion.dnsQType = SOA;
    char* domainName = strstr(dnsClientData->fqdn, ".");
    strcpy(dnsQueryPacket->dnsQuestion.dnsQname, domainName + 1);

    dnsQueryPacket->dnsQuestion.dnsQClass = IN ;

    dnsQueryPacket->dnsHeader.dns_id = (UInt16)interfaceIndex;

     // query message (message type)
    DnsHeaderSetQr(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // standary query
    DnsHeaderSetOpcode(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // valid from responses
    DnsHeaderSetAA(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // truncated or not
    DnsHeaderSetTC(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // recursion desired
    DnsHeaderSetRD(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // recursion available
    DnsHeaderSetRA(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // for future use
    DnsHeaderSetReserved(&dnsQueryPacket->dnsHeader.dns_hdr, 0);
     // response code
    DnsHeaderSetRcode(&dnsQueryPacket->dnsHeader.dns_hdr, 0);


    Message* msg = NULL;
    AppToUdpSend* info = NULL;

    enum DnsMessageType dnsMsgType = DNS_QUERY;
    msg = MESSAGE_Alloc(
                        node,
                        TRANSPORT_LAYER,
                        TransportProtocol_UDP,
                        MSG_TRANSPORT_FromAppSend);

    MESSAGE_PacketAlloc(node,
            msg,
            sizeof(Address)+
                sizeof(enum DnsMessageType) +
                sizeof(struct DnsQueryPacket) +
                sizeof(BOOL),
            TRACE_DNS);

    memcpy(MESSAGE_ReturnPacket(msg),
            (char*)(&dnsMsgType),
            sizeof(enum DnsMessageType));

    memcpy(MESSAGE_ReturnPacket(msg) +
            sizeof(enum DnsMessageType),
            (char*)dnsQueryPacket,
            sizeof(struct DnsQueryPacket));

    memcpy(MESSAGE_ReturnPacket(msg) +
                sizeof(enum DnsMessageType) +
                sizeof(struct DnsQueryPacket),
           (char*)(&sourceAddress),
           sizeof(Address));

    memcpy(MESSAGE_ReturnPacket(msg) +
                sizeof(enum DnsMessageType) +
                sizeof(struct DnsQueryPacket) +
                sizeof(Address),
           (char*)(&isPrimary),
           sizeof(BOOL));

    MESSAGE_InfoAlloc(node, msg, sizeof(AppToUdpSend));

    info = (AppToUdpSend*) MESSAGE_ReturnInfo(msg);
    memset(info, 0, sizeof(AppToUdpSend));
    info->sourceAddr = sourceAddress;

    info->sourcePort = (short)APP_DNS_CLIENT;
    if (dnsClientData->primaryDNS.networkType == NETWORK_INVALID)
    {
        ERROR_ReportErrorArgs("No Primary DNS is configured for NodeID %d"\
            "and interfaceId %d \n",
            node->nodeId,
            interfaceIndex);
    }
    memcpy(&(info->destAddr),
        &dnsClientData->primaryDNS, sizeof(Address));
    info->destPort = (UInt16) APP_DNS_SERVER;
    info->priority = APP_DEFAULT_TOS;
    info->outgoingInterface = interfaceId;
    if (DEBUG)
    {
        char remoteAddrStr[MAX_STRING_LENGTH] = "";
        if (info->destAddr.networkType != NETWORK_INVALID)
        {
            IO_ConvertIpAddressToString(&info->destAddr, remoteAddrStr);
        }
        printf("In DNSHostSendAddressChangeUpdateToServer: Node %d"
            " sending SOA(%s)\n query to its PDNS %s\n", node->nodeId,
            dnsQueryPacket->dnsQuestion.dnsQname, remoteAddrStr);
    }
    if (dnsClientData->secondaryDNS.networkType != NETWORK_INVALID)
    {
        Message* secDupMsg = MESSAGE_Duplicate (node, msg);
        AppToUdpSend* secInfo = NULL;
        secInfo = (AppToUdpSend*) MESSAGE_ReturnInfo(secDupMsg);
        memcpy(&(secInfo->destAddr),
            &dnsClientData->secondaryDNS, sizeof(Address));
        if (DEBUG)
        {
            char remoteAddrStr[MAX_STRING_LENGTH] = "";
            if (secInfo->destAddr.networkType != NETWORK_INVALID)
            {
                IO_ConvertIpAddressToString(
                    &secInfo->destAddr,
                    remoteAddrStr);
            }
            printf("In DNSHostSendAddressChangeUpdateToServer: Node %d"
                " sending SOA query to its SDNS %s\n",
                node->nodeId,
                remoteAddrStr);
        }
        MESSAGE_Send(node, secDupMsg, 0);
        dnsData->stat.numOfDnsSOAQuerySent++;
    }
    Message* dupMsg = MESSAGE_Duplicate(node, msg);
    dnsClientData->nextMessage = dupMsg;
    dnsClientData->retryCount = 0;
    dnsClientData->isNameserverResolved = FALSE;
    AppToUdpSend* timer = NULL;
    Message* timerMsg = MESSAGE_Alloc(node,
                            APP_LAYER,
                            APP_DNS_CLIENT,
                            MSG_APP_DnsRetryResolveNameServer);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppToUdpSend));
    timer = (AppToUdpSend*)MESSAGE_ReturnInfo(timerMsg);
    timer->outgoingInterface = interfaceId;
    MESSAGE_Send(node, timerMsg, TIMEOUT_INTERVAL_OF_DNS_QUERY_REPLY);
    MESSAGE_Send(node, msg, 0);
    dnsData->stat.numOfDnsSOAQuerySent++;
    dnsClientData->retryCount++;
    MEM_free(dnsQueryPacket);
}


//--------------------------------------------------------------------------
// FUNCTION       :: DNSHandleChangeAddressEvent
// PURPOSE        :: Handles any change in the interface address
// PARAMETERS     :: node - Pointer to Node structure
//                   interfaceIndex - interface index
//                   oldAddress - Address* old global address
//                   networkType - type of network protocol
// RETURN         :: NULL
//--------------------------------------------------------------------------
void DNSClientHandleChangeAddressEvent(Node* node,
                                       Int32 interfaceIndex,
                                       Address* oldAddress,
                                       NodeAddress subnetMask,
                                       NetworkType networkType)
{
    struct DnsData* dnsData = NULL;
    struct DnsClientData* dnsClientData = NULL;
    DnsClientDataList :: iterator item;
    NetworkDataIp* ip = node->networkData.networkVar;
    IpInterfaceInfoType* intf =
                 (IpInterfaceInfoType*)ip->interfaceInfo[interfaceIndex];
    dnsData = (struct DnsData*)node->appData.dnsData;
    BOOL sendUpdate = FALSE;
    oldAddress = NULL; // to suppress warnings
    subnetMask = 0; // to suppress warnings

    if (!dnsData)
    {
        ERROR_ReportErrorArgs("DNS is not enabled: %d", node->nodeId);
    }

    // If DNS is not already allocated
    if (dnsData->clientData == NULL)
    {
        ERROR_ReportErrorArgs("No DNS Client Information" \
            "is configured for Node Id: %d",
            node->nodeId);
    }
    item = dnsData->clientData->begin();

    while (item != dnsData->clientData->end())
    {
        dnsClientData = (struct DnsClientData*)*item;
        if (( dnsClientData->interfaceNo == interfaceIndex )||
            ( dnsClientData->interfaceNo == ALL_INTERFACE))
        {
            sendUpdate = TRUE;
            if ((intf) &&
              (intf->isDhcpEnabled == TRUE) &&
              (intf->addressState != INVALID))
            {
                if (dnsClientData->isDnsAsignedDynamically)
                {
                    dnsClientData->primaryDNS = intf->primaryDnsServer;
                    if (intf->listOfSecondaryDNSServer != NULL)
                    {
                        if (intf->listOfSecondaryDNSServer->first != NULL)
                        {
                            memcpy(&dnsClientData->secondaryDNS,
                                   intf->listOfSecondaryDNSServer->
                                            first->data,
                                   sizeof(Address));
                        }
                    }
                }

                if (dnsClientData->fqdn)
                {
                    DNSHostSendAddressChangeUpdateToServer(node,
                                   interfaceIndex,
                                   networkType,
                                   dnsClientData);
                }
                break;
            }
        }
        item++;
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsClientInit
// LAYER        :: Application Layer
// PURPOSE      :: Initialize Pr. DNS and Secnd. DNS Server to Dns Client
// PARAMETERS   :: node - Pointer to node.
//                 interfaceNo - Interface No for which Pr. DNS to be set
//                 primaryDns - Address of Primary DNS Server
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsClientInit(
                 Node* node,
                 Int32 interfaceNo,
                 Address primaryDns,
                 Address primaryDnsIpv6Addr)
{
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;;

    if (DEBUG)
    {
        printf("In AppDnsClientInit for node %d\n", node->nodeId);
    }
    // If DNS is not already allocated
    if (dnsData == NULL)
    {
        dnsData = (struct DnsData*)MEM_malloc(sizeof(struct DnsData));
        memset(dnsData, 0, sizeof(struct DnsData));
        node->appData.dnsData = (void*)dnsData;
        dnsData->clientData = new DnsClientDataList;
        dnsData->appReqList = new DnsAppReqItemList;
        dnsData->cache = new CacheRecordList;
        dnsData->clientResolveState = new ClientResolveStateList;
        dnsData->zoneTransferClientData = new ClientZoneTransferDataList;
        dnsData->tcpConnDataList = new TcpConnInfoList;
        dnsData->nameServerList = new NameServerList;
    }

    struct DnsClientData* dnsClientData = (struct DnsClientData*)
                                        MEM_malloc(sizeof(struct DnsClientData));
    memset(dnsClientData, 0, sizeof(struct DnsClientData));
    dnsClientData->interfaceNo = (Int16)interfaceNo;
    dnsClientData->primaryDNS = primaryDns;
    dnsClientData->ipv6PrimaryDNS = primaryDnsIpv6Addr;
    dnsClientData->isDnsAsignedDynamically = FALSE;
    memset(&(dnsClientData->secondaryDNS), 0, sizeof(Address));

    dnsData->clientData->push_back(dnsClientData);
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsClientInit
// LAYER        :: Application Layer
// PURPOSE      :: Initialize Pr. DNS and Secnd. DNS Server to Dns Client
// PARAMETERS   :: node - Pointer to node.
//                 nodeInput - Configuration Information
//                 interfaceNo - Interface No for which Pr. DNS to be set
//                 primaryDns - Node Id of Primary DNS Server
//                 secondaryDns - Node Id of Primary DNS Server(secondary)
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsClientInit(
                 Node* node,
                 Int32 interfaceNo,
                 Address primaryDns,
                 Address primaryDnsIpv6Addr,
                 Address secondaryDns,
                 Address secondaryDnsIpv6Addr,
                 BOOL isDhcpClient = FALSE)
{
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;
    if ((primaryDns.networkType != NETWORK_INVALID)&&
        (secondaryDns.networkType != NETWORK_INVALID))
    {
        if (!MAPPING_CompareAddress(primaryDns, secondaryDns))
        {
            ERROR_ReportErrorArgs("The Node: %d can not be configured "
                "with same Primary DNS server and Secondary DNS server",
                node->nodeId);
        }
    }
    if (DEBUG)
    {
        printf("In AppDnsClientInit with secondary for node %d\n",
                                                    node->nodeId);
    }
    // If DNS is not already allocated
    if (dnsData == NULL)
    {
        dnsData = (struct DnsData*)MEM_malloc(sizeof(struct DnsData));
        memset(dnsData, 0, sizeof(struct DnsData));
        node->appData.dnsData = (void*)dnsData;
        dnsData->clientData = new DnsClientDataList;
        dnsData->appReqList = new DnsAppReqItemList;
        dnsData->cache = new CacheRecordList;
        dnsData->clientResolveState = new ClientResolveStateList;
        dnsData->zoneTransferClientData = new ClientZoneTransferDataList;
        dnsData->tcpConnDataList = new TcpConnInfoList;
        dnsData->nameServerList = new NameServerList;
    }

    struct DnsClientData* dnsClientData =(struct DnsClientData*)
                                        MEM_malloc(sizeof(struct DnsClientData));
    memset(dnsClientData, 0, sizeof(struct DnsClientData));
    dnsClientData->interfaceNo = (Int16)interfaceNo;
    dnsClientData->primaryDNS = primaryDns;
    dnsClientData->ipv6PrimaryDNS = primaryDnsIpv6Addr;
    dnsClientData->isDnsAsignedDynamically = isDhcpClient;
    dnsClientData->secondaryDNS = secondaryDns;
    dnsClientData->ipv6SecondaryDNS = secondaryDnsIpv6Addr;

    dnsData->clientData->push_back(dnsClientData);
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsServerInit
// LAYER        :: Application Layer
// PURPOSE      :: Initialize various parameter related to Dns Server
// PARAMETERS   :: node - Pointer to node.
//                 nodeInput - Configuration Information
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsServerInit(Node* node, const NodeInput* nodeInput)
{
    NodeInput treeStructureInput;
    NodeInput domainNameInput;
    BOOL wasFoundTreeInfoFile = FALSE;
    BOOL wasFoundDomainNameFile = FALSE;
    char errStr[MAX_STRING_LENGTH] = "";
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;

    if (DEBUG)
    {
        printf("In AppDnsServerInit for node %d\n", node->nodeId);
    }

    if (dnsData == NULL)
    {
        dnsData = (struct DnsData*)MEM_malloc(sizeof(struct DnsData));
        memset(dnsData, 0, sizeof(struct DnsData));
        dnsData->clientData = new DnsClientDataList;
        dnsData->appReqList = new DnsAppReqItemList;
        dnsData->cache = new CacheRecordList;
        dnsData->clientResolveState = new ClientResolveStateList;
        dnsData->zoneTransferClientData = new ClientZoneTransferDataList;
        dnsData->tcpConnDataList = new TcpConnInfoList;
        dnsData->nameServerList = new NameServerList;
        node->appData.dnsData = (void*)dnsData;
    }

    struct DnsServerData* dnsServerData =
        (struct DnsServerData*)MEM_malloc(sizeof(struct DnsServerData));
    memset(dnsServerData, 0, sizeof(struct DnsServerData));
    dnsData->server = dnsServerData;

    struct DnsTreeInfo* dnsTreeInfo =
        (struct DnsTreeInfo*)MEM_malloc(sizeof(struct DnsTreeInfo));
    memset(dnsTreeInfo, 0, sizeof(struct DnsTreeInfo));
    dnsData->server->dnsTreeInfo = dnsTreeInfo;

    struct ZoneData* zoneData = (struct ZoneData*)
                                MEM_malloc(sizeof(struct ZoneData));
    memset(zoneData, 0, sizeof(struct ZoneData));
    dnsData->zoneData = zoneData;

    dnsData->dnsServer = TRUE;

    IO_ReadCachedFile(node->nodeId,
                      ANY_ADDRESS,
                      nodeInput,
                      "DNS-DOMAIN-NAME-SPACE-FILE",
                      &wasFoundTreeInfoFile,
                      &treeStructureInput);


    if (!wasFoundTreeInfoFile)
    {
        ERROR_ReportErrorArgs(
            "Node %d:DNS Tree Config File couldn't be found\n",
            node->nodeId);
    }
    //"DNS Tree Config File couldn't be found");

    DnsReadTreeConfigParameter(node,
        dnsData,
        &treeStructureInput,
        nodeInput);

    IO_ReadCachedFile(node->nodeId,
                      ANY_ADDRESS,
                      nodeInput,
                      "DNS-DOMAIN-NAMES-FILE",
                      &wasFoundDomainNameFile,
                      &domainNameInput);

    if (wasFoundDomainNameFile == TRUE)
    {
        DnsReadDomainNameFile(node,
                              dnsData,
                              nodeInput,
                              &domainNameInput);
    }
    else
    {
        ERROR_ReportErrorArgs(
            "Node %d:The DNS register file not present\n",
            node->nodeId);
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsSetFQDN
// LAYER        :: Application Layer
// PURPOSE      :: Initialize various parameter related to Dns Server
// PARAMETERS   :: node - Pointer to node.
//                 nodeInput - Configuration Information
//                 dnsdata - pointer to dns data
//                 outputNodeAddress
//                 domainName
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsSetFQDN(
              Node* node,
              const NodeInput* nodeInput,
              struct DnsData* dnsdata,
              Address outputNodeAddress,
              char*  domainName)
{
    BOOL  retVal = FALSE;
    NodeId tempNodeId = 0;
    Int16 interfaceIndex = 0;
    DnsClientDataList :: iterator item;
    NetworkDataIp* ip = node->networkData.networkVar;
    IpInterfaceInfoType* intf = NULL;
    struct DnsClientData* dnsClientData = NULL;
    AddressMapType* map = node->partitionData->addressMapPtr;
    tempNodeId = MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                       outputNodeAddress);
    interfaceIndex = (Int16)MAPPING_GetInterfaceIndexFromInterfaceAddress(
                            node,
                            outputNodeAddress);
    intf = (IpInterfaceInfoType*)ip->interfaceInfo[interfaceIndex];

    NetworkProtocolType networkType =
                MAPPING_GetNetworkProtocolTypeForInterface(
                                                map,
                                                node->nodeId,
                                                interfaceIndex);

    item = dnsdata->clientData->begin();

    while (item != dnsdata->clientData->end())
    {
        dnsClientData = (struct DnsClientData*)*item;

        if (( dnsClientData->interfaceNo == interfaceIndex )||
            ( dnsClientData->interfaceNo == ALL_INTERFACE))
        {
            if (networkType == DUAL_IP)
            {
                if ((dnsClientData->oldIpAddress.networkType ==
                            NETWORK_IPV6)&&
                    (dnsClientData->ipv6Address.networkType ==
                            NETWORK_INVALID))
                {
                    dnsClientData->ipv6Address = dnsClientData->oldIpAddress;
                    memset(&dnsClientData->oldIpAddress, 0, sizeof(Address));
                }
            }
            if (dnsClientData->oldIpAddress.networkType == NETWORK_INVALID)
            {
                dnsClientData->oldIpAddress = outputNodeAddress;
            }
            else
            {
                dnsClientData->ipv6Address = outputNodeAddress;
            }
            dnsClientData->networkType = networkType;

            if (!dnsClientData->fqdn)
            {
                dnsClientData->fqdn = (char*)MEM_malloc(DNS_NAME_LENGTH);
            }
            sprintf(dnsClientData->fqdn, "host%d", tempNodeId);

            IO_ReadString(tempNodeId,
                          ANY_ADDRESS,
                          nodeInput,
                          "HOSTNAME",
                          &retVal,
                          dnsClientData->fqdn);
            if (DEBUG)
            {
                printf("Hostname for node %d is %s\n",
                        tempNodeId,
                        dnsClientData->fqdn);
            }
            strcat(dnsClientData->fqdn, DOT_SEPARATOR);
            strcat(dnsClientData->fqdn, domainName);

            std::string fqdnStr(dnsClientData->fqdn);
            AppDnsConcatenatePeriodIfNotPresent(&fqdnStr);
            strcpy(dnsClientData->fqdn, fqdnStr.c_str());
            break;
        }
        item++;
    }
    return;
}
//--------------------------------------------------------------------------
// FUNCTION     :: DNSInitializeHostName
// LAYER        :: Application Layer
// PURPOSE      :: initializes DNS host name
// PARAMETERS   :: node - Pointer to node.
//                 nodeInput - pointer to node input
//                 dnsdata - dns data
// RETURN       :: None
//--------------------------------------------------------------------------

static void DNSInitializeHostName(Node* node,
                                  const NodeInput* nodeInput,
                                  struct DnsData* dnsdata)
{
    char interfaceAddressString[50] = "";
    char domainName[DNS_NAME_LENGTH] = "";
    BOOL wasFoundDomainNameFile = FALSE;
    BOOL isDomainNameFilePresent = FALSE;
    BOOL isNodeId = FALSE;
    NodeInput domainNameInput;
    Int32 numInputs = 0;
    Int32 lineCount = 0;
    char* fileName = NULL;
    memset(&domainNameInput, 0, sizeof(NodeInput));

    for (Int32 i = 0; i < nodeInput->numLines; i++)
    {
        if (!strcmp(nodeInput->variableNames[i], "DNS-DOMAIN-NAMES-FILE"))
        {
            fileName = nodeInput->values[i];
            wasFoundDomainNameFile = TRUE;
            break;
        }
    }

    if (wasFoundDomainNameFile)
    {
        for (Int32 i = 0; i < nodeInput->numFiles; i++)
        {
            if (strstr(nodeInput->cachedFilenames[i], fileName))
            {
                domainNameInput = *(nodeInput->cached[i]);
                isDomainNameFilePresent = TRUE;
                break;
            }
        }
    }

    if (!wasFoundDomainNameFile || !isDomainNameFilePresent)
    {
        ERROR_ReportErrorArgs(
            "Node %d:The DNS register file not present\n",
            node->nodeId);
    }
    Address* ipAddress = NULL;
    for (; lineCount < domainNameInput.numLines; lineCount++)
    {
        const char* currentLine = domainNameInput.inputStrings[lineCount];

        numInputs = sscanf(currentLine, "%s %s",
                           interfaceAddressString,
                           domainName);

        NodeId nodeId = 0;
        Address outputNodeAddress;
        memset(&outputNodeAddress, 0, sizeof(Address));

        NetworkType networkType =
                MAPPING_GetNetworkType(interfaceAddressString);
        if (NULL == ipAddress)
        {
            ipAddress = (Address*)MEM_malloc(sizeof(Address));
        }
        memset(ipAddress, 0, sizeof(Address));
        if (networkType == NETWORK_IPV4)
        {
            Int32 numHostBits;
            ipAddress->networkType = NETWORK_IPV4;

            IO_ParseNodeIdHostOrNetworkAddress(interfaceAddressString,
                                              &ipAddress->interfaceAddr.ipv4,
                                              &numHostBits,
                                              &isNodeId);

            if (numHostBits != 0)
            {
                // Find the pointer to the partition map
                // For all the subnets in the scenario, Get the Subnet List.
                // For all the members in the Subnet List
                // Extract the interface index and Address.
                // Find the subnet mask of this Adress.
                // Using the subnet mask, find the subnet address
                // If this subnet address is equal to the Subnet address
                // given in file then it means that this address lies in the subnet

                Int32 countNumSubnets = 0;
                Int32 countNumMembers = 0;
                Int32 interfaceIndex = 0;
                NodeId nodeId = 0;
                NodeAddress subnetmask = 0;
                NodeAddress subnetAddress = 0;

                PartitionData* partitionData = node->partitionData;
                PartitionSubnetData* subnetData =
                                        &partitionData->subnetData;
                for (countNumSubnets = 0;
                    countNumSubnets < subnetData->numSubnets;
                    countNumSubnets++)
                {
                    PartitionSubnetList subnetList =
                         subnetData->subnetList[countNumSubnets];

                    for (countNumMembers = 0;
                        countNumMembers < subnetList.numMembers;
                        countNumMembers++)
                    {
                        nodeId =
                            subnetList.memberList[countNumMembers].nodeId;

                        interfaceIndex = subnetList.
                                memberList[countNumMembers].interfaceIndex;

                        NodeAddress nodeAddress =
                            subnetList.memberList[countNumMembers].address.
                             interfaceAddr.ipv4;

                        subnetmask = MAPPING_GetSubnetMaskForInterface(node,
                                        nodeId, interfaceIndex);
                        subnetAddress = nodeAddress & subnetmask;

                        if (subnetAddress == ipAddress->interfaceAddr.ipv4)
                        {
                            outputNodeAddress =
                            subnetList.memberList[countNumMembers].address;
                            // check the domain name of the Node with the
                            // domain Name specified in the .register file
                            // if matched then the corresponding interface IP
                            // address will be registered under this node

                            nodeId =
                              subnetList.memberList[countNumMembers].nodeId;

                            if (nodeId != node->nodeId)
                            {
                                continue;
                            }

                            AppDnsSetFQDN(node,
                                          nodeInput,
                                          dnsdata,
                                          outputNodeAddress,
                                          domainName);
                        }
                    }
                }
            }
            else
            {
                IO_AppParseDestString(node,
                                      NULL,
                                      interfaceAddressString,
                                      &nodeId,
                                      &outputNodeAddress);

                if (nodeId == 0)
                {
                    ERROR_ReportErrorArgs(
                        "In Line No %d of .dnsname file String\n"
                             "mentioned is not a valid IP address",
                             lineCount + 1);
                }

                if (nodeId != node->nodeId)
                {
                    continue;
                }
                AppDnsSetFQDN(node,
                              nodeInput,
                              dnsdata,
                              outputNodeAddress,
                              domainName);
            }
        }
        else if (networkType == NETWORK_IPV6)
        {
            UInt32 numHostBits = 0;
            NodeId isNodeId = 0;
            ipAddress->networkType = NETWORK_IPV6;
            BOOL isIpAddr = FALSE;
            IO_ParseNodeIdHostOrNetworkAddress(interfaceAddressString,
                                              &ipAddress->interfaceAddr.ipv6,
                                              &isIpAddr,
                                              &isNodeId,
                                              &numHostBits);

            if (numHostBits != 128)
            {
                // Find the pointer to the partition map
                // For all the subnets in the scenario, Get the Subnet List.
                // For all the members in the Subnet List
                // Extract the interface index and Address.
                // Find the subnet mask of this Adress.
                // Using the subnet mask, find the subnet address
                // If this subnet address is equal to the Subnet address
                // given in file then it means that this address lies in the subnet

                Int32 countNumSubnets = 0;
                Int32 countNumMembers = 0;
                NodeId nodeId = 0;
                Address subnetAddress;

                PartitionData* partitionData = node->partitionData;
                PartitionSubnetData* subnetData = &partitionData->subnetData;
                for (countNumSubnets = 0;
                    countNumSubnets < subnetData->numSubnets;
                    countNumSubnets++)
                {
                    PartitionSubnetList subnetList =
                         subnetData->subnetList[countNumSubnets];

                    for (countNumMembers = 0;
                        countNumMembers < subnetList.numMembers;
                        countNumMembers++)
                    {
                        memset(&subnetAddress, 0, sizeof(Address));
                        subnetAddress.networkType = NETWORK_IPV6;
                        MAPPING_GetSubnetAddressFromInterfaceAddress(node,
                             &subnetList.memberList[countNumMembers].address.
                             interfaceAddr.ipv6,
                             &subnetAddress.interfaceAddr.ipv6);

                        if (!MAPPING_CompareAddress(subnetAddress,
                                                    *ipAddress))
                        {
                            outputNodeAddress =
                            subnetList.memberList[countNumMembers].address;
                            // check the domain name of the Node with the
                            // domain Name specified in the .register file
                            // if matched then the corresponding interface IP
                            // address will be registered under this node

                            nodeId =
                              subnetList.memberList[countNumMembers].nodeId;

                            if (nodeId != node->nodeId)
                            {
                                continue;
                            }

                            AppDnsSetFQDN(node,
                                          nodeInput,
                                          dnsdata,
                                          outputNodeAddress,
                                          domainName);
                        }
                    }
                }
            }
            else
            {
                IO_AppParseDestString(node,
                                      NULL,
                                      interfaceAddressString,
                                      &nodeId,
                                      &outputNodeAddress,
                                      NETWORK_IPV6);

                if (nodeId == 0)
                {
                    ERROR_ReportErrorArgs("In Line No %d of .dnsname file"
                            "String\n mentioned is not a valid IP address",
                            lineCount + 1);
                }

                if (nodeId != node->nodeId)
                {
                    continue;
                }
                AppDnsSetFQDN(node,
                              nodeInput,
                              dnsdata,
                              outputNodeAddress,
                              domainName);
            }
        }
    }
    if (NULL != ipAddress)
    {
        MEM_free(ipAddress);
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsConfigurationParametersInit
// LAYER        :: Application Layer
// PURPOSE      :: Initialization of DNS Config Parameters
// PARAMETERS   :: node - Pointer to node.
//                 nodeInput - Configuration Information
// RETURN       :: None
//--------------------------------------------------------------------------
void AppDnsConfigurationParametersInit(
                                Node* node,
                                const NodeInput* nodeInput)
{
    BOOL retVal = FALSE;
    char buf[MAX_STRING_LENGTH] = "";
    Int32 i = 0;
    BOOL primaryDnsServerFound = FALSE;
    Address primaryDns;
    Address secondaryDns;
    BOOL val = FALSE;
    struct DnsData* dnsData = NULL;
    BOOL clientConfigured = FALSE;
    BOOL serverConfigured = FALSE;

    memset(&primaryDns, 0, sizeof(Address));
    memset(&secondaryDns, 0, sizeof(Address));

    // Check whether the node is DNS Server
    if (DEBUG)
    {
        printf("In AppDnsConfigurationParametersInit for node %d\n",
               node->nodeId);
    }

    IO_ReadBool(node->nodeId,
                  ANY_ADDRESS,
                  nodeInput,
                  "DNS-SERVER",
                  &retVal,
                  &val);

    if (retVal == TRUE)
    {
        serverConfigured = TRUE;
        if (val)
        {
            // check for DHCP client
            for (i = 0; i < node->numberInterfaces; i++)
            {
                Int32 clientMatchType = 0;
                if (AppDhcpCheckDhcpEntityConfigLevel(
                                            node,
                                            nodeInput,
                                            i,
                                            "DHCP-DEVICE-TYPE",
                                            &clientMatchType,
                                            "CLIENT"))
                {
                    ERROR_ReportErrorArgs("Node %d can not be both "
                            "DNS Server as well as DHCP client\n",
                            node->nodeId);

                }
            }
            AppDnsServerInit(node, nodeInput);
        }
    }

    // check if this node is configured as DNS client having primary and
    // secondary Dns Server for its all interface
    BOOL dnsDisabledAtAllInterface = TRUE;
    for (i = 0; i < node->numberInterfaces; i++)
    {
        Address nodeAddress;
        BOOL isEnable = FALSE;
        const AddressMapType* map = node->partitionData->addressMapPtr;

        NetworkProtocolType protocolType =
                MAPPING_GetNetworkProtocolTypeForInterface(map,
                                                           node->nodeId,
                                                           i);
        if (protocolType == IPV4_ONLY)
        {
            IO_ReadBool(
                node->nodeId,
                NetworkIpGetInterfaceAddress(node, i),
                nodeInput,
                "DNS-ENABLED",
                &isEnable,
                &val);
            if (isEnable && val)
            {
                dnsDisabledAtAllInterface = FALSE;
                // This is done here such that if DNS-CLIENT is
                // configured on any of the interfaces of a node then,
                // use bool variable clientConfigured to represent
                // that DNS-CLIENT is present.
                // Hence this variable should remain true if an interface
                // is found on which DNS-CLIENT is configured.
                if (!clientConfigured)
                {
                   IO_ReadBool(
                       node->nodeId,
                       NetworkIpGetInterfaceAddress(node, i),
                       nodeInput,
                       "DNS-CLIENT",
                       &clientConfigured,
                       &val);
                }
            }
        }
        else if (protocolType == IPV6_ONLY || protocolType == DUAL_IP)
        {
            nodeAddress = MAPPING_GetInterfaceAddressForInterface(
                                   node, node->nodeId, NETWORK_IPV6, i);
            IO_ReadBool(
                node->nodeId,
                &nodeAddress.interfaceAddr.ipv6,
                nodeInput,
                "DNS-ENABLED",
                &isEnable,
                &val);
            if (isEnable && val)
            {
                dnsDisabledAtAllInterface = FALSE;
                // This is done here such that if DNS-CLIENT is
                // configured on any of the interfaces of a node then,
                // use bool variable clientConfigured to represent
                // that DNS-CLIENT is present.
                // Hence this variable should remain true if an interface
                // is found on which DNS-CLIENT is configured.
                if (!clientConfigured)
                {
                    IO_ReadBool(
                        node->nodeId,
                        &nodeAddress.interfaceAddr.ipv6,
                        nodeInput,
                        "DNS-CLIENT",
                        &clientConfigured,
                        &val);
                }
            }
        }
    }
    if (clientConfigured == FALSE && serverConfigured == FALSE)
    {
        // if DNS is disabled at interface level for all interfaces of this
        // node then no need to continue; just return
        if (dnsDisabledAtAllInterface == TRUE)
        {
            return;
        }
        ERROR_ReportErrorArgs("Node %d is DNS enabled but no DNS "
                            "Server or DNS Client configured\n",
                            node->nodeId);
    }
    Address primaryDnsAddr;
    Address secondaryDnsAddr;
    Address primaryDnsIpv6Addr;
    Address secondaryDnsIpv6Addr;
    memset(&primaryDnsAddr, 0, sizeof(Address));
    memset(&secondaryDnsAddr, 0, sizeof(Address));
    memset(&primaryDnsIpv6Addr, 0, sizeof(Address));
    memset(&secondaryDnsIpv6Addr, 0, sizeof(Address));
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (DEBUG)
        {
            printf("Initializing DNS client per interface\n");
        }

        Address nodeAddress;
        const AddressMapType* map = node->partitionData->addressMapPtr;

        NetworkProtocolType protocolType =
                MAPPING_GetNetworkProtocolTypeForInterface(map,
                                                           node->nodeId,
                                                               i);
        if (protocolType == IPV4_ONLY)
        {
            IO_ReadString(node->nodeId,
                          NetworkIpGetInterfaceAddress(node, i),
                          nodeInput,
                          "DNS-SERVER-PRIMARY",
                          &primaryDnsServerFound,
                          buf);
        }
        else if (protocolType == IPV6_ONLY || protocolType == DUAL_IP)
        {
            nodeAddress = MAPPING_GetInterfaceAddressForInterface(
                                   node, node->nodeId, NETWORK_IPV6, i);
            IO_ReadString(
                    node->nodeId,
                    &nodeAddress.interfaceAddr.ipv6,
                    nodeInput,
                    "DNS-SERVER-PRIMARY",
                    &primaryDnsServerFound,
                    buf);
            if (!primaryDnsServerFound)
            {
                IO_ReadString(node->nodeId,
                          NetworkIpGetInterfaceAddress(node, i),
                          nodeInput,
                          "DNS-SERVER-PRIMARY",
                          &primaryDnsServerFound,
                          buf);
            }
        }
        if (primaryDnsServerFound == TRUE)
        {
            BOOL isNodeId = FALSE;
            NodeAddress dest_addr = 0;
            IO_ParseNodeIdHostOrNetworkAddress(buf,&primaryDns,
                                                   &isNodeId);
            if (!isNodeId)
            {
                if (primaryDns.networkType == NETWORK_IPV6)
                {
                    primaryDnsIpv6Addr = primaryDns;
                }
                else if (primaryDns.networkType == NETWORK_IPV4)
                {
                    primaryDnsAddr = primaryDns;
                }
            }
            else if (isNodeId == TRUE)
            {
                IO_ParseNodeIdOrHostAddress(buf, &dest_addr, &isNodeId);
                NetworkProtocolType dns_protocol_type =
                            INVALID_NETWORK_TYPE;
                NetworkProtocolType self_protocol_type =
                            INVALID_NETWORK_TYPE;

                dns_protocol_type =
                    MAPPING_GetNetworkProtocolTypeForNode(node, dest_addr);

                self_protocol_type =
                  MAPPING_GetNetworkProtocolTypeForNode(node, node->nodeId);

                if (((self_protocol_type == IPV6_ONLY) &&
                    (dns_protocol_type == IPV4_ONLY)) ||
                    ((self_protocol_type == IPV4_ONLY) &&
                    (dns_protocol_type == IPV6_ONLY)))
                {
                    ERROR_ReportErrorArgs("The Node: %d protocol type and PDNS"
                        " Server %d protocol type Do not match\n",
                        node->nodeId,
                        dest_addr);
                }
                if (self_protocol_type == IPV6_ONLY)
                {
                    primaryDnsIpv6Addr =
                        MAPPING_GetInterfaceAddressForInterface(node,
                                                         dest_addr,
                                                         NETWORK_IPV6,
                                                         DEFAULT_INTERFACE);
                }
                else if (self_protocol_type == IPV4_ONLY)
                {
                    primaryDnsAddr =
                        MAPPING_GetInterfaceAddressForInterface(node,
                                                         dest_addr,
                                                         NETWORK_IPV4,
                                                         DEFAULT_INTERFACE);
                }
                else if (self_protocol_type == DUAL_IP)
                {
                     // Search through first IPv6 address
                     primaryDnsIpv6Addr =
                         MAPPING_GetInterfaceAddressForInterface(node,
                                                         dest_addr,
                                                         NETWORK_IPV6,
                                                         DEFAULT_INTERFACE);
                     if (primaryDnsAddr.networkType == NETWORK_INVALID)
                     {
                        // Search through first IPv4 address
                        primaryDnsAddr =
                            MAPPING_GetInterfaceAddressForInterface(node,
                                                         dest_addr,
                                                         NETWORK_IPV4,
                                                         DEFAULT_INTERFACE);
                     }
                     else if (dns_protocol_type == DUAL_IP)
                     {
                        primaryDnsAddr =
                            MAPPING_GetInterfaceAddressForInterface(node,
                                                      dest_addr,
                                                      NETWORK_IPV4,
                                                      DEFAULT_INTERFACE);
                     }
                }
            }
        }
        else  // for handling DHCP
        {
            BOOL dhcpEnabled = FALSE;
            if (protocolType == IPV4_ONLY)
            {
                IO_ReadBoolInstance(node->nodeId,
                      NetworkIpGetInterfaceNetworkAddress(node, i),
                      nodeInput,
                      "DHCP-ENABLED",
                      i,
                      TRUE,
                      &retVal,
                      &dhcpEnabled);
                if (retVal == TRUE)
                {
                    if (dhcpEnabled)
                    {
                        Int32 clientMatchType = 0;
                        if (AppDhcpCheckDhcpEntityConfigLevel(
                                            node,
                                            nodeInput,
                                            i,
                                            "DHCP-DEVICE-TYPE",
                                            &clientMatchType,
                                            "CLIENT"))
                        {
                            AppDnsClientInit(
                                 node,
                                 i,
                                 primaryDnsAddr,
                                 primaryDnsIpv6Addr,
                                 secondaryDnsAddr,
                                 secondaryDnsIpv6Addr,
                                 TRUE);
                        }
                    }
                }
            }
        }
        Address address;
        if (protocolType == IPV4_ONLY)
        {
            IO_ReadString(node->nodeId,
                          NetworkIpGetInterfaceAddress(node, i),
                          nodeInput,
                          "DNS-SERVER-SECONDARY",
                          &retVal,
                          buf);
        }
        else if (protocolType == IPV6_ONLY || protocolType == DUAL_IP)
        {
            address = MAPPING_GetInterfaceAddressForInterface(
                                        node, node->nodeId, NETWORK_IPV6, i);
            IO_ReadString(
                    node->nodeId,
                    &address.interfaceAddr.ipv6,
                    nodeInput,
                    "DNS-SERVER-SECONDARY",
                    &retVal,
                    buf);
            if (!retVal)
            {
                IO_ReadString(node->nodeId,
                          NetworkIpGetInterfaceAddress(node, i),
                          nodeInput,
                          "DNS-SERVER-SECONDARY",
                          &retVal,
                          buf);
            }
        }

        if (retVal)
        {
            BOOL isNodeId = FALSE;
            NodeAddress dest_addr = 0;
            if (!primaryDnsServerFound)
            {
                ERROR_ReportErrorArgs(
                    "Every Secondary DNS Server should"
                    "have a Primary DNS Server");
            }

            IO_ParseNodeIdHostOrNetworkAddress(buf,&secondaryDns,
                                                   &isNodeId);
            if (!isNodeId)
            {
                if (secondaryDns.networkType == NETWORK_IPV6)
                {
                    secondaryDnsIpv6Addr = secondaryDns;
                }
                else if (secondaryDns.networkType == NETWORK_IPV4)
                {
                    secondaryDnsAddr = secondaryDns;
                }
            }
            else if (isNodeId == TRUE)
            {
                IO_ParseNodeIdOrHostAddress(buf, &dest_addr, &isNodeId);
                const AddressMapType* map =
                    node->partitionData->addressMapPtr;
                NetworkProtocolType dns_protocol_type =
                                                INVALID_NETWORK_TYPE;
                NetworkProtocolType self_protocol_type =
                                                INVALID_NETWORK_TYPE;

                dns_protocol_type =
                    MAPPING_GetNetworkProtocolTypeForNode(node, dest_addr);

                self_protocol_type =
                  MAPPING_GetNetworkProtocolTypeForNode(node, node->nodeId);

                if (((self_protocol_type == IPV6_ONLY) &&
                    (dns_protocol_type == IPV4_ONLY)) ||
                    ((self_protocol_type == IPV4_ONLY) &&
                    (dns_protocol_type == IPV6_ONLY)))
                {
                    ERROR_ReportErrorArgs(
                        "The Node: %d protocol type and SDNS"
                        " Server %d protocol type Do not match\n",
                        node->nodeId,
                        dest_addr);
                }
                self_protocol_type =
                    MAPPING_GetNetworkProtocolTypeForInterface(map,
                                                               node->nodeId,
                                                               i);

                if (self_protocol_type == IPV6_ONLY)
                {
                    secondaryDnsIpv6Addr =
                        MAPPING_GetInterfaceAddressForInterface(node,
                                                         dest_addr,
                                                         NETWORK_IPV6,
                                                         DEFAULT_INTERFACE);
                }
                else if (self_protocol_type == IPV4_ONLY)
                {
                    secondaryDnsAddr =
                        MAPPING_GetInterfaceAddressForInterface(node,
                                                         dest_addr,
                                                         NETWORK_IPV4,
                                                         DEFAULT_INTERFACE);
                }
                else if (self_protocol_type == DUAL_IP)
                {
                     // Search through first IPv6 address
                     secondaryDnsIpv6Addr =
                         MAPPING_GetInterfaceAddressForInterface(node,
                                                         dest_addr,
                                                         NETWORK_IPV6,
                                                         DEFAULT_INTERFACE);
                     if (secondaryDnsAddr.networkType == NETWORK_INVALID)
                     {
                        // Search through first IPv4 address
                        secondaryDnsAddr =
                        MAPPING_GetInterfaceAddressForInterface(node,
                                                         dest_addr,
                                                         NETWORK_IPV4,
                                                         DEFAULT_INTERFACE);
                     }
                    else if (dns_protocol_type == DUAL_IP)
                     {
                        secondaryDnsAddr =
                        MAPPING_GetInterfaceAddressForInterface(node,
                                                         dest_addr,
                                                         NETWORK_IPV4,
                                                         DEFAULT_INTERFACE);
                     }
                }
            }

            AppDnsClientInit(node,
                             i,
                             primaryDnsAddr,
                             primaryDnsIpv6Addr,
                             secondaryDnsAddr,
                             secondaryDnsIpv6Addr);
        }
        else
        {
            if (primaryDnsServerFound)
            {
                AppDnsClientInit(node,
                                 i,
                                 primaryDnsAddr,
                                 primaryDnsIpv6Addr);
            }
        }
    }

    dnsData = (struct DnsData*)node->appData.dnsData;
    if (!dnsData)
    {
        ERROR_ReportErrorArgs("The Node: %d has no dnsdata", node->nodeId);
    }
    if (dnsData->dnsServer != TRUE)
    {
        // Register with DHCP and IPv6AutoConfig for any ip address changes
        NetworkIpAddAddressChangedHandlerFunction(node,
                            &DNSClientHandleChangeAddressEvent);
    }
    // Check whether HOSTS file is mentioned globally or node-wise
    AppDnsHostsFileInit(node, nodeInput);

    // Put the default cache refresh time
    dnsData->cacheRefreshTime =  CACHE_REFRESH_INTERVAL;

    // read the cache refresh time interval
    IO_ReadString(node->nodeId,
                  ANY_ADDRESS,
                  nodeInput,
                  "DNS-CACHE-TIMEOUT-INTERVAL",
                  &retVal,
                  buf);

    if (retVal == TRUE)
    {
        AppDnsReadCacheTimeOutInterval(node, buf);
    }

    IO_ReadBool(node->nodeId,
                  ANY_ADDRESS,
                  nodeInput,
                  "DNS-STATISTICS",
                  &retVal,
                  &val);
    if (retVal && val == TRUE)
    {
        dnsData->dnsStats = TRUE;
    }
    else
    {
        dnsData->dnsStats = FALSE;
    }
    DNSInitializeHostName(node, nodeInput, dnsData);
}

//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsComputeDomainName
// LAYER        :: Application Layer
// PURPOSE      :: computes domain name
// PARAMETERS   :: node - Pointer to node.
//                 label - label
//                 zoneId - zone id,
//                 level -  level
//                 treeStructureInput - pointer to node input
//                 parentNodeId -  parent node id
//                 domain - domain
// RETURN       :: None
//--------------------------------------------------------------------------

void AppDnsComputeDomainName(Node* node,
                         char* label,
                         Int32 zoneId,
                         UInt32 level,
                         const NodeInput* treeStructureInput,
                         NodeAddress parentNodeId,
                         char* domain)
{
    const char* dot = DOT_SEPARATOR;
    const char* rootLabel = ROOT_LABEL;
    char tempnodeAddress[MAX_STRING_LENGTH] = "";
    char tempparentNodeAddress[MAX_STRING_LENGTH] = "";
    UInt32 tempLevel = 0;
    char tempLabel[DNS_NAME_LENGTH] = "";
    char tempzoneMasterOrSlave[8] = "";
    UInt32 tempZoneNo = 0;
    char tempTimeAddedStr[MAX_STRING_LENGTH] = "";

    for (Int32 levelCount = level; levelCount >= 0; levelCount--)
    {
        if (DEBUG)
        {
            printf("enetring level %d for second loop\n", levelCount);
        }
        for (Int32 lineCount1 = 0;
            lineCount1 < treeStructureInput->numLines;
            lineCount1++)
        {
            const char* tempCurrentLine =
                treeStructureInput->inputStrings[lineCount1];
            Int32 numInputs = sscanf(tempCurrentLine,
                                "%s %u %s %s %u %s %s",
                                tempnodeAddress,
                                &tempLevel,
                                tempparentNodeAddress,
                                tempLabel,
                                &tempZoneNo,
                                tempzoneMasterOrSlave,
                                tempTimeAddedStr);
            if (numInputs < 7)
            {
                Int32 num_inputs = sscanf(tempCurrentLine,
                                        "%s %s %s",
                                        tempLabel,
                                        tempTimeAddedStr,
                                        tempnodeAddress);
                if (num_inputs == 3)
                {
                    continue;
                }
            }
            if (DEBUG)
            {
                printf("second loop\n");
            }
            NodeAddress tempNodeId = 0;
            NodeAddress tempparentNodeId = 0;
            Address destAddr;
            memset(&destAddr, 0, sizeof(Address));
            IO_AppParseDestString(
                node,
                NULL,
                tempnodeAddress,
                &tempNodeId,
                &destAddr);
            if (tempNodeId != 0)
            {
                if (DEBUG)
                {
                    printf("Src is a valid ip\n");
                }
                tempNodeId = MAPPING_GetNodeIdFromInterfaceAddress(node,
                                destAddr);
                if (DEBUG)
                {
                    printf("Src node id %d\n", tempNodeId);
                }
            }
            else
            {
                ERROR_ReportErrorArgs("Node can be ip address only\n");
            }
            if (tempparentNodeAddress[0] != '0' ||
                (strlen(tempparentNodeAddress) >= 2))
            {
                IO_AppParseDestString(
                    node,
                    NULL,
                    tempparentNodeAddress,
                    &tempparentNodeId,
                    &destAddr);
            }
            else
            {
                tempparentNodeId = 0;
            }
            if (tempparentNodeId != 0)
            {
                if (DEBUG)
                {
                    printf("Parent is a valid ip\n");
                }
                tempparentNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                        node,
                                        destAddr);
                if (DEBUG)
                {
                    printf("Parent node id %d\n", tempparentNodeId);
                }
            }
            else if (strcmp(tempparentNodeAddress, "0"))
            {
                ERROR_ReportErrorArgs(
                    "Parent Node can be ip address only\n");
            }

             // check the validity of domain name
             // last character is hyphen
            Int32 strLen = strlen(tempLabel);
            if (strcmp(tempLabel, "/") && tempLevel != 0)
            {
                for (Int32 index = 0; index< strLen; index++)
                {
                    Int32 asciiVal = tempLabel[index];
                    if (!(((asciiVal >= ASCII_VALUE_OF_DIGIT_0) &&
                        (asciiVal <= ASCII_VALUE_OF_DIGIT_9)) ||
                        ((asciiVal >= ASCII_VALUE_OF_CAPS_A) &&
                        (asciiVal <= ASCII_VALUE_OF_CAPS_Z)) ||
                        ((asciiVal >= ASCII_VALUE_OF_SMALL_A) &&
                        (asciiVal <= ASCII_VALUE_OF_SMALL_Z)) ||
                        (asciiVal == ASCII_VALUE_OF_SPECIAL_CHAR_HYPHEN)))
                    {
                            ERROR_ReportErrorArgs("Domain name can't have "
                                "character '%c'\n", tempLabel[index]);
                    }
                }

                if ((tempLabel[0] == '-') || (tempLabel[strLen-1] == '-'))
                {
                    printf(" For label %s \n", tempLabel);
                    ERROR_ReportErrorArgs(
                                "last/first character can't be '-' \n");
                }
            }

            if ((parentNodeId == tempNodeId)&&
                strcmp(tempzoneMasterOrSlave, "S"))
            {
                if (DEBUG)
                {
                    printf("parentNodeId %d\n", parentNodeId);
                }
                if (strcmp(tempLabel, rootLabel))
                {
                    if (!strcmp(tempLabel, label))
                    {
                        if ((level != tempLevel) &&
                            ((unsigned)zoneId != tempZoneNo))
                        {
                            ERROR_ReportErrorArgs("For Secondary: %d, "
                                " Either ZoneId or level does not match"
                                " with its Primary\n",
                                node->nodeId);
                        }
                    }
                    else
                    {
                        strcat(domain, tempLabel);
                        strcat(domain, dot);
                    }
                    parentNodeId = tempparentNodeId;
                    if (DEBUG)
                    {
                        printf("parentNodeId is %d after current "
                                "domain name %s\n", parentNodeId,
                                domain);
                    }
                }
            }
        }
    }
}


//--------------------------------------------------------------------------
// FUNCTION     :: DnsFinalize
// LAYER        :: Application Layer
// PURPOSE      :: Dns Finalization
// PARAMETERS   :: node - Partition Data Ptr
// RETURN       :: None
//--------------------------------------------------------------------------
void DnsFinalize(Node* node)
{
    struct DnsData* dnsData = (struct DnsData*)node->appData.dnsData;

    // Print out stats if user specifies it.
    if ((dnsData != NULL) && (dnsData->dnsStats == TRUE))
    {
        char buf[MAX_STRING_LENGTH] = "";
        sprintf(buf, "Number of SOA Query Packets Sent = %d",
            dnsData->stat.numOfDnsSOAQuerySent);

        IO_PrintStat(
            node,
            "Application",
            "DNS",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of SOA Reply Packets Received = %d",
            dnsData->stat.numOfDnsSOAReplyRecv);

        IO_PrintStat(
            node,
            "Application",
            "DNS",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of NS Query Packets Sent = %d",
            dnsData->stat.numOfDnsNSQuerySent);

        IO_PrintStat(
            node,
            "Application",
            "DNS",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of NS Reply Packets Received = %d",
            dnsData->stat.numOfDnsNSReplyRecv);

        IO_PrintStat(
            node,
            "Application",
            "DNS",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of A/AAAA Query Packets Sent = %d",
            dnsData->stat.numOfDnsQuerySent);

        IO_PrintStat(
            node,
            "Application",
            "DNS",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of A/AAAA Reply Packets Received = %d",
            dnsData->stat.numOfDnsReplyRecv);

        IO_PrintStat(
            node,
            "Application",
            "DNS",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of DNS Name Resolved = %d",
            dnsData->stat.numOfDnsNameResolved);
        IO_PrintStat(
            node,
            "Application",
            "DNS",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of DNS Name Resolved using Cache = %d",
                dnsData->stat.numOfDnsNameResolvedFromCache);

            IO_PrintStat(
                node,
                "Application",
                "DNS",
                ANY_DEST,
                -1, // instance Id,
                buf);

        sprintf(buf, "Number of DNS Name Unresolved = %d",
            dnsData->stat.numOfDnsNameUnresolved);
        IO_PrintStat(
            node,
            "Application",
            "DNS",
            ANY_DEST,
            -1, // instance Id,
            buf);

        char buf1[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(dnsData->stat.
                  avgDelayForSuccessfullAddressResolution, buf1);
        sprintf(buf, "Delay for successful domain name resolutions = %s",
                buf1);
        IO_PrintStat(
            node,
            "Application",
            "DNS",
            ANY_DEST,
            -1, // instance Id,
            buf);

        TIME_PrintClockInSecond(dnsData->stat.
                          avgDelayForUnsuccessfullAddressResolution, buf1);
        sprintf(buf, "Delay for unsuccessful domain name resolutions = %s",
                buf1);
        IO_PrintStat(
            node,
            "Application",
            "DNS",
            ANY_DEST,
            -1, // instance Id,
            buf);


        if (dnsData->dnsServer == TRUE )
        {
            sprintf(buf, "Number of Query Packets Received = %d",
                dnsData->stat.numOfDnsQueryRecv);

            IO_PrintStat(
                node,
                "Application",
                "DNS",
                ANY_DEST,
                -1, // instance Id,
                buf);

            sprintf(buf, "Number of Reply Packets Sent = %d",
                dnsData->stat.numOfDnsReplySent);

            IO_PrintStat(
                node,
                "Application",
                "DNS",
                ANY_DEST,
                -1, // instance Id,
                buf);

            sprintf(buf, "Number of Zone Update Packet Received = %d",
                dnsData->stat.numOfDnsUpdateRecv);
            IO_PrintStat(
                node,
                "Application",
                "DNS",
                ANY_DEST,
                -1, // instance Id,
                buf);

            sprintf(buf, "Number of Zone Update Packet Sent = %d",
                dnsData->stat.numOfDnsUpdateSent);
            IO_PrintStat(
                node,
                "Application",
                "DNS",
                ANY_DEST,
                -1, // instance Id,
                buf);

            sprintf(buf, "Number of DNS Notify Packet Sent = %d",
                dnsData->stat.numOfDnsNotifySent);
            IO_PrintStat(
                node,
                "Application",
                "DNS",
                ANY_DEST,
                -1, // instance Id,
                buf);

            sprintf(buf, "Number of DNS Notify Response Packet Sent = %d",
                dnsData->stat.numOfDnsNotifyResponseSent);
            IO_PrintStat(
                node,
                "Application",
                "DNS",
                ANY_DEST,
                -1, // instance Id,
                buf);

            sprintf(buf, "Number of DNS Update Requests Packet Sent = %d",
                dnsData->stat.numOfDnsUpdateRequestsSent);
            IO_PrintStat(
                node,
                "Application",
                "DNS",
                ANY_DEST,
                -1, // instance Id,
                buf);

            sprintf(buf, "Number of DNS Update Requests Packet Received = %d",
                dnsData->stat.numOfDnsUpdateRequestsReceived);
            IO_PrintStat(
                node,
                "Application",
                "DNS",
                ANY_DEST,
                -1, // instance Id,
                buf);
        }
    }

    // free all allocated memeory
    if (dnsData != NULL)
    {
        if (dnsData->cache != NULL)
        {
            if (dnsData->cache->size())
            {
                CacheRecordList :: iterator cacheIt = dnsData->cache->begin();
                while (cacheIt != dnsData->cache->end())
                {
                    struct CacheRecord* cacheRec =
                            (struct CacheRecord*)*cacheIt;
                    cacheIt++;
                    delete(cacheRec->urlNameString);
                    MEM_free(cacheRec);
                }
            }
            delete(dnsData->cache);
            dnsData->cache = NULL;
        }

        if (dnsData->appReqList)
        {
            if (dnsData->appReqList->size())
            {
                DnsAppReqItemList :: iterator appReqListIt =
                                            dnsData->appReqList->begin();
                while (appReqListIt != dnsData->appReqList->end())
                {
                    struct DnsAppReqListItem* listItem =
                                (struct DnsAppReqListItem*)*appReqListIt;
                    if (listItem->interfaceList)
                    {
                        if (listItem->interfaceList->size())
                        {
                            AppReqInterfaceList ::
                                iterator appReqIntListIt =
                                        listItem->interfaceList->begin();
                            while (appReqIntListIt !=
                                        listItem->interfaceList->end())
                            {
                                Int16* listItem1 = (Int16*)*appReqIntListIt;
                                appReqIntListIt++;
                                MEM_free(listItem1);
                                listItem1 = NULL;
                            }
                        }
                        delete(listItem->interfaceList);
                        listItem->interfaceList = NULL;
                    }
                    appReqListIt++;
                    delete (listItem->serverUrl);
                    MEM_free(listItem);
                    listItem = NULL;
                }
            }
            delete(dnsData->appReqList);
            dnsData->appReqList = NULL;
        }

        if (dnsData->clientData)
        {
            if (dnsData->clientData->size())
            {
                DnsClientDataList :: iterator clientDataListIt =
                                            dnsData->clientData->begin();
                while (clientDataListIt != dnsData->clientData->end())
                {
                    struct DnsClientData* listItem =
                            (struct DnsClientData*)*clientDataListIt;
                    if (listItem->nameServerList)
                    {
                        if (listItem->nameServerList->size())
                        {
                            ServerList :: iterator serverListIt =
                                listItem->nameServerList->begin();
                            while (serverListIt !=
                                   listItem->nameServerList->end())
                            {
                                Address* listItem1 =
                                            (Address*)*serverListIt;
                                serverListIt++;
                                MEM_free(listItem1);
                                listItem1 = NULL;
                            }
                        }
                        delete(listItem->nameServerList);
                        listItem->nameServerList = NULL;
                    }
                    if (listItem->fqdn)
                    {
                        MEM_free(listItem->fqdn);
                        listItem->fqdn = NULL;
                    }
                    clientDataListIt++;
                    MEM_free(listItem);
                    listItem = NULL;
                }
            }
            delete(dnsData->clientData);
            dnsData->clientData = NULL;
        }
        if (dnsData->zoneData)
        {
            if (dnsData->zoneData->retryQueue)
            {
                if (dnsData->zoneData->retryQueue->size())
                {
                     RetryQueueList :: iterator retryQueueListIt =
                                        dnsData->zoneData->retryQueue->begin();
                    while (retryQueueListIt !=
                                dnsData->zoneData->retryQueue->end())
                    {
                        struct RetryQueueData* listItem =
                                    (struct RetryQueueData*)*retryQueueListIt;
                        retryQueueListIt++;
                        MEM_free(listItem);
                        listItem = NULL;
                    }
                }
                delete(dnsData->zoneData->retryQueue);
                dnsData->zoneData->retryQueue = NULL;
            }

            if (dnsData->zoneData->notifyRcvd)
            {
                if (dnsData->zoneData->notifyRcvd->size())
                {
                    NotifyReceivedList :: iterator notifyRcvdListIt =
                                    dnsData->zoneData->notifyRcvd->begin();
                    while (notifyRcvdListIt !=
                                dnsData->zoneData->notifyRcvd->end())
                    {
                        NotifyReceivedData* listItem =
                            (struct NotifyReceivedData*)*notifyRcvdListIt;
                        notifyRcvdListIt++;
                        MEM_free(listItem);
                        listItem = NULL;
                    }
                }
                delete(dnsData->zoneData->notifyRcvd);
                dnsData->zoneData->notifyRcvd = NULL;
            }
            if (dnsData->zoneData->data)
            {
                if (dnsData->zoneData->data->size())
                {
                    ZoneDataList :: iterator dataListIt =
                                        dnsData->zoneData->data->begin();
                    while (dataListIt != dnsData->zoneData->data->end())
                    {
                        data* listItem = (data*)*dataListIt;
                        dataListIt++;
                        MEM_free(listItem);
                        listItem = NULL;
                    }
                }
                delete(dnsData->zoneData->data);
                dnsData->zoneData->data = NULL;
            }
            MEM_free(dnsData->zoneData);
            dnsData->zoneData = NULL;
        }
        if (dnsData->server)
        {
            if (dnsData->server->dnsTreeInfo)
            {
                MEM_free(dnsData->server->dnsTreeInfo);
                dnsData->server->dnsTreeInfo = NULL;
            }
            if (dnsData->server->rrList)
            {
                if (dnsData->server->rrList->size())
                {
                    DnsRrRecordList :: iterator rrListIt =
                                        dnsData->server->rrList->begin();
                    while (rrListIt != dnsData->server->rrList->end())
                    {
                        struct DnsRrRecord* listItem =
                                (DnsRrRecord*)*rrListIt;
                        rrListIt++;
                        MEM_free(listItem);
                        listItem = NULL;
                    }
                }
                delete(dnsData->server->rrList);
                dnsData->server->rrList = NULL;
            }
            MEM_free(dnsData->server);
            dnsData->server = NULL;
        }
        if (dnsData->clientResolveState)
        {
            if (dnsData->clientResolveState->size())
            {
                ClientResolveStateList :: iterator clientResolveIt =
                                        dnsData->clientResolveState->begin();
                while (clientResolveIt != dnsData->clientResolveState->end())
                {
                    struct ClientResolveState* listItem =
                            (struct ClientResolveState*)*clientResolveIt;
                    clientResolveIt++;
                    delete(listItem->queryUrl);
                    MEM_free(listItem);
                    listItem = NULL;
                }
            }
            delete(dnsData->clientResolveState);
            dnsData->clientResolveState = NULL;
        }
        if (dnsData->zoneTransferServerData)
        {
            if (dnsData->zoneTransferServerData->size())
            {
                ServerZoneTransferDataList :: iterator serverZoneIt =
                                   dnsData->zoneTransferServerData->begin();
                while (serverZoneIt !=
                       dnsData->zoneTransferServerData->end())
                {
                    struct DnsServerZoneTransferServer* listItem =
                        (struct DnsServerZoneTransferServer*)*serverZoneIt;
                    serverZoneIt++;
                    MEM_free(listItem);
                    listItem = NULL;
                }
            }
            delete(dnsData->zoneTransferServerData);
            dnsData->zoneTransferServerData = NULL;
        }
        if (dnsData->zoneTransferClientData)
        {
            if (dnsData->zoneTransferClientData->size())
            {
                ClientZoneTransferDataList :: iterator clientZoneIt =
                                    dnsData->zoneTransferClientData->begin();
                while (clientZoneIt !=
                        dnsData->zoneTransferClientData->end())
                {
                    struct DnsServerZoneTransferClient* listItem =
                        (struct DnsServerZoneTransferClient*)*clientZoneIt;
                    if (listItem->dataSentPtr)
                    {
                        MEM_free(listItem->dataSentPtr);
                        listItem->dataSentPtr = NULL;
                    }
                    clientZoneIt++;
                    MEM_free(listItem);
                    listItem = NULL;
                }
            }
            delete(dnsData->zoneTransferClientData);
            dnsData->zoneTransferClientData = NULL;
        }
        if (dnsData->tcpConnDataList)
        {
            if (dnsData->tcpConnDataList->size())
            {
                TcpConnInfoList :: iterator connInfoIt =
                                        dnsData->tcpConnDataList->begin();
                while (connInfoIt != dnsData->tcpConnDataList->end())
                {
                    struct TcpConnInfo* listItem =
                        (struct TcpConnInfo*)*connInfoIt;
                    if (listItem->dataRecvd)
                    {
                        MEM_free(listItem->dataRecvd);
                        listItem->dataRecvd = NULL;
                    }
                    if (listItem->packetToSend)
                    {
                        MEM_free(listItem->packetToSend);
                        listItem->packetToSend = NULL;
                    }
                    if (listItem->tempPtr)
                    {
                        MEM_free(listItem->tempPtr);
                        listItem->tempPtr = NULL;
                    }
                    connInfoIt++;
                    MEM_free(listItem);
                    listItem = NULL;
                }
            }
            delete(dnsData->tcpConnDataList);
            dnsData->tcpConnDataList = NULL;
        }
        if (dnsData->dataSentPtr)
        {
            MEM_free(dnsData->dataSentPtr);
            dnsData->dataSentPtr = NULL;
        }
        if (dnsData->nameServerList)
        {
            if (dnsData->nameServerList->size())
            {
                NameServerList :: iterator nameServerIt =
                                        dnsData->nameServerList->begin();
                while (nameServerIt != dnsData->nameServerList->end())
                {
                    data* listItem = (data*)*nameServerIt;
                    nameServerIt++;
                    MEM_free(listItem);
                    listItem = NULL;
                }
            }
            delete(dnsData->nameServerList);
            dnsData->nameServerList = NULL;
        }

        MEM_free(dnsData);
        dnsData = NULL;
    }
}

//--------------------------------------------------------------------------
// NAME        : AppDnsCheckForLocalHost.
// PURPOSE     : Used to check if destination string is localhost and update
//               destination address accordingly
// PARAMETERS:
// + node       : Node*    : pointer to the node,
// + sourceAddr : Address  : soirce address
// + destString : char     : destination string
// + destAddr   : Address* : updated destination address if localhost
// RETURN      :
// bool        : TRUE if localhost and destination address updated
//--------------------------------------------------------------------------

bool AppDnsCheckForLocalHost(
                    Node* node,
                    Address sourceAddr,
                    char* destString,
                    Address* destAddr)
{
    bool isLocalHost = FALSE;
    if (!strcmp(destString, "localhost.") ||
        !strcmp(destString, "localhost"))
    {
        NodeId nodeId;
        if (sourceAddr.networkType == NETWORK_IPV4)
        {
            IO_AppParseDestString(
                            node,
                            NULL,
                            "127.0.0.1",
                            &nodeId,
                            destAddr);
            isLocalHost = TRUE;
        }
        else if (sourceAddr.networkType == NETWORK_IPV6)
        {
            IO_AppParseDestString(
                            node,
                            NULL,
                            "::1",
                            &nodeId,
                            destAddr);
            isLocalHost = TRUE;
        }
    }
    return (isLocalHost);
}
