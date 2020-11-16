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
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

#include <stdio.h>

#if 0 

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "app_voip.h"
#include "external.h"
#include "auto-ipnetworkemulator.h"
#include "voip_interface.h"
#include "transport_rtp.h"
#include "app_forward.h"

#define TPKT_REQUIRED_VERSION 3

typedef struct struct_tpkt_str
{
    u_char *version;
    u_char *reserved;
    u_short *length;
} TPKT;

#define BEARER_CAPABILITY 0x04

typedef struct struct_bearer_capability_str
{
    u_char *informationElement;
    u_char *length;
    u_char *data;
} BearerCapability;

#define CAUSE 0x08

typedef struct struct_cause_str
{
    u_char *informationElement;
    u_char *length;
    u_char *data;
    u_char *causeValue;
} Cause;

#define DISPLAY 0x28

typedef struct struct_display_str
{
    u_char *informationElement;
    u_char *length;
    u_char *data;
} Display;

#define CALLING_PARTY_NUMBER 0x6C

typedef struct struct_calling_party_number_str
{
    u_char *informationElement;
    u_char *length;
    u_char *data;
} CallingPartyNumber;

#define CALLED_PARTY_NUMBER 0x70

typedef struct struct_called_party_number_str
{
    u_char *informationElement;
    u_char *length;
    u_char *data;
} CalledPartyNumber;


#define USER_USER 0x7e

typedef struct struct_user_user_str
{
    u_char *informationElement;
    u_short *length;
    u_char *protocolDiscriminator;
} UserUser;

typedef struct struct_q931_str
{
    u_char *protocolDiscriminator;
    u_char *refValueLength;
    u_char *refValue;
    u_char *type;
    BearerCapability bearer;
    Cause cause;
    Display display;
    CallingPartyNumber callingPartyNumber;
    CalledPartyNumber calledPartyNumber;
    UserUser userUser;
} Q931;

// only supports count == 1
typedef struct struct_name_address_str
{
    u_char *count; // > 0 if sourceAddress present
    u_char *type;
    u_char *length;
    u_char *address;
} NameAddress;

typedef struct struct_vendor_identifier_str
{
    u_char *t35CountryCode;
    u_char *t35Extension;
    u_short *manufacturerCode;
    u_char *productIDLength;
    u_char *productID;
    u_char *versionLength;
    u_char *version;

} VendorIdentifier;

typedef struct struct_source_info_str
{
    u_char *unknown; // 22 -- vendor
    u_char *unknownNonStandard; // 0xC0
    VendorIdentifier vendorIdentifier;
    u_char *flags;
    u_char flagsValue;
} SourceInfo;

typedef struct struct_h225_address_str
{
    u_char *type;
    u_char typeValue;
    u_long *ipAddress;
    u_short *port;
} H225Address;

typedef enum
{
    TRANSPORT_ADDRESS,
    ALIAS_ADDRESS
} AddressType;

typedef struct struct_variable_address_str
{
    int isNameAddress;
    int isH225Address;
    NameAddress nameAddress;
    H225Address h225Address;
} VariableAddress;

typedef struct struct_call_identifier_str
{
    u_char *length;
    u_char *guid;
} CallIdentifier;

typedef struct struct_protocol_identifier_str
{
    u_char *length;
    u_char *identifier;
} ProtocolIdentifier;

typedef struct struct_conference_identifier_str
{
    u_long *id1;
    u_long *id2;
    u_long *id3;
    u_long *id4;
} ConferenceIdentifier;

#define SETUP 0x05

typedef struct struct_setup_uuie_str
{
    u_char *firstByte;

    BOOL h245AddressPresent;
    BOOL sourceAddressPresent;
    BOOL destinationAddressPresent;
    BOOL destCallSignalAddressPresent;

    ProtocolIdentifier protocolIdentifier;
    VariableAddress h245Address;
    VariableAddress sourceAddress;
    SourceInfo sourceInfo;
    VariableAddress destinationAddress;
    VariableAddress destCallSignalAddress;
    u_char *activeMC;
    ConferenceIdentifier conferenceIdentifier;
    u_char *conferenceGoalCallType;
    u_char *firstExtensionByte;
    // optional call services
    VariableAddress sourceCallSignalAddress;
    // optional remote extension address
    CallIdentifier callIdentifier;
    // optional h245 security capability
    // optional tokens
    // optional crypto tokens
    // optional fast start
    u_char *mediaWaitForConnectPresent;
    u_char *mediaWaitForConnect;
    u_char *canOverlapSendPresent;
    u_char *canOverlapSend;
    u_char *multipleCallsPresent;
    u_char *multipleCalls;
    u_char *maintainConnectionPresent;
    u_char *maintainConnection;
    // optional
} SetupUUIE;

#define CONNECT 0x07

typedef struct struct_connect_uuie_str
{
    u_char *firstByte;
    ProtocolIdentifier protocolIdentifier;
    VariableAddress sourceAddress;
    SourceInfo destinationInfo;
    ConferenceIdentifier conferenceIdentifier;
    CallIdentifier callIdentifier;
} ConnectUUIE;

#define CALL_PROCEEDING 0x02

typedef struct struct_call_proceeding_uuie_str
{
    u_char *firstByte;
    BOOL h245AddressPresent;
    ProtocolIdentifier protocolIdentifier;
    SourceInfo destinationInfo;
    VariableAddress h245Address;
} CallProceedingUUIE;

#define ALERTING 0x01

typedef struct struct_alerting_uuie_str
{
    u_char *firstByte;
    BOOL h245AddressPresent;
    ProtocolIdentifier protocolIdentifier;
    SourceInfo destinationInfo;
    VariableAddress h245Address;
} AlertingUUIE;

#define H225_SETUP 0
#define H225_CONNECT 2

typedef struct struct_h225_str
{
    u_char *firstByte;
    u_char bodyType;
} H225;

typedef enum
{
    REQUEST = 0,
    RESPONSE,
    COMMAND,
    INDICATION
} H245MessageType;

typedef enum
{
    NON_STANDARD_DATA = 0,
    NULL_DATA,
    VIDEO_DATA,
    AUDIO_DATA,
} DataTypeType;

typedef enum
{
    G711ULAW64K = 3,
} AudioCapabilityType;

typedef struct struct_audio_capability_str
{
    u_short *first2Bytes;
    AudioCapabilityType type;
    u_char *data;
} AudioCapability;

typedef enum
{
    H261_VIDEO_CAPABILITY = 1,    
} VideoCapabilityType;

typedef struct struct_video_capability_str
{
    u_short *first2Bytes;
    u_short *maxBitRate;
    VideoCapabilityType type;
    u_char *stillImageTransmission;
    u_char *extensionBitField;
    u_char *extensionCount;
    u_char *videoBadMBsCap;

    BOOL extensionPresent;
    BOOL qcifMPIPresent;
    BOOL cifMPIPresent;

    int qcifMPI;
    int cifMPI;
    BOOL temporalSpatial;
} VideoCapability;

#define H2250_LOGICAL_CHANNEL_PARAMETERS 8

typedef struct struct_data_type_str
{
    u_char *firstByte;
    DataTypeType type;
    AudioCapability audioCapability;
    VideoCapability videoCapability;
} DataType;

typedef struct 
{
    u_long *first4Bytes;
    u_char *sessionID;
    VariableAddress ipAddress;
    u_char *silenceSuppression;
} H2250LogicalChannelParameters;

typedef struct struct_open_logical_channel_str
{
    u_char *unknown;
    u_short *number;
    DataType dataType;
    H2250LogicalChannelParameters h2250Parameters;
} OpenLogicalChannel;

typedef struct 
{
    u_char *firstByte;
    u_char *secondByte;
    BOOL nonStandardOpt;
    BOOL sessionIDOpt;
    BOOL mediaChannelOpt;
    BOOL mediaControlChannelOpt;
    BOOL dynamicRTPPayloadTypeOpt;
    BOOL portNumberOpt;

    u_char *sessionID;
    u_char *dynamicRTPPayloadType;
    VariableAddress mediaChannel;
    VariableAddress mediaControlChannel;
} H2250LogicalChannelAckParameters;

typedef struct struct_open_logical_channel_ack_str
{
    u_short *number;
    u_char *numBytes;
    u_char *data;
    H2250LogicalChannelAckParameters h2250AckParameters;
} OpenLogicalChannelAck;

typedef enum
{
    NON_STANDARD_REQUEST = 0,
    MASTER_SLAVE_DETERMINATION,
    TERMINAL_CAPABILITY_SET,
    OPEN_LOGICAL_CHANNEL,
} H245RequestType;

typedef enum
{
    NON_STANDARD_RESPONSE = 0,
    MASTER_SLAVE_DETERMINATION_ACK,
    MASTER_SLAVE_DETERMINATION_REJECT,
    TERMINAL_CAPABILITY_SET_ACK,
    TERMINAL_CAPABILITY_SET_REJECT,
    OPEN_LOGICAL_CHANNEL_ACK,
    OPEN_LOGICAL_CHANNEL_REJECT,
    CLOSE_LOGICAL_CHANNEL_ACK,
} H245ResponseType;

typedef struct struct_h245_str
{
    u_char *firstByte;
    u_char *secondByte;
    H245MessageType messageType;
} H245;

// #define DEBUG

#define TPKT_SIZE 4
#define Q931_TYPE_OFFSET 4
#define Q931_DISPLAY_LENGTH_OFFSET 11
#define Q931_BASE_SIZE 16
#define H225_SETUP_SRC_ADDR_OFFSET 91
#define H225_SETUP_DST_ADDR_OFFSET 62
#define H225_H323_ID_LENGTH_OFFSET 11
#define H225_CONNECT_ADDR_OFFSET 10

void InitializeVoipInterface(EXTERNAL_Interface *iface)
{
    AutoIPNEData *data;

    data = (AutoIPNEData*) iface->data;

    // If running in Nat-Yes mode, add the known h323hostcall port to
    // receive incoming VOIP connections.  This isn't necessary in other
    // modes because address swapping is not necessary.
    if (data->nat)
    {
        AddIPSocketPort(
            data,
            1720,
            HandleH225);
    }
}

void ParseTPKT(TPKT *tpkt, u_char **next)
{
    tpkt->version = *next;
    tpkt->reserved = tpkt->version + 1;
    tpkt->length = (u_short*) (tpkt->reserved + 1);
    *next = (u_char*) (tpkt->length + 1);
}

void ParseQ931(Q931 *q931, u_char **next)
{
    BOOL gotUserUser;
    char err[MAX_STRING_LENGTH];
    u_char type;

    q931->protocolDiscriminator = *next;
    q931->refValueLength = (u_char*) (q931->protocolDiscriminator + 1);
    q931->refValue = (u_char*) (q931->refValueLength + 1);
    q931->type = (u_char*) (q931->refValue + *q931->refValueLength);
    *next = (u_char*) (q931->type + 1);
    gotUserUser = FALSE;
    while (!gotUserUser)
    {
        type = **next;
        switch (type)
        {
            case BEARER_CAPABILITY:
                q931->bearer.informationElement = *next;
                q931->bearer.length = q931->bearer.informationElement + 1;
                q931->bearer.data = q931->bearer.length + 1;
                *next = q931->bearer.data + *q931->bearer.length;
                break;

            case CAUSE:
                q931->cause.informationElement = *next;
                q931->cause.length = q931->cause.informationElement + 1;
                q931->cause.data = q931->cause.length + 1;
                q931->cause.causeValue =
                    q931->cause.data + (*q931->cause.length - 1);
                *next = q931->cause.causeValue + 1;
                break;


            case DISPLAY:
                q931->display.informationElement = *next;
                q931->display.length = q931->display.informationElement + 1;
                q931->display.data = q931->display.length + 1;
                *next = q931->display.data + *q931->display.length;
                break;

            case CALLING_PARTY_NUMBER:
                q931->callingPartyNumber.informationElement = *next;
                q931->callingPartyNumber.length =
                    q931->callingPartyNumber.informationElement + 1;
                q931->callingPartyNumber.data =
                    q931->callingPartyNumber.length + 1;
                *next = q931->callingPartyNumber.data +
                    *q931->callingPartyNumber.length;
                break;

            case CALLED_PARTY_NUMBER:
                q931->calledPartyNumber.informationElement = *next;
                q931->calledPartyNumber.length =
                    q931->calledPartyNumber.informationElement + 1;
                q931->calledPartyNumber.data =
                    q931->calledPartyNumber.length + 1;
                *next = q931->calledPartyNumber.data +
                    *q931->calledPartyNumber.length;
                break;

           case USER_USER:
                q931->userUser.informationElement = *next;
                q931->userUser.length =
                    (u_short*) (q931->userUser.informationElement + 1);
                q931->userUser.protocolDiscriminator =
                    (u_char*) (q931->userUser.length + 1);
                *next = q931->userUser.protocolDiscriminator + 1;
                gotUserUser = TRUE;
                break;

           default:
                sprintf(err, "Unknown q931 type 0x%x", type);
                ERROR_ReportWarning(err);
                return;
                break;
        }
    }
}

void ParseVariableAddress(
    VariableAddress *addr,
    u_char **next,
    AddressType type)
{
    u_char *count;

    memset(addr, 0, sizeof(VariableAddress));

    count = *next;
    if (type == TRANSPORT_ADDRESS)
    {
        // parse transport address
        addr->isH225Address = TRUE;
        addr->h225Address.type = *next;
        addr->h225Address.typeValue = (*addr->h225Address.type) & 0x0F;
        addr->h225Address.ipAddress =
            (u_long*) (addr->h225Address.type + 1);
        addr->h225Address.port =
            (u_short*) (addr->h225Address.ipAddress + 1);

        *next = (u_char*) (addr->h225Address.port + 1);
    }
    else
    {
        // parse alias address
        addr->nameAddress.count = *next;
        if (*addr->nameAddress.count > 0)
        {
            // only handles 1 address
            assert(*addr->nameAddress.count == 1);
            addr->isNameAddress = TRUE;
            addr->nameAddress.type = addr->nameAddress.count + 1;
            addr->nameAddress.length = addr->nameAddress.type + 1;
            addr->nameAddress.address = addr->nameAddress.length + 1;
            *next = addr->nameAddress.address
                + (*addr->nameAddress.length + 1) * 2;
        }
        else
        {
            // no address
            *next = addr->nameAddress.count + 1;
        }
    }
}

void VariableAddressToString(VariableAddress *addr, char *string)
{
    int i;
    char *ch;

    ch = (char*) addr->nameAddress.address + 1;
    for (i = 0; i < *addr->nameAddress.length + 1; i++)
    {
        string[i] = *ch;
        ch += 2;
    }
    string[i] = 0;
}

void PrintVariableAddress(VariableAddress *addr)
{
    char s[MAX_STRING_LENGTH];

    if (addr->isNameAddress)
    {
        VariableAddressToString(addr, s);
#ifdef DEBUG
        printf("    %s\n", s);
#endif
    }

    if (addr->isH225Address)
    {
#ifdef DEBUG
        printf("    ");
        PrintIPAddress(addr->h225Address.ipAddress);
        printf(":%d\n", ntohs(*addr->h225Address.port));
#endif
    }
}

int SwapVariableAddress(
    EXTERNAL_Interface *iface,
    VariableAddress *addr,
    u_short *sum,
    u_char *packet)
{
    AutoIPNEData *data = (AutoIPNEData*) iface->data;

    if (!data->nat)
    {
        return 0;
    }

    if (addr->isNameAddress)
    {
        return SwapAddress(iface,
                           addr->nameAddress.address,
                           (*addr->nameAddress.length + 1) * 2,
                           sum,
                           packet);
    }

    if (addr->isH225Address)
    {
        return SwapAddress(iface,
                           (u_char*) addr->h225Address.ipAddress,
                           sizeof(u_long),
                           sum,
                           packet);
    }

    // Nothing swapped -- return error
    return 1;
}

void ParseVendorIdentifier(VendorIdentifier *vendor, u_char **next)
{
    vendor->t35CountryCode = *next;
    vendor->t35Extension = vendor->t35CountryCode + 1;
    vendor->manufacturerCode = (u_short*) (vendor->t35Extension + 1);

    vendor->productIDLength = (u_char*) (vendor->manufacturerCode + 1);
    vendor->productID = vendor->productIDLength + 1;

    vendor->versionLength = vendor->productID
        + (*vendor->productIDLength + 1);
    vendor->version = vendor->versionLength + 1;
    *next = vendor->version + (*vendor->versionLength + 1);
}

void ParseSourceInfo(SourceInfo *s, u_char **next)
{
    s->unknown = *next;

    // parse source info
    s->unknownNonStandard = (u_char*) (s->unknown + 1);

    // parse vendor identifier
    *next = s->unknownNonStandard + 1;
    ParseVendorIdentifier(&s->vendorIdentifier, next);

    s->flags = *next;
    s->flagsValue = (*s->flags) & 0xF0;
    *next = s->flags + 1;
}

void ParseProtocolIdentifier(ProtocolIdentifier *p, u_char **next)
{
    p->length = *next;
    p->identifier = p->length + 1;
    *next = p->identifier + *p->length;
}

void ParseConferenceIdentifier(ConferenceIdentifier *c, u_char **next)
{
    c->id1 = (u_long*) (*next);
    c->id2 = c->id1 + 1;
    c->id3 = c->id2 + 1;
    c->id4 = c->id3 + 1;
    *next = (u_char*) (c->id4 + 1);
}

void ParseCallIdentifier(CallIdentifier *c, u_char **next)
{
    c->length = *next;
    c->guid = c->length + 1;
    *next = c->guid + *c->length;
}

void ParseH225Setup(SetupUUIE *setup, u_char **next)
{
    char err[MAX_STRING_LENGTH];

    setup->firstByte = *next;
    *next = setup->firstByte + 1;

    setup->h245AddressPresent = (*setup->firstByte & 0x40) != 0;
    setup->sourceAddressPresent = (*setup->firstByte & 0x20) != 0;
    setup->destinationAddressPresent = (*setup->firstByte & 0x10) != 0;
    setup->destCallSignalAddressPresent = (*setup->firstByte & 0x08) != 0;

    // Parse protocol identifier
    ParseProtocolIdentifier(&setup->protocolIdentifier, next);

    // parse source address
#ifdef DEBUG
    printf("H.225 setup\n");
#endif
    if (setup->h245AddressPresent)
    {
        ParseVariableAddress(&setup->h245Address, next, TRANSPORT_ADDRESS);
#ifdef DEBUG
        printf("  h245 address:\n");
        PrintVariableAddress(&setup->h245Address);
#endif
    }

    if (setup->sourceAddressPresent)
    {
        ParseVariableAddress(&setup->sourceAddress, next, ALIAS_ADDRESS);
#ifdef DEBUG
        printf("  source address:\n");
        PrintVariableAddress(&setup->sourceAddress);
#endif
    }

    // Parse source info
    ParseSourceInfo(&setup->sourceInfo, next);

    if (setup->destinationAddressPresent)
    {
        ParseVariableAddress(
            &setup->destinationAddress,
            next,
            ALIAS_ADDRESS);
#ifdef DEBUG
        printf("  destination address:\n");
        PrintVariableAddress(&setup->destinationAddress);
#endif
    }

    if (setup->destCallSignalAddressPresent)
    {
        if (!setup->destinationAddressPresent)
        {
            *next = *next - 1;
        }
        ParseVariableAddress(&setup->destCallSignalAddress, next,
                TRANSPORT_ADDRESS);
#ifdef DEBUG
        printf("  destCallSignal address:\n");
        PrintVariableAddress(&setup->destCallSignalAddress);
#endif
    }


    setup->activeMC = *next;
    *next = setup->activeMC + 1;

    ParseConferenceIdentifier(&setup->conferenceIdentifier, next);
    setup->conferenceGoalCallType = *next;

    setup->firstExtensionByte = setup->conferenceGoalCallType + 1;

    // parse source call signal address
    // not sure what is taken here, a8 (meeting) => 45 0C 07
    //                              f0 (phone) => 5D 0D 80 07
    if (*setup->firstExtensionByte == 0x45)
    {
        *next = (u_char*) (setup->firstExtensionByte + 3);
    }
    else if (*setup->firstExtensionByte == 0x5D)
    {
        *next = (u_char*) (setup->firstExtensionByte + 4);
    }
    else
    {
        sprintf(err, "Unknown setup first extension byte 0x%x",
                     *setup->firstExtensionByte);
        ERROR_ReportWarning(err);
        return;
    }
    ParseVariableAddress(
        &setup->sourceCallSignalAddress,
        next,
        TRANSPORT_ADDRESS);
#ifdef DEBUG
    printf("  Source call signal address:\n");
    PrintVariableAddress(&setup->sourceCallSignalAddress);
#endif

    // parse call identifier
    ParseCallIdentifier(&setup->callIdentifier, next);

    setup->mediaWaitForConnectPresent = *next;
    if (*setup->mediaWaitForConnectPresent)
    {
        setup->mediaWaitForConnect = setup->mediaWaitForConnectPresent + 1;
    }
    else
    {
        return;
    }

    setup->canOverlapSendPresent = setup->mediaWaitForConnect + 1;
    if (*setup->canOverlapSendPresent)
    {
        setup->canOverlapSend = setup->canOverlapSendPresent + 1;
    }
    else
    {
        return;
    }

    setup->multipleCallsPresent = setup->canOverlapSend + 1;
    if (*setup->multipleCallsPresent)
    {
        setup->multipleCalls = setup->multipleCallsPresent + 1;
    }
    else
    {
        return;
    }

    setup->maintainConnectionPresent = setup->multipleCalls + 1;
    if (*setup->maintainConnectionPresent)
    {
        setup->maintainConnection = setup->maintainConnectionPresent + 1;
    }
    else
    {
        return;
    }

    // a little more here, but we ignore
}

void ParseH225Connect(H225 *h225, ConnectUUIE *connect, u_char **next)
{
    connect->firstByte = *next;
    *next = connect->firstByte + 1;

    // Parse protocol identifier
    ParseProtocolIdentifier(&connect->protocolIdentifier, next);

    // Parse source address
    ParseVariableAddress(&connect->sourceAddress, next, TRANSPORT_ADDRESS);
#ifdef DEBUG
    printf("H.225 connect\n");
    printf("  Source address:\n");
    PrintVariableAddress(&connect->sourceAddress);
#endif

    // Parse source info
    ParseSourceInfo(&connect->destinationInfo, next);

    // Parse conference identifier
    ParseConferenceIdentifier(&connect->conferenceIdentifier, next);

    // Parse call identifier
    ParseCallIdentifier(&connect->callIdentifier, next);

    // a little more here, but we ignore
}

void ParseCallProceeding(CallProceedingUUIE *c, u_char **next)
{
    c->firstByte = *next;
    c->h245AddressPresent = (*c->firstByte & 0x40) != 0;

    *next = c->firstByte + 1;
    ParseProtocolIdentifier(&c->protocolIdentifier, next);
    ParseSourceInfo(&c->destinationInfo, next);

    if (c->h245AddressPresent)
    {
        *next = *next - 1;
        ParseVariableAddress(&c->h245Address, next, TRANSPORT_ADDRESS);
#ifdef DEBUG
        printf("H.225 call proceeding\n");
        printf("  Address:\n");
        PrintVariableAddress(&c->h245Address);
#endif
    }

    // more, but we ignore
}

void ParseAlerting(AlertingUUIE *a, u_char **next)
{
    a->firstByte = *next;
    a->h245AddressPresent = (*a->firstByte & 0x40) != 0;

    *next = a->firstByte + 1;
    ParseProtocolIdentifier(&a->protocolIdentifier, next);
    ParseSourceInfo(&a->destinationInfo, next);

    if (a->h245AddressPresent)
    {
        *next = *next - 1;
        ParseVariableAddress(&a->h245Address, next, TRANSPORT_ADDRESS);
#ifdef DEBUG
        printf("H.225 alerting\n");
        printf("  Address:\n");
        PrintVariableAddress(&a->h245Address);
#endif
    }

    // more, but we ignore
}

void HandleH225(
    EXTERNAL_Interface *iface,
    u_char *packet,
    u_char *data,
    int size,
    u_short *sum,
    AutoIPNE_EmulatePacketFunction **func)
{
    AutoIPNEData *ipneData;
    TPKT tpkt; // the tpkt header
    Q931 q931; // the q931 header
    H225 h225; // the h225 header
    SetupUUIE setup;
    ConnectUUIE connect;
    CallProceedingUUIE callProceeding;
    AlertingUUIE alerting;
    u_char *next;
    u_char *nextTpkt;
    static BOOL fragmentedTpkt = FALSE;
    static u_short lastTpktLength;
    u_short port;

    assert(iface != NULL);
    assert(packet != NULL);
    assert(data != NULL);
    assert(sum != NULL);

    // If there is no data (only a header)
    if (data - packet == size)
    {
        return;
    }

    // extract voip data
    ipneData = (AutoIPNEData*) iface->data;
    assert(ipneData != NULL);
    
    if (ipneData->debug)
    {
        printf("IPNE VOIP: got h225 packet\n");
    }

    nextTpkt = data;
    while (nextTpkt < packet + size)
    {
        // parse tpkt
        if (fragmentedTpkt == FALSE)
        {
            next = nextTpkt;
            ParseTPKT(&tpkt, &next);
    
            // Verify that the tpkt is valid
            if ((*tpkt.version != TPKT_REQUIRED_VERSION)
                || (*tpkt.reserved != 0))
            {
                return;
            }
    
            // Compute the next tpkt offset
            nextTpkt = nextTpkt + ntohs(*tpkt.length);
    
            // If this tpkt is fragmented then record information for next
            // call to HandleH225
            if (next >= packet + size)
            {
                fragmentedTpkt = TRUE;
                lastTpktLength = ntohs(*tpkt.length);
                if (ipneData->debug)
                {
                    printf("split tpkt\n");
                }
                return;
            }
        }
        else
        {
            // This tpkt is a continuation of a fragmented tpkt
            next = data;
            nextTpkt = nextTpkt + lastTpktLength - 4;
            fragmentedTpkt = FALSE;
#ifdef DEBUG
            printf("unsplit tpkt\n");
#endif
        }

        ParseQ931(&q931, &next);

        h225.firstByte = next;
        h225.bodyType = *(h225.firstByte) & 0x7;
        next = h225.firstByte + 1;
    
        switch (*q931.type)
        {
            case ALERTING:
                ParseAlerting(&alerting, &next);

                if (alerting.h245AddressPresent)
                {
                    SwapVariableAddress(iface,
                                        &alerting.h245Address,
                                        sum,
                                        packet);
                }
                break;

            case CALL_PROCEEDING:
                ParseCallProceeding(&callProceeding, &next);

                if (callProceeding.h245AddressPresent)
                {
                    SwapVariableAddress(iface,
                                        &callProceeding.h245Address,
                                        sum,
                                        packet);
                }
                break;

            case SETUP:
                assert(h225.bodyType == H225_SETUP);
                ParseH225Setup(&setup, &next);

                if (setup.h245AddressPresent)
                {
                    if (SwapVariableAddress(iface,
                                            &setup.h245Address,
                                            sum,
                                            packet))
                    {
                        ERROR_ReportWarning("Error swapping H.225 "
                            "h245 address in Setup\n");
                    }

                    AddIPSocketPort(
                        ipneData,
                        ntohs(*setup.h245Address.h225Address.port),
                        HandleH245);
                }

                if (setup.sourceAddressPresent)
                {
                    // don't check for warning
                    SwapVariableAddress(iface,
                                        &setup.sourceAddress,
                                        sum,
                                        packet);
                }

                if (setup.destinationAddressPresent)
                {
                    // don't check for warning
                    SwapVariableAddress(iface,
                                        &setup.destinationAddress,
                                        sum,
                                        packet);
                }

                if (setup.destCallSignalAddressPresent)
                {
                    if (SwapVariableAddress(iface,
                                        &setup.destCallSignalAddress,
                                        sum,
                                        packet))
                    {
                        ERROR_ReportWarning("Error swapping H.225 dest "
                            "call signal address in Setup\n");
                    }
                }

                if (SwapVariableAddress(iface,
                                    &setup.sourceCallSignalAddress,
                                    sum,
                                    packet))
                {
                    ERROR_ReportWarning("Error swapping H.225 source "
                        "call signal address in Setup\n");
                }
                break;

            case CONNECT:
                assert(h225.bodyType == H225_CONNECT);
                ParseH225Connect(&h225, &connect, &next);

                // Extract the H.245 connect address and port
                if (connect.sourceAddress.isH225Address)
                {
                    port = ntohs(*connect.sourceAddress.h225Address.port);

#ifdef DEBUG
                    printf("H.225 connected on port %d\n", port);
#endif

                    // Listen for H.245 communication on packets originating
                    // from this port, or sent to this port
                    AddIPSocketPort(ipneData,
                                    port,
                                    HandleH245);
                }

                // Swap the real <-> qualnet address
                SwapVariableAddress(iface,
                                    &connect.sourceAddress,
                                    sum,
                                    packet);
                break;

            case 0x5A: // releaseComplete
                break;

            default:
#ifdef DEBUG
                sprintf(err, "unknown H.225 type %d\n", *type);
                ERROR_ReportWarning(err);
#endif
                break;
        }
    }
}

#define TPKT_LENGTH_OFFSET 2
#define H245_OPEN_LOGICAL_CHANNEL_TYPE_OFFSET 4
#define H245_MEDIA_CHANNEL_ADDRESS_OFFSET 10
#define H245_MEDIA_CHANNEL_PORT_OFFSET 14
#define H245_MEDIA_CONTROL_CHANNEL_ADDRESS_OFFSET 17

void ParseH2250Parameters(
    H2250LogicalChannelParameters *h,
    u_char **next)
{
    h->first4Bytes = (u_long*) *next;
    h->sessionID = (u_char*) (h->first4Bytes + 1);
    *next = h->sessionID + 1;

    ParseVariableAddress(&h->ipAddress, next, TRANSPORT_ADDRESS);
#ifdef DEBUG
    printf("H.2250 parameters\n");
    printf("  ip address:\n");
    PrintVariableAddress(&h->ipAddress);
#endif

    h->silenceSuppression = *next;
    *next = h->silenceSuppression + 1;
}

void ParseAudioCapability(AudioCapability *a, u_char **next)
{
    char err[MAX_STRING_LENGTH];

    // Parse data type
    a->first2Bytes = (u_short*) (*next);
    a->type = (AudioCapabilityType)
              ((ntohs(*a->first2Bytes) & 0x01E0) >> 5);
    a->data = (u_char*) (a->first2Bytes + 1);

    switch (a->type)
    {
        case G711ULAW64K:
            // skip over data
            *next = a->data + 1;
            break;

        default:
            sprintf(err, "Unsupported audio type 0x%x", a->type);
            ERROR_ReportWarning(err);
            break;
    }

}

void ParseVideoCapability(VideoCapability *v, u_char **next)
{
    char err[MAX_STRING_LENGTH];

    v->first2Bytes = (u_short*) (*next);
    v->type = (VideoCapabilityType) 
        ((ntohs(*v->first2Bytes) & 0x01C0) >> 6);
    
    switch (v->type)
    {
        case H261_VIDEO_CAPABILITY:
            v->extensionPresent = (ntohs(*v->first2Bytes) & 0x20) != 0;
            v->qcifMPIPresent = (ntohs(*v->first2Bytes) & 0x10) != 0;
            v->cifMPIPresent = (ntohs(*v->first2Bytes) & 0x80) != 0;

            if (v->qcifMPIPresent && v->cifMPIPresent)
            {
                assert(0);
            }

            if (v->qcifMPIPresent)
            {
                v->qcifMPI = ((*v->first2Bytes & 0x06) >> 1) + 1;
                v->temporalSpatial = (*v->first2Bytes & 0x01);
            }

            if (v->cifMPIPresent)
            {
                v->cifMPI = ((*v->first2Bytes & 0x06) >> 1) + 1;
                v->temporalSpatial = (*v->first2Bytes & 0x01);
            }

            v->maxBitRate = v->first2Bytes + 1;
            v->stillImageTransmission = (u_char*) (v->maxBitRate + 1);

            if (v->extensionPresent)
            {
                *next = v->stillImageTransmission + 4;
            }
            else
            {
                *next = v->stillImageTransmission + 1;
            }
            break;

        default:
            sprintf(err, "Unsupported video type 0x%x", v->type);
            ERROR_ReportWarning(err);
            break;
    }
}

void ParseDataType(DataType *d, u_char **next)
{
    d->firstByte = *next;
    // note: don't incremenet next
    d->type = (DataTypeType) ((*d->firstByte & 0x1C) >> 2);

    switch (d->type)
    {
        case NON_STANDARD_DATA:
            break;

        case NULL_DATA:
            break;

        case VIDEO_DATA:
            ParseVideoCapability(&d->videoCapability, next);
            break;

        case AUDIO_DATA:
            ParseAudioCapability(&d->audioCapability, next);
            break;
    }

}

void ParseOpenLogicalChannel(
    OpenLogicalChannel *c,
    u_char **next)
{
    c->unknown = *next;
    c->number = (u_short*) (c->unknown + 1);
    *next = (u_char*) (c->number + 1);

    ParseDataType(&c->dataType, next);

    // Parse multiplex parameters
    ParseH2250Parameters(&c->h2250Parameters, next);
}

void ParseH2250LogicalChannelAckParameters(
    H2250LogicalChannelAckParameters *h,
    u_char **next)
{
    h->firstByte = *next;
    *next = h->firstByte + 1;

    h->nonStandardOpt = (*h->firstByte & 0x20) != 0;
    h->sessionIDOpt = (*h->firstByte & 0x10) != 0;
    h->mediaChannelOpt = (*h->firstByte & 0x08) != 0;
    h->mediaControlChannelOpt = (*h->firstByte & 0x04) != 0;
    h->dynamicRTPPayloadTypeOpt = (*h->firstByte & 0x02) != 0;
    h->portNumberOpt = (*h->firstByte & 0x01) != 0;

    if (h->nonStandardOpt)
    {
        assert(0);
    }

    if (h->sessionIDOpt)
    {
        h->sessionID = *next;
        *next = h->sessionID + 1;
    }

#ifdef DEBUG
    printf("H.2250 ack parameters\n");
#endif
    if (h->mediaChannelOpt)
    {
        ParseVariableAddress(&h->mediaChannel, next, TRANSPORT_ADDRESS);
#ifdef DEBUG
        printf("  media channel:\n");
        PrintVariableAddress(&h->mediaChannel);
#endif
    }

    if (h->mediaControlChannelOpt)
    {
        ParseVariableAddress(
            &h->mediaControlChannel,
            next,
            TRANSPORT_ADDRESS);
#ifdef DEBUG
        printf("  media control channel:\n");
        PrintVariableAddress(&h->mediaControlChannel);
#endif
    }

    // ignore rest
    return;
}

void ParseOpenLogicalChannelAck(
    OpenLogicalChannelAck *a,
    u_char **next)
{
    a->number = (u_short*) (*next);
    a->numBytes = (u_char*) (a->number + 1);
    a->data = a->numBytes + 1;
    //*next = a->data + *a->numBytes;
    *next = a->data + 2;

    ParseH2250LogicalChannelAckParameters(
        &a->h2250AckParameters,
        next);
}

void ParseH245Request(
    EXTERNAL_Interface *iface,
    u_char *packet,
    u_short *sum,
    H245 *h245,
    u_char **next)
{
    OpenLogicalChannel openLogicalChannel;
    H245RequestType requestType;

    requestType = (H245RequestType) (*h245->firstByte & 0x0F);
    switch (requestType)
    {
        case NON_STANDARD_REQUEST:
            break;

        case MASTER_SLAVE_DETERMINATION:
            break;

        case TERMINAL_CAPABILITY_SET:
            break;

        case OPEN_LOGICAL_CHANNEL:
            memset(&openLogicalChannel, 0, sizeof(OpenLogicalChannel));
            ParseOpenLogicalChannel(&openLogicalChannel, next);

            SwapVariableAddress(
                iface,
                &openLogicalChannel.h2250Parameters.ipAddress,
                sum,
                packet);
            break;
    }
}

void ParseH245Response(
    EXTERNAL_Interface *iface,
    u_char *packet,
    u_short *sum,
    H245 *h245,
    u_char **next)
{
    OpenLogicalChannelAck openLogicalChannelAck;
    H245ResponseType responseType;
    VariableAddress *addr;
    AutoIPNEData *ipData;

    ipData = (AutoIPNEData*) iface->data;
    assert(ipData != NULL);

    h245->secondByte = *next;
    *next = h245->secondByte + 1;
    responseType = (H245ResponseType)
                   (((*h245->firstByte & 0xF) << 1)
                   + ((*h245->secondByte & 0x80) >> 7));
    switch (responseType)
    {
        case NON_STANDARD_RESPONSE:
            break;

        case MASTER_SLAVE_DETERMINATION_ACK:
            break;

        case MASTER_SLAVE_DETERMINATION_REJECT:
            break;

        case TERMINAL_CAPABILITY_SET_ACK:
            break;

        case TERMINAL_CAPABILITY_SET_REJECT:
            break;

        case OPEN_LOGICAL_CHANNEL_ACK:
            memset(
                &openLogicalChannelAck,
                0,
                sizeof(OpenLogicalChannelAck));
            ParseOpenLogicalChannelAck(&openLogicalChannelAck,
                                       next);

            addr = &openLogicalChannelAck.h2250AckParameters.mediaChannel;
            SwapVariableAddress(
                iface,
                addr,
                sum,
                packet);
            if (addr->isH225Address)
            {
                AddIPSocket(
                    ipData,
                    *addr->h225Address.ipAddress,
                    ntohs(*addr->h225Address.port),
                    0,
                    0,
                    HandleH323);
            }

            SwapVariableAddress(
                iface,
                &openLogicalChannelAck.h2250AckParameters.mediaControlChannel,
                sum,
                packet);
            break;
    
        case OPEN_LOGICAL_CHANNEL_REJECT:
            break;

        case CLOSE_LOGICAL_CHANNEL_ACK:
            break;
    }
}

void HandleH245(
    EXTERNAL_Interface *iface,
    u_char *packet,
    u_char *data,
    int size,
    u_short *sum,
    AutoIPNE_EmulatePacketFunction **func)
{
    AutoIPNEData *ipneData;
    TPKT tpkt;
    H245 h245;
    u_char *next;
    u_char *nextTpkt;
    static BOOL fragmentedTpkt = FALSE;
    static u_short lastTpktLength;

    assert(iface != NULL);
    assert(packet != NULL);
    assert(data != NULL);
    assert(sum != NULL);

    ipneData = (AutoIPNEData*) iface->data;
    assert(ipneData != NULL);

    if (ipneData->debug)
    {
        printf("IPNE VOIP: got h245 packet\n");
    }

    nextTpkt = data;
    while (nextTpkt < packet + size)
    {
        // If the previous tpkt was not fragmented then parse as normal
        if (fragmentedTpkt == FALSE)
        {
            next = nextTpkt;
            ParseTPKT(&tpkt, &next);

            // Verify that the tpkt is valid
            if ((*tpkt.version != 3) || (*tpkt.reserved != 0))
            {
                return;
            }

            // Compute the next tpkt offset
            nextTpkt = nextTpkt + ntohs(*tpkt.length);

            // If this tpkt is fragmented then record information for next
            // call to HandleH245
            if (next >= packet + size)
            {
                fragmentedTpkt = TRUE;
                lastTpktLength = ntohs(*tpkt.length);
#ifdef DEBUG
                printf(
                    "split h245 tpkt length = %d\n",
                    (int) lastTpktLength);
#endif
                return;
            }
        }
        else
        {
            // This tpkt is a continuation of a fragmented tpkt
            next = data;
            nextTpkt = nextTpkt + lastTpktLength - 4;
            fragmentedTpkt = FALSE;
#ifdef DEBUG
            printf(
                "unsplit h245 packet length = %d\n",
                (int) lastTpktLength);
#endif
        }

        h245.firstByte = next;
        next = h245.firstByte + 1;
        h245.messageType = (H245MessageType)
            ((*h245.firstByte & 0x60) >> 5);
#ifdef DEBUG
        printf("type = 0x%x\n", h245.messageType);
#endif
        switch (h245.messageType)
        {
            case REQUEST:
                ParseH245Request(iface, packet, sum, &h245, &next);
                break;
    
            case RESPONSE:
                ParseH245Response(iface, packet, sum, &h245, &next);
                break;
    
            case COMMAND:
                break;
    
            case INDICATION:
                break;

            default:
                break;
        }
    }
}

void HandleH323(
    EXTERNAL_Interface *iface,
    u_char *packet,
    u_char *data,
    int size,
    u_short *sum,
    AutoIPNE_EmulatePacketFunction **func)
{
    AutoIPNEData* ipneData = (AutoIPNEData*) iface->data;
    assert(ipneData != NULL);

    if (ipneData->debug)
    {
        printf("IPNE VOIP: got h323 packet\n");
    }
}

#endif 
