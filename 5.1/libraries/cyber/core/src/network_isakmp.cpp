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

//
// PROTOCOL   :: ISAKMP
// LAYER      :: Network

// MAJOR REFERENCES ::
// + RFC 2408
// + RFC 2409
// + RFC 2407
// MINOR REFERENCES ::
// + RFC 2401
// + RFC 2412

// COMMENTS   :: None
//

#include "api.h"
#include "message.h"
#include "fileio.h"
#include "network_ip.h"
#include "crypto.h"
#include "network_ipsec.h"
#include "network_isakmp.h"
#include "network_iahep.h"


#define RETRY_LIMIT         3
#define ISAKMP_RETRANS_INTERVAL     10 * SECOND

#define MAX_PROPOSAL_NAME_LEN    24
#define MAX_PROTOCOL_NAME_LEN    24
#define MAX_TRANSFORM_NAME_LEN   24

#define BUFFER_SIZE     512
#define MAX_STRING_LEN  16

#define ISAKMP_DEBUG    0

//*************************************************************************
// Declarations of Function Prototype.
// NOTE :description of these functions is given with their definition only
//*************************************************************************

void ISAKMPInitiatorSendCookie(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPResponderReplyCookie(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorSendSA(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPResponderReplySA(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorRecvSA(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvKENonce(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendKENonce(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendIDAuth(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvIDAuth(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorSendSANonce(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorRecvSANonce(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendKEIDAuth(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvKEIDAuth(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPResponderReplySANonce(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPResponderReplySANonceIDAuth(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorRecvSANonceIDAuth(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorSendSAKENonceID(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPResponderReplySAKENonceIDAuth(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorRecvSAKENonceIDAuth(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendAuth(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvAuth(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendIDHash(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvIDHash(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendIDCertSig(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvIDCertSig(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendKEHashIDNonce(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvKEHashIDNonce(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendKEIDNonce(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvKEIDNonce(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendHash(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvHash(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendHashNonceKEIDCert(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvHashNonceKEIDCert(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendNonceKEID(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvNonceKEID(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPSendCertSig(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPRecvCertSig(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPResponderReplySAKENonceIDHash(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorRecvSAKENonceIDHash(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPResponderReplySAKENonceIDCertSig(Node*, ISAKMPNodeConf*,Message*);

void ISAKMPInitiatorRecvSAKENonceIDCertSig(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorSendSAHashKEIDNonce(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPResponderReplySAKEIDNonceHash(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorRecvSAKEIDNonceHash(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorSendSAHashNonceKEIDCert(Node*, ISAKMPNodeConf*,Message*);

void ISAKMPResponderReplySANonceKEIDHash(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorRecvSANonceKEIDHash(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorSendHashSANonceKEIDID(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPResponderReplyHashSANonceKEIDID(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorRecvHashSANonceKEIDID(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorSendHashSA(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPResponderReplyHashSA(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPInitiatorRecvHashSA(Node*, ISAKMPNodeConf*, Message*);

void ISAKMPExchangeFinalize(Node*, ISAKMPNodeConf*, Message*);

static
void ISAKMPAddKE(Node* node,
                 ISAKMPNodeConf* nodeconfig,
                 ISAKMPPaylKeyEx* ke_payload);

static
UInt16 ISAKMPValidatepayload(ISAKMPStats* &stats,
                             ISAKMPNodeConf* nodeconfig,
                             unsigned char payload_type,
                             char* currentOffset);

//************************************************************************
//  Exchange Scenariao for diffrent Exchange type
//************************************************************************

IsakmpExchFunc isakmp_idprot_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSA,
                                    ISAKMPInitiatorRecvSA,
                                    ISAKMPSendKENonce,
                                    ISAKMPRecvKENonce,
                                    ISAKMPSendIDAuth,
                                    ISAKMPRecvIDAuth,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySA,
                                    ISAKMPRecvKENonce,
                                    ISAKMPSendKENonce,
                                    ISAKMPRecvIDAuth,
                                    ISAKMPSendIDAuth,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_base_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSANonce,
                                    ISAKMPInitiatorRecvSANonce,
                                    ISAKMPSendKEIDAuth,
                                    ISAKMPRecvKEIDAuth,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySANonce,
                                    ISAKMPRecvKEIDAuth,
                                    ISAKMPSendKEIDAuth,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_auth_only_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSANonce,
                                    ISAKMPInitiatorRecvSANonceIDAuth,
                                    ISAKMPSendIDAuth,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySANonceIDAuth,
                                    ISAKMPRecvIDAuth,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_aggresive_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSAKENonceID,
                                    ISAKMPInitiatorRecvSAKENonceIDAuth,
                                    ISAKMPSendAuth,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySAKENonceIDAuth,
                                    ISAKMPRecvAuth,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_ikeMainPreShared_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSA,
                                    ISAKMPInitiatorRecvSA,
                                    ISAKMPSendKENonce,
                                    ISAKMPRecvKENonce,
                                    ISAKMPSendIDHash,
                                    ISAKMPRecvIDHash,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySA,
                                    ISAKMPRecvKENonce,
                                    ISAKMPSendKENonce,
                                    ISAKMPRecvIDHash,
                                    ISAKMPSendIDHash,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_ikeMainDigSig_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSA,
                                    ISAKMPInitiatorRecvSA,
                                    ISAKMPSendKENonce,
                                    ISAKMPRecvKENonce,
                                    ISAKMPSendIDCertSig,
                                    ISAKMPRecvIDCertSig,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySA,
                                    ISAKMPRecvKENonce,
                                    ISAKMPSendKENonce,
                                    ISAKMPRecvIDCertSig,
                                    ISAKMPSendIDCertSig,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_ikeMainPubKey_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSA,
                                    ISAKMPInitiatorRecvSA,
                                    ISAKMPSendKEHashIDNonce,
                                    ISAKMPRecvKEIDNonce,
                                    ISAKMPSendHash,
                                    ISAKMPRecvHash,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySA,
                                    ISAKMPRecvKEHashIDNonce,
                                    ISAKMPSendKEIDNonce,
                                    ISAKMPRecvHash,
                                    ISAKMPSendHash,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_ikeMainRevPubKey_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSA,
                                    ISAKMPInitiatorRecvSA,
                                    ISAKMPSendHashNonceKEIDCert,
                                    ISAKMPRecvNonceKEID,
                                    ISAKMPSendHash,
                                    ISAKMPRecvHash,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySA,
                                    ISAKMPRecvHashNonceKEIDCert,
                                    ISAKMPSendNonceKEID,
                                    ISAKMPRecvHash,
                                    ISAKMPSendHash,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_ikeAggPreShared_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSAKENonceID,
                                    ISAKMPInitiatorRecvSAKENonceIDHash,
                                    ISAKMPSendHash,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySAKENonceIDHash,
                                    ISAKMPRecvHash,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_ikeAggDigSig_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSAKENonceID,
                                    ISAKMPInitiatorRecvSAKENonceIDCertSig,
                                    ISAKMPSendCertSig,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySAKENonceIDCertSig,
                                    ISAKMPRecvCertSig,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_ikeAggPubKey_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSAHashKEIDNonce,
                                    ISAKMPInitiatorRecvSAKEIDNonceHash,
                                    ISAKMPSendHash,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySAKEIDNonceHash,
                                    ISAKMPRecvHash,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_ikeAggRevPubKey_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendSAHashNonceKEIDCert,
                                    ISAKMPInitiatorRecvSANonceKEIDHash,
                                    ISAKMPSendHash,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplySANonceKEIDHash,
                                    ISAKMPRecvHash,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_ikeQuick_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendHashSANonceKEIDID,
                                    ISAKMPInitiatorRecvHashSANonceKEIDID,
                                    ISAKMPSendHash,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplyHashSANonceKEIDID,
                                    ISAKMPRecvHash,
                                    ISAKMPExchangeFinalize
                                }
};

IsakmpExchFunc isakmp_ikeNewGroup_func = {
                                {
                                    ISAKMPInitiatorSendCookie,
                                    ISAKMPInitiatorSendHashSA,
                                    ISAKMPInitiatorRecvHashSA,
                                    ISAKMPExchangeFinalize
                                },
                                {
                                    ISAKMPResponderReplyCookie,
                                    ISAKMPResponderReplyHashSA,
                                    ISAKMPExchangeFinalize
                                }
};


//------------------------------------------------------------------------//
// NAME       :: ISAKMPSetTimer
// LAYER      :: Network
// PURPOSE    :: Set timers of various types.
// PARAMETERS :: Node* - node pointer
//               ISAKMPNodeConf* - isakmp configuration at this node
//               int eventType - event type for the timer event
//               UInt16 value   - current state of the exchange
//               clocktype delay - timer delay
// RETURN     :: None.
//------------------------------------------------------------------------//

static
void ISAKMPSetTimer(
    Node* node,
    ISAKMPNodeConf* nodeconfig,
    int eventType,
    UInt32 value,
    clocktype delay = 0)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    clocktype timerDelay = 0;

    ISAKMPTimerInfo* info = NULL;
    Message* newMsg = MESSAGE_Alloc(node,
                                    NETWORK_LAYER,
                                    NETWORK_PROTOCOL_ISAKMP,
                                    eventType);

    MESSAGE_InfoAlloc(node, newMsg, sizeof(ISAKMPTimerInfo));
    info = (ISAKMPTimerInfo*) MESSAGE_ReturnInfo(newMsg);
    info->nodeconfig = nodeconfig;

    switch (eventType)
    {
        case MSG_NETWORK_ISAKMP_SchedulePhase1:
        {
            // Set phase 1 start timer
            timerDelay = (clocktype)delay;
            break;
        }
        case MSG_NETWORK_ISAKMP_ScheduleNextPhase:
        {
            // Set phase start timer for New Group Mode
            timerDelay = (clocktype)delay;
            break;
        }
        case MSG_NETWORK_ISAKMP_SchedulePhase2:
        {
            // Set phase 2 start timer
            timerDelay = (clocktype)delay;
            break;
        }
        case MSG_NETWORK_ISAKMP_RxmtTimer:
        {
            // Set retransmission timer
            //should use link propagation delay to set the retrans interval

            timerDelay = (clocktype) ((ISAKMP_RETRANS_INTERVAL
                      * (nodeconfig->exchange->retrycounter + 1))
                   + RANDOM_erand(interfaceInfo->isakmpdata->seed) * SECOND
                   + delay);

            info->value = value;
            info->phase = nodeconfig->exchange->phase;

            if (ISAKMP_DEBUG)
            {
                char srcStr[MAX_STRING_LENGTH];
                char timeStr[100];
                char clockStr[100];
                IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
                ctoa(node->getNodeTime(), timeStr);
                ctoa(timerDelay, clockStr);
                printf("\n%s has set a RxmtTimer for step %u at"
                    "Simulation time = %s with delay = %s\n",
                    srcStr, value, timeStr, clockStr);
            }

            break;
        }
        case MSG_NETWORK_ISAKMP_RefreshTimer:
        {
            // Set Refresh timer
            if (nodeconfig->exchange->initiator == INITIATOR)
            {
                timerDelay = (clocktype)delay * MINUTE;
            }
            else
            {
                timerDelay = (clocktype)((delay + RANDOM_erand(
                    interfaceInfo->isakmpdata->seed)) * MINUTE);
            }

            info->value = value;
            info->phase = nodeconfig->exchange->phase;

            if (ISAKMP_DEBUG)
            {
                char srcStr[MAX_STRING_LENGTH];
                char timeStr[100];
                char clockStr[100];
                IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
                ctoa(node->getNodeTime(), timeStr);
                ctoa(timerDelay, clockStr);
                printf("\n%s has set a RefreshTimer for SPI %u at"
                    "Simulation time = %s with delay = %s\n",
                    srcStr, value, timeStr, clockStr);
            }

            break;
        }
        default:
            // Shouldn't get here.
            ERROR_Assert(FALSE, "Invalid Timer EventType\n");
    }

    MESSAGE_Send(node, newMsg, timerDelay);
}

//
// FUNCTION   :: ISAKMPGetPhase1Transform
// LAYER      :: Network
// PURPOSE    :: Extarct phase-1 transform from the phase-1 transform list.
// PARAMETERS :: ISAKMPPhase1TranList - phase-1 transform list
//               char* - transform Name
// RETURN     :: ISAKMPPhase1Transform : phase-1 transform
//

static
ISAKMPPhase1Transform* ISAKMPGetPhase1Transform(
    ISAKMPPhase1TranList* ph1_trans_list,
    char* transformName)
{
    while (ph1_trans_list != NULL)
    {
        if (!strcmp(ph1_trans_list->transform.transformName, transformName))
        {
            return &ph1_trans_list->transform;
        }
        else
        {
            ph1_trans_list = ph1_trans_list->next;
        }
    }
    if (ph1_trans_list == NULL)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "Configuration missing for Phase 1 transform %s\n",
            transformName);
        ERROR_Assert(FALSE, errStr);
    }
    return NULL;
}

//
// FUNCTION   :: ISAKMPGetPhase2Transform
// LAYER      :: Network
// PURPOSE    :: Extarct phase-2 transform from the phase-2 transform list .
// PARAMETERS :: ISAKMPPhase2TranList - phase-2 transform list
//               char* - transform Name
// RETURN     :: ISAKMPPhase2Transform : phase-2 transform
//

static
ISAKMPPhase2Transform* ISAKMPGetPhase2Transform(
    ISAKMPPhase2TranList* ph2_trans_list,
    char* transformName)
{
    while (ph2_trans_list != NULL)
    {
        if (!strcmp(ph2_trans_list->transform.transformName, transformName))
        {
            return &ph2_trans_list->transform;
        }
        else
        {
            ph2_trans_list = ph2_trans_list->next;
        }
    }
    if (ph2_trans_list == NULL)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "Configuration missing for Phase 2 transform %s\n",
            transformName);
        ERROR_Assert(FALSE, errStr);
    }
    return NULL;
}

//
// FUNCTION   :: ISAKMPGetFlags
// LAYER      :: Network
// PURPOSE    :: To find which flags are set in configuration
// PARAMETERS :: char* flagStr - user configurued flags
// RETURN     :: unsigned char - flags
// NOTE       ::

static
unsigned char ISAKMPGetFlags(char* flagStr)
{
    if (!strcmp(flagStr, "ACE"))
    {
        return ISAKMP_FLAG_A |ISAKMP_FLAG_C | ISAKMP_FLAG_E;
    }
    else if (!strcmp(flagStr, "CE"))
    {
        return ISAKMP_FLAG_C | ISAKMP_FLAG_E;
    }
    else if (!strcmp(flagStr, "AE"))
    {
        return ISAKMP_FLAG_A | ISAKMP_FLAG_E;
    }
    else if (!strcmp(flagStr, "AC"))
    {
        return ISAKMP_FLAG_A | ISAKMP_FLAG_C;
    }
    else if (!strcmp(flagStr, "A"))
    {
        return ISAKMP_FLAG_A;
    }
    else if (!strcmp(flagStr, "C"))
    {
        return ISAKMP_FLAG_C;
    }
    else if (!strcmp(flagStr, "E"))
    {
        return ISAKMP_FLAG_E;
    }
    else if (!strcmp(flagStr, "NONE"))
    {
        return ISAKMP_FLAG_NONE;
    }
    else
    {
        ERROR_ReportError("Unknown Flag Type");
    }
    return ISAKMP_FLAG_NONE;
}

//
// FUNCTION   :: ISAKMPGetNodeIdType
// LAYER      :: Network
// PURPOSE    :: To find ID type of a node
// PARAMETERS :: char*  nodeIDTypeStr - user configurued node-id type
// RETURN     :: unsigned char - node id type
// NOTE       ::

static
unsigned char ISAKMPGetNodeIdType(char*  nodeIDTypeStr)
{
    if (!strcmp(nodeIDTypeStr, "IPV4_ADDR"))
    {
        return ISAKMP_ID_IPV4_ADDR;
    }
    else if (!strcmp(nodeIDTypeStr, "IPV4_ADDR_SUBNET"))
    {
        return ISAKMP_ID_IPV4_ADDR_SUBNET;
    }
    else
    {
        ERROR_ReportError("Unknown NODE ID Type");
    }
    return ISAKMP_ID_INVALID;
}

//
// FUNCTION   :: ISAKMPGetTransformId
// LAYER      :: Network
// PURPOSE    :: To find doi specific transform identifier
// PARAMETERS :: strTransID - user configurued transform-id
// RETURN     :: unsigned char - transform identifier
// NOTE       ::

static
unsigned char ISAKMPGetTransformId(char*  strTransID)
{
    if (!strcmp(strTransID, "KEY_IKE"))
    {
        return IPSEC_KEY_IKE;
    }
    else if (!strcmp(strTransID, "AH_MD5"))
    {
        return IPSEC_AH_MD5;
    }
    else if (!strcmp(strTransID, "AH_SHA"))
    {
        return IPSEC_AH_SHA;
    }
    else if (!strcmp(strTransID, "AH_DES"))
    {
        return IPSEC_AH_DES;
    }
    else if (!strcmp(strTransID, "ESP_DES_IV64"))
    {
        return IPSEC_ESP_DES_IV64;
    }
    else if (!strcmp(strTransID, "ESP_DES"))
    {
        return IPSEC_ESP_DES;
    }
    else if (!strcmp(strTransID, "ESP_3DES"))
    {
        return IPSEC_ESP_3DES;
    }
    else if (!strcmp(strTransID, "ESP_RC5"))
    {
        return IPSEC_ESP_RC5;
    }
    else if (!strcmp(strTransID, "ESP_IDEA"))
    {
        return IPSEC_ESP_IDEA;
    }
    else if (!strcmp(strTransID, "ESP_CAST"))
    {
        return IPSEC_ESP_CAST;
    }
    else if (!strcmp(strTransID, "ESP_BLOWFISH"))
    {
        return IPSEC_ESP_BLOWFISH;
    }
    else if (!strcmp(strTransID, "ESP_3IDEA"))
    {
        return IPSEC_ESP_3IDEA;
    }
    else if (!strcmp(strTransID, "ESP_DES_IV32"))
    {
        return IPSEC_ESP_DES_IV32;
    }
    else if (!strcmp(strTransID, "ESP_RC4"))
    {
        return IPSEC_ESP_RC4;
    }
    else if (!strcmp(strTransID, "ESP_NULL"))
    {
        return IPSEC_ESP_NULL;
    }
    else
    {
        ERROR_ReportError("Unknown NODE ID Type");
    }
    return IPSEC_ESP_NULL;
}

//
// FUNCTION   :: IPsecGetHashAlgo
// LAYER      :: Network
// PURPOSE    :: To find hash algo from configured hash-algo value
// PARAMETERS :: char* hashAlgoStr - user configurued hash algo
// RETURN     :: ISAKMPHashAlgo - hash-algo
// NOTE       ::

static
ISAKMPHashAlgo IPsecGetHashAlgo(char* hashAlgoStr)
{
    if (!strcmp(hashAlgoStr, "MD5"))
    {
        return IPSEC_HASH_MD5;
    }
    else if (!strcmp(hashAlgoStr, "SHA"))
    {
        return IPSEC_HASH_SHA;
    }
    else if (!strcmp(hashAlgoStr, "TIGER"))
    {
        return IPSEC_HASH_TIGER;
    }
    else if (!strcmp(hashAlgoStr, "DEFAULT"))
    {
        return DEFAULT_HASH_ALGO;
    }
    else
    {
        ERROR_ReportError("Unknown hash algorithm");
    }
    return DEFAULT_HASH_ALGO;
}

#ifdef ISAKMP_SAVE_PHASE1
//
// FUNCTION   :: IPsecGetHashAlgoName
// LAYER      :: Network
// PURPOSE    :: Reverse function of IPsecGetHashAlgo
// PARAMETERS :: ISAKMPHashAlgo hashAlgo - hash algorithm
// RETURN     :: const char* - hash-algo name
// NOTE       ::

static
const char* IPsecGetHashAlgoName(ISAKMPHashAlgo hashAlgo)
{
    if (hashAlgo == IPSEC_HASH_MD5)
    {
        return "MD5";
    }
    else if (hashAlgo == IPSEC_HASH_SHA)
    {
        return "SHA";
    }
    else if (hashAlgo == IPSEC_HASH_TIGER)
    {
        return "TIGER";
    }
    ERROR_ReportError("Unknown hash algorithm");
    return NULL;
}
#endif //ISAKMP_SAVE_PHASE1


//
// FUNCTION   :: ISAKMPGetCertificateType
// LAYER      :: Network
// PURPOSE    :: To find which cerificate are set in configuration
// PARAMETERS :: char* certStr - user configured cert
// RETURN     :: ISAKMPCertType
// NOTE       ::

static
ISAKMPCertType ISAKMPGetCertificateType(char* certStr)
{
    if (!strcmp(certStr, "PKCS7"))
    {
        return ISAKMP_CERT_PKCS7;
    }
    else if (!strcmp(certStr, "PGP"))
    {
        return ISAKMP_CERT_PGP;
    }
    else if (!strcmp(certStr, "DNS_SIGNED"))
    {
        return ISAKMP_CERT_DNS_SIGNED;
    }
    else if (!strcmp(certStr, "X509_SIG"))
    {
        return ISAKMP_CERT_X509_SIG;
    }
    else if (!strcmp(certStr, "X509_KEYEX"))
    {
        return ISAKMP_CERT_X509_KEYEX ;
    }
    else if (!strcmp(certStr, "KERBEROS"))
    {
        return ISAKMP_CERT_KERBEROS ;
    }
    else if (!strcmp(certStr, "CRL"))
    {
        return ISAKMP_CERT_CRL;
    }
    else if (!strcmp(certStr, "ARL"))
    {
        return ISAKMP_CERT_ARL;
    }
    else if (!strcmp(certStr, "SPKI"))
    {
        return ISAKMP_CERT_SPKI;
    }
    else if (!strcmp(certStr, "X509_ATTRI"))
    {
        return ISAKMP_CERT_X509_ATTRI;
    }
    else if (!strcmp(certStr, "NONE"))
    {
        return ISAKMP_CERT_NONE;
    }
    else
    {
        ERROR_ReportError("Unknown Certificate Type");
    }
    return ISAKMP_CERT_NONE;
}


//
// FUNCTION   :: IPsecGetAuthMethod
// LAYER      :: Network
// PURPOSE    :: To find Auth MEthod from configured auth method value
// PARAMETERS :: char* authMethStr - user configurued authention method
// RETURN     :: ISAKMPAuthMethod - Auth MEthod
// NOTE       ::

static
ISAKMPAuthMethod IPsecGetAuthMethod(char* authMethStr)
{
    if (!strcmp(authMethStr, "PRE_SHARED"))
    {
        return PRE_SHARED;
    }
    else if (!strcmp(authMethStr, "DSS_SIG"))
    {
        return DSS_SIG;
    }
    else if (!strcmp(authMethStr, "RSA_SIG"))
    {
        return RSA_SIG;
    }
    if (!strcmp(authMethStr, "RSA_ENCRYPT"))
    {
        return RSA_ENCRYPT;
    }
    if (!strcmp(authMethStr, "REVISED_RSA_ENCRYPT"))
    {
        return REVISED_RSA_ENCRYPT;
    }
    else if (!strcmp(authMethStr, "DEFAULT"))
    {
        return DEFAULT_AUTH_METHOD;
    }
    else
    {
        ERROR_ReportError("Unknown authentication method");
    }
    return DEFAULT_AUTH_METHOD;
}

#ifdef ISAKMP_SAVE_PHASE1
//
// FUNCTION   :: IPsecGetAuthMethodName
// LAYER      :: Network
// PURPOSE    :: Reverse function of IPsecGetAuthMethod
// PARAMETERS :: ISAKMPAuthMethod authmethod - auth method
// RETURN     :: const char* - Auth Method name
// NOTE       ::

static
const char* IPsecGetAuthMethodName(ISAKMPAuthMethod authmethod)
{
    if (authmethod == PRE_SHARED)
    {
        return "PRE_SHARED";
    }
    else if (authmethod == DSS_SIG)
    {
        return "DSS_SIG";
    }
    else if (authmethod == RSA_SIG)
    {
        return "RSA_SIG";
    }
    else if (authmethod == RSA_ENCRYPT)
    {
        return "RSA_ENCRYPT";
    }
    else if (authmethod == REVISED_RSA_ENCRYPT)
    {
        return "REVISED_RSA_ENCRYPT";
    }
    ERROR_ReportError("Unknown authentication method");
    return NULL;
}
#endif //ISAKMP_SAVE_PHASE1

//
// FUNCTION   :: ISAKMPGetGrpDesc
// LAYER      :: Network
// PURPOSE    :: To find Group Description from configured Group Desc value
// PARAMETERS :: char* groupdes - user configurued group description
// RETURN     :: ISAKMPGrpDesc - Group Description
// NOTE       ::

static
ISAKMPGrpDesc ISAKMPGetGrpDesc(char* groupdes)
{
    if (!strcmp(groupdes, "MODP_768"))
    {
        return MODP_768;
    }
    else if (!strcmp(groupdes, "MODP_1024"))
    {
        return MODP_1024;
    }
    else if (!strcmp(groupdes, "EC2N_155"))
    {
        return EC2N_155;
    }
    else if (!strcmp(groupdes, "EC2N_185"))
    {
        return EC2N_185;
    }
    else if (!strcmp(groupdes, "DEFAULT"))
    {
        return DEFAULT_GROUP_DESCRIPTION;
    }
    else
    {
        ERROR_ReportError("Unknown group description");
    }
    return DEFAULT_GROUP_DESCRIPTION;
}

#ifdef ISAKMP_SAVE_PHASE1
//
// FUNCTION   :: ISAKMPGetGrpDescName
// LAYER      :: Network
// PURPOSE    :: Reverse function of ISAKMPGetGrpDesc
// PARAMETERS :: ISAKMPGrpDesc grpdesc - group description
// RETURN     :: const char* - Group Description name
// NOTE       ::

static
const char* ISAKMPGetGrpDescName(ISAKMPGrpDesc grpdesc)
{
    if (grpdesc == MODP_1024)
    {
        return "MODP_1024";
    }
    else if (grpdesc == MODP_768)
    {
        return "MODP_768";
    }
    else if (grpdesc == EC2N_155)
    {
        return "EC2N_155";
    }
    else if (grpdesc == EC2N_185)
    {
        return "EC2N_185";
    }
    ERROR_ReportError("Unknown group description");
    return NULL;
}
#endif //ISAKMP_SAVE_PHASE1

//
// FUNCTION   :: IPsecGetDOI
// LAYER      :: Network
// PURPOSE    :: to find the DOI for given DOI string
// PARAMETERS :: char* doiStr - user configurued doi
// RETURN     :: DOI - domain of interpretation
// NOTE       ::

static
DOI IPsecGetDOI(char* doiStr)
{
    if (!strcmp(doiStr, "ISAKMP_DOI"))
    {
        return ISAKMP_DOI;
    }
    else if (!strcmp(doiStr, "IPSEC_DOI"))
    {
        return IPSEC_DOI;
    }
    else
    {
        ERROR_ReportError("Unknown DOI");
    }
    return INVALID_DOI;
}

#ifdef ISAKMP_SAVE_PHASE1
//
// FUNCTION   :: IPsecGetDOIName
// LAYER      :: Network
// PURPOSE    :: Reverse function of IPsecGetDOI
// PARAMETERS :: UInt32 doi
// RETURN     :: DOI string for given DOI
// NOTE       ::

static
const char* IPsecGetDOIName(UInt32 doi)
{
    if (doi == ISAKMP_DOI)
    {
        return "ISAKMP_DOI";
    }
    else if (doi == IPSEC_DOI)
    {
        return "IPSEC_DOI";
    }
    ERROR_ReportError("Unknown DOI");
    return NULL;
}
#endif //ISAKMP_SAVE_PHASE1

//
// FUNCTION   :: ISAKMPGetExchType
// LAYER      :: Network
// PURPOSE    :: To find Ecchange type from configured Ecchange type value
// PARAMETERS :: char* exchStr - user configured exchange type
//               int phaseType - negotiation phase type
// RETURN     :: unsigned char - Exchange type
// NOTE       ::

static
unsigned char ISAKMPGetExchType(char*  exchStr, int phaseType)
{
    if (!strcmp(exchStr, "EXCH_BASE"))
    {
        return ISAKMP_ETYPE_BASE;
    }
    else if (!strcmp(exchStr, "EXCH_IDENT"))
    {
        return ISAKMP_ETYPE_IDENT;
    }
    else if (!strcmp(exchStr, "EXCH_AUTH"))
    {
        return ISAKMP_ETYPE_AUTH;
    }
    else if (!strcmp(exchStr, "EXCH_AGGR"))
    {
        return ISAKMP_ETYPE_AGG;
    }
    else if (!strcmp(exchStr, "EXCH_INFO"))
    {
        return ISAKMP_ETYPE_INF;
    }
    else if (!strcmp(exchStr, "EXCH_MAIN_PRE_SHARED")
             && phaseType == PHASE_1)
    {
        return ISAKMP_IKE_ETYPE_MAIN_PRE_SHARED;
    }
    else if (!strcmp(exchStr, "EXCH_MAIN_DIG_SIG")
             && phaseType == PHASE_1)
    {
        return ISAKMP_IKE_ETYPE_MAIN_DIG_SIG;
    }
    else if (!strcmp(exchStr, "EXCH_MAIN_PUB_KEY")
             && phaseType == PHASE_1)
    {
        return ISAKMP_IKE_ETYPE_MAIN_PUB_KEY;
    }
    else if (!strcmp(exchStr, "EXCH_MAIN_REV_PUB_KEY")
             && phaseType == PHASE_1)
    {
        return ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY;
    }
    else if (!strcmp(exchStr, "EXCH_AGG_PRE_SHARED")
             && phaseType == PHASE_1)
    {
        return ISAKMP_IKE_ETYPE_AGG_PRE_SHARED;
    }
    else if (!strcmp(exchStr, "EXCH_AGG_DIG_SIG")
             && phaseType == PHASE_1)
    {
        return ISAKMP_IKE_ETYPE_AGG_DIG_SIG;
    }
    else if (!strcmp(exchStr, "EXCH_AGG_PUB_KEY")
             && phaseType == PHASE_1)
    {
        return ISAKMP_IKE_ETYPE_AGG_PUB_KEY;
    }
    else if (!strcmp(exchStr, "EXCH_AGG_REV_PUB_KEY")
             && phaseType == PHASE_1)
    {
        return ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY;
    }
    else if (!strcmp(exchStr, "EXCH_QUICK")
             && phaseType == PHASE_2)
    {
        return ISAKMP_IKE_ETYPE_QUICK;
    }
    else if (!strcmp(exchStr, "EXCH_NEW_GROUP")
             && phaseType == PHASE_1)
    {
        return ISAKMP_IKE_ETYPE_NEW_GROUP;
    }
    else
    {
        ERROR_ReportError("Unknown Exchange Type");
    }
    return ISAKMP_ETYPE_NONE;
}

//
// FUNCTION   :: ISAKMPGetExchFuncList
// LAYER      :: Network
// PURPOSE    :: To find the exchange scenario(list of functions)
//               for given exchange type for initiator or responder
// PARAMETERS :: unsigned char exchType - exchange type
//               UInt32 initiator -  initiator or responder
// RETURN     :: exchange Functions list
// NOTE       ::

static
IsakmpFunList ISAKMPGetExchFuncList(unsigned char exchType, UInt32 initiator)
{
    if (exchType == ISAKMP_ETYPE_IDENT)
    {
        return &isakmp_idprot_func[initiator];
    }
    else if (exchType == ISAKMP_ETYPE_BASE)
    {
        return &isakmp_base_func[initiator];
    }
    else if (exchType == ISAKMP_ETYPE_AUTH)
    {
        return &isakmp_auth_only_func[initiator];
    }
    else if (exchType == ISAKMP_ETYPE_AGG)
    {
        return &isakmp_aggresive_func[initiator];
    }
    else if (exchType == ISAKMP_IKE_ETYPE_MAIN_PRE_SHARED)
    {
        return &isakmp_ikeMainPreShared_func[initiator];
    }
    else if (exchType == ISAKMP_IKE_ETYPE_MAIN_DIG_SIG)
    {
        return &isakmp_ikeMainDigSig_func[initiator];
    }
    else if (exchType == ISAKMP_IKE_ETYPE_MAIN_PUB_KEY)
    {
        return &isakmp_ikeMainPubKey_func[initiator];
    }
    else if (exchType == ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY)
    {
        return &isakmp_ikeMainRevPubKey_func[initiator];
    }
    else if (exchType == ISAKMP_IKE_ETYPE_AGG_PRE_SHARED)
    {
        return &isakmp_ikeAggPreShared_func[initiator];
    }
    else if (exchType == ISAKMP_IKE_ETYPE_AGG_DIG_SIG)
    {
        return &isakmp_ikeAggDigSig_func[initiator];
    }
    else if (exchType == ISAKMP_IKE_ETYPE_AGG_PUB_KEY)
    {
        return &isakmp_ikeAggPubKey_func[initiator];
    }
    else if (exchType == ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY)
    {
        return &isakmp_ikeAggRevPubKey_func[initiator];
    }
    else if (exchType == ISAKMP_IKE_ETYPE_QUICK)
    {
        return &isakmp_ikeQuick_func[initiator];
    }
    else if (exchType == ISAKMP_IKE_ETYPE_NEW_GROUP)
    {
        return &isakmp_ikeNewGroup_func[initiator];
    }
    else
    {
        ERROR_ReportError("Unknown Exchange Type");
    }
    return NULL;
}



//
// FUNCTION   :: IsIKEExchange
// LAYER      :: Network
// PURPOSE    :: check whether exchange type is an IKE exchange
// PARAMETERS :: unsigned char exchType - exchange type received
// RETURN     :: BOOL
// NOTE       ::

BOOL IsIKEExchange(unsigned char exchType)
{
    switch (exchType)
    {
        case ISAKMP_IKE_ETYPE_MAIN_PRE_SHARED:
        case ISAKMP_IKE_ETYPE_MAIN_DIG_SIG:
        case ISAKMP_IKE_ETYPE_MAIN_PUB_KEY:
        case ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY:
        case ISAKMP_IKE_ETYPE_AGG_PRE_SHARED:
        case ISAKMP_IKE_ETYPE_AGG_DIG_SIG:
        case ISAKMP_IKE_ETYPE_AGG_PUB_KEY:
        case ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY:
        case ISAKMP_IKE_ETYPE_QUICK:
        case ISAKMP_IKE_ETYPE_NEW_GROUP:
            return TRUE;
        default:
            return FALSE;
    }
}



//
// FUNCTION   :: IsPhase1IKEExchange
// LAYER      :: Network
// PURPOSE    :: check whether exchange type is Phase 1 IKE exchange
// PARAMETERS :: unsigned char exchType - exchange type received
// RETURN     :: BOOL
// NOTE       ::

BOOL IsPhase1IKEExchange(unsigned char exchType)
{
    switch (exchType)
    {
        case ISAKMP_IKE_ETYPE_MAIN_PRE_SHARED:
        case ISAKMP_IKE_ETYPE_MAIN_DIG_SIG:
        case ISAKMP_IKE_ETYPE_MAIN_PUB_KEY:
        case ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY:
        case ISAKMP_IKE_ETYPE_AGG_PRE_SHARED:
        case ISAKMP_IKE_ETYPE_AGG_DIG_SIG:
        case ISAKMP_IKE_ETYPE_AGG_PUB_KEY:
        case ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY:
            return TRUE;
        default:
            return FALSE;
    }
}



//
// FUNCTION   :: ISAKMPGetProcessDelay
// LAYER      :: Network
// PURPOSE    :: To get the process delay for encryption
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
// RETURN     :: clocktype
// NOTE       ::

clocktype ISAKMPGetProcessDelay(Node* node,
                                ISAKMPNodeConf* nodeconfig)
{
    UInt16 i = 0;
    clocktype delay = 0;

    ISAKMPExchange* exch = nodeconfig->exchange;
    ISAKMPPhase1 * phase1 = nodeconfig->phase1;

    if (phase1->isakmp_sa
        && (exch == NULL || exch->phase1_trans_no_selected <= 0))
    {
        delay = phase1->isakmp_sa->processdelay;
        return delay;
    }

    //search in all the transform available
    for (i = 0; i < phase1->numofTransforms; i++)
    {
        //if selected transform found, access processdelay
        if ((exch->phase1_trans_no_selected - 1) == i)
        {
            delay = phase1->transform[i]->processdelay;
            return delay;
        }
    }
    return delay;
}




//
// FUNCTION   :: ISAKMPGetNodeConfig
// LAYER      :: Network
// PURPOSE    :: Get NodeConfig for given source and destination ip address
// PARAMETERS :: Node*  - node information
//               NodeAddress node ip-Address
//               NodeAddress peer ip-Address
// RETURN     :: ISAKMPNodeConf*
// NOTE       ::

ISAKMPNodeConf* ISAKMPGetNodeConfig(Node* node,
                                    NodeAddress source,
                                    NodeAddress dest)
{
    UInt32 interfaceIndex =
        (UInt32) NetworkIpGetInterfaceIndexFromAddress(node, source);

    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;

    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];

    if (interfaceInfo->isISAKMPEnabled == FALSE)
    {
        return NULL;
    }

    ISAKMPNodeConf* &nodeconfig = interfaceInfo->isakmpdata->nodeConfData;
    ISAKMPNodeConf* commonConfData =
        interfaceInfo->isakmpdata->commonConfData;

    if (nodeconfig == NULL)
    {
        // read wild-card config
        if (commonConfData != NULL)
        {
            nodeconfig = (ISAKMPNodeConf*)MEM_malloc(sizeof(ISAKMPNodeConf));
            memcpy(nodeconfig, commonConfData, sizeof(ISAKMPNodeConf));

            nodeconfig->phase1 =
                (ISAKMPPhase1*)MEM_malloc(sizeof(ISAKMPPhase1));

            memcpy(nodeconfig->phase1,
                commonConfData->phase1, sizeof(ISAKMPPhase1));

            //There is only one Phase-2 config in Wild-card Feature
            nodeconfig->phase2_list =
                (ISAKMPPhase2List*)MEM_malloc(sizeof(ISAKMPPhase2List));

            nodeconfig->phase2_list->is_ipsec_sa = FALSE;
            nodeconfig->phase2_list->next = NULL;

            nodeconfig->phase2_list->phase2 =
                (ISAKMPPhase2*)MEM_malloc(sizeof(ISAKMPPhase2));

            memcpy(nodeconfig->phase2_list->phase2,
                commonConfData->phase2_list->phase2, sizeof(ISAKMPPhase2));

            nodeconfig->nodeAddress = source;
            nodeconfig->peerAddress = dest;
            nodeconfig->link = NULL;
            return nodeconfig;
        }
    }
    else
    {
        ISAKMPNodeConf* current = nodeconfig;
        ISAKMPNodeConf* prev = NULL;

        //look for isakmp configuration info for this destination
        while (current && current->peerAddress != dest)
        {
            prev = current;
            current = current->link;
        }
        if (current == NULL)
        {
            // read wild-card config
            if (commonConfData != NULL)
            {
                current = (ISAKMPNodeConf*)MEM_malloc(
                    sizeof(ISAKMPNodeConf));
                memcpy(current, commonConfData, sizeof(ISAKMPNodeConf));

                current->phase1 =
                (ISAKMPPhase1*)MEM_malloc(sizeof(ISAKMPPhase1));

                memcpy(current->phase1,
                    commonConfData->phase1, sizeof(ISAKMPPhase1));

                //There is only one Phase-2 config in Wild-card Feature
                current->phase2_list =
                    (ISAKMPPhase2List*)MEM_malloc(sizeof(ISAKMPPhase2List));

                current->phase2_list->is_ipsec_sa = FALSE;
                current->phase2_list->next = NULL;

                current->phase2_list->phase2 =
                (ISAKMPPhase2*)MEM_malloc(sizeof(ISAKMPPhase2));

                memcpy(current->phase2_list->phase2,
                commonConfData->phase2_list->phase2, sizeof(ISAKMPPhase2));

                current->nodeAddress = source;
                current->peerAddress = dest;
                current->link = NULL;
                prev->link = current;
            }
        }
        return current;
    }
    return NULL;
}

//
// FUNCTION   :: ISAKMPReadPhase1Transforms
// LAYER      :: Network
// PURPOSE    :: To Read Phase-1 transforms from configuration file
// PARAMETERS :: const NodeInput* - isakmp configuration information
//               ISAKMPPhase1TranList* - reference phase-1 transform list
//               Int32 *j - line number in isakmp configuration file
// RETURN     :: void
// NOTE       ::

static
void ISAKMPReadPhase1Transforms(const NodeInput* isakmpConf,
                                ISAKMPPhase1TranList* &ph1_trans_list,
                                Int32 *j)
{
    Int32 i = *j;
    const char* currentLine;
    char        paramStr[MAX_STRING_LENGTH] = {0};
    char        valueStr[MAX_STRING_LENGTH] = {0};

    ISAKMPPhase1TranList* prev;
    ISAKMPPhase1TranList* temp;

    currentLine = isakmpConf->inputStrings[i];
    sscanf(currentLine, "%s", paramStr);

    // search for the "Phase-1-Transforms" parameter
    while (strcmp(paramStr, "Phase-1-Transforms")
        && i < isakmpConf->numLines-1)
    {
        i++;
        currentLine = isakmpConf->inputStrings[i];
        sscanf(currentLine, "%s", paramStr);
    }

    if (!strcmp(paramStr, "Phase-1-Transforms"))
    {
        i++;
        currentLine = isakmpConf->inputStrings[i];
        sscanf(currentLine, "%s%s", paramStr, valueStr);

        //read first Transform
        if (!strcmp(paramStr, "TRANSFORM_NAME"))
        {
            ph1_trans_list = (ISAKMPPhase1TranList*)MEM_malloc(
                sizeof(ISAKMPPhase1TranList));

            memset(ph1_trans_list, 0, sizeof(ISAKMPPhase1TranList));

            ph1_trans_list->next = NULL;
            prev = ph1_trans_list;
            temp = ph1_trans_list;
            strcpy(temp->transform.transformName, valueStr);

            //assigning default processing delay and cert type
            temp->transform.processdelay = DEFAULT_PROCESSING_DELAY;
            temp->transform.certType = ISAKMP_CERT_NONE;

           while (i < isakmpConf->numLines-1)
           {
               i++;
               currentLine = isakmpConf->inputStrings[i];
               sscanf(currentLine, "%s%s", paramStr, valueStr);

               if (!strcmp(paramStr, "TRANSFORM_ID"))
               {
                   temp->transform.transformId =
                                              ISAKMPGetTransformId(valueStr);
               }
               else if (!strcmp(paramStr, "ENCRYPTION_ALGORITHM"))
               {
                   temp->transform.encryalgo =
                       IPsecGetEncryptionAlgo(valueStr);
               }
               else if (!strcmp(paramStr, "HASH_ALGORITHM"))
               {
                   temp->transform.hashalgo = IPsecGetHashAlgo(valueStr);
               }
               else if (!strcmp(paramStr, "CERTIFICATION_TYPE"))
               {
                   temp->transform.certType =
                                          ISAKMPGetCertificateType(valueStr);
               }
               else if (!strcmp(paramStr, "AUTHENTICATION_METHOD"))
               {
                   temp->transform.authmethod = IPsecGetAuthMethod(valueStr);
               }
               else if (!strcmp(paramStr, "GROUP_DESCRIPTION"))
               {
                   temp->transform.groupdes = ISAKMPGetGrpDesc(valueStr);
               }
               else if (!strcmp(paramStr, "PROCESSING_DELAY"))
               {
                   temp->transform.processdelay = TIME_ConvertToClock(
                                                                   valueStr);
                   if (temp->transform.processdelay < 0)
                   {
                        char errStr[MAX_STRING_LENGTH];
                        sprintf(errStr, "Positive delay value is expected"
                                  " for transform %s\n",
                                  temp->transform.transformName);
                        ERROR_Assert(FALSE,errStr);
                   }
               }
               else if (!strcmp(paramStr, "LIFE"))
               {
                   if (!strcmp(valueStr, "0"))
                   {
                       ERROR_ReportError("phase1 LIFE should not be zero");
                   }

                   temp->transform.life = (UInt16)atoi(valueStr);

                   if (temp->transform.life == 0)
                   {
                       temp->transform.life =
                                           DEFAULT_PHASE1_TRANSFORM_LIFETIME;
                   }
               }
               //read more Transforms
               else if (!strcmp(paramStr, "TRANSFORM_NAME"))
               {
                   temp = (ISAKMPPhase1TranList*) MEM_malloc(
                           sizeof(ISAKMPPhase1TranList));
                   memset(temp, 0, sizeof(ISAKMPPhase1TranList));
                   temp->next = NULL;
                   prev->next = temp;
                   prev = temp;
                   strcpy(temp->transform.transformName, valueStr);

                   //assigning default processing delay and cert type
                   temp->transform.processdelay = DEFAULT_PROCESSING_DELAY;
                   temp->transform.certType = ISAKMP_CERT_NONE;
               }
               else
               {
                  break;
               }
           }
        }
        else
        {
           ERROR_ReportError("information for [Phase-1-Transforms] missing");
        }

    *j = i;
    }
}

//
// FUNCTION   :: ISAKMPReadPhase2Transforms
// LAYER      :: Network
// PURPOSE    :: To Read Phase-2 transforms from configuration file
// PARAMETERS :: const NodeInput* - isakmp configuration information
//               ISAKMPPhase2TranList* - reference phase-2 transform list
//               Int32 *j - line number in isakmp configuration file
// RETURN     :: void
// NOTE       ::


static
void ISAKMPReadPhase2Transforms(const NodeInput* isakmpConf,
                                ISAKMPPhase2TranList* &ph2_trans_list,
                                Int32* j)
{
    Int32 i = *j;
    const char*                currentLine;
    char                       paramStr[MAX_STRING_LENGTH] = {0};
    char                       valueStr[MAX_STRING_LENGTH] = {0};

    ISAKMPPhase2TranList*   prev = NULL;
    ISAKMPPhase2TranList*   temp = NULL;

    currentLine = isakmpConf->inputStrings[i];
    sscanf(currentLine, "%s", paramStr);

    while (strcmp(paramStr, "Phase-2-Transforms") &&
        i < isakmpConf->numLines-1)
    {
        i++;
        currentLine = isakmpConf->inputStrings[i];
        sscanf(currentLine, "%s", paramStr);
    }

    if (!strcmp(paramStr, "Phase-2-Transforms"))
    {
        i++;
        currentLine = isakmpConf->inputStrings[i];
        sscanf(currentLine, "%s%s", paramStr, valueStr);

        //read first Transforms
        if (!strcmp(paramStr, "TRANSFORM_NAME"))
        {
            ph2_trans_list = (ISAKMPPhase2TranList*)MEM_malloc(
                sizeof(ISAKMPPhase2TranList));
            memset(ph2_trans_list, 0, sizeof(ISAKMPPhase2TranList));
            ph2_trans_list->next = NULL;
            prev = ph2_trans_list;
            temp = ph2_trans_list;
            strcpy(temp->transform.transformName, valueStr);

           while (i < isakmpConf->numLines-1)
           {
               i++;
               currentLine = isakmpConf->inputStrings[i];
               sscanf(currentLine, "%s%s", paramStr, valueStr);

               if (!strcmp(paramStr, "TRANSFORM_ID"))
               {
                   temp->transform.transformId =
                                              ISAKMPGetTransformId(valueStr);
               }
               else if (!strcmp(paramStr, "ENCAPSULATION_MODE"))
               {
                   temp->transform.mode = IPsecGetMode(valueStr);
               }
               else if (!strcmp(paramStr, "GROUP_DESCRIPTION"))
               {
                   temp->transform.groupdes = ISAKMPGetGrpDesc(valueStr);
               }
               else if (!strcmp(paramStr, "AUTHENTICATION_ALGORITHM"))
               {
                   temp->transform.authalgo =
                                        IPsecGetAuthenticationAlgo(valueStr);
               }
               else if (!strcmp(paramStr, "LIFE"))
               {
                   if (!strcmp(valueStr, "0"))
                   {
                       ERROR_ReportError("phase2 LIFE should not be zero");
                   }

                   temp->transform.life = (UInt16)atoi(valueStr);

                   if (temp->transform.life == 0)
                   {
                       temp->transform.life =
                           DEFAULT_PHASE2_TRANSFORM_LIFETIME;
                   }
               }
               //read more Transforms
               else if (!strcmp(paramStr, "TRANSFORM_NAME"))
               {
                   temp = (ISAKMPPhase2TranList*) MEM_malloc(
                           sizeof(ISAKMPPhase2TranList));
                   memset(temp, 0, sizeof(ISAKMPPhase2TranList));
                   temp->next = NULL;
                   prev->next = temp;
                   prev = temp;
                   strcpy(temp->transform.transformName, valueStr);
               }
               else
               {
                  break;
               }
           }
        }
        else
        {
            ERROR_ReportError("info under [Phase-2-Transforms] missing");
        }
    *j = i;
    }
}

//
// FUNCTION   :: ISAKMPReadPhase1Config
// LAYER      :: Network
// PURPOSE    :: To Read Phase-1 configuration for node-peer from config file
// PARAMETERS :: Node* node
//               const NodeInput* - isakmp configuration information
//               ISAKMPPhase1* - reference phase-1 information
//               UInt32 interfaceIndex - interface Index
//               Int32 *j - line number in isakmp configuration file
// RETURN     :: void
// NOTE          ::

static
void ISAKMPReadPhase1Config(Node* node,
                            const NodeInput* isakmpConf,
                            ISAKMPPhase1* &phase1,
                            UInt32 interfaceIndex,
                            Int32 *j)
{
    Int32 i = *j + 1;
    const char*  currentLine = isakmpConf->inputStrings[i];
    char         paramStr[MAX_STRING_LENGTH] = {0};
    char         valueStr[MAX_STRING_LENGTH] = {0};
    UInt32       phase;
    char*        next = NULL;
    char*        transformName = NULL;

    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];
    ISAKMPPhase1TranList* &ph1_trans_list =
        interfaceInfo->isakmpdata->ph1_trans_list;

    sscanf(currentLine, "%s%u", paramStr, &phase);

    //read phase1 configuration parameters
    //All parameters are necessary and should be specified in given order.

    if (!strcmp(paramStr, "PHASE") && phase == PHASE_1)
    {
        phase1 = (ISAKMPPhase1*) MEM_malloc(sizeof(ISAKMPPhase1));
        memset(phase1, 0, sizeof(ISAKMPPhase1));
        i++;
        currentLine = isakmpConf->inputStrings[i];
        sscanf(currentLine, "%s%s", paramStr, valueStr);

        if (!strcmp(paramStr, "DOI"))
        {
            phase1->doi = IPsecGetDOI(valueStr);
            i++;
            currentLine = isakmpConf->inputStrings[i];
            sscanf(currentLine, "%s%s", paramStr, valueStr);
        }
        else
        {
            ERROR_Assert(FALSE, "Phase 1 DOI Parameter missing");
        }
        if (!strcmp(paramStr,"EXCHANGE_TYPE"))
        {
            phase1->exchtype = ISAKMPGetExchType(valueStr, PHASE_1);

            if (phase1->exchtype == ISAKMP_IKE_ETYPE_NEW_GROUP
                || phase1->exchtype == ISAKMP_IKE_ETYPE_QUICK)
            {
                ERROR_Assert(FALSE, "Wrong Phase 1 EXCHANGE_TYPE defined");
            }

            i++;
            currentLine = isakmpConf->inputStrings[i];
            sscanf(currentLine, "%s%s", paramStr, valueStr);
        }
        else
        {
            ERROR_Assert(FALSE, "Phase 1 EXCHANGE_TYPE Parameter missing");
        }
        if (!strcmp(paramStr, "FLAGS"))
        {
            phase1->flags = ISAKMPGetFlags(valueStr);
            i++;
            currentLine = isakmpConf->inputStrings[i];
            IO_GetDelimitedToken(paramStr, currentLine, " ", &next);
        }
        else
        {
            ERROR_Assert(FALSE, "Phase 1 FLAGS Parameter missing");
        }
        if (!strcmp(paramStr, "CERTIFICATE_ENABLED"))
        {
            sscanf(currentLine, "%s%s", paramStr, valueStr);
            if (!strcmp(valueStr, "YES"))
            {
                phase1->isCertEnabled = TRUE;
            }
            else if (!strcmp(valueStr, "NO"))
            {
                phase1->isCertEnabled = FALSE;
            }
            else
            {
                char errStr[MAX_STRING_LENGTH];
                sprintf(errStr, "Invalid value for CERTIFICATE_ENABLED."
                            " Continue with the default value: NO \n");
                ERROR_ReportWarning(errStr);
                //assign default value
                phase1->isCertEnabled = DEFAULT_CERT_ENABLED;
            }
            i++;
            currentLine = isakmpConf->inputStrings[i];
            IO_GetDelimitedToken(paramStr, currentLine, " ", &next);
        }
        else
        {
            // assign default value
            phase1->isCertEnabled = DEFAULT_CERT_ENABLED;
        }
        if (!strcmp(paramStr, "NEW_GROUP_MODE_ENABLED"))
        {
            //scan the configured values
            sscanf(currentLine, "%s%s", paramStr, valueStr);
            if (!strcmp(valueStr, "YES"))
            {
                //first check for IKE exchange
                if (!IsPhase1IKEExchange(phase1->exchtype))
                {
                    char errStr[MAX_STRING_LENGTH];
                    sprintf(errStr, "IKE New Group Mode can be enabled with"
                                " IKE Phase 1 exchanges only\n");
                    ERROR_ReportError(errStr);
                }
                phase1->isNewGroupModeEnabled = TRUE;
            }
            else if (!strcmp(valueStr, "NO"))
            {
                phase1->isNewGroupModeEnabled = FALSE;
            }
            else
            {
                char errStr[MAX_STRING_LENGTH];
                sprintf(errStr, "Invalid value for NEW_GROUP_MODE_ENABLED."
                            " Continue with the default value: NO \n");
                ERROR_ReportWarning(errStr);
                //assign default value
                phase1->isNewGroupModeEnabled = DEFAULT_NEW_GROUP_ENABLED;
            }
            i++;
            currentLine = isakmpConf->inputStrings[i];
            IO_GetDelimitedToken(paramStr, currentLine, " ", &next);
        }
        else
        {
            // assign default value
            phase1->isNewGroupModeEnabled = DEFAULT_NEW_GROUP_ENABLED;
        }
        if (!strcmp(paramStr, "TRANSFORMS"))
        {
            UInt32  k = 0;
            transformName = (char*) MEM_malloc(MAX_TRANSFORM_NAME_LEN);
            while ((transformName = IO_GetDelimitedToken(transformName,
                                                next, " ", &next)) != NULL)
            {
                ISAKMPPhase1Transform* getPhase1Transfrom =
                                    ISAKMPGetPhase1Transform(ph1_trans_list,
                                                             transformName);
                if (IsPhase1IKEExchange(phase1->exchtype)
                    && getPhase1Transfrom->transformId != IPSEC_KEY_IKE)
                {
                    char errStr[MAX_STRING_LENGTH];
                    sprintf(errStr, "Transform ID KEY_IKE is required for"
                                " the defined exchange type of Phase 1\n");
                    ERROR_ReportError(errStr);
                }

                phase1->transform[k++] = getPhase1Transfrom;
                phase1->numofTransforms++;
            }
        }
        else
        {
            ERROR_Assert(FALSE, "Phase 1 TRANSFORMS Parameter missing");
        }
    }
    else
    {
        ERROR_Assert(FALSE, "Phase 1 configuration information is missing"
            "in .isakmp file");
    }
    *j = i;
    MEM_free(transformName);
}

//
// FUNCTION   :: ISAKMPReadProtocol
// LAYER      :: Network
// PURPOSE    :: To Read Protocol specific configuration  from config file
// PARAMETERS :: Node* node
//               const NodeInput* - isakmp configuration information
//               ISAKMPProtocol* - reference protocol information
//               char* protocolID - protocol identifier
//               UInt32 interfaceIndex - interface Index
//               Int32 i - line number in isakmp configuration file
// RETURN     :: void
// NOTE       ::

static
void ISAKMPReadProtocol(Node* node,
                        const NodeInput* isakmpConf,
                        ISAKMPProtocol* &protocol,
                        char* protocolID,
                        UInt32 interfaceIndex,
                        Int32 i)
{
    const char* currentLine;
    char        paramStr[MAX_STRING_LENGTH] = {0};
    char        valueStr[MAX_STRING_LENGTH] = {0};
    char*       next = NULL;
    char*       transformName = NULL;
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];
    ISAKMPPhase2TranList* &ph2_trans_list =
        interfaceInfo->isakmpdata->ph2_trans_list;

    currentLine = isakmpConf->inputStrings[i];
    sscanf(currentLine, "%s", paramStr);

    while (strcmp(paramStr,protocolID) && i < isakmpConf->numLines-1)
    {
        i++;
        currentLine = isakmpConf->inputStrings[i];
        sscanf(currentLine, "%s", paramStr);
    }

    //read configuration for a Given Protocol under PROTOCOLS parameter
    if (!strcmp(paramStr, protocolID))
    {
        i++;
        currentLine = isakmpConf->inputStrings[i];
        sscanf(currentLine, "%s%s", paramStr, valueStr);

        if (!strcmp(paramStr, "PROTOCOL_ID"))
        {
            protocol->protocolId = IPsecGetSecurityProtocol(valueStr);
            i++;
            currentLine = isakmpConf->inputStrings[i];
            IO_GetDelimitedToken(paramStr, currentLine, " ", &next);

        }
        else
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr, "PROTOCOL_ID param missing for %s: \n",
                protocolID);
            ERROR_Assert(FALSE, errStr);
        }
        if (!strcmp(paramStr, "TRANSFORMS"))
        {
            UInt32  k = 0;
            transformName = (char*) MEM_malloc(MAX_TRANSFORM_NAME_LEN);

            //read configuration for all the transform specified
            while ((transformName =
              IO_GetDelimitedToken(transformName, next, " ", &next)) != NULL)
            {
                protocol->transform[k++] = ISAKMPGetPhase2Transform(
                                              ph2_trans_list, transformName);
                protocol->numofTransforms++;
            }
        }
        else
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr, "TRANSFORMS param missing for %s: \n",
                protocolID);
            ERROR_Assert(FALSE, errStr);
        }
        MEM_free(transformName);
    }
    else
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "Configuration for protocol %s: missing\n",
            protocolID);
        ERROR_Assert(FALSE, errStr);
    }
}

//
// FUNCTION   :: ISAKMPReadProposal
// LAYER      :: Network
// PURPOSE    :: To Read a Proposal from configuration file
// PARAMETERS :: Node* node
//               const NodeInput* - isakmp configuration information
//               ISAKMPProposal* - reference protocol information
//               char* proposalID - proposal identifier
//               UInt32 interfaceIndex - interface Index
//               Int32 i - line number in isakmp configuration file
// RETURN     :: void
// NOTE       ::

static
void ISAKMPReadProposal(Node* node,
                        const NodeInput* isakmpConf,
                        ISAKMPProposal* &proposal,
                        char* proposalID,
                        UInt32 interfaceIndex,
                        Int32 i)
{
    const char*  currentLine;
    char         paramStr[MAX_STRING_LENGTH] = {0};
    char*        protocolID = NULL;
    char*        next = NULL;

    currentLine = isakmpConf->inputStrings[i];
    sscanf(currentLine, "%s", paramStr);

    while (strcmp(paramStr, proposalID) && i < isakmpConf->numLines-1)
    {
        i++;
        currentLine = isakmpConf->inputStrings[i];
        sscanf(currentLine, "%s", paramStr);
    }

    //read configuration for a Given Protocol under PROPOSALS parameter
    if (!strcmp(paramStr, proposalID))
    {
        i++;
        currentLine = isakmpConf->inputStrings[i];
        IO_GetDelimitedToken(paramStr, currentLine, " ", &next);

        if (!strcmp(paramStr, "PROTOCOLS"))
        {
            //can set proposalId to 1 as we process the proposals using next
            //payload type and not reading this value at receiver end
            proposal->proposalId = 1;
            ISAKMPProtocol* tempProtocol;
            protocolID = (char*)MEM_malloc(MAX_PROTOCOL_NAME_LEN);
            proposal->protocol = (ISAKMPProtocol*) MEM_malloc(
                sizeof(ISAKMPProtocol));

            memset(proposal->protocol, 0, sizeof(ISAKMPProtocol));

            if ((protocolID =
                IO_GetDelimitedToken(protocolID, next, " ", &next)) == NULL)
            {
                ERROR_Assert(FALSE, "PROTOCOLS Parameter value missing");
            }

            ISAKMPReadProtocol(node,
              isakmpConf, proposal->protocol, protocolID, interfaceIndex, i);

            proposal->numofProtocols++;
            tempProtocol = proposal->protocol;

            //read configuration for all the protocol specified
            while ((protocolID = IO_GetDelimitedToken(
                protocolID, next, " ", &next)) != NULL)
            {
                tempProtocol->nextproto = (ISAKMPProtocol*) MEM_malloc(
                    sizeof(ISAKMPProtocol));
                memset(tempProtocol->nextproto, 0, sizeof(ISAKMPProtocol));

                ISAKMPReadProtocol(node, isakmpConf,
                    tempProtocol->nextproto,
                    protocolID,
                    interfaceIndex,
                    i);

                proposal->numofProtocols++;
                tempProtocol = tempProtocol->nextproto;
            }
        }
        else
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr, "PROTOCOLS param missing for Proposal %s\n",
                proposalID);
            ERROR_Assert(FALSE, errStr);
        }
        MEM_free(protocolID);
    }
    else
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "Configuration for Proposal %s: missing\n",
            proposalID);
        ERROR_Assert(FALSE, errStr);
    }
}

//
// FUNCTION   :: ISAKMPReadPhase2Config
// LAYER      :: Network
// PURPOSE    :: Read Phase-2 configuration for a node-peer from config file
// PARAMETERS :: Node* node
//               const NodeInput* - isakmp configuration information
//               ISAKMPPhase2* - reference phase-2 information
//               UInt32 interfaceIndex - interface Index
//               Int32 *j - line number in isakmp configuration file
// RETURN     :: void
// NOTE       ::

static
UInt32 ISAKMPReadPhase2Config(Node* node,
                              const NodeInput* isakmpConf,
                              ISAKMPNodeConf* &nodeconfig,
                              ISAKMPPhase2* &phase2,
                              UInt32 interfaceIndex,
                              Int32* j)
{
    Int32 i = *j + 1;
    const char*     currentLine = isakmpConf->inputStrings[i];
    char            paramStr[MAX_STRING_LENGTH] = {0};
    char            valueStr[MAX_STRING_LENGTH] = {0};
    UInt32          phase;
    int             numHostBits;
    BOOL            isNodeId;
    char*           next = NULL;
    char*           proposalID = NULL;

    sscanf(currentLine, "%s%u", paramStr, &phase);

    //read phase2 configuration parameters
    //All parameters are necessary and should be specified in given order.
    if (!strcmp(paramStr, "PHASE") && phase == PHASE_2)
    {
        phase2 = (ISAKMPPhase2*) MEM_malloc(sizeof(ISAKMPPhase2));
        memset(phase2, 0, sizeof(ISAKMPPhase2));
        i++;
        currentLine = isakmpConf->inputStrings[i];
        sscanf(currentLine, "%s%s", paramStr, valueStr);
        if (!strcmp(paramStr, "LOCAL-ID-TYPE"))
        {
            phase2->localIdType = ISAKMPGetNodeIdType(valueStr);
            i++;
            currentLine = isakmpConf->inputStrings[i];
            sscanf(currentLine, "%s%s", paramStr, valueStr);
        }
        else
        {
            ERROR_Assert(FALSE, "LOCAL-ID-TYPE Parameter missing");
        }
        if (!strcmp(paramStr, "LOCAL-NETWORK"))
        {
            if (!strcmp(valueStr, "*"))
            {
                phase2->localNetwork.interfaceAddr.ipv4 = ANY_SOURCE_ADDR;
            }
            else
            {
                IO_ParseNodeIdHostOrNetworkAddress(valueStr,
                    &phase2->localNetwork.interfaceAddr.ipv4,
                    &numHostBits, &isNodeId);
            }

            i++;
            currentLine = isakmpConf->inputStrings[i];
            sscanf(currentLine, "%s%s", paramStr, valueStr);
        }
        else
        {
            ERROR_Assert(FALSE, "LOCAL-NETWORK Parameter missing");
        }
        if (!strcmp(paramStr, "LOCAL-NETMASK"))
        {
            if (!strcmp(valueStr, "*"))
            {
                phase2->localNetMask.interfaceAddr.ipv4 = 0;
            }
            else
            {
                IO_ParseNodeIdHostOrNetworkAddress(valueStr,
                    &phase2->localNetMask.interfaceAddr.ipv4,
                    &numHostBits, &isNodeId);
            }

            i++;
            currentLine = isakmpConf->inputStrings[i];
            sscanf(currentLine, "%s%s", paramStr, valueStr);
        }
        else
        {
            ERROR_Assert(FALSE, "LOCAL-NETMASK Parameter missing");
        }
        if (!strcmp(paramStr, "REMOTE-ID-TYPE"))
        {
            phase2->remoteIdType = ISAKMPGetNodeIdType(valueStr);
            i++;
            currentLine = isakmpConf->inputStrings[i];
            sscanf(currentLine, "%s%s", paramStr, valueStr);
        }
        else
        {
            ERROR_Assert(FALSE, "REMOTE-ID-TYPE Parameter missing");
        }
        if (!strcmp(paramStr, "REMOTE-NETWORK"))
        {
            if (!strcmp(valueStr, "*"))
            {
                phase2->peerNetwork.interfaceAddr.ipv4 = ANY_DEST;
            }
            else
            {
                IO_ParseNodeIdHostOrNetworkAddress(valueStr,
                    &phase2->peerNetwork.interfaceAddr.ipv4,&numHostBits,
                    &isNodeId);
            }

            i++;
            currentLine = isakmpConf->inputStrings[i];
            sscanf(currentLine, "%s%s", paramStr, valueStr);
        }
        else
        {
            ERROR_Assert(FALSE, "REMOTE-NETWORK Parameter missing");
        }
        if (!strcmp(paramStr, "REMOTE-NETMASK"))
        {
            if (!strcmp(valueStr, "*"))
            {
                phase2->peerNetMask.interfaceAddr.ipv4 = 0;
            }
            else
            {
                IO_ParseNodeIdHostOrNetworkAddress(valueStr,
                    &phase2->peerNetMask.interfaceAddr.ipv4,
                    &numHostBits,
                    &isNodeId);
            }

            i++;
            currentLine = isakmpConf->inputStrings[i];
            sscanf(currentLine, "%s%s", paramStr, valueStr);
        }
        else
        {
            ERROR_Assert(FALSE, "REMOTE-NETMASK Parameter missing");
        }
        if (!strcmp(paramStr, "UPPER-LAYER-PROTOCOL"))
        {
            phase2->upperProtocol =
                (unsigned char)IPsecGetProtocolNumber(valueStr);
            i++;
            currentLine = isakmpConf->inputStrings[i];
            sscanf(currentLine, "%s%s", paramStr, valueStr);
        }
        else
        {
            ERROR_Assert(FALSE, "UPPER-LAYER-PROTOCOL Parameter missing");
        }
        if (!strcmp(paramStr, "DOI"))
        {
            phase2->doi = IPsecGetDOI(valueStr);
            i++;
            currentLine = isakmpConf->inputStrings[i];
            sscanf(currentLine, "%s%s", paramStr, valueStr);
        }
        else
        {
            ERROR_Assert(FALSE, "Phase 2 DOI Parameter missing");
        }
        if (!strcmp(paramStr, "EXCHANGE_TYPE"))
        {
            phase2->exchtype = ISAKMPGetExchType(valueStr, PHASE_2);
            i++;
            currentLine = isakmpConf->inputStrings[i];
            sscanf(currentLine, "%s%s", paramStr, valueStr);
        }
        else
        {
            ERROR_Assert(FALSE, "Phase 2 EXCHANGE_TYPE Parameter missing");
        }
        if (!strcmp(paramStr, "FLAGS"))
        {
            phase2->flags = ISAKMPGetFlags(valueStr);
            i++;
            currentLine = isakmpConf->inputStrings[i];
            IO_GetDelimitedToken(paramStr, currentLine, " ", &next);
        }
        else
        {
            ERROR_Assert(FALSE, "Phase 2 FLAGS Parameter missing");
        }
        if (!strcmp(paramStr, "PROPOSALS"))
        {
            proposalID = (char*)MEM_malloc(MAX_PROPOSAL_NAME_LEN);
            ISAKMPProposal* tempProposal;

            phase2->proposal = (ISAKMPProposal*) MEM_malloc(
                sizeof(ISAKMPProposal));

            memset(phase2->proposal, 0, sizeof(ISAKMPProposal));

            if ((proposalID =
                IO_GetDelimitedToken(proposalID, next, " ", &next)) == NULL)
            {
                ERROR_Assert(FALSE, "PROPOSALS Parameter value missing");
            }

            ISAKMPReadProposal(node,
                isakmpConf, phase2->proposal, proposalID,interfaceIndex, i);

            //Update phase2proposals list for this node-peer
            if (nodeconfig->phase2proposals == NULL)
            {
                nodeconfig->phase2proposals = phase2->proposal;
                nodeconfig->lastproposal = phase2->proposal;
            }
            else
            {
                nodeconfig->lastproposal->nextproposal = phase2->proposal;
                nodeconfig->lastproposal = phase2->proposal;
            }

            phase2->numofProposals++;
            tempProposal = phase2->proposal;

            //read configuration for all the proposals specified
            while ((proposalID =
                IO_GetDelimitedToken(proposalID, next, " ", &next)) != NULL)
            {
                tempProposal->nextproposal = (ISAKMPProposal*) MEM_malloc(
                    sizeof(ISAKMPProposal));

                memset(tempProposal->nextproposal, 0,sizeof(ISAKMPProposal));

                ISAKMPReadProposal(node,
                                    isakmpConf,
                                    tempProposal->nextproposal,
                                    proposalID,
                                    interfaceIndex,
                                    i);

                //Update phase2proposals list for this node-peer
                nodeconfig->lastproposal->nextproposal =
                    tempProposal->nextproposal;
                nodeconfig->lastproposal = tempProposal->nextproposal;

                tempProposal = tempProposal->nextproposal;
                phase2->numofProposals++;
            }
        }
        else
        {
            ERROR_Assert(FALSE, "Phase 2 PROPOSALS Parameter missing");
        }
        MEM_free(proposalID);
    }
    else
    {
        return 0;
    }
    *j = i;
    return 1;
}

//
// FUNCTION   :: ISAKMPReadNodePeerConf
// LAYER      :: Network
// PURPOSE    :: To Read configuration for a node-peer pair from config file
// PARAMETERS :: Node* node
//               const NodeInput* - isakmp configuration information
//               ISAKMPNodeConf* - reference node's isakmp information
//               const char node_peer_config[] - node-peer-config identifier
//               UInt32 interfaceIndex - interface Index
//               Int32 j - line number in isakmp configuration file
// RETURN     :: void
// NOTE       ::

static
void ISAKMPReadNodePeerConf(Node* node,
                            const NodeInput* isakmpConf,
                            ISAKMPNodeConf* &nodeconfig,
                            const char node_peer_config[],
                            UInt32 interfaceIndex,
                            Int32 j)
{
    Int32 i = j + 1;
    const char*         currentLine = isakmpConf->inputStrings[i];
    char                paramStr[MAX_STRING_LENGTH] = {0};

    sscanf(currentLine, "%s", paramStr);

    while (strcmp(paramStr, node_peer_config)
        && i < isakmpConf->numLines - 1)
    {
        i++;
        currentLine = isakmpConf->inputStrings[i];
        sscanf(currentLine, "%s", paramStr);
    }

    //read node-peer configuration
    // only one phase1 configuration should be specified for a node-peer
    // however multiple phase-2 configuration can be specified corresponding
    // to source and destination networks

    if (!strcmp(paramStr, node_peer_config))
    {
        //Read phase-1 configuration for a node-peer
        ISAKMPReadPhase1Config(node, isakmpConf,
            nodeconfig->phase1, interfaceIndex, &i);

        ISAKMPPhase2List* phase2_list = NULL;
        ISAKMPPhase2*     phase2 = NULL;

        //Read phase-2 configuration for diffrent networks for a node-peer
        while (ISAKMPReadPhase2Config(
            node, isakmpConf, nodeconfig, phase2, interfaceIndex, &i))
        {
            if (nodeconfig->phase2_list == NULL)
            {
                nodeconfig->phase2_list = (ISAKMPPhase2List*) MEM_malloc(
                    sizeof(ISAKMPPhase2List));
                memset(nodeconfig->phase2_list, 0, sizeof(ISAKMPPhase2List));
                phase2_list = nodeconfig->phase2_list;
                phase2_list->phase2 = phase2;
            }
            else
            {
                phase2_list->next = (ISAKMPPhase2List*) MEM_malloc(
                    sizeof(ISAKMPPhase2List));
                memset(phase2_list->next, 0, sizeof(ISAKMPPhase2List));
                phase2_list = phase2_list->next;
                phase2_list->phase2 = phase2;
            }
        }
        if (nodeconfig->phase2_list == NULL)
        {
            ERROR_Assert(FALSE, "Phase 2 configuration missing for "
                " corresponding Phase 1 configuration in .isakmp file");
        }
    }
    else
    {
        ERROR_Assert(FALSE, "node-peer configuration information is missing"
            "in .isakmp file");
    }
}

//
// FUNCTION   :: ISAKMPParseConfigFile
// LAYER      :: Network
// PURPOSE    :: To Read a configuration for a node from configuration file
// PARAMETERS :: Node* node
//               const NodeInput* - isakmp configuration information
//               clocktype - ISAKMP PHASE-1 START TIME
//               UInt32 interfaceIndex - interface Index
// RETURN     :: void
// NOTE       ::

static
void ISAKMPParseConfigFile(Node* node,
                           const NodeInput* isakmpConf,
                           clocktype timeVal,
                           UInt32 interfaceIndex)
{
    Int32 isakmpInformationIsPresent = 0;
    Int32 i = 0;
    ISAKMPNodeConf* tempconfig = NULL;

    NodeAddress interfaceAddress =
        (NodeAddress) NetworkIpGetInterfaceAddress(node, interfaceIndex);

    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];

    ISAKMPNodeConf* &commonConfData =
        interfaceInfo->isakmpdata->commonConfData;
    ISAKMPNodeConf* &nodeconfig = interfaceInfo->isakmpdata->nodeConfData;
    ISAKMPPhase1TranList* &ph1_trans_list =
        interfaceInfo->isakmpdata->ph1_trans_list;

    ISAKMPPhase2TranList* &ph2_trans_list =
        interfaceInfo->isakmpdata->ph2_trans_list;

    interfaceInfo->isakmpdata->stats =
        (ISAKMPStats*) MEM_malloc(sizeof(ISAKMPStats));

    memset(interfaceInfo->isakmpdata->stats, 0, sizeof(ISAKMPStats));

    interfaceInfo->isakmpdata->phase1_start_time = timeVal;
    Int32 j = 0;

    //read phase1 and phase2 transform configurations and create the list
    //of phase1 and phase2 transform supported

    ISAKMPReadPhase1Transforms(isakmpConf, ph1_trans_list, &j);
    ISAKMPReadPhase2Transforms(isakmpConf, ph2_trans_list, &j);

    while (i < isakmpConf->numLines)
    {
        const char*   currentLine = isakmpConf->inputStrings[i];
        char          paramStr[MAX_STRING_LENGTH] = {0};
        char          valueStr[MAX_STRING_LENGTH] = {0};
        NodeAddress   nodeAddress = 0;
        NodeAddress   peerAddress = 0;
        int           numHostBits;
        BOOL          isNodeId;
        char          node_peer_config[15] = {0};

        Int32 numValRead;
        numValRead = sscanf(currentLine, "%s%s", paramStr, valueStr);

        if (!strcmp(paramStr, "NODE"))
        {
            if (numValRead != 2)
            {
                ERROR_Assert(FALSE, "Node IP Address is not specified");
            }

            if (!strcmp(valueStr, "*"))
            {
                nodeAddress = ANY_DEST;
            }
            else
            {
                IO_ParseNodeIdHostOrNetworkAddress(valueStr,
                    &nodeAddress,
                    &numHostBits,
                    &isNodeId);

                if (MAPPING_GetInterfaceIndexFromInterfaceAddress(
                    node, nodeAddress) == -1)
                {
                    ERROR_Assert(FALSE, "INVALID IPV4 Address");
                }
            }
#ifdef CYBER_CORE
            if ((((!ip->iahepEnabled) || (ip->iahepData->nodeType == BLACK_NODE))
                && (nodeAddress == interfaceAddress || nodeAddress == ANY_DEST))
                || ((ip->iahepEnabled) && (ip->iahepData->nodeType == RED_NODE)))
#else
            if (nodeAddress == interfaceAddress || nodeAddress == ANY_DEST)
#endif
            {
                // Found this nodes configuration
                Int32 j = i + 1;

                isakmpInformationIsPresent = 1;

                while (j < isakmpConf->numLines)
                {
                    currentLine =  isakmpConf->inputStrings[j];
                    numValRead  =  sscanf(currentLine,
                                        "%s%s%s",
                                        paramStr,
                                        valueStr,
                                        node_peer_config);

                    if (strcmp(paramStr, "NODE"))
                    {
                        if (!strcmp(paramStr, "PEER"))
                        {
                            if (numValRead != 3)
                            {
                                ERROR_Assert(FALSE, "PEER Param Missing");
                            }
                            if (!strcmp(valueStr, "*"))
                            {
                                peerAddress = ANY_DEST;
                            }
                            else
                            {
                            IO_ParseNodeIdHostOrNetworkAddress(valueStr,
                                 &peerAddress,
                                 &numHostBits,
                                 &isNodeId);

                            if (MAPPING_GetInterfaceIndexFromInterfaceAddress(
                                   node, peerAddress)== -1)
                               {
                                   ERROR_Assert(
                                       FALSE, "INVALID IPV4 Address");
                               }
                            }

                            if (peerAddress == ANY_DEST
                                && commonConfData == NULL)
                            {
                                commonConfData = (ISAKMPNodeConf*)MEM_malloc(
                                    sizeof(ISAKMPNodeConf));
                                memset(commonConfData,
                                       0, sizeof(ISAKMPNodeConf));

                                // Read common config for phase1 and phase 2
                                commonConfData->nodeAddress = nodeAddress;
                                commonConfData->peerAddress = peerAddress;
                                commonConfData->interfaceIndex =
                                    interfaceIndex;

                                ISAKMPReadNodePeerConf(node,
                                                        isakmpConf,
                                                        commonConfData,
                                                        node_peer_config,
                                                        interfaceIndex,
                                                        j);
                                i = j;
                                j++;
                                continue;
                            }

                            if (nodeconfig == NULL)
                            {
                                nodeconfig = (ISAKMPNodeConf*)
                                    MEM_malloc(sizeof(ISAKMPNodeConf));
                                memset(nodeconfig, 0,sizeof(ISAKMPNodeConf));
                                tempconfig = nodeconfig;
                                //Read node-peer config for phase1 and phase2
                                tempconfig->nodeAddress = nodeAddress;
                                tempconfig->peerAddress = peerAddress;
                                tempconfig->interfaceIndex = interfaceIndex;
                                ISAKMPReadNodePeerConf(node,
                                                        isakmpConf,
                                                        tempconfig,
                                                        node_peer_config,
                                                        interfaceIndex,
                                                        j);
                            }
                            else
                            {
                                tempconfig->link = (ISAKMPNodeConf*)
                                    MEM_malloc(sizeof(ISAKMPNodeConf));
                                memset(tempconfig->link,
                                    0, sizeof(ISAKMPNodeConf));
                                tempconfig = tempconfig->link;
                                tempconfig->nodeAddress = nodeAddress;
                                tempconfig->peerAddress = peerAddress;
                                tempconfig->interfaceIndex = interfaceIndex;
                                ISAKMPReadNodePeerConf(node,
                                                        isakmpConf,
                                                        tempconfig,
                                                        node_peer_config,
                                                        interfaceIndex,
                                                        j);
                            }

                            //node with greater ip-address will initiate the
                            // negotiation
                            if (nodeAddress > peerAddress)
                            {
                                ISAKMPSetTimer(
                                    node,
                                    tempconfig,
                                    MSG_NETWORK_ISAKMP_SchedulePhase1,
                                    0,
                                    timeVal);
                            }
                        } // if PEER

                        i = j;
                    } // if not NODE
                    else
                    {
                        // it ends the current interface configuration
                        // so process subsequent lines
                        i = j;
                        break;
                    }
                    j++;
                } // conf lines
            } // nodeAddress matches
            else
            {
                // Read the next line
                i++;
            }
        } // if NODE
        else
        {
            // Read the next line
            i++;
        }
    }

    if (isakmpInformationIsPresent == 0)
    {
        interfaceInfo->isISAKMPEnabled = FALSE;
    }
}

// FUNCTION      ::    ISAKMPInit
// LAYER         ::    Network
// PURPOSE       ::    Function to Initialize ISAKMP for a node
// PARAMETERS    ::    Node* - The node initializing ISAKMP
//                     const NodeInput* - QualNet main configuration file
//                     UInt32 interfaceIndex - interface Index
// RETURN        ::    void
// NOTE          ::
//

void ISAKMPInit(Node* node,
                const NodeInput* nodeInput,
                UInt32 interfaceIndex)
{
    char buf[8];
    NodeInput isakmpInput;
    BOOL retVal;
    clocktype timeVal = 0;

    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;

    IO_ReadCachedFile(node->nodeId,
          NetworkIpGetInterfaceAddress(node, interfaceIndex),
          nodeInput,
          "ISAKMP-CONFIG-FILE",
          &retVal,
          &isakmpInput);

    if (!retVal)
    {
        ERROR_Assert(FALSE, "ISAKMP configuration file missing");
    }

    IO_ReadTime(node->nodeId,
                NetworkIpGetInterfaceAddress(node, interfaceIndex),
                nodeInput,
                "ISAKMP-PHASE-1-START-TIME",
                &retVal,
                &timeVal);

    if (!retVal)
    {
       timeVal = (clocktype)ISAKMP_PHASE1_START_TIME;
    }

    //read ipsec parameter to enable/disable ipsec with isakmp.
    IO_ReadString(
        node->nodeId,
        NetworkIpGetInterfaceAddress(node, interfaceIndex),
        nodeInput,
        "ISAKMP-ENABLE-IPSEC",
        &retVal,
        buf);

    if (!retVal || !strcmp(buf, "NO"))
    {
        ip->isIPsecEnabled = FALSE;
    }
    else if (!strcmp(buf, "YES"))
    {
        ip->isIPsecEnabled = TRUE;
    }
    else
    {
        ERROR_ReportError("ISAKMP-ENABLE-IPSEC expects YES or NO");
    }

    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];
    interfaceInfo->isakmpdata = (ISAKMPData*) MEM_malloc(sizeof(ISAKMPData));
    memset(interfaceInfo->isakmpdata, 0, sizeof(ISAKMPData));

    RANDOM_SetSeed(interfaceInfo->isakmpdata->seed,
               node->globalSeed,
               node->nodeId,
               NETWORK_PROTOCOL_ISAKMP,
               interfaceIndex);

    //parse isakmp configuration
    ISAKMPParseConfigFile(node, &isakmpInput, timeVal, interfaceIndex);
}

//
// FUNCTION   :: ISAKMPDropExchange
// LAYER      :: Network
// PURPOSE    :: to drop a exchange if some error occurs
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
// RETURN     :: void
// NOTE       ::

static
void ISAKMPDropExchange(Node* node, ISAKMPNodeConf* nodeconfig)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    if (nodeconfig->exchange->phase == PHASE_1)
    {
        //uninstall isakmp sa from map
        MapISAKMP_SA* &map_isakmp_sa =
            interfaceInfo->isakmpdata->map_isakmp_sa;
        MapISAKMP_SA* nextp = NULL;
        MapISAKMP_SA* prevp = NULL;
        if (map_isakmp_sa != NULL)
        {
            if (map_isakmp_sa->peerAddress == nodeconfig->peerAddress
                && map_isakmp_sa->isakmp_sa != NULL)
            {
                prevp = map_isakmp_sa;
                map_isakmp_sa = map_isakmp_sa->link;
                MEM_free(prevp->isakmp_sa);
                MEM_free(prevp);
            }
            else
            {
                prevp = map_isakmp_sa;
                nextp = map_isakmp_sa->link;
                while (nextp != NULL)
                {
                    if (nextp->peerAddress == nodeconfig->peerAddress
                        && nextp->isakmp_sa != NULL)
                    {
                        prevp->link = nextp->link;
                        MEM_free(nextp->isakmp_sa);
                        MEM_free(nextp);
                        break;
                    }
                    else
                    {
                        prevp = nextp;
                        nextp = nextp->link;
                    }
                }//while
            }
            nodeconfig->phase1->isakmp_sa = NULL;
        }
    }
    else
    {
        if (nodeconfig->current_pointer_list
           && nodeconfig->current_pointer_list->phase2 == nodeconfig->phase2)
        {
            // uninstall ipsec sa
            nodeconfig->current_pointer_list->is_ipsec_sa = FALSE;
            MEM_free(nodeconfig->phase2->ipsec_sa);
            nodeconfig->phase2->ipsec_sa = NULL;
        }
    }

    stats->numOfExchDropped++;

    if (IsPhase1IKEExchange(nodeconfig->exchange->exchType))
    {
        nodeconfig->phase1->isNewGroupModePerformed = FALSE;
    }

    MEM_free(nodeconfig->exchange->IDi);
    MEM_free(nodeconfig->exchange->IDr);
    MEM_free(nodeconfig->exchange->sig_i);
    MEM_free(nodeconfig->exchange->sig_r);
    MEM_free(nodeconfig->exchange->hash_i);
    MEM_free(nodeconfig->exchange->hash_r);
    MEM_free(nodeconfig->exchange->cert_i);
    MEM_free(nodeconfig->exchange->cert_r);
    MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);

    MEM_free(nodeconfig->exchange);
    nodeconfig->exchange = NULL;
}

//
// FUNCTION   :: ISAKMPSetUp_Negotiation
// LAYER      :: Network
// PURPOSE    :: to Setup a phase-1 or phase-2 negotiation
// PARAMETERS :: Node* node,
//               ISAKMPNodeConf* nodeconfig - node isakmp configuration
//               Message* msg - message received
//               NodeAddress source - node ip-address
//               NodeAddress dest -   peer ip-address
//               UInt32 i_r - whether initiator or responder
//               unsigned char phase - phase-1 or phase-1
// RETURN     :: void
// NOTE       ::

void ISAKMPSetUp_Negotiation(Node* node,
                             ISAKMPNodeConf* nodeconfig,
                             Message* msg,
                             NodeAddress source,
                             NodeAddress dest,
                             UInt32 i_r,
                             unsigned char phase)
{
    UInt32 interfaceIndex;
    NetworkDataIp* ip = NULL;
    IpInterfaceInfoType* interfaceInfo = NULL;
    ISAKMPNodeConf* nodeconf = NULL;

    BOOL forNewGroupMode = FALSE;

    if (nodeconfig == NULL)
    {
        //find isakmp config info for given source and destination
        nodeconf = ISAKMPGetNodeConfig(node, source, dest);

       if (nodeconf == NULL)
        {
            //No Configuration available for this source and destination
            return;
        }
    }
    else
    {
        nodeconf = nodeconfig;
    }

    if (nodeconf && phase == PHASE_1)
    {
        if (i_r == INITIATOR
            && nodeconf->phase1->isNewGroupModeEnabled
            && !(nodeconf->phase1->isNewGroupModePerformed)
            && IsISAKMPSAPresent(node,
                                 nodeconf->nodeAddress,
                                 nodeconf->peerAddress))
        {
            forNewGroupMode = TRUE;
            //going to perfrom IKE New Group Mode exchange
            nodeconf->phase1->isNewGroupModePerformed = TRUE;
        }
        else if (i_r == RESPONDER
                 && IsISAKMPSAPresent(node,
                                 nodeconf->nodeAddress,
                                 nodeconf->peerAddress))
        {
            forNewGroupMode = TRUE;
            //going to perfrom IKE New Group Mode exchange
            nodeconf->phase1->isNewGroupModePerformed = TRUE;
        }
    }

    if (phase == PHASE_1 && !forNewGroupMode)
    {
        interfaceIndex = NetworkIpGetInterfaceIndexFromAddress(node, source);
        ip = (NetworkDataIp*)node->networkData.networkVar;

        interfaceInfo = ip->interfaceInfo[interfaceIndex];
        MapISAKMP_SA* map_isakmp_sa =
            interfaceInfo->isakmpdata->map_isakmp_sa;

        // look for isakmp sa for this node-peer
        while (map_isakmp_sa != NULL)
        {
            if (map_isakmp_sa->peerAddress == nodeconf->peerAddress
                && map_isakmp_sa->isakmp_sa != NULL)
            {
                break;
            }
            map_isakmp_sa = map_isakmp_sa->link;
        }

        //isakmp sa found
        if (map_isakmp_sa != NULL)
        {
            //if node was initiator during phase1
            if (map_isakmp_sa->initiator == INITIATOR)
            {
                //start phase-2 negotiation
                nodeconf->phase2 = nodeconf->phase2_list->phase2;
                nodeconf->current_pointer_list = nodeconf->phase2_list;
                ISAKMPSetUp_Negotiation(
                    node, nodeconf, msg, source, dest, i_r, PHASE_2);
            }
            return;
        }
    }
    else if (phase == PHASE_2
             && i_r == INITIATOR
             && nodeconf->current_pointer_list->is_ipsec_sa)
    {
        //ipsec sa is present, so need to negotiate
        return;
    }

    ISAKMPExchange* &exch = nodeconf->exchange;

    if (nodeconf
        && exch != NULL
        && !forNewGroupMode)   //Already an exchange running
    {
        if (i_r == RESPONDER
            && nodeconf->nodeAddress < nodeconf->peerAddress)
        {
            ISAKMPDropExchange(node, nodeconf);
        }
        else
        {
            return;
        }
    }

    if (nodeconf->exchange == NULL)
    {
        exch = (ISAKMPExchange*)MEM_malloc(sizeof(ISAKMPExchange));
        memset(exch, 0, sizeof(ISAKMPExchange));
    }

    exch->initiator = i_r;
    exch->step = 0;
    exch->phase = phase;

    if (phase == PHASE_1)
    {
        if (i_r == INITIATOR)
        {
            exch->exchType = nodeconf->phase1->exchtype;
            if (forNewGroupMode)
            {
                //changing exchange type to New Group mode
                nodeconf->phase1->exchtype = ISAKMP_IKE_ETYPE_NEW_GROUP;
                exch->exchType = ISAKMP_IKE_ETYPE_NEW_GROUP;
            }
        }
        else
        {
            exch->exchType = ((ISAKMPHeader*)msg->packet)->exch_type;
        }
        exch->doi = nodeconf->phase1->doi;
        exch->flags = nodeconf->phase1->flags;
    }
    else
    {
        if (i_r == INITIATOR)
        {
            exch->exchType = nodeconf->phase2->exchtype;
            exch->doi = nodeconf->phase2->doi;
            exch->flags = nodeconf->phase2->flags;
        }
        else
        {
            exch->exchType = ((ISAKMPHeader*)msg->packet)->exch_type;
            exch->doi = IPSEC_DOI;
        }
    }

    // get function list for given exchange type
    exch->funcList = ISAKMPGetExchFuncList(exch->exchType, i_r);

    //send first message of negotiation
    (*(*exch->funcList)[exch->step])(node, nodeconf, msg);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char timeStr[100];
        IO_ConvertIpAddressToString(nodeconf->nodeAddress, srcStr);
        ctoa(node->getNodeTime(), timeStr);

        if (!forNewGroupMode)
        {
            printf("\n%s starting ISAKMPSetUp_Negotiation: at time %s",
                    srcStr, timeStr);
        }
        else
        {
            printf("\n%s starting ISAKMPSetUp_Negotiation for New Group mode"
                   ": at time %s", srcStr, timeStr);
        }
    }
}

//
// FUNCTION   :: ISAKMP_IsZero
// LAYER      :: Network
// PURPOSE    :: check for the zero value at given location and size
// PARAMETERS :: const char* p - starting addresss
//               UInt32 sz - number of bytes
// RETURN     :: 1 if TRUE 0 if false
// NOTE       ::

static
UInt32 ISAKMP_IsZero(const char* p, UInt32 sz)
{
    if (p == NULL)
    {
        return 0;
    }
    while (sz-- > 0)
    {
        if (*p++ != 0)
        {
            return 0;
        }
    }
    return 1;
}

//
// FUNCTION   :: ISAKMPGenCookie
// LAYER      :: Network
// PURPOSE    :: To generate a cookie
// PARAMETERS :: NodeAddress source - ip-address of source
//               char* cookie - cookie
// RETURN     :: void
// NOTE       :: this is just a stub function as actual implementation is
//                 not required for simulation purpose

static
void ISAKMPGenCookie(NodeAddress source, char* cookie)
{
    // assuming that cookie contains the IP Address of it's generator
    memcpy(cookie, &source, sizeof(NodeAddress));
}

//
// FUNCTION   :: ISAKMP_GenKey
// LAYER      :: Network
// PURPOSE    :: To generate a key from Initiator and Responder key data
// PARAMETERS :: ISAKMPExchange* exch - exchange running
//               char* Key_i - initiator cookie data
//               char* Key_r - responder cookie data
// RETURN     :: void
// NOTE       :: this is just a stub function as actual implementation is
//               not required for simulation purpose

static
void ISAKMP_GenKey(ISAKMPExchange* exch, char* Key_i, char* Key_r)
{
    for (UInt32 i = 0; i < KEY_SIZE; i++)
    {
        exch->Key[i] = Key_i[i] ^ Key_r[i];
    }
    exch->Key[KEY_SIZE] = '\0';
}

//
// FUNCTION   :: ISAKMPGetNotifyData
// LAYER      :: Network
// PURPOSE    :: To find the Notification data for a given notify type
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - node isakmp configuration
//               char* &notify_data - resulting notify data
//               UInt16 notify_type - notify type
//               UInt16 &len_notify_data - resulting notify data length
// RETURN     :: void
// NOTE       :: this is just a stub function as actual implementation is
//                 not required for simulation purpose

static
void ISAKMPGetNotifyData(ISAKMPNodeConf* nodeconfig,
                   char* &notify_data,
                   UInt16 notify_type,
                   UInt16 &len_notify_data)
{
    // Processing of Authentication only flag needs to be done here
    len_notify_data = 0;
    notify_data = NULL;

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        printf("\n%s sending Notification: %d",
            srcStr, notify_type);
    }
}




//
// FUNCTION   :: ISAKMPGetHash
// LAYER      :: Network
// PURPOSE    :: To get the hash data
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               char* &hash_data - hash payload data
//               UInt32 &len_hash_data - length of hash payload data
// RETURN     :: void
// NOTE       :: This function is not implement yet.
//               do we really need in Simulation ???

static
void ISAKMPGetHash(ISAKMPNodeConf* nodeconfig,
                   char* &hash_data,
                   UInt32 &len_hash_data)
{
    ISAKMPHashAlgo hashalgo = DEFAULT_HASH_ALGO;
    ISAKMPPhase1* phase1 = nodeconfig->phase1;
    ISAKMPExchange* exch = nodeconfig->exchange;
    UInt16 i = 0;

    if (phase1->isakmp_sa)
    {
        hashalgo = phase1->isakmp_sa->hashalgo;
    }
    else if (nodeconfig->exchange)
    {
        //search in all the transform available
        for (i = 0; i < phase1->numofTransforms; i++)
        {
            //if selected transform found, access processdelay
            if ((exch->phase1_trans_no_selected - 1) == i)
            {
                hashalgo = phase1->transform[i]->hashalgo;
            }
        }
    }
    else
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "Hash info not found\n");
        ERROR_ReportError(errStr);
    }

    if (hashalgo == IPSEC_HASH_MD5)
    {
         //MD5 has hash value length of 128 bits
        hash_data = (char*)MEM_malloc(128);
        memset(hash_data, '\0', 128);
        len_hash_data = 16; //hash value length in bytes
    }
    else if (hashalgo == IPSEC_HASH_SHA)
    {
        //SHA has hash value length of 160 bits
        hash_data = (char*)MEM_malloc(160);
        memset(hash_data, '\0', 160);
        len_hash_data = 20; //hash value length in bytes
    }
    else if (hashalgo == IPSEC_HASH_TIGER)
    {
        //TIGER has hash value length of 192 bits
        hash_data = (char*)MEM_malloc(192);
        memset(hash_data, '\0', 192);
        len_hash_data = 24; //hash value length in bytes
    }

    strcpy(hash_data, "NA");

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        printf("\n%s has it's Hash of length %u", srcStr, len_hash_data);
    }
}



//
// FUNCTION   :: ISAKMPAddHash
// LAYER      :: Network
// PURPOSE    :: To add the hash Payload to ISAKMP message
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               char* currentOffset - offset of hash payload
//               char* hash_data - hash payload data
//               UInt32 len_hash_data - length of hash payload data
// RETURN     :: void
// NOTE       ::

void ISAKMPAddHash(ISAKMPNodeConf* nodeconfig,
                     char* &currentOffset,
                     char* hash_data,
                     UInt32 len_hash_data)
{
    ISAKMPPaylHash hash_payload;

    memset(&hash_payload, 0, SIZE_HASH_Payload);

    ISAKMPExchange* exch = nodeconfig->exchange;

    hash_payload.h.np_type = ISAKMP_NPTYPE_NONE;
    hash_payload.h.len = (UInt16)(SIZE_HASH_Payload + len_hash_data);

    memcpy(currentOffset, &hash_payload, SIZE_HASH_Payload);

    currentOffset = currentOffset + SIZE_HASH_Payload;
    memcpy(currentOffset, hash_data, len_hash_data);

    if (exch)
    {
        if (exch->initiator == INITIATOR)
        {
            exch->hash_i = (char*)MEM_malloc(len_hash_data + 1);
            strcpy(exch->hash_i, hash_data);
        }
        else
        {
            exch->hash_r = (char*)MEM_malloc(len_hash_data + 1);
            strcpy(exch->hash_r, hash_data);
        }
    }
}


//
// FUNCTION   :: ISAKMPSendDeleteMessage
// LAYER      :: Network
// PURPOSE    :: to send the Information Exchange message
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - node isakmp configuration
//               IPSEC_SA* ipsec_sa , deleted SA information
// RETURN     :: void
// NOTE       ::

static
void ISAKMPSendDeleteMessage(Node* node,
                          ISAKMPNodeConf* nodeconfig,
                          IPSEC_SA* ipsec_sa)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    UInt32*          spi = NULL;
    Message*         newMsg = NULL;
    ISAKMPHeader*    isakmp_sendheader = NULL;

    UInt16            len_packet = 0;

    clocktype       delay = 0;
    char* currentOffset = NULL;
    char* hash_data = NULL;
    UInt32 len_hash = 0;
    UInt32 len_hash_data = 0;

    ISAKMPPaylHash* hash_payload = NULL;
    ISAKMPPaylDel* delete_payload = NULL;

    BOOL isIkeExchange = FALSE;
    BOOL isSAExchCompleted = FALSE;
    unsigned char exchType = 0;

    //getting exchange type
    if (nodeconfig->phase2 && nodeconfig->phase2->ipsec_sa)
    {
        exchType = nodeconfig->phase2->exchtype;
    }
    else if (nodeconfig->phase1 && nodeconfig->phase1->isakmp_sa)
    {
        exchType = nodeconfig->phase1->exchtype;
    }

    isIkeExchange = IsIKEExchange(exchType);

    if (nodeconfig->phase1->isakmp_sa
        || (nodeconfig->exchange
            && nodeconfig->exchange->phase1_trans_no_selected)
       )
    {
        isSAExchCompleted = TRUE;
    }

    if (isIkeExchange && isSAExchCompleted)
    {
        //get hash data
        ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);
        len_hash  = SIZE_HASH_Payload + len_hash_data;
    }

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    if (isIkeExchange && isSAExchCompleted)
    {
        len_packet = (UInt16)(SIZE_ISAKMP_HEADER + len_hash
                                           + SIZE_DELETE_Payload + SIZE_SPI);
    }
    else
    {
        len_packet = SIZE_ISAKMP_HEADER + SIZE_DELETE_Payload + SIZE_SPI;
    }

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;

    isakmp_sendheader->msgid = 1;

    ISAKMPGenCookie(nodeconfig->nodeAddress, isakmp_sendheader->init_cookie);
    ISAKMPGenCookie(nodeconfig->peerAddress, isakmp_sendheader->resp_cookie);

    if (isIkeExchange && isSAExchCompleted)
    {
        isakmp_sendheader->np_type = ISAKMP_NPTYPE_HASH;
    }
    else
    {
        isakmp_sendheader->np_type = ISAKMP_NPTYPE_D;
    }

    isakmp_sendheader->len = len_packet;

    if (isIkeExchange && isSAExchCompleted)
    {
        currentOffset = (char*)(isakmp_sendheader + 1);

        //add hash payload
        hash_payload = (ISAKMPPaylHash*)currentOffset;
        ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);
        hash_payload->h.np_type = ISAKMP_NPTYPE_D;

        delete_payload = (ISAKMPPaylDel*)(hash_payload + 1);
    }
    else
    {
        delete_payload = (ISAKMPPaylDel*)(isakmp_sendheader + 1);
    }

    delete_payload->h.len = SIZE_DELETE_Payload + SIZE_SPI;
    delete_payload->h.np_type = ISAKMP_NPTYPE_NONE;

    // copy doi
    delete_payload->doi = ipsec_sa->doi;

    //only one SPI is been sent in delete payload
    delete_payload->num_spi = 1;
    delete_payload->spi_size = SIZE_SPI;

    // copy protocol id
    delete_payload->prot_id = (unsigned char)ipsec_sa->proto;

    //copy SPI for which delete message is been sent
    spi = (UInt32*)(delete_payload + 1);
    *spi = ipsec_sa->SPI;

    if (isIkeExchange && isSAExchCompleted)
    {
        if (IsPhase1IKEExchange(exchType)
            || exchType == ISAKMP_IKE_ETYPE_NEW_GROUP)
        {
            delay = ISAKMPGetProcessDelay(node, nodeconfig);
        }
        else
        {
            delay = nodeconfig->phase1->isakmp_sa->processdelay;
        }
    }

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);

        if (isIkeExchange && isSAExchCompleted)
        {
            printf("\n%s has sent an hash delete msg to %s at"
                "Simulation time = %s with delay %s\n",
                srcStr, dstStr, timeStr, delayStr);
        }
        else
        {
            printf("\n%s has sent an delete msg to %s at"
                "Simulation time = %s\n", srcStr, dstStr, timeStr);
        }
    }

    if (isIkeExchange && isSAExchCompleted)
    {
        stats->numPayloadHashSend++;
    }
    //increase stats for delete message
    stats->numPayloadDeleteSend++;
}


//
// FUNCTION   :: ISAKMPInfoExchange
// LAYER      :: Network
// PURPOSE    :: to send the Information Exchange message
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - node isakmp configuration
//               UInt16 notify_type - notification type
// RETURN     :: void
// NOTE       ::

static
void ISAKMPInfoExchange(Node* node,
                          ISAKMPNodeConf* nodeconfig,
                          UInt16 notify_type)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char*            currentOffset = NULL;
    UInt32*          spi = NULL;
    Message*         newMsg = NULL;
    ISAKMPHeader*    isakmp_sendheader = NULL;
    ISAKMPExchange*  exch = nodeconfig->exchange;
    ISAKMPPhase1* phase1 = nodeconfig->phase1;

    UInt16            len_packet = 0;
    UInt16            len_notify = 0;

    clocktype delay = 0;
    char* hash_data = NULL;
    char* notify_data = NULL;
    ISAKMPPaylHash* hash_payload = NULL;
    ISAKMPPaylNotif* notify_payload = NULL;

    UInt32    len_hash = 0;
    UInt32    len_hash_data = 0;
    UInt16    len_notify_data = 0;

    BOOL isIkeExchange = IsIKEExchange(exch->exchType);

    BOOL isSAExchCompleted = FALSE;

    if (phase1->isakmp_sa
        || (nodeconfig->exchange && exch->phase1_trans_no_selected))
    {
        isSAExchCompleted = TRUE;
    }

    if (isIkeExchange && isSAExchCompleted)
    {
        //get hash data
        ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);
        len_hash  = SIZE_HASH_Payload + len_hash_data;
    }

    //get notify data to be send
    ISAKMPGetNotifyData(nodeconfig, notify_data, notify_type, len_notify_data);

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    if (exch->phase == PHASE_1)
    {
        len_notify = SIZE_NOTIFY_Payload  + len_notify_data;
    }
    else
    {
        len_notify = SIZE_NOTIFY_Payload + SIZE_SPI + len_notify_data;
    }

    if (isIkeExchange && isSAExchCompleted)
    {
        len_packet = (UInt16)(SIZE_ISAKMP_HEADER + len_hash + len_notify);
    }
    else
    {
        len_packet = SIZE_ISAKMP_HEADER + len_notify;
    }

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);

    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;

    if (isIkeExchange && isSAExchCompleted)
    {
        isakmp_sendheader->np_type = ISAKMP_NPTYPE_HASH;
    }
    else
    {
        isakmp_sendheader->np_type = ISAKMP_NPTYPE_N;
    }

    isakmp_sendheader->len = len_packet;

    if (isIkeExchange && isSAExchCompleted)
    {
        currentOffset = (char*)(isakmp_sendheader + 1);

        //add hash payload
        hash_payload = (ISAKMPPaylHash*)currentOffset;
        ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);
        hash_payload->h.np_type = ISAKMP_NPTYPE_N;

        currentOffset = (char*)(hash_payload + 1);
        currentOffset = currentOffset + len_hash_data;
        notify_payload = (ISAKMPPaylNotif*)currentOffset;
    }
    else
    {
        notify_payload = (ISAKMPPaylNotif*)(isakmp_sendheader + 1);
    }

    notify_payload->h.len = len_notify;
    notify_payload->h.np_type = ISAKMP_NPTYPE_NONE;

    //copy doi and protocol id
    notify_payload->doi = exch->doi;
    notify_payload->prot_id = (unsigned char)exch->proto;

    if (exch->phase == PHASE_1)
    {
        notify_payload->spi_size = 0;
    }
    else
    {
        notify_payload->spi_size = SIZE_SPI;
    }

    notify_payload->type = notify_type;

    if (notify_payload->spi_size != 0)
    {
        spi = (UInt32*)(notify_payload + 1);
        *spi = exch->SPI;
        currentOffset = (char*)(spi + 1);
    }
    else
    {
        currentOffset = (char*)(notify_payload + 1);
    }

    if (notify_data)
    {
        memcpy(currentOffset, notify_data, len_notify_data);
    }

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    // Dont add to retransmission list as peer will not reply to this msg

    if (isIkeExchange && isSAExchCompleted)
    {
        if (IsPhase1IKEExchange(exch->exchType)
            || exch->exchType == ISAKMP_IKE_ETYPE_NEW_GROUP)
        {
            delay = ISAKMPGetProcessDelay(node, nodeconfig);
        }
        else
        {
            delay = nodeconfig->phase1->isakmp_sa->processdelay;
        }
    }

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);

        if (isIkeExchange && isSAExchCompleted)
        {
            printf("\n%s has sent an hash info Exch to %s at"
                "Simulation time = %s with delay %s\n",
                srcStr, dstStr, timeStr, delayStr);
        }
        else
        {
            printf("\n%s has sent an info Exch to %s at"
                "Simulation time = %s\n", srcStr, dstStr, timeStr);
        }
    }

    stats->numOfInformExchSend++;
    if (isIkeExchange && isSAExchCompleted)
    {
        stats->numPayloadHashSend++;
    }
    stats->numPayloadNotifySend++;
}

//
// FUNCTION   :: ISAKMPPhase1GetTransData
// LAYER      :: Network
// PURPOSE    :: To retrive the attribute value for a phase-1 transform
// PARAMETERS :: ISAKMPPhase1Transform* - phase 1 transform configuration
// RETURN     :: void
// NOTE       ::

static
void ISAKMPPhase1GetTransData(ISAKMPPhase1Transform* p1_transform)
{
    char buf[BUFFER_SIZE] = {'\0'};
    UInt16 j = 0;
    ISAKMPDataAttr attr;

    if (p1_transform->authmethod)
    {
        attr.type = AUTH_MEHTOD_PH1;
        attr.lorv = (UInt16)p1_transform->authmethod;
        memcpy(&buf[j], (char*)&attr, 4);
        j += 4;
    }
    if (p1_transform->encryalgo)
    {
        attr.type = ENCRYP_ALGO_PH1;
        attr.lorv = (UInt16)p1_transform->encryalgo;
        memcpy(&buf[j], (char*)&attr, 4);
        j += 4;
    }
    if (p1_transform->certType)
    {
        attr.type = CERT_TYPE_PH1;
        attr.lorv = (UInt16)p1_transform->certType;
        memcpy(&buf[j], (char*)&attr, 4);
        j += 4;
    }
    if (p1_transform->hashalgo)
    {
        attr.type = HASH_ALGO_PH1;
        attr.lorv = (UInt16)p1_transform->hashalgo;
        memcpy(&buf[j], (char*)&attr, 4);
        j += 4;
    }
    if (p1_transform->groupdes)
    {
        attr.type = GRP_DESC_PH1;
        attr.lorv = (UInt16)p1_transform->groupdes;
        memcpy(&buf[j], (char*)&attr, 4);
        j += 4;
    }
    if (p1_transform->life)
    {
        attr.type = SA_LIFE_PH1;
        attr.lorv = p1_transform->life;
        memcpy(&buf[j], (char*)&attr, 4);
        j += 4;
    }
    p1_transform->len_attr = j;
    p1_transform->attributes = (char*) MEM_malloc(j);

    //copy phase1 transform attributes
    memcpy(p1_transform->attributes, buf, j);
}

//
// FUNCTION   :: ISAKMPPhase2GetTransData
// LAYER      :: Network
// PURPOSE    :: To retrive the attribute value for a phase-2 transform
// PARAMETERS :: ISAKMPPhase1Transform* phase 2 transform configuration
// RETURN     :: void
// NOTE       ::

static
void ISAKMPPhase2GetTransData(ISAKMPPhase2Transform* p2_transform)
{
    char buf[BUFFER_SIZE] = {'\0'};
    UInt16 j = 0;
    ISAKMPDataAttr attr;

    if (p2_transform->authalgo)
    {
        attr.type = AUTH_ALGO_PH2;
        attr.lorv = (UInt16)p2_transform->authalgo;
        memcpy(&buf[j], (char*)&attr, 4);
        j += 4;
    }
    if (p2_transform->mode)
    {
        attr.type = ENC_MODE_PH2;
        attr.lorv = (UInt16)p2_transform->mode;
        memcpy(&buf[j], (char*)&attr, 4);
        j += 4;
    }
    if (p2_transform->groupdes)
    {
        attr.type = GRP_DESC_PH2;
        attr.lorv = (UInt16)p2_transform->groupdes;
        memcpy(&buf[j], (char*)&attr, 4);
        j += 4;
    }
    if (p2_transform->life)
    {
        attr.type = SA_LIFE_PH2;
        attr.lorv = p2_transform->life;
        memcpy(&buf[j], (char*)&attr, 4);
        j += 4;
    }
    p2_transform->len_attr = j;
    p2_transform->attributes = (char*) MEM_malloc(j);

    //copy phase2 transform attributes
    memcpy(p2_transform->attributes, buf, j);
}

//
// FUNCTION   :: ISAKMPAddSecurityAssociationPayload
// LAYER      :: Network
// PURPOSE    :: To add the SA Payload in a ISAKMP message
// PARAMETERS :: ISAKMPPaylSA* &saptr - SA payload offset in the message
//               unsigned char np_type - next payload type
//               UInt16 len - lenth of the payload
//               DOI doi - domain of interpretation
//               UInt32 sit - situation as defined by the RFC 2407
// RETURN     :: void
// NOTE       ::

static
void ISAKMPAddSecurityAssociationPayload(ISAKMPPaylSA* &saptr,
                                         unsigned char np_type,
                                         UInt16 len,
                                         DOI doi,
                                         UInt32 sit)
{
    ISAKMPPaylSA* &plSA = saptr;

    if (plSA == NULL)
    {
        return;
    }

    //copy the values of diffrent field
    plSA->h.np_type = np_type;
    plSA->h.len = len;
    plSA->doi = doi;
    plSA->sit = sit;
}

//
// FUNCTION   :: ISAKMPAddProposalPayload
// LAYER      :: Network
// PURPOSE    :: To add the Proposal Payload in a ISAKMP message
// PARAMETERS :: ISAKMPPaylProp * - Proposal payload offset in the message
//               unsigned char np_type - next payload type
//               UInt16 len - lenth of the payload
//               unsigned char propnum - proposal number
//               IPsecProtocol proto - protocol
//               unsigned char spi_size - SPI size
//               UInt32 num_t - number of transform
//               char* spi - SPI
// RETURN     :: void
// NOTE       ::

static
void ISAKMPAddProposalPayload(ISAKMPPaylProp * &proposalptr,
                              UInt32 np_type,
                              UInt16 len,
                              unsigned char propnum,
                              IPsecProtocol proto,
                              unsigned char spi_size,
                              UInt32 num_t,
                              char* spi)
{
    ISAKMPPaylProp* &plProp = proposalptr;
    char*  spiptr;

    if (plProp == NULL)
    {
        return;
    }

    //copy the values of diffrent field
    plProp->h.np_type = (unsigned char)np_type;
    plProp->h.len = len;
    plProp->p_no = propnum;
    plProp->prot_id = (unsigned char)proto;
    plProp->spi_size = spi_size;
    plProp->num_t = (unsigned char)num_t;
    plProp++;

    //copy spi
    if (spi)
    {
        memcpy((char*)plProp, spi, spi_size);
        spiptr = (char*)plProp;
        spiptr = spiptr + spi_size;
        plProp = (ISAKMPPaylProp*)spiptr;
        MEM_free(spi);
    }
}

//
// FUNCTION   :: ISAKMPAddTransformPayload
// LAYER      :: Network
// PURPOSE    :: To add the Transform Payload in a ISAKMP message
// PARAMETERS :: ISAKMPPaylTrans* - Transform payload offset in the message
//               unsigned char np_type - next payload type
//               UInt32 transnum - transform number
//               unsigned char t_id - transform id
//               UInt16 len_attr - lenght of attributes
//               char* attributes - attributes to be added
// RETURN     :: void
// NOTE       ::

static
void ISAKMPAddTransformPayload(ISAKMPPaylTrans* &transptr,
                              UInt32 np_type,
                              UInt32 transnum,
                              unsigned char t_id,
                              UInt16 len_attr,
                              char* attributes)
{
    ISAKMPPaylTrans* &pltrans = transptr;
    char*  attrptr = NULL;
    if (pltrans == NULL)
    {
        return;
    }

    //copy the values of diffrent field
    pltrans->h.np_type = (unsigned char)np_type;
    pltrans->h.len = len_attr + SIZE_TRANSFORM_Payload;
    pltrans->t_no = (unsigned char)transnum;
    pltrans->t_id = t_id;
    pltrans++;

    //add transform attributes
    if (attributes)
    {
        memcpy((char*)pltrans, attributes, len_attr);
        attrptr = (char*)pltrans;
        attrptr = attrptr+ len_attr;
        pltrans = (ISAKMPPaylTrans*)attrptr;
    }
}


//
// FUNCTION   :: FindExchConfigForCookie
// LAYER      :: Network
// PURPOSE    :: To retrive the node-peer config for init and resp cookie
// PARAMETERS :: char* init_cookie - initiator cookie
//               char* resp_cookie - responder cookie
//               ISAKMPNodeConf* &nodeconfig -isakmp config for this exchange
// RETURN     :: void
// NOTE       ::

void FindExchConfigForCookie(char* init_cookie,
                             char* resp_cookie,
                             ISAKMPNodeConf* &nodeconfig)
{
    while (nodeconfig)
    {
        if (nodeconfig->exchange != NULL
            && !strcmp(init_cookie, nodeconfig->exchange->init_cookie))
        {
            if (ISAKMP_IsZero(nodeconfig->exchange->resp_cookie,COOKIE_SIZE))
            {
                NodeAddress peer = 0;

                // assume cookie contains ipv4 Address
                memcpy(&peer,resp_cookie, sizeof(NodeAddress));
                if (peer == nodeconfig->peerAddress)
                {
                    break;
                }
            }
            else if (!strcmp(resp_cookie, nodeconfig->exchange->resp_cookie))
            {
                break;
            }
        }
        nodeconfig = nodeconfig->link;
    }
}

//
// FUNCTION   :: IsISAKMPSAPresent
// LAYER      :: Network
// PURPOSE    :: check for an ISAKMP SA for given source and destination node
// PARAMETERS :: Node* node - node data
//               NodeAddress source - source address
//               NodeAddress dest - peer address
// RETURN     :: BOOL - TRUE or FALSE
// NOTE       ::

BOOL IsISAKMPSAPresent(Node* node, NodeAddress source, NodeAddress dest)
{
    UInt32 interfaceIndex =
        NetworkIpGetInterfaceIndexFromAddress(node, source);
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;

    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];

    if (interfaceInfo->isISAKMPEnabled == FALSE)
    {
        return FALSE;
    }

    MapISAKMP_SA* map_isakmp_sa = interfaceInfo->isakmpdata->map_isakmp_sa;

    // search phase1 SA for the peer in Phase1 SA map.
    while (map_isakmp_sa != NULL)
    {
        if (map_isakmp_sa->peerAddress == dest
            && map_isakmp_sa->isakmp_sa != NULL)
        {
            break;
        }
        map_isakmp_sa = map_isakmp_sa->link;
    }

    if (map_isakmp_sa == NULL)
    {
        return FALSE;
    }
    return TRUE;
}

//
// FUNCTION   :: IsIPSecSAPresent
// LAYER      :: Network
// PURPOSE    :: check for an IPSEC SA for given source and dest network
// PARAMETERS :: Node* node - node data
//               NodeAddress source - source address
//               NodeAddress dest - peer address
//               UInt32 interfaceIndex - source interface index
// RETURN     :: BOOL - TRUE or FALSE
// NOTE       ::

BOOL IsIPSecSAPresent(Node* node,
                        NodeAddress source,
                        NodeAddress dest,
                        UInt32 interfaceIndex,
                        ISAKMPNodeConf* &nodeconfig)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];

    nodeconfig = interfaceInfo->isakmpdata->nodeConfData;

    ISAKMPPhase2List* current_pointer_list;
    ISAKMPPhase2* phase2 ;
    UInt32 numLocalHostBits, numRemoteHostBits ;

    while (nodeconfig)
    {
        current_pointer_list = nodeconfig->phase2_list;
        while (current_pointer_list)
        {
            phase2 = current_pointer_list->phase2;

            numLocalHostBits = ConvertSubnetMaskToNumHostBits(
                phase2->localNetMask.interfaceAddr.ipv4);
            numRemoteHostBits = ConvertSubnetMaskToNumHostBits(
                phase2->peerNetMask.interfaceAddr.ipv4);

            if (ISAKMP_DEBUG)
            {
                char addrStr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(source, addrStr);

                IO_ConvertIpAddressToString(
                    phase2->localNetwork.interfaceAddr.ipv4, addrStr);

                IO_ConvertIpAddressToString(dest, addrStr);

                IO_ConvertIpAddressToString(
                    phase2->peerNetwork.interfaceAddr.ipv4, addrStr);

            }

            //check for security policy for source and destination network
            if (IsIpAddressInSubnet(dest,
                phase2->peerNetwork.interfaceAddr.ipv4,numRemoteHostBits)
                && IsIpAddressInSubnet(source,
                phase2->localNetwork.interfaceAddr.ipv4,numLocalHostBits))
            {
                nodeconfig->current_pointer_list = current_pointer_list;
                nodeconfig->phase2 =
                    nodeconfig->current_pointer_list->phase2;
                return current_pointer_list->is_ipsec_sa;
            }
            current_pointer_list = current_pointer_list->next;
        }

        nodeconfig = nodeconfig->link;
    }
    return FALSE;
}

//
// FUNCTION   :: ISAKMPInitiatorSendCookie
// LAYER      :: Network
// PURPOSE    :: sending Initiator cookie
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp config for a node-peer
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorSendCookie(Node * node,
                                  ISAKMPNodeConf* nodeconfig,
                                  Message* msg)
{
    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPHeader* isakmp_header = NULL;
    Message* newMsg = NULL;

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        printf("\nStart Phase-%u, Exchange-%u, b/w %s and %s",
            nodeconfig->exchange->phase,
            nodeconfig->exchange->exchType,
            srcStr,
            dstStr);
    }

    newMsg = MESSAGE_Alloc(
        node, MAC_LAYER, IPSEC_ISAKMP, MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(node, newMsg, SIZE_ISAKMP_HEADER, TRACE_ISAKMP);

    isakmp_header = (ISAKMPHeader*) MESSAGE_ReturnPacket(newMsg);
    memset(isakmp_header, '\0', SIZE_ISAKMP_HEADER);

    //generate initiator cookie
    ISAKMPGenCookie(nodeconfig->nodeAddress, isakmp_header->init_cookie);

    if (nodeconfig->exchange->phase == PHASE_1)
    {
        isakmp_header->exch_type = nodeconfig->phase1->exchtype;
        isakmp_header->msgid = 0;
    }
    else
    {
        isakmp_header->exch_type = nodeconfig->phase2->exchtype;
        isakmp_header->msgid = 1;
    }
    isakmp_header->len = SIZE_ISAKMP_HEADER;

    memcpy(nodeconfig->exchange->init_cookie,
        isakmp_header->init_cookie, COOKIE_SIZE);

    nodeconfig->exchange->msgid = isakmp_header->msgid;

    nodeconfig->exchange->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
         node,
         newMsg,
         source,
         dest,
         ANY_INTERFACE,
         IPTOS_PREC_INTERNETCONTROL,
         IPPROTO_ISAKMP,
         9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\n%s has sent cookie to %s"
            " at Simulation time = %s\n", srcStr, dstStr, timeStr);
    }
}

//
// FUNCTION   :: ISAKMPResponderReplyCookie
// LAYER      :: Network
// PURPOSE    :: sending resonder cookie
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp config for a node-peer
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPResponderReplyCookie(Node * node,
                                   ISAKMPNodeConf* nodeconfig,
                                   Message* msg)
{
    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    Message* newMsg = NULL;
    ISAKMPHeader* isakmp_recvheader = NULL;
    ISAKMPHeader* isakmp_send_header = NULL;

    newMsg = MESSAGE_Alloc(
        node, MAC_LAYER, IPSEC_ISAKMP, MSG_MAC_FromNetwork);
    MESSAGE_PacketAlloc(node, newMsg, SIZE_ISAKMP_HEADER, TRACE_ISAKMP);

    isakmp_send_header = (ISAKMPHeader*) MESSAGE_ReturnPacket(newMsg);
    memset(isakmp_send_header, 0, SIZE_ISAKMP_HEADER);

    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    //generate responder cookie
    ISAKMPGenCookie(nodeconfig->nodeAddress, isakmp_send_header->resp_cookie);

    memcpy(nodeconfig->exchange->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);

    memcpy(isakmp_send_header->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);

    memcpy(nodeconfig->exchange->resp_cookie,
        isakmp_send_header->resp_cookie, COOKIE_SIZE);

    nodeconfig->exchange->msgid = isakmp_recvheader->msgid;
    isakmp_send_header->msgid = isakmp_recvheader->msgid;
    isakmp_send_header->exch_type = isakmp_recvheader->exch_type;
    isakmp_send_header->flags = isakmp_recvheader->flags;
    isakmp_send_header->len = isakmp_recvheader->len;
    nodeconfig->exchange->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\n%s has replied cookie to %s"
            " at Simulation time = %s\n", srcStr, dstStr, timeStr);
    }
}

//
// FUNCTION   :: IsValidTransId
// LAYER      :: Network
// PURPOSE    :: check for validity of transform id based on protocol
// PARAMETERS :: IPsecProtocol proto - protocol
//               unsigned char trans_id - transform id
// RETURN     :: unsigned char
// NOTE       ::

unsigned char IsValidTransId(IPsecProtocol proto, unsigned char trans_id)
{
    if (proto == IPSEC_ISAKMP)
    {
        switch (trans_id)
        {
            case IPSEC_KEY_IKE:
                return 0;
            default:
                return ISAKMP_NTYPE_INVALID_TRANSFORM_ID;
        }
    }
    if (proto == IPSEC_AH)
    {
        switch (trans_id)
        {
            case IPSEC_AH_MD5:
            case IPSEC_AH_SHA:
            case IPSEC_AH_DES:
                return 0;
            default:
                return ISAKMP_NTYPE_INVALID_TRANSFORM_ID;
        }
    }
    if (proto == IPSEC_ESP)
    {
        switch (trans_id)
        {
            case IPSEC_ESP_DES_IV64:
            case IPSEC_ESP_DES:
            case IPSEC_ESP_3DES:
            case IPSEC_ESP_RC5:
            case IPSEC_ESP_IDEA:
            case IPSEC_ESP_CAST:
            case IPSEC_ESP_BLOWFISH:
            case IPSEC_ESP_3IDEA:
            case IPSEC_ESP_DES_IV32:
            case IPSEC_ESP_RC4:
            case IPSEC_ESP_NULL:
                return 0;
            default:
                return ISAKMP_NTYPE_INVALID_TRANSFORM_ID;
        }
    }
    return ISAKMP_NTYPE_INVALID_PROTOCOL_ID;

}



//
// FUNCTION   :: IsValidCertType
// LAYER      :: Network
// PURPOSE    :: check for validity of certificate type
// PARAMETERS :: unsigned char certType - encode type received
// RETURN     :: unsigned char
// NOTE       ::

unsigned char IsValidCertType(unsigned char certType)
{
    switch (certType)
    {
        case ISAKMP_CERT_NONE:
        case ISAKMP_CERT_PKCS7:
        case ISAKMP_CERT_PGP:
        case ISAKMP_CERT_DNS_SIGNED:
        case ISAKMP_CERT_X509_SIG:
        case ISAKMP_CERT_X509_KEYEX:
        case ISAKMP_CERT_KERBEROS:
        case ISAKMP_CERT_CRL:
        case ISAKMP_CERT_ARL:
        case ISAKMP_CERT_SPKI:
        case ISAKMP_CERT_X509_ATTRI:
            return 0;
        default:
            return ISAKMP_NTYPE_INVALID_CERTIFICATE;
    }
}



//
// FUNCTION   :: ISAKMPValidatePayloadTransform
// LAYER      :: Network
// PURPOSE    :: check for validity of transform payload received
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylTrans* payload - transform payload
//               ISAKMPProtocol* protocol - protocol
// RETURN     :: UInt16 - 0 or error notification type
// NOTE       ::

UInt16 ISAKMPValidatePayloadTransform(ISAKMPNodeConf* nodeconfig,
                                  ISAKMPPaylTrans* payload,
                                  IPsecProtocol ipsecProto,
                                  ISAKMPProtocol* protocol)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    ISAKMPGenericHeader gen_header = payload->h;
    UInt16 notify_type = 0;
    char* currentOffset;

    //general header Processing
    switch (gen_header.np_type)
    {
        case ISAKMP_NPTYPE_T:
        case ISAKMP_NPTYPE_NONE:
            break;
        default:
            return ISAKMP_NTYPE_INVALID_PAYLOAD_TYPE;
            break;
    }//switch

    if (gen_header.reserved != 0)
    {
        return ISAKMP_NTYPE_INVALID_RESERVED_FIELD;
    }

    //validate transform id
    notify_type = IsValidTransId(ipsecProto, payload->t_id);
    if (notify_type != 0)
    {
        return notify_type;
    }

    if (exch->phase == PHASE_1)
    {
        ISAKMPPhase1 * phase1 = nodeconfig->phase1;

        //search in all the transform available
        for (UInt32 i = 0; i < phase1->numofTransforms; i++)
        {
            //if transform id match for this transform
            if (payload->t_id == phase1->transform[i]->transformId)
            {
                UInt32 attr_size =
                    payload->h.len - SIZE_TRANSFORM_Payload;

                ISAKMPDataAttr* attr = (ISAKMPDataAttr*)(payload + 1);

                //validate attributes
                while (attr_size > 0)
                {
                    if ((attr->type == ENCRYP_ALGO_PH1
                       && attr->lorv == phase1->transform[i]->encryalgo)
                       || (attr->type == CERT_TYPE_PH1
                       && attr->lorv == phase1->transform[i]->certType)
                       || (attr->type == AUTH_MEHTOD_PH1
                       && attr->lorv == phase1->transform[i]->authmethod)
                       || (attr->type == HASH_ALGO_PH1
                       && attr->lorv == phase1->transform[i]->hashalgo)
                       || (attr->type == GRP_DESC_PH1
                       && attr->lorv == phase1->transform[i]->groupdes)
                       || (attr->type == SA_LIFE_PH1))
                    {
                        if (attr->type & AF_BIT)
                        {
                            attr++;
                            attr_size = attr_size - SIZE_DATA_ATTRIBUTE;
                        }
                        else
                        {
                            currentOffset = (char*)(attr + 1);
                            currentOffset = currentOffset + attr->lorv;
                            attr = (ISAKMPDataAttr*)(currentOffset);
                            attr_size = attr_size - SIZE_DATA_ATTRIBUTE
                                - attr->lorv;
                        }
                    }
                    else
                    {
                        //attribute are not matching for this transform;
                        //but we will continue the search in rest of the
                        //transforms as we can have multiple transform with
                        //same transform id
                        notify_type =
                            ISAKMP_NTYPE_ATTRIBUTES_NOT_SUPPORTED;
                        break;
                    }
                }//while

                if (attr_size <= 0)
                {
                    if (exch->trans_selected == NULL)
                    {
                        exch->trans_selected = payload;
                        exch->phase1_trans_no_selected = (UInt16)(i + 1);
                    }
                    return 0;
                }
            }
        }// for
    }
    else
    {
        for (UInt32 i = 0; i < protocol->numofTransforms; i++)
        {
            if (payload->t_id == protocol->transform[i]->transformId)
            {
                UInt32 attr_size =
                    payload->h.len - SIZE_TRANSFORM_Payload;

                ISAKMPDataAttr* attr = (ISAKMPDataAttr*)(payload + 1);

                while (attr_size > 0)
                {
                    if ((attr->type == AUTH_ALGO_PH2
                       && attr->lorv == protocol->transform[i]->authalgo)
                       || (attr->type == ENC_MODE_PH2
                       && attr->lorv == protocol->transform[i]->mode)
                       || (attr->type == GRP_DESC_PH2
                       && attr->lorv == protocol->transform[i]->groupdes)
                       || (attr->type == SA_LIFE_PH2))
                    {
                        if (attr->type & AF_BIT)
                        {
                            attr++;
                            attr_size = attr_size - SIZE_DATA_ATTRIBUTE;
                        }
                        else
                        {
                            currentOffset = (char*)(attr + 1);
                            currentOffset = currentOffset + attr->lorv;
                            attr = (ISAKMPDataAttr*)(currentOffset);
                            attr_size = attr_size - SIZE_DATA_ATTRIBUTE
                                - attr->lorv;
                        }
                    }
                    else
                    {
                        //attribute are not matching for this transform;
                        //but we will continue the search in rest of the
                        //transforms as we can have multiple transform with
                        //same transform id
                        notify_type =
                            ISAKMP_NTYPE_ATTRIBUTES_NOT_SUPPORTED;
                        break;
                    }
                }//while
                if (attr_size <= 0)
                {
                    if (exch->trans_selected == NULL)
                    {
                        exch->trans_selected = payload;
                    }
                    return 0;
                }
            }
        }// for
    }
    return notify_type;
}

//
// FUNCTION   :: SetupIPSecSA
// LAYER      :: Network
// PURPOSE    :: save temporarily the negotiated IPSEC SA
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPDataAttr* attr - negotiated transform attributes
//               UInt32 attr_size - size of attributes
// RETURN     :: void
// NOTE       ::

void SetupIPSecSA(ISAKMPNodeConf* nodeconfig,
                  ISAKMPDataAttr* attr,
                  UInt32 attr_size)
{
    IPSEC_SA* ipsec_sa    = (IPSEC_SA*)MEM_malloc(sizeof(IPSEC_SA));
    memset(ipsec_sa, 0, sizeof(IPSEC_SA));

    char*  currentOffset;
    UInt16 type;
    UInt16 value;

    if (nodeconfig->exchange->initiator == INITIATOR)
    {
        nodeconfig->phase2->ipsec_sa = ipsec_sa;
    }
    else
    {
        //save temporarily. Will find the correct phase2 config only after
        //successfully receiving the identification payload
        nodeconfig->ipsec_sa = ipsec_sa;
    }

    ipsec_sa->doi = nodeconfig->exchange->doi;
    ipsec_sa->SPI = nodeconfig->exchange->SPI;
    ipsec_sa->proto = nodeconfig->exchange->proto;

    //save sa attributes
    while (attr_size > 0)
    {
        if (attr->type & AF_BIT)
        {
            type = attr->type;
            value = attr->lorv;
            attr++;
            attr_size = attr_size - SIZE_DATA_ATTRIBUTE;
        }
        else
        {
            type = attr->type;
            currentOffset = (char*)(attr + 1);
            value = *(UInt16*)currentOffset;
            currentOffset = currentOffset + attr->lorv;
            attr = (ISAKMPDataAttr*)(currentOffset);
            attr_size = attr_size - SIZE_DATA_ATTRIBUTE - attr->lorv;
        }
        switch (type)
        {
            case AUTH_ALGO_PH2:
                ipsec_sa->authalgo = (IPsecAuthAlgo)value;
                break;
            case ENC_MODE_PH2:
                ipsec_sa->mode = (IPsecSAMode)value;
                break;
            case GRP_DESC_PH2:
                ipsec_sa->groupdes = (ISAKMPGrpDesc)value;
                break;
            case SA_LIFE_PH2:
                ipsec_sa->life = value;
                break;
            default:
                break;
        }
    }
}

//
// FUNCTION   :: SetupISAKMPSA
// LAYER      :: Network
// PURPOSE    :: save temporarily the negotiated ISAKMP SA
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPDataAttr* attr - negotiated transform attributes
//               UInt32 attr_size - size of attributes
// RETURN     :: void
// NOTE       ::

void SetupISAKMPSA(Node* node,
                   ISAKMPNodeConf* nodeconfig,
                   ISAKMPDataAttr* attr,
                   UInt32 attr_size)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    MapISAKMP_SA* &map_isakmp_sa = interfaceInfo->isakmpdata->map_isakmp_sa;
    MapISAKMP_SA* nextp;
    MapISAKMP_SA* prevp;

    //build isakmp sa map
    if (map_isakmp_sa == NULL)
    {
        map_isakmp_sa = (MapISAKMP_SA*)MEM_malloc(sizeof(MapISAKMP_SA));
        memset(map_isakmp_sa, 0, sizeof(MapISAKMP_SA));
        nextp = map_isakmp_sa;
    }
    else
    {
        prevp = map_isakmp_sa;
        nextp = map_isakmp_sa->link ;
        while (nextp != NULL)
        {
            prevp = nextp;
            nextp = nextp->link;
        }
        nextp = (MapISAKMP_SA*)MEM_malloc(sizeof(MapISAKMP_SA));
        memset(nextp, 0, sizeof(MapISAKMP_SA));
        prevp->link = nextp;
    }

    ISAKMP_SA* &isakmp_sa = nextp->isakmp_sa;
    nextp->nodeAddress = nodeconfig->nodeAddress;
    nextp->peerAddress = nodeconfig->peerAddress;
    nextp->initiator = nodeconfig->exchange->initiator;

    isakmp_sa    = (ISAKMP_SA*)MEM_malloc(sizeof(ISAKMP_SA));
    memset(isakmp_sa, 0, sizeof(ISAKMP_SA));

    nodeconfig->phase1->isakmp_sa = isakmp_sa;

    char*  currentOffset;
    UInt16 type;
    UInt16 value;

    isakmp_sa->doi = nodeconfig->exchange->doi;
    memcpy(isakmp_sa->init_cookie,
        nodeconfig->exchange->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sa->resp_cookie,
        nodeconfig->exchange->resp_cookie, COOKIE_SIZE);
    isakmp_sa->proto = nodeconfig->exchange->proto;

    //save isakmp sa attributes
    while (attr_size > 0)
    {
        if (attr->type & AF_BIT)
        {
            type = attr->type;
            value = attr->lorv;
            attr++;
            attr_size = attr_size - SIZE_DATA_ATTRIBUTE;
        }
        else
        {
            type = attr->type;
            currentOffset = (char*)(attr + 1);
            value = *(UInt16*)currentOffset ;
            currentOffset = currentOffset + attr->lorv;
            attr = (ISAKMPDataAttr*)(currentOffset);
            attr_size = attr_size - SIZE_DATA_ATTRIBUTE - attr->lorv;
        }

        switch (type)
        {
            case ENCRYP_ALGO_PH1:
                isakmp_sa->encryalgo = (IPsecEncryptionAlgo)value;
                break;
            case CERT_TYPE_PH1:
                isakmp_sa->certType = (ISAKMPCertType)value;
                break;
            case AUTH_MEHTOD_PH1:
                isakmp_sa->authmethod = (ISAKMPAuthMethod)value;
                break;
            case HASH_ALGO_PH1:
                isakmp_sa->hashalgo = (ISAKMPHashAlgo)value;
                break;
            case GRP_DESC_PH1:
                isakmp_sa->groupdes = (ISAKMPGrpDesc)value;
                break;
            case SA_LIFE_PH1:
                isakmp_sa->life = value;
                break;
            default:
                break;
        }
    }
    isakmp_sa->processdelay = ISAKMPGetProcessDelay(node, nodeconfig);
}



//
// FUNCTION   :: ISAKMPValidatePayloadProposal
// LAYER      :: Network
// PURPOSE    :: processing of Payload Proposal Received
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylProp* prop_payload - proposal payload to validate.
// RETURN     :: UInt16 - validation result
// NOTE       ::

UInt16 ISAKMPValidatePayloadProposal(ISAKMPNodeConf* nodeconfig,
                                     ISAKMPPaylProp* prop_payload)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    char* spi = NULL;
    ISAKMPGenericHeader gen_header ;
    UInt16 notify_type = 0;
    ISAKMPProposal* proposal = NULL;
    ISAKMPProtocol* protocol = NULL;
    ISAKMPPaylTrans* transform = NULL;
    IPsecProtocol ipsecProto;
    char*    currentOffset = NULL;

    ISAKMPPaylProp*  payload = prop_payload;

    UInt32 moreprop = 1;
    while (moreprop)
    {
        gen_header = payload->h;

        //general header Processing
        switch (gen_header.np_type)
        {
            case ISAKMP_NPTYPE_P:
                moreprop = 1;
                break;
            case ISAKMP_NPTYPE_NONE:
                moreprop = 0;
                break;
            default:
                return ISAKMP_NTYPE_INVALID_PAYLOAD_TYPE;
                break;
        }//switch

        if (gen_header.reserved != 0)
        {
            return ISAKMP_NTYPE_INVALID_RESERVED_FIELD;
        }

        switch (payload->prot_id)
        {
            case IPSEC_ISAKMP:
                ipsecProto = IPSEC_ISAKMP;
                break;
            case IPSEC_AH:
                ipsecProto = IPSEC_AH;
                break;
            case IPSEC_ESP:
                ipsecProto = IPSEC_ESP;
                break;
            default:
                return ISAKMP_NTYPE_INVALID_PROTOCOL_ID;
                break;
        }//switch

        if (exch->phase == PHASE_2)
        {
            proposal = nodeconfig->phase2proposals;
            while (proposal)
            {
                if (proposal->proposalId == payload->p_no)
                {
                    //proposal matched now match the protocol
                    protocol = proposal->protocol;
                    while (protocol)
                    {
                        if (protocol->protocolId == payload->prot_id)
                        {
                            //protocol matched
                            break;
                        }
                        protocol = protocol->nextproto;
                    }
                    if (protocol != NULL)
                    {
                        break;
                    }
                }
                proposal = proposal->nextproposal;
            }
            if (proposal == NULL)
            {
                currentOffset = (char*)payload;
                currentOffset = currentOffset + payload->h.len;
                payload = (ISAKMPPaylProp*)currentOffset;
                continue;
            }
        }

        currentOffset = (char*)payload;
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload
            + payload->spi_size;
        transform = (ISAKMPPaylTrans*)(currentOffset);

        //validate all the transform received
        UInt32 i = 0;
        for (; i < payload->num_t; i++)
        {
            if (exch->phase == PHASE_1)
            {
                notify_type = ISAKMPValidatePayloadTransform(
                    nodeconfig, transform, ipsecProto, NULL);
            }
            else
            {
                notify_type = ISAKMPValidatePayloadTransform(
                    nodeconfig, transform, ipsecProto, protocol);
            }
            if (notify_type != 0)
            {
                return notify_type;
            }
            currentOffset = (char*)transform;
            currentOffset = currentOffset + transform->h.len;
            transform = (ISAKMPPaylTrans*)currentOffset;
        }

        //save the selected proposal  among all received proposals
        if (exch->prop_selected == NULL && exch->trans_selected != NULL)
        {
            exch->prop_selected = payload;
            exch->proto = ipsecProto;
            if (exch->phase == PHASE_2)
            {
                spi = (char*)(payload + 1);
                sscanf(spi, "%d", &exch->SPI); //assume spi size is 4 byte
            }
        }

        currentOffset = (char*)payload;
        currentOffset = currentOffset + payload->h.len;
        payload = (ISAKMPPaylProp*)currentOffset;

    }
    return notify_type;
}

//
// FUNCTION   :: ISAKMPValidatePayloadSA
// LAYER      :: Network
// PURPOSE    :: processing of SA Proposal Received
// PARAMETERS :: ISAKMPStats* &stats - isakmp stats
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylSA* payload - SA payload to be validated
// RETURN     :: UInt16 - validation result
// NOTE       ::

UInt16 ISAKMPValidatePayloadSA(ISAKMPStats* &stats,
                           ISAKMPNodeConf* nodeconfig,
                           ISAKMPPaylSA* payload)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    ISAKMPGenericHeader gen_header = payload->h;
    char* currentOffset;
    UInt16 notify_type = 0;

    stats->numPayloadSARcv++;

    //general header Processing
    if (gen_header.reserved != 0)
    {
        return ISAKMP_NTYPE_INVALID_RESERVED_FIELD;
    }
    if (payload->doi != exch->doi)
    {
        return ISAKMP_NTYPE_DOI_NOT_SUPPORTED;
    }
    if (payload->sit != IPSEC_SIT_IDENTITY_ONLY
        && payload->sit != IPSEC_SIT_SECRECY
        && payload->sit != IPSEC_SIT_INTEGRITY)
    {
        return ISAKMP_NTYPE_SITUATION_NOT_SUPPORTED;
    }

    //validate proposal payload
    notify_type = ISAKMPValidatePayloadProposal(
        nodeconfig, (ISAKMPPaylProp*)(payload + 1));
    if (notify_type != 0)
    {
        return notify_type;
    }

    if (exch->prop_selected == NULL)
    {
        return ISAKMP_NTYPE_NO_PROPOSAL_CHOSEN;
    }
    currentOffset = (char*)payload;
    currentOffset = currentOffset + gen_header.len;

    //validate other payloads
    notify_type = ISAKMPValidatepayload(
        stats, nodeconfig, gen_header.np_type, currentOffset);

    return notify_type;
}

//
// FUNCTION   :: ISAKMPReceiveDeleteMessage
// LAYER      :: Network
// PURPOSE    :: Processing of Delete Payload received
// PARAMETERS :: Node* node,
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylNotif* nonce_payload - delete payload received
// RETURN     :: UInt16 - error or Notification type
// NOTE       ::

static
UInt16 ISAKMPReceiveDeleteMessage(Node* node,
                                   Message* msg,
                                   ISAKMPNodeConf* nodeconfig,
                                   unsigned char expectedtype)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    UInt32 packetsize = MESSAGE_ReturnActualPacketSize(msg);
    ISAKMPHeader*   isakmp_recvheader;

    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    if (isakmp_recvheader->np_type != expectedtype)
    {
        //either get duplicate packet or some invalid packet
        return ISAKMP_DROP_Message;
    }

    //general Message Processing
    if (packetsize != isakmp_recvheader->len)
    {
        return ISAKMP_NTYPE_UNEQUAL_PAYLOAD_LENGTHS;
    }
    //ISAKMP Header Processing

    if (isakmp_recvheader->flags & ISAKMP_FLAG_INVALID)
    {
        return ISAKMP_NTYPE_INVALID_FLAGS;
    }

    if (isakmp_recvheader->flags & ISAKMP_FLAG_E)
    {
        // Decrypt the message payload using Phase-1 encryption
        // algorithm and key established
        // Not required for Simulation
    }

    ISAKMPPaylDel* delete_payload = NULL;
    ISAKMPPaylHash* recv_hash_payload = NULL;
    char* currentOffset = NULL;

    //check for message type
    if (isakmp_recvheader->np_type == ISAKMP_NPTYPE_HASH)
    {
        recv_hash_payload = (ISAKMPPaylHash*)(isakmp_recvheader + 1);
        currentOffset = (char*)recv_hash_payload;
        currentOffset = currentOffset + recv_hash_payload->h.len;

        stats->numPayloadHashRcv++;

        //now getting delete payload
        delete_payload = (ISAKMPPaylDel*)(currentOffset);
    }
    else
    {
        //extract the delete message
        delete_payload = (ISAKMPPaylDel*)(isakmp_recvheader + 1);
    }

    ISAKMPGenericHeader gen_header = delete_payload->h;

    stats->numPayloadDeleteRcv++;

    //general header Processing
    if (gen_header.reserved != 0)
    {
        return ISAKMP_DROP_Message;
    }

    UInt32 SPI = *(UInt32*)(delete_payload + 1);

    ISAKMPPhase2List* phase2_list = nodeconfig->phase2_list;

    while (phase2_list)
    {
        IPSEC_SA* &ipsec_sa = phase2_list->phase2->ipsec_sa;

        if (phase2_list->is_ipsec_sa
            && ipsec_sa->doi == delete_payload->doi
            && ipsec_sa->proto == delete_payload->prot_id
            && ipsec_sa->SPI == SPI)
        {
            phase2_list->is_ipsec_sa = FALSE;

            //if (ip->isIPsecEnabled == TRUE)
            {
                IPsecSecurityAssociationEntry* sa = NULL;
                IPsecSecurityPolicyEntry* sp = NULL;

                //Remove SA from database
                sa = IPsecRemoveMatchingSAfromSAD(node, ipsec_sa->proto,
                                     nodeconfig->peerAddress, ipsec_sa->SPI);

                sp = IPsecGetMatchingSP(
                    phase2_list->phase2->localNetwork,
                    phase2_list->phase2->peerNetwork,
                    phase2_list->phase2->upperProtocol,
                    ip->interfaceInfo[nodeconfig->interfaceIndex]->spdOUT->spd);

                IPsecRemoveSAfromSP(sp, sa);

                sa = IPsecRemoveMatchingSAfromSAD(node, ipsec_sa->proto,
                     nodeconfig->nodeAddress, ipsec_sa->SPI);

                sp = IPsecGetMatchingSP(
                    phase2_list->phase2->peerNetwork,
                    phase2_list->phase2->localNetwork,
                    phase2_list->phase2->upperProtocol,
                    ip->interfaceInfo[nodeconfig->interfaceIndex]->spdIN->spd);

                IPsecRemoveSAfromSP(sp, sa);
            }

            MEM_free(ipsec_sa);
            ipsec_sa = NULL;
            return 0;
        }
        phase2_list = phase2_list->next;
    }

    return ISAKMP_DROP_Message;
}

//
// FUNCTION   :: ISAKMPProcessValidationResult
// LAYER      :: Network
// PURPOSE    :: Processing message validation result
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               UInt16 - validation  result
// RETURN     :: void
// NOTE       ::

static
void ISAKMPProcessValidationResult(Node* node,
                                   ISAKMPNodeConf* nodeconfig,
                                   UInt16 notify_type)
{
    UInt32 i_r = nodeconfig->exchange->initiator;
    unsigned char phase = nodeconfig->exchange->phase;

    //if not unidentified message
    if (notify_type != ISAKMP_DROP_Message)
    {
         //received msg is Error notification msg
        if (notify_type == ISAKMP_DROP_EXchange)
        {
            ISAKMPDropExchange(node, nodeconfig);
        }
        else    // some error found in header or payload fields
        {
            ISAKMPInfoExchange(node, nodeconfig, notify_type);
            ISAKMPDropExchange(node, nodeconfig);
        }

        //resume other phase-2 establishments
        if (phase == PHASE_2)
        {
            if (i_r == INITIATOR)
            {
                nodeconfig->current_pointer_list =
                    nodeconfig->current_pointer_list->next;

                if (nodeconfig->current_pointer_list)
                {
                   nodeconfig->phase2 =
                       nodeconfig->current_pointer_list->phase2;
                   ISAKMPSetUp_Negotiation(
                        node, nodeconfig, NULL, 0, 0, i_r, PHASE_2);
                }
            }
        }
    }
}

//
// FUNCTION   :: ISAKMPValidateMessage
// LAYER      :: Network
// PURPOSE    :: Processing of a ISAKMP msg received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - received isakmm message
// RETURN     :: UInt16 - validation  result
// NOTE       ::

static
UInt16 ISAKMPValidateMessage(Node* node,
                             ISAKMPNodeConf* nodeconfig,
                             Message* msg,
                             unsigned char expectedtype)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    UInt32 packetsize = MESSAGE_ReturnActualPacketSize(msg);
    ISAKMPExchange* exch = nodeconfig->exchange;
    ISAKMPHeader*   isakmp_recvheader;
    char* currentOffset = NULL;

    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    if (isakmp_recvheader->np_type != expectedtype)
    {
        //check for hash message
        if (isakmp_recvheader->np_type == ISAKMP_NPTYPE_HASH)
        {
            //extracting Hash payload from isakmp recv message
            ISAKMPPaylHash* recv_hash_payload =
                                    (ISAKMPPaylHash*)(isakmp_recvheader + 1);
            currentOffset = (char*)recv_hash_payload;
            currentOffset = currentOffset + recv_hash_payload->h.len;

            //check for next message type
            if (recv_hash_payload->h.np_type == ISAKMP_NPTYPE_D)
            {
                ISAKMPReceiveDeleteMessage(
                    node, msg, nodeconfig, ISAKMP_NPTYPE_HASH);
                return ISAKMP_DROP_Message;
            }
        }
        //check for delete message
        else if (isakmp_recvheader->np_type == ISAKMP_NPTYPE_D)
        {
            ISAKMPReceiveDeleteMessage(
                node, msg, nodeconfig, ISAKMP_NPTYPE_D);
            return ISAKMP_DROP_Message;
        }
        else if (isakmp_recvheader->np_type != ISAKMP_NPTYPE_N)
        {
            //either got duplicate packet or some invalid packet
            return ISAKMP_DROP_Message;
        }
    }

    //general Message Processing
    if (packetsize != isakmp_recvheader->len)
    {
        return ISAKMP_NTYPE_UNEQUAL_PAYLOAD_LENGTHS;
    }
    //ISAKMP Header Processing
    if (memcmp(
        exch->init_cookie, isakmp_recvheader->init_cookie, COOKIE_SIZE)
        || memcmp(
        exch->resp_cookie, isakmp_recvheader->resp_cookie, COOKIE_SIZE))
    {
        return ISAKMP_NTYPE_INVALID_COOKIE;
    }
    if (isakmp_recvheader->exch_type != exch->exchType)
    {
        return ISAKMP_NTYPE_INVALID_EXCHANGE_TYPE;
    }
    if (isakmp_recvheader->msgid != exch->msgid)
    {
        return ISAKMP_NTYPE_INVALID_MESSAGE_ID;
    }
    if (isakmp_recvheader->flags & ISAKMP_FLAG_INVALID)
    {
        return ISAKMP_NTYPE_INVALID_FLAGS;
    }

    if (isakmp_recvheader->flags & ISAKMP_FLAG_E)
    {
        // Decrypt the message payload using Phase-1 encryption
        // algorithm and key established
        // Not required for Simulation
    }
    if (isakmp_recvheader->flags & ISAKMP_FLAG_C)
    {
        exch->waitforcommit = TRUE;
    }
    currentOffset = (char*)(isakmp_recvheader + 1);

    return ISAKMPValidatepayload(
        stats, nodeconfig, isakmp_recvheader->np_type, currentOffset);
}

//
// FUNCTION   :: ISAKMPValidatePayloadID
// LAYER      :: Network
// PURPOSE    :: Processing of a ID payload received
// PARAMETERS :: ISAKMPStats* &stats - isakmp stats
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylId* id_payload - Identity payload to be validated
// RETURN     :: UInt16 - validation result
// NOTE       :: actual Validation of ID type is not been implemented

UInt16 ISAKMPValidatePayloadID(ISAKMPStats* &stats,
                           ISAKMPNodeConf* nodeconfig,
                           ISAKMPPaylId* id_payload)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    ISAKMPGenericHeader gen_header = id_payload->h;
    char* currentOffset = NULL;
    UInt16         notify_type = 0;
    UInt16         len_id = 0;

    stats->numPayloadIdRcv++;

    // general header Processing
    if (gen_header.reserved != 0)
    {
        return ISAKMP_NTYPE_INVALID_RESERVED_FIELD;
    }

    currentOffset = (char*)id_payload;
    currentOffset = currentOffset + gen_header.len;

    notify_type = ISAKMPValidatepayload(
        stats, nodeconfig, gen_header.np_type, currentOffset);

    if (notify_type != 0)
    {
        return notify_type;
    }

    len_id = id_payload->h.len - SIZE_ID_Payload;

    // Recalculate currentOffset as it will be used while assigning
    // values to exch->IDr or exch->IDi
    currentOffset = (char*)id_payload;
    currentOffset = currentOffset + SIZE_ID_Payload;

    unsigned char aLocalIdType = id_payload->id_data.ipsec_doi_data.id_type;

    if (nodeconfig->exchange->initiator == RESPONDER
    && nodeconfig->exchange->phase == PHASE_2)
    {
        Address*  localNetwork = (Address *)(id_payload + 1);
        Address*  localNetMask = (Address *)(localNetwork + 1);
        unsigned char upperProtocol =
            id_payload->id_data.ipsec_doi_data.protocol_id;

        ISAKMPPhase2List* phase2_list = nodeconfig->phase2_list;

        while (phase2_list)
        {
            if (aLocalIdType == phase2_list->phase2->remoteIdType
                && (localNetwork->interfaceAddr.ipv4 ==
                    phase2_list->phase2->peerNetwork.interfaceAddr.ipv4 ||
                    localNetwork->interfaceAddr.ipv4 == ANY_DEST ||
                    phase2_list->phase2->peerNetwork.interfaceAddr.ipv4 ==
                    ANY_DEST)
                && (localNetMask->interfaceAddr.ipv4 ==
                    phase2_list->phase2->peerNetMask.interfaceAddr.ipv4 ||
                    localNetMask->interfaceAddr.ipv4 == 0 ||
                    phase2_list->phase2->peerNetMask.interfaceAddr.ipv4 == 0)
                && upperProtocol == phase2_list->phase2->upperProtocol)
            {
                nodeconfig->phase2 = phase2_list->phase2;
                nodeconfig->phase2->ipsec_sa = nodeconfig->ipsec_sa;
                nodeconfig->ipsec_sa = NULL;
                nodeconfig->current_pointer_list = phase2_list;
                exch->flags = nodeconfig->phase2->flags;
                break;
            }
            else
            {
                phase2_list = phase2_list->next;
            }
        }
        if (phase2_list == NULL)
        {
            return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
        }
    }
    else
    {
        Address*  localaddress = (Address *)(id_payload + 1);
        if (aLocalIdType != ISAKMP_ID_IPV4_ADDR
            || localaddress->interfaceAddr.ipv4 != nodeconfig->peerAddress)
        {
            return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
        }
    }

    if (exch->initiator == INITIATOR)
    {
        exch->IDr = (char*)MEM_malloc(len_id + 1);
        memcpy(exch->IDr, currentOffset, len_id);
        exch->IDr[len_id] = '\0';
    }
    else
    {
        exch->IDi = (char*)MEM_malloc(len_id + 1);
        memcpy(exch->IDi, currentOffset, len_id);
        exch->IDi[len_id] = '\0';
    }

    return notify_type;
}

//
// FUNCTION   :: ISAKMPValidatePayloadSIG
// LAYER      :: Network
// PURPOSE    :: Processing of a Signature payload received
// PARAMETERS :: ISAKMPStats* &stats - isakmp stats
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylSig* sig_payload - Signature payload to validate
// RETURN     :: UInt16 - validation result
// NOTE       :: actual Validation of auth data is't been implemented

UInt16 ISAKMPValidatePayloadSIG(ISAKMPStats* &stats,
                            ISAKMPNodeConf* nodeconfig,
                            ISAKMPPaylSig* sig_payload)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    ISAKMPGenericHeader gen_header = sig_payload->h;
    char* currentOffset = NULL;
    UInt16    notify_type = 0;
    UInt16    len_sig = 0;

    stats->numPayloadAuthRcv++;

    // general header Processing
    if (gen_header.reserved != 0)
    {
        return ISAKMP_NTYPE_INVALID_RESERVED_FIELD;
    }
    currentOffset = (char*)sig_payload;
    currentOffset = currentOffset + gen_header.len;

    notify_type = ISAKMPValidatepayload(
        stats, nodeconfig, gen_header.np_type, currentOffset);
    if (notify_type != 0)
    {
        return notify_type;
    }

    len_sig = sig_payload->h.len - SIZE_SIG_Payload;
    currentOffset = (char*)(sig_payload + 1);
    if (exch->initiator == INITIATOR)
    {
        exch->sig_r = (char*)MEM_malloc(len_sig + 1);
        memcpy(exch->sig_r, currentOffset, len_sig);
        exch->sig_r[len_sig] = '\0';
    }
    else
    {
        exch->sig_i = (char*)MEM_malloc(len_sig + 1);
        memcpy(exch->sig_i, currentOffset, len_sig);
        exch->sig_i[len_sig] = '\0';
    }

    return notify_type;
}



//
// FUNCTION   :: ISAKMPValidatePayloadHash
// LAYER      :: Network
// PURPOSE    :: Processing of a Hash payload received
// PARAMETERS :: ISAKMPStats* &stats - isakmp stats
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylHash* hash_payload - Hash payload to validate
// RETURN     :: UInt16 - validation result
// NOTE       :: actual Validation of auth data is't been implemented

UInt16 ISAKMPValidatePayloadHash(ISAKMPStats* &stats,
                            ISAKMPNodeConf* nodeconfig,
                            ISAKMPPaylHash* hash_payload)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    ISAKMPGenericHeader gen_header = hash_payload->h;
    char* currentOffset = NULL;
    UInt16    notify_type = 0;
    UInt16    len_hash = 0;

    stats->numPayloadHashRcv++;

    // general header Processing
    if (gen_header.reserved != 0)
    {
        return ISAKMP_NTYPE_INVALID_RESERVED_FIELD;
    }
    currentOffset = (char*)hash_payload;
    currentOffset = currentOffset + gen_header.len;

    notify_type = ISAKMPValidatepayload(
        stats, nodeconfig, gen_header.np_type, currentOffset);
    if (notify_type != 0)
    {
        return notify_type;
    }

    len_hash = hash_payload->h.len - SIZE_HASH_Payload;
    currentOffset = (char*)(hash_payload + 1);
    if (exch->initiator == INITIATOR)
    {
        exch->hash_r = (char*)MEM_malloc(len_hash + 1);
        memcpy(exch->hash_r, currentOffset, len_hash);
        exch->hash_r[len_hash] = '\0';
    }
    else
    {
        exch->hash_i = (char*)MEM_malloc(len_hash + 1);
        memcpy(exch->hash_i, currentOffset, len_hash);
        exch->hash_i[len_hash] = '\0';
    }

    return notify_type;
}


//
// FUNCTION   :: ISAKMPValidatePayloadCert
// LAYER      :: Network
// PURPOSE    :: Processing of a Certificate payload received
// PARAMETERS :: ISAKMPStats* &stats - isakmp stats
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylCert* cert_payload - Cert payload to validate
// RETURN     :: UInt16 - validation result
// NOTE       :: actual Validation of auth data is't been implemented

UInt16 ISAKMPValidatePayloadCert(ISAKMPStats* &stats,
                            ISAKMPNodeConf* nodeconfig,
                            ISAKMPPaylCert* cert_payload)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    ISAKMPGenericHeader gen_header = cert_payload->h;
    char* currentOffset = NULL;
    UInt16    notify_type = 0;
    UInt16    len_cert = 0;

    stats->numPayloadCertRcv++;

    // general header Processing
    if (gen_header.reserved != 0)
    {
        return ISAKMP_NTYPE_INVALID_RESERVED_FIELD;
    }

    //validate certificate type
    if (IsValidCertType(cert_payload->encode))
    {
        return ISAKMP_NTYPE_INVALID_CERTIFICATE;
    }

    currentOffset = (char*)cert_payload;
    currentOffset = currentOffset + gen_header.len;

    notify_type = ISAKMPValidatepayload(
        stats, nodeconfig, gen_header.np_type, currentOffset);
    if (notify_type != 0)
    {
        return notify_type;
    }

    len_cert = cert_payload->h.len - (UInt16)(SIZE_CERT_Payload);

    //this should be only when cert_payload contains certificate data
    if (len_cert > 0)
    {
        currentOffset = (char*)(cert_payload + 1);
        if (exch->initiator == INITIATOR)
        {
            exch->cert_r = (char*)MEM_malloc(len_cert + 1);
            memcpy(exch->cert_r, currentOffset, len_cert);
            exch->cert_r[len_cert] = '\0';
        }
        else
        {
            exch->cert_i = (char*)MEM_malloc(len_cert + 1);
            memcpy(exch->cert_i, currentOffset, len_cert);
            exch->cert_i[len_cert] = '\0';
        }
    }
    return notify_type;
}



//
// FUNCTION   :: ISAKMPRecvKEIDAuth
// LAYER      :: Network
// PURPOSE    :: Processing of a KE_ID_AUTH message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - received isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvKEIDAuth(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;

    UInt16    notify_type;
    notify_type =
        ISAKMPValidateMessage(node, nodeconfig, msg, ISAKMP_NPTYPE_KE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if (exch->exchType == ISAKMP_ETYPE_BASE && exch->initiator == INITIATOR)
    {
            ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }

    if (exch->exchType == ISAKMP_ETYPE_BASE
        && exch->initiator == INITIATOR)
    {
        if (exch->waitforcommit == TRUE)
        {
            exch->step++;
            return ;
        }
        else if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
    }
    exch->step++;
    (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}

//
// FUNCTION   :: ISAKMPRecvAuth
// LAYER      :: Network
// PURPOSE    :: Processing of a  AUTH message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - received isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvAuth(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    UInt16    notify_type;
    ISAKMPExchange* exch = nodeconfig->exchange;

    notify_type = ISAKMPValidateMessage(node,
                                        nodeconfig,
                                        msg,
                                        ISAKMP_NPTYPE_SIG);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if ((exch->exchType == ISAKMP_ETYPE_AGG && exch->initiator == RESPONDER))
    {
        if (exch->waitforcommit == TRUE)
        {
            exch->step++;
            return ;
        }
        else if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
    }

    exch->step++;
    (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}

//
// FUNCTION   :: ISAKMPRecvIDAuth
// LAYER      :: Network
// PURPOSE    :: Processing of a  ID_AUTH message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - received isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvIDAuth(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;

    UInt16    notify_type;
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_ID);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if ((exch->exchType == ISAKMP_ETYPE_IDENT
        && exch->initiator == INITIATOR)
        || (exch->exchType == ISAKMP_ETYPE_AUTH
        && exch->initiator == RESPONDER))
    {
        if (exch->waitforcommit == TRUE)
        {
            exch->step++;
            return ;
        }
        else if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
     }

     exch->step++;
     (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}

//
// FUNCTION   :: ISAKMPSavePhase1Exchange
// LAYER      :: Network
// PURPOSE    :: Save the ISAKMP SA negotiated
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
// RETURN     :: void
// NOTE       ::

void ISAKMPSavePhase1Exchange(Node* node, ISAKMPNodeConf* nodeconfig)
{
#ifdef ISAKMP_SAVE_PHASE1

    char filename[16] = {'\0'};
    char buff[BUFFER_SIZE];

    ISAKMPExchange* exch = nodeconfig->exchange;
    ISAKMP_SA* isakmp_sa = nodeconfig->phase1->isakmp_sa;

    sprintf(filename, "node%d.ipsec", node->nodeId);
    FILE* fp = fopen(filename, "a+");

    char addrStr[MAX_STRING_LENGTH];

    IO_ConvertIpAddressToString(
        nodeconfig->nodeAddress, addrStr);

    sprintf(buff, "\n\nNode %s", addrStr);
    fwrite(buff, strlen(buff), 1, fp);

    IO_ConvertIpAddressToString(
        nodeconfig->peerAddress, addrStr);

    sprintf(buff, " Peer %s\n", addrStr);
    fwrite(buff, strlen(buff), 1, fp);

    fwrite("ISAKMP SA\n", strlen("ISAKMP SA\n"), 1, fp);
    fwrite("#------------------\n", strlen("#------------------\n"), 1, fp);

    sprintf(buff, "INITIATOR_COOKIE %s\n", isakmp_sa->init_cookie);
    fwrite(buff, strlen(buff), 1, fp);

    sprintf(buff, "RESPONDER_COOKIE %s\n", isakmp_sa->resp_cookie);
    fwrite(buff, strlen(buff), 1, fp);

    if (isakmp_sa->proto)
    {
        sprintf(buff, "PROTOCOL %s\n",
            IPsecGetSecurityProtocolName(isakmp_sa->proto));
        fwrite(buff, strlen(buff), 1, fp);
    }

    sprintf(buff, "DOI %s\n", IPsecGetDOIName(isakmp_sa->doi));
    fwrite(buff, strlen(buff), 1, fp);

    if (isakmp_sa->encryalgo)
    {
        sprintf(buff, "ENCRYP_ALGO %s\n",
            IPsecGetEncryptionAlgoName(isakmp_sa->encryalgo));
        fwrite(buff, strlen(buff), 1, fp);
    }
    if (isakmp_sa->authmethod)
    {
        sprintf(buff, "AUTH_METHOD %s\n",
            IPsecGetAuthMethodName(isakmp_sa->authmethod));
        fwrite(buff, strlen(buff), 1, fp);
    }
    if (isakmp_sa->hashalgo)
    {
        sprintf(buff, "HASH_ALGO %s\n",
            IPsecGetHashAlgoName(isakmp_sa->hashalgo));
        fwrite(buff, strlen(buff), 1, fp);
    }
    if (isakmp_sa->groupdes)
    {
        sprintf(buff, "GROUP_DESC %s\n",
            ISAKMPGetGrpDescName(isakmp_sa->groupdes));
        fwrite(buff, strlen(buff), 1, fp);
    }

    sprintf(buff, "LIFE %d\n", isakmp_sa->life);
    fwrite(buff, strlen(buff), 1, fp);

    byte hexstr[MAX_STRING_LENGTH];
    bitstream_to_hexstr(hexstr, (const byte *)exch->Key, KEY_SIZE);

    sprintf(buff, "PHASE1_KEY %s\n", hexstr);
    fwrite(buff, strlen(buff), 1, fp);

    fclose(fp);

#endif //ISAKMP_SAVE_PHASE1

    // though not supported yet
    // one should set refresh timer here according to the ISAKMP SA life
    MEM_free(nodeconfig->exchange->IDi);
    MEM_free(nodeconfig->exchange->IDr);
    MEM_free(nodeconfig->exchange->sig_i);
    MEM_free(nodeconfig->exchange->sig_r);
    MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);

    MEM_free(nodeconfig->exchange);
    nodeconfig->exchange = NULL;
}

//
// FUNCTION   :: ISAKMPGetNumHostBitsfromSubnetMask
// LAYER      :: Network
// PURPOSE    :: Get Number of HostBits from SubnetMask
// PARAMETERS :: NodeAddress subnetMask
// RETURN     :: int - number of host bits
// NOTE       :: this function is same as
//            :: AddressMap_ConvertSubnetMaskToNumHostBits in mapping.cpp

static
int ISAKMPGetNumHostBitsfromSubnetMask(NodeAddress subnetMask)
{
    int numHostBits = 0;
    unsigned mask = 1;

    if (subnetMask == 0)
    {
        // all the 32 bits of ipv4 address are host bits
        return 32;
    }

    while (1)
    {
        if (subnetMask & mask)
        {
            return numHostBits;
        }
        numHostBits++;
        mask = mask << 1;
    }
}
//
// FUNCTION   :: ISAKMPInitIPsecParam
// LAYER      :: Network
// PURPOSE    :: Initialize IPsec Parameters using negotiated IPSEC SA
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
// RETURN     :: void
// NOTE       ::

static
void ISAKMPInitIPsecParam(Node* node, ISAKMPNodeConf* nodeconfig)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    Int32 interfaceIndex = nodeconfig->interfaceIndex;
    IpInterfaceInfoType* intfInfo = ip->interfaceInfo[interfaceIndex];

    // check whether the ipsec is enabled to use ipsec sa establishd by
    // isakmp protocol
    //if (ip->isIPsecEnabled != TRUE)
    //{
    //    return;
    //}
    char authKey[MAX_STRING_LENGTH] = {'\0'};
    char encryptionKey[MAX_STRING_LENGTH] = {'\0'};
    IPsecProcessingRate rateParams;
    NodeAddress srcRange;
    Int32 numSrcHostBits;
    NodeAddress destRange;
    Int32 numDestHostBits;
    UInt16 srcPortNumber = 0;
    UInt16 destPortNumber = 0;
    IPsecPolicy policy;
    IPsecSecurityPolicyEntry* newSP = NULL;
    IPsecSecurityAssociationEntry* newSA = NULL;
    char addrStr1[MAX_STRING_LENGTH];
    IPsecSelectorAddrList addrList;
    size_t index = 0;
    ISAKMPExchange* exch = nodeconfig->exchange;
    IPSEC_SA* ipsec_sa = nodeconfig->phase2->ipsec_sa;
    IPsecSelectorAddrList tempAddressList;

    if (ip->sad == NULL)
    {
        IPsecSADInit(&ip->sad);
    }
    if (intfInfo->spdIN == NULL)
    {
        IPsecSPDInit(&intfInfo->spdIN);
    }
    if (intfInfo->spdOUT == NULL)
    {
        IPsecSPDInit(&intfInfo->spdOUT);
    }

    strcpy(encryptionKey, exch->Key);
    strcpy(authKey, exch->Key);

    rateParams.desCbcRate = IPSEC_DES_CBC_PROCESSING_RATE;
    rateParams.hmacMd596Rate = IPSEC_HMAC_MD5_96_PROCESSING_RATE;
    rateParams.hmacSha196Rate = IPSEC_HMAC_SHA_1_96_PROCESSING_RATE;

    memset(&addrList, 0, sizeof(IPsecSelectorAddrList));

    IO_ConvertIpAddressToString((NodeAddress) ipsec_sa->SPI, addrStr1);

    newSA = IPsecCreateNewSA(
        ipsec_sa->mode,
        nodeconfig->nodeAddress,
        nodeconfig->peerAddress,
        ipsec_sa->proto,
        addrStr1,
        ipsec_sa->authalgo,
        authKey,
        nodeconfig->phase1->isakmp_sa->encryalgo,
        encryptionKey,
        &rateParams);

    // Assign name address map
    struct IPsecSelectorAddrListEntry* newListEntry;
    newListEntry = (struct IPsecSelectorAddrListEntry*)
                    MEM_malloc(sizeof(struct
                    IPsecSelectorAddrListEntry));
    newListEntry->src = nodeconfig->nodeAddress;
    newListEntry->dest = nodeconfig->peerAddress;
    newListEntry->mode = ipsec_sa->mode;
    newListEntry->securityProtocol = ipsec_sa->proto;
    newListEntry->saEntry = newSA;
    addrList.push_back(newListEntry);

     // Add the newSA to SA database
    IPsecSADAddEntry(node, newSA);

    srcRange = nodeconfig->phase2->localNetwork.interfaceAddr.ipv4;
    numSrcHostBits = ISAKMPGetNumHostBitsfromSubnetMask(
        nodeconfig->phase2->localNetMask.interfaceAddr.ipv4);
    destRange = nodeconfig->phase2->peerNetwork.interfaceAddr.ipv4;
    numDestHostBits = ISAKMPGetNumHostBitsfromSubnetMask(
        nodeconfig->phase2->peerNetMask.interfaceAddr.ipv4);

    // Create a SP for the outbound direction

    policy = IPSEC_USE;

    if (!intfInfo->spdOUT->spd->empty())
    {
        newSP = IPsecGetMatchingSP(nodeconfig->phase2->localNetwork,
                                   nodeconfig->phase2->peerNetwork,
                                   nodeconfig->phase2->upperProtocol,
                                   intfInfo->spdOUT->spd);
    }

    if (newSP == NULL)
    {
        vector<IPsecSAFilter*> saFilter;

        IPsecSAFilter* filter;
        filter = (IPsecSAFilter*) MEM_malloc(sizeof(IPsecSAFilter));
        memset(filter, 0, sizeof(IPsecSAFilter));

        filter->ipsecProto = ipsec_sa->proto;
        filter->ipsecLevel = (enum IPsecLevel) IPSEC_LEVEL_REQUIRE;
        filter->ipsecMode = ipsec_sa->mode;
        filter->tunnelSrcAddr = nodeconfig->nodeAddress;
        filter->tunnelDestAddr = nodeconfig->peerAddress;
        saFilter.push_back(filter);

        newSP = IPsecCreateNewSP(
            node,
            interfaceIndex,
            srcRange,
            numSrcHostBits,
            destRange,
            numDestHostBits,
            srcPortNumber,
            destPortNumber,
            nodeconfig->phase2->upperProtocol,
            IPSEC_OUT,
            policy,
            saFilter,
            &rateParams);

         // Add the newSP to security policy database
        if (!IPsecIsDuplicateSP(node, (int) interfaceIndex, newSP))
        {
            IPsecSPDAddEntry(node, interfaceIndex, newSP);
            tempAddressList = addrList;

            // Update SA pointer in SPDOut
            // Iterate through each of the sa filters configured in the SP
            // entry. Compare it against the SA addr map on that node. Point
            // to that entry in addrMap that matches the SA filters.
            for (int i = 0; i < node->numberInterfaces; i++)
            {
                IpInterfaceInfoType* intfInfo = ip->interfaceInfo[i];


                if (intfInfo->spdOUT)
                {
                    IPsecSecurityPolicyInformation* spdInfo = intfInfo->spdOUT;
                    IPsecSecurityPolicyDatabase* spd;
                    spd = spdInfo->spd;

                    while (index < spd->size())
                    {
                        IPsecSecurityPolicyEntry* entryPtr = spd->at(index);

                        for (size_t i = 0;
                             i < entryPtr->saFilter.size();
                             i++)
                        {
                            BOOL numSAIncremented = FALSE;

                            // SP for Transport mode
                            if (entryPtr->saFilter.at(i)->ipsecMode
                                == IPSEC_TRANSPORT)
                            {
                                for (size_t j = 0;
                                     j < tempAddressList.size();
                                     j++)
                                {
                                    if (IPsecCheckIfTransportModeSASelectorsMatch
                                        (entryPtr, *(tempAddressList.at(j)),
                                        (int) i))
                                    {
                                        entryPtr->saPtr[i] =
                                                tempAddressList.at(j)->saEntry;
                                        if (!numSAIncremented)
                                        {
                                            entryPtr->numSA++;
                                            numSAIncremented = TRUE;
                                        }
                                    }
                                }
                                tempAddressList = addrList;
                            }// if close

                            // SP for Tunnel mode
                            if (entryPtr->saFilter.at(i)->ipsecMode
                                == IPSEC_TUNNEL)
                            {
                                for (size_t j = 0;
                                     j < tempAddressList.size();
                                     j++)
                                {
                                    if (IPsecCheckIfTunnelModeSASelectorsMatch
                                        (entryPtr,
                                        *(tempAddressList.at(j)),
                                        (int) i))
                                    {
                                        entryPtr->saPtr[i] =
                                            tempAddressList.at(j)->saEntry;
                                        if (!numSAIncremented)
                                        {
                                            entryPtr->numSA++;
                                            numSAIncremented = TRUE;
                                        }
                                    }
                                }
                                tempAddressList = addrList;
                            }// if close
                        }// for close
                        index++;
                    }// while close
                    index = 0;
                }// if close
            }// for
        }
        MEM_free(newSP);
    }

    IO_ConvertIpAddressToString((NodeAddress) ipsec_sa->SPI, addrStr1);

    newSA = IPsecCreateNewSA(
        ipsec_sa->mode,
        nodeconfig->peerAddress,
        nodeconfig->nodeAddress,
        ipsec_sa->proto,
        addrStr1,
        ipsec_sa->authalgo,
        authKey,
        nodeconfig->phase1->isakmp_sa->encryalgo,
        encryptionKey,
        &rateParams);

    // Assign name address map

    memset(newListEntry, 0, sizeof(IPsecSelectorAddrListEntry));
    newListEntry->src = nodeconfig->peerAddress;
    newListEntry->dest = nodeconfig->nodeAddress;
    newListEntry->mode = ipsec_sa->mode;
    newListEntry->securityProtocol = ipsec_sa->proto;
    newListEntry->saEntry = newSA;
    addrList.push_back(newListEntry);

    // Add the newSA to SA database
    IPsecSADAddEntry(node, newSA);

    // Create a SP for the inbound direction

    newSP = NULL;

    if (!intfInfo->spdIN->spd->empty())
    {
        newSP = IPsecGetMatchingSP(nodeconfig->phase2->peerNetwork,
                                   nodeconfig->phase2->localNetwork,
                                   nodeconfig->phase2->upperProtocol,
                                   intfInfo->spdIN->spd);
    }

    if (newSP == NULL)
    {
        vector<IPsecSAFilter*> saFilter;

        IPsecSAFilter* filter;
        filter = (IPsecSAFilter*) MEM_malloc(sizeof(IPsecSAFilter));
        memset(filter, 0, sizeof(IPsecSAFilter));

        filter->ipsecProto = ipsec_sa->proto;
        filter->ipsecLevel = (enum IPsecLevel) IPSEC_LEVEL_REQUIRE;
        filter->ipsecMode = ipsec_sa->mode;
        filter->tunnelSrcAddr = nodeconfig->peerAddress;
        filter->tunnelDestAddr = nodeconfig->nodeAddress;
        saFilter.push_back(filter);

        newSP = IPsecCreateNewSP(
            node,
            interfaceIndex,
            destRange,
            numDestHostBits,
            srcRange,
            numSrcHostBits,
            srcPortNumber,
            destPortNumber,
            nodeconfig->phase2->upperProtocol,
            IPSEC_IN,
            policy,
            saFilter,
            &rateParams);

         // Add the newSP to security policy database
        if (!IPsecIsDuplicateSP(node, (int) interfaceIndex, newSP))
        {
            IPsecSPDAddEntry(node, interfaceIndex, newSP);
            tempAddressList = addrList;

            // Update SA pointer in SPDin
            // Iterate through each of the sa filters configured in the SP
            // entry. Compare it against the SA addr map on that node. Point
            // to that entry in addrMap that matches the SA filters.
            // Update SA pointer in SPDIn
            for (int i = 0; i < node->numberInterfaces; i++)
            {
                IpInterfaceInfoType* intfInfo = ip->interfaceInfo[i];

                if (intfInfo->spdIN)
                {
                    IPsecSecurityPolicyInformation* spdInfo = intfInfo->spdIN;
                    IPsecSecurityPolicyDatabase* spd;
                    spd = spdInfo->spd;

                    while (index < spd->size())
                    {
                        IPsecSecurityPolicyEntry* entryPtr = spd->at(index);

                        for (size_t i = 0;
                             i < entryPtr->saFilter.size();
                             i++)
                        {
                            BOOL numSAIncremented = FALSE;

                            // SP for Transport mode
                            if (entryPtr->saFilter.at(i)->ipsecMode
                                == IPSEC_TRANSPORT)
                            {
                                for (size_t j = 0;
                                     j < tempAddressList.size();
                                     j++)
                                {
                                    if (IPsecCheckIfTransportModeSASelectorsMatch
                                        (entryPtr,
                                        *(tempAddressList.at(j)),
                                        (int) i))
                                    {
                                        entryPtr->saPtr[i] =
                                                tempAddressList.at(j)->saEntry;
                                        if (!numSAIncremented)
                                        {
                                            entryPtr->numSA++;
                                            numSAIncremented = TRUE;
                                        }
                                    }
                                }
                                tempAddressList = addrList;
                            }// if close

                            // SP for Tunnel mode
                            if (entryPtr->saFilter.at(i)->ipsecMode
                                == IPSEC_TUNNEL)
                            {
                                for (size_t j = 0;
                                     j < tempAddressList.size();
                                     j++)
                                {
                                    if (IPsecCheckIfTunnelModeSASelectorsMatch
                                        (entryPtr,
                                        *(tempAddressList.at(j)),
                                        (int) i))
                                    {
                                        entryPtr->saPtr[i] =
                                                tempAddressList.at(j)->saEntry;
                                        if (!numSAIncremented)
                                        {
                                            entryPtr->numSA++;
                                            numSAIncremented = TRUE;
                                        }
                                    }
                                }
                                tempAddressList = addrList;
                            }// if close
                        }// for close
                        index++;
                    }// while close
                    index = 0;
                }// if close
            }// for
        }
        MEM_free(newSP);
    }
}

//
// FUNCTION   :: ISAKMPSavePhase2Exchange
// LAYER      :: Network
// PURPOSE    :: Save the IPSEC SA negotiated
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
// RETURN     :: void
// NOTE       ::

void ISAKMPSavePhase2Exchange(Node* node, ISAKMPNodeConf* nodeconfig)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    IPSEC_SA* ipsec_sa = nodeconfig->phase2->ipsec_sa;

#ifdef ISAKMP_SAVE_PHASE2

    Int32 numSrcHostBits;
    Int32 numDestHostBits;

    char filename[16] = {'\0'};
    sprintf(filename, "node%d.ipsec", node->nodeId);
    FILE* fp = fopen(filename, "a+");

    char addrStr1[MAX_STRING_LENGTH];
    char addrStr2[MAX_STRING_LENGTH];
    char addrStr3[MAX_STRING_LENGTH];
    char addrStr4[MAX_STRING_LENGTH];
    const char *modestr = NULL;
    const char *upperProtocolstr = NULL;

    if (ipsec_sa->mode == IPSEC_TRANSPORT)
    {
        modestr = "TRANSPORT";
    }
    else
    {
        modestr = "TUNNEL";
    }

    fprintf(fp, "\n\n[%d] ",node->nodeId);

    IO_ConvertIpAddressToString(nodeconfig->peerAddress, addrStr3);
    IO_ConvertIpAddressToString(nodeconfig->nodeAddress, addrStr4);

    assert(ipsec_sa->mode == IPSEC_TRANSPORT ||
           ipsec_sa->mode == IPSEC_TUNNEL);
    fprintf(fp, "SA %s %s %s %d -m %s\n",
            addrStr4,
            addrStr3,
            IPsecGetSecurityProtocolName(ipsec_sa->proto),
            ipsec_sa->SPI,
            modestr);

    byte hexstr[MAX_STRING_LENGTH];
    bitstream_to_hexstr(hexstr, (const byte *)exch->Key, KEY_SIZE);
    fprintf(fp, " -E %s \"%s\" ",
            IPsecGetEncryptionAlgoName(
            nodeconfig->phase1->isakmp_sa->encryalgo),
            hexstr);
    fprintf(fp, "-A %s \"%s\";\n\n",
            IPsecGetAuthenticationAlgoName(ipsec_sa->authalgo),
            hexstr);

    fprintf(fp, "[%d] ",node->nodeId);
    fprintf(fp, "SA %s %s %s %d -m %s\n",
            addrStr3,
            addrStr4,
            IPsecGetSecurityProtocolName(ipsec_sa->proto),
            ipsec_sa->SPI,
            modestr);

    fprintf(fp, " -E %s \"%s\" ",
            IPsecGetEncryptionAlgoName(
            nodeconfig->phase1->isakmp_sa->encryalgo),
            hexstr);
    fprintf(fp, "-A %s \"%s\";\n\n",
            IPsecGetAuthenticationAlgoName(ipsec_sa->authalgo),
            hexstr);

    numSrcHostBits = ISAKMPGetNumHostBitsfromSubnetMask(
        nodeconfig->phase2->localNetMask.interfaceAddr.ipv4);

    numDestHostBits = ISAKMPGetNumHostBitsfromSubnetMask(
        nodeconfig->phase2->peerNetMask.interfaceAddr.ipv4);

    if (nodeconfig->phase2->localNetwork.interfaceAddr.ipv4 ==
        ANY_SOURCE_ADDR)
    {
        strcpy(addrStr1, "0.0.0.0");
    }
    else
    {
        IO_ConvertIpAddressToString(
            nodeconfig->phase2->localNetwork.interfaceAddr.ipv4, addrStr1);
    }

    if (nodeconfig->phase2->peerNetwork.interfaceAddr.ipv4 ==
        ANY_DEST)
    {
        strcpy(addrStr2, "0.0.0.0");
    }
    else
    {
        IO_ConvertIpAddressToString(
            nodeconfig->phase2->peerNetwork.interfaceAddr.ipv4, addrStr2);
    }

    if (nodeconfig->phase2->upperProtocol == IPPROTO_TCP)
    {
        upperProtocolstr = "TCP";
    }
    if (nodeconfig->phase2->upperProtocol == IPPROTO_UDP)
    {
        upperProtocolstr = "UDP";
    }
    else
    {
        upperProtocolstr = "ANY";
    }
    if (ipsec_sa->mode == IPSEC_TRANSPORT)
    {
        fprintf(fp, "[%d] ",node->nodeId);
        fprintf(fp, "SP N%d-%s N%d-%s %s -P IN IPSEC %s/%s//REQUIRE;\n",
            numDestHostBits,
            addrStr2,
            numSrcHostBits,
            addrStr1,
            upperProtocolstr,
            IPsecGetSecurityProtocolName(ipsec_sa->proto),
            modestr);

        fprintf(fp, "[%d] ",node->nodeId);
        fprintf(fp, "SP N%d-%s N%d-%s %s -P OUT IPSEC %s/%s//REQUIRE;\n",
            numSrcHostBits,
            addrStr1,
            numDestHostBits,
            addrStr2,
            upperProtocolstr,
            IPsecGetSecurityProtocolName(ipsec_sa->proto),
            modestr);
    }
    else
    {
        fprintf(fp, "[%d] ",node->nodeId);
        fprintf(fp, "SP N%d-%s N%d-%s %s -P IN IPSEC %s/%s/%s-%s/REQUIRE;\n",
            numDestHostBits,
            addrStr2,
            numSrcHostBits,
            addrStr1,
            upperProtocolstr,
            IPsecGetSecurityProtocolName(ipsec_sa->proto),
            modestr,
            addrStr3,
            addrStr4);

        fprintf(fp, "[%d] ",node->nodeId);
        fprintf(fp, "SP N%d-%s N%d-%s %s -P OUT IPSEC %s/%s/%s-%s/REQUIRE;\n",
            numSrcHostBits,
            addrStr1,
            numDestHostBits,
            addrStr2,
            upperProtocolstr,
            IPsecGetSecurityProtocolName(ipsec_sa->proto),
            modestr,
            addrStr4,
            addrStr3);
    }
    fclose(fp);

#endif // ISAKMP_SAVE_PHASE2

    nodeconfig->current_pointer_list->is_ipsec_sa = TRUE;
    nodeconfig->current_pointer_list->reestabRequired = FALSE;

    if (nodeconfig->current_pointer_list->phase2 != nodeconfig->phase2)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "Node %u: No IPSec SA found\n",
            node->nodeId);
        ERROR_Assert(FALSE, errStr);
    }

    ISAKMPInitIPsecParam(node, nodeconfig);

    // start refresh timer here according to the SA life
    ISAKMPSetTimer(node,
               nodeconfig,
               MSG_NETWORK_ISAKMP_RefreshTimer,
               ipsec_sa->SPI,
               ipsec_sa->life);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\n%s has saved the phase2 SA with %s"
            " at Simulation time = %s\n", srcStr, dstStr, timeStr);
    }

    MEM_free(exch->IDi);
    MEM_free(exch->IDr);
    MEM_free(exch->sig_i);
    MEM_free(exch->sig_r);
    MESSAGE_Free(node, exch->lastSentPkt);

    MEM_free(nodeconfig->exchange);
    nodeconfig->exchange = NULL;
}

//
// FUNCTION   :: ISAKMPExchangeFinalize
// LAYER      :: Network
// PURPOSE    :: finalize function for a Exchange
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - received isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPExchangeFinalize(Node* node,
                               ISAKMPNodeConf* nodeconfig,
                               Message* msg)
{
    if (ISAKMP_DEBUG)
    {
        printf("\nInside Exchange finalize NodeId = %d",node->nodeId);
    }

    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    if (nodeconfig->exchange->waitforcommit)
    {
        if (ISAKMPValidateMessage(node, nodeconfig, msg, ISAKMP_NPTYPE_N))
        {
            return ;
        }
    }
    switch (nodeconfig->exchange->exchType)
    {
        case ISAKMP_ETYPE_BASE:
            stats->numOfBaseExch++;
            break;
        case ISAKMP_ETYPE_IDENT:
            stats->numOfIdProtExch++;
            break;
        case ISAKMP_ETYPE_AUTH:
            stats->numOfAuthOnlyExch++;
            break;
        case ISAKMP_ETYPE_AGG:
            stats->numOfAggresExch++;
            break;
        case ISAKMP_IKE_ETYPE_MAIN_PRE_SHARED:
            stats->numOfIkeMainPreSharedExch++;
            break;
        case ISAKMP_IKE_ETYPE_MAIN_DIG_SIG:
            stats->numOfIkeMainDigSigExch++;
            break;
        case ISAKMP_IKE_ETYPE_MAIN_PUB_KEY:
            stats->numOfIkeMainPubKeyExch++;
            break;
        case ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY:
            stats->numOfIkeMainRevPubKeyExch++;
            break;
        case ISAKMP_IKE_ETYPE_AGG_PRE_SHARED:
            stats->numOfIkeAggresPreSharedExch++;
            break;
        case ISAKMP_IKE_ETYPE_AGG_DIG_SIG:
            stats->numOfIkeAggresDigSigExch++;
            break;
        case ISAKMP_IKE_ETYPE_AGG_PUB_KEY:
            stats->numOfIkeAggresPubKeyExch++;
            break;
        case ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY:
            stats->numOfIkeAggresRevPubKeyExch++;
            break;
        case ISAKMP_IKE_ETYPE_QUICK:
            stats->numOfIkeQuickExch++;
            break;
        case ISAKMP_IKE_ETYPE_NEW_GROUP:
            stats->numOfIkeNewGroupExch++;
            break;
        default:
            break;
    }

    UInt32 i_r = nodeconfig->exchange->initiator;
    if (nodeconfig->exchange->phase == PHASE_1)
    {
        BOOL isIKEPhase1exch = IsPhase1IKEExchange(
                                             nodeconfig->exchange->exchType);
        BOOL isIKEExchange = IsIKEExchange(nodeconfig->exchange->exchType);

        // save phase1 SA in a file
        ISAKMPSavePhase1Exchange(node, nodeconfig);

        if (i_r == INITIATOR)
        {
            if (nodeconfig->phase1->isNewGroupModeEnabled
                && !(nodeconfig->phase1->isNewGroupModePerformed)
                && isIKEPhase1exch)
            {
                //adding encryption delay for IKE exchange
                ISAKMPSetTimer(
                    node,
                    nodeconfig,
                    MSG_NETWORK_ISAKMP_ScheduleNextPhase,
                    0,
                    ISAKMPGetProcessDelay(node, nodeconfig));
            }
            else
            {
                nodeconfig->phase2 = nodeconfig->phase2_list->phase2;
                nodeconfig->current_pointer_list = nodeconfig->phase2_list;

                if (isIKEExchange)
                {
                    //adding encryption delay for IKE exchange
                    ISAKMPSetTimer(
                        node,
                        nodeconfig,
                        MSG_NETWORK_ISAKMP_SchedulePhase2,
                        0,
                        ISAKMPGetProcessDelay(node, nodeconfig));
                }
                else
                {
                    ISAKMPSetUp_Negotiation(
                            node, nodeconfig, msg, 0, 0, i_r, PHASE_2);
                }
            }
        }
    }
    else
    {
        // save phase2 SA in a file
        ISAKMPSavePhase2Exchange(node, nodeconfig);

        if (i_r == INITIATOR)
        {
            nodeconfig->current_pointer_list =
                nodeconfig->current_pointer_list->next;
            if (nodeconfig->current_pointer_list)
            {
               nodeconfig->phase2 = nodeconfig->current_pointer_list->phase2;
               ISAKMPSetUp_Negotiation(
                    node, nodeconfig, msg, 0, 0, i_r, PHASE_2);
            }
            else // check if any reestablishment pending
            {
                ISAKMPPhase2List* phase2_list = nodeconfig->phase2_list;
                while (phase2_list)
                {
                    if (phase2_list->reestabRequired == TRUE)
                    {
                        nodeconfig->phase2 = phase2_list->phase2;
                        nodeconfig->current_pointer_list = phase2_list;
                        ISAKMPSetUp_Negotiation(
                            node, nodeconfig, msg, 0, 0, i_r, PHASE_2);

                        stats->numOfReestablishments++;
                        break;
                    }
                    phase2_list = phase2_list->next;
                }
            }
        }
    }
}

//
// FUNCTION   :: ISAKMPAddAUTH
// LAYER      :: Network
// PURPOSE    :: To add the signature Payload to ISAKMP message
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               char* currentOffset - offset of signature payload
//               char* sig_data - signature payload data
//               UInt32 len_sig_data - length of signature payload data
// RETURN     :: void
// NOTE       ::

void ISAKMPAddAUTH(ISAKMPNodeConf* nodeconfig,
                     char* &currentOffset,
                     char* sig_data,
                     UInt32 len_sig_data)
{
    ISAKMPPaylSig sig_payload;

    memset(&sig_payload, 0, SIZE_SIG_Payload);

    ISAKMPExchange* exch = nodeconfig->exchange;

    sig_payload.h.np_type = ISAKMP_NPTYPE_NONE;
    sig_payload.h.len = (UInt16)(SIZE_SIG_Payload + len_sig_data);

    memcpy(currentOffset, &sig_payload, SIZE_SIG_Payload);

    currentOffset = currentOffset + SIZE_SIG_Payload;
    memcpy(currentOffset, sig_data, len_sig_data);

    if (exch->initiator == INITIATOR)
    {
        exch->sig_i = (char*)MEM_malloc(len_sig_data + 1);
        strcpy(exch->sig_i, sig_data);
    }
    else
    {
        exch->sig_r = (char*)MEM_malloc(len_sig_data + 1);
        strcpy(exch->sig_r, sig_data);
    }
}



//
// FUNCTION   :: ISAKMPAddCert
// LAYER      :: Network
// PURPOSE    :: To add the certificate Payload to ISAKMP message
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               char* currentOffset - offset of signature payload
//               char* cert_data - certificate payload data
//               UInt32 len_cert_data - length of certificate payload data
// RETURN     :: void
// NOTE       ::

void ISAKMPAddCert(ISAKMPNodeConf* nodeconfig,
                     char* &currentOffset,
                     char* cert_data,
                     UInt32 len_cert_data)
{
    UInt16 i = 0;
    ISAKMPPaylCert cert_payload;

    memset(&cert_payload, 0, SIZE_CERT_Payload);

    ISAKMPPhase1* phase1 = nodeconfig->phase1;
    ISAKMPExchange* exch = nodeconfig->exchange;

    cert_payload.h.np_type = ISAKMP_NPTYPE_NONE;
    cert_payload.h.len = (UInt16)(SIZE_CERT_Payload);

    if (phase1->isakmp_sa)
    {
        cert_payload.encode =
                     (unsigned char) nodeconfig->phase1->isakmp_sa->certType;
    }
    else if (nodeconfig->exchange)
    {
        //search in all the transform available
        for (i = 0; i < phase1->numofTransforms; i++)
        {
            //if selected transform found, access certType
            if ((exch->phase1_trans_no_selected - 1) == i)
            {
                cert_payload.encode =
                             (unsigned char) phase1->transform[i]->certType;
            }
        }
    }

    memcpy(currentOffset, &cert_payload, SIZE_CERT_Payload);

    if (cert_data != NULL)
    {
        currentOffset = currentOffset + SIZE_CERT_Payload;
        memcpy(currentOffset, cert_data, len_cert_data);

        cert_payload.h.len = (UInt16)(cert_payload.h.len + len_cert_data);
        if (exch->initiator == INITIATOR)
        {
            exch->cert_i = (char*)MEM_malloc(len_cert_data + 1);
            strcpy(exch->cert_i, cert_data);
        }
        else
        {
            exch->cert_r = (char*)MEM_malloc(len_cert_data + 1);
            strcpy(exch->cert_r, cert_data);
        }
    }
}



//
// FUNCTION   :: ISAKMPAddID
// LAYER      :: Network
// PURPOSE    :: To add the identification Payload to ISAKMP message
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylId* id_payload - offset of identity payload
//               char* id_data - identity payload data
//               UInt32 len_id_data - length of identity payload data
// RETURN     :: void
// NOTE       ::

void ISAKMPAddID(ISAKMPNodeConf* nodeconfig,
                   ISAKMPPaylId* id_payload,
                   char* id_data,
                   UInt32 len_id_data)
{
    char* currentOffset = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;

    id_payload->h.np_type = ISAKMP_NPTYPE_NONE;
    id_payload->h.len = (UInt16)(SIZE_ID_Payload + len_id_data);
    currentOffset = (char*)(id_payload + 1);
    memcpy(currentOffset, id_data, len_id_data);

    if (nodeconfig->exchange->initiator == INITIATOR
        && nodeconfig->exchange->phase == PHASE_2)
    {
        // add ID type
        id_payload->id_data.ipsec_doi_data.id_type =
            nodeconfig->phase2->localIdType;

        // add upper layer protocol
        id_payload->id_data.ipsec_doi_data.protocol_id =
            nodeconfig->phase2->upperProtocol;

        if (ISAKMP_DEBUG)
        {
            Address*  localNetwork;
            Address*  localNetMask;
            printf("ID Type %d", nodeconfig->phase2->localIdType);
            localNetwork = (Address*)id_data;
            printf("Local Net: %d", localNetwork->interfaceAddr.ipv4);
            localNetMask = (Address*)(localNetwork + 1);
            printf("Local NetMask: %d", localNetMask->interfaceAddr.ipv4);
        }
    }
    else
    {
        // add ID type
        id_payload->id_data.ipsec_doi_data.id_type = ISAKMP_ID_IPV4_ADDR;
    }

    if (exch->initiator == INITIATOR)
    {
        exch->IDi = (char*)MEM_malloc(len_id_data + 1);
        memcpy(exch->IDi, id_data, len_id_data);
    }
    else
    {
        exch->IDr = (char*)MEM_malloc(len_id_data + 1);
        memcpy(exch->IDr, id_data, len_id_data);
    }
}

//
// FUNCTION   :: ISAKMPGetID
// LAYER      :: Network
// PURPOSE    :: To get the ID data
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               char* &id_data - identity payload data
//               UInt32 &len_id_data - length of identity payload data
// RETURN     :: void
// NOTE       :: This function is not implement yet.
//               do we really need this in Simulation ???

static
void ISAKMPGetID(ISAKMPNodeConf* nodeconfig,
                 char* &id_data,
                 UInt32 &len_id_data)
{
    UInt32 len = 0;

    if (nodeconfig->exchange->initiator == INITIATOR
        && nodeconfig->exchange->phase == PHASE_2)
    {
        Address*  localNetwork;
        Address*  localNetMask;
        len =  2 * sizeof(Address);
        id_data = (char*)MEM_malloc(len);
        memset(id_data, 0, len);

        // add Local Network address
        localNetwork = (Address *)id_data;
        localNetwork->interfaceAddr.ipv4 =
            nodeconfig->phase2->localNetwork.interfaceAddr.ipv4;

        // add Remote Network address
        localNetMask = (Address *)(localNetwork + 1);
        localNetMask->interfaceAddr.ipv4 =
            nodeconfig->phase2->localNetMask.interfaceAddr.ipv4;

        len_id_data = len;
    }
    else
    {
        Address*  localAddress;
        len = sizeof(Address);
        id_data = (char*)MEM_malloc(len);
        memset(id_data, 0, len);

        localAddress = (Address *)id_data;
        localAddress->interfaceAddr.ipv4 = nodeconfig->nodeAddress;
        len_id_data = len;
    }
}

//
// FUNCTION   :: ISAKMPGetSig
// LAYER      :: Network
// PURPOSE    :: To get the Signature data
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               char* &sig_data - signature payload data
// RETURN     :: void
// NOTE       :: This function is not implement yet.
//               do we really need in Simulation ???

static
void ISAKMPGetSig(ISAKMPNodeConf* nodeconfig, char* &sig_data)
{
    sig_data = (char*)MEM_malloc(8);
    memset(sig_data, '\0', 8);
    strcpy(sig_data, "NA");

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        printf("\n%s has it's Signature as %s", srcStr, sig_data);
    }
}



//
// FUNCTION   :: ISAKMPGetCertData
// LAYER      :: Network
// PURPOSE    :: To get the Certificate data
// PARAMETERS :: ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               char* &cert_data - certificate payload data
//               UInt32 &len_cert_data - length of certificate payload data
// RETURN     :: void
// NOTE       :: This function is not implement yet.
//               do we really need this in Simulation ???

static
void ISAKMPGetCertData(ISAKMPNodeConf* nodeconfig,
                 char* &cert_data,
                 UInt32 &len_cert_data)
{
    UInt16 i = 0;

    ISAKMPCertType certType = ISAKMP_CERT_NONE;
    ISAKMPPhase1* phase1 = nodeconfig->phase1;
    ISAKMPExchange* exch = nodeconfig->exchange;

    if (phase1->isakmp_sa)
    {
        certType = nodeconfig->phase1->isakmp_sa->certType;
    }
    else if (nodeconfig->exchange)
    {
        //search in all the transform available
        for (i = 0; i < phase1->numofTransforms; i++)
        {
            //if selected transform found, access certType
            if ((exch->phase1_trans_no_selected - 1) == i)
            {
                certType = phase1->transform[i]->certType;
            }
        }
    }
    else
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "Certificate type not found\n");
        ERROR_ReportError(errStr);
    }

    //assuming variable length field as 1024 in the test bases for simulation
    //this should be added in virtual payload of the message.
    if (!nodeconfig->phase1->isCertEnabled
        || certType == ISAKMP_CERT_NONE)
    {
        len_cert_data = 0;
    }
    else
    {
        len_cert_data = CERT_PAYLOAD_SIZE;
    }
}



//
// FUNCTION   :: ISAKMPSendAuth
// LAYER      :: Network
// PURPOSE    :: To send the Auth msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendAuth(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;
    Message*        newMsg = NULL;
    ISAKMPHeader*    isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;

    char* sig_data = NULL;

    UInt32            len_packet = 0;
    UInt32            len_sig = 0;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetSig(nodeconfig, sig_data);

    len_sig      = SIZE_SIG_Payload + (int)strlen(sig_data);

    len_packet    = SIZE_ISAKMP_HEADER + len_sig ;

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SIG;
    isakmp_sendheader->len = len_packet;

    char* currentOffset = (char*)(isakmp_sendheader + 1);

    //add signature payload
    ISAKMPAddAUTH(nodeconfig, currentOffset, sig_data,
        (int)strlen(sig_data));

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }
    if (exch->phase == PHASE_2)
    {
        if (exch->flags & ISAKMP_FLAG_E)
        {
            if (exch->exchType == ISAKMP_ETYPE_AGG)
            {
                isakmp_sendheader->flags = ISAKMP_FLAG_E;

                // Encrypt the message payload using Phase-1 encryption
                // algorithm and key established
                // Not required for Simulation
            }
        }
    }

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\n%s has sent Auth to %s at Simulation time = %s\n",
            srcStr, dstStr, timeStr);
    }

    stats->numPayloadAuthSend++;

    if (exch->exchType == ISAKMP_ETYPE_AGG
        && exch->initiator == INITIATOR
        && !exch->waitforcommit)
    {
        if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
        ISAKMPExchangeFinalize(node, nodeconfig, msg);
    }
}

//
// FUNCTION   :: ISAKMPSendIDAuth
// LAYER      :: Network
// PURPOSE    :: To send the ID_Auth msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendIDAuth(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char* currentOffset = NULL;
    Message*        newMsg = NULL;
    ISAKMPHeader*    isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;

    clocktype       delay = 0;
    char* id_data = NULL;
    char* sig_data = NULL;

    UInt32 len_packet = 0;
    UInt32 len_id = 0;
    UInt32 len_id_data = 0;
    UInt32 len_sig = 0;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetSig(nodeconfig, sig_data);

    len_id    = SIZE_ID_Payload + len_id_data;
    len_sig      = SIZE_SIG_Payload + (int)strlen(sig_data);

    len_packet    = SIZE_ISAKMP_HEADER + len_id + len_sig ;

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_ID;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)(isakmp_sendheader + 1);
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);
    id_payload->h.np_type = ISAKMP_NPTYPE_SIG;

    currentOffset = (char*)(id_payload + 1);
    currentOffset = currentOffset + len_id_data;

    // add signature payload
    ISAKMPAddAUTH(nodeconfig, currentOffset, sig_data,
        (int)strlen(sig_data));

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags |ISAKMP_FLAG_C;
    }

    if (nodeconfig->exchange->phase == PHASE_1
        && exch->exchType == ISAKMP_ETYPE_IDENT
        && ((exch->flags & ISAKMP_FLAG_E) && !(exch->flags & ISAKMP_FLAG_C)))
    {
        // in Phase-1. Functionality like encrypting the ID, Auth payloads
        // should be added here.
        // Actual calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }


    if (exch->phase == PHASE_2)
    {
        if (exch->flags & ISAKMP_FLAG_E)
        {
            if (exch->exchType == ISAKMP_ETYPE_IDENT)
            {
                isakmp_sendheader->flags =
                                isakmp_sendheader->flags | ISAKMP_FLAG_E;

                // Encrypt the message payload using Phase-1 encryption
                // algorithm and key established
                // Not required for Simulation
                // Adding processing delay for encryption
                delay = nodeconfig->phase1->isakmp_sa->processdelay;
            }
        }
    }
    MEM_free(id_data);
    MEM_free(sig_data);

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\n%s has sent ID,Auth to %s at Simulation time = %s"
               " with delay %s\n", srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadIdSend++;
    stats->numPayloadAuthSend++;

    if (exch->exchType == ISAKMP_ETYPE_IDENT
        && exch->initiator == RESPONDER
        && !exch->waitforcommit)
    {
        if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
        ISAKMPExchangeFinalize(node, nodeconfig, msg);
    }
    else if (exch->exchType == ISAKMP_ETYPE_AUTH
        && exch->initiator == INITIATOR
        && !exch->waitforcommit)
    {
        if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
        ISAKMPExchangeFinalize(node, nodeconfig, msg);
    }
}

//
// FUNCTION   :: ISAKMPSendKEIDAuth
// LAYER      :: Network
// PURPOSE    :: To send the KE_ID_AUTH msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendKEIDAuth(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char* currentOffset = NULL;
    Message*        newMsg = NULL;
    ISAKMPHeader*   isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;

    char* id_data  = NULL;
    char* sig_data = NULL;

    UInt32 len_packet = 0;
    UInt16 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt32 len_id = 0;
    UInt32 len_id_data = 0;
    UInt32 len_sig = 0;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetSig(nodeconfig, sig_data);

    len_id    = SIZE_ID_Payload + len_id_data;
    len_sig   = SIZE_SIG_Payload + (int)strlen(sig_data);

    len_packet    = SIZE_ISAKMP_HEADER + len_ke + len_id + len_sig ;

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_KE;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)(isakmp_sendheader + 1);

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);
    id_payload->h.np_type = ISAKMP_NPTYPE_SIG;
    id_payload->h.len = len_id;

    currentOffset = (char*)(id_payload + 1);
    currentOffset = currentOffset + len_id_data;

    // add signature payload
    ISAKMPAddAUTH(nodeconfig, currentOffset, sig_data,
        (int)strlen(sig_data));


    if (exch->exchType == ISAKMP_ETYPE_BASE
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(nodeconfig->exchange, exch->Key_i, exch->Key_r);
    }

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }

    MEM_free(id_data);
    MEM_free(sig_data);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\n%s has sent KE,ID,Auth to %s at Simulation time = %s\n",
            srcStr, dstStr, timeStr);
    }

    stats->numPayloadKeyExSend++;
    stats->numPayloadIdSend++;
    stats->numPayloadAuthSend++;

    if (exch->exchType == ISAKMP_ETYPE_BASE
        && exch->initiator == RESPONDER
        && !exch->waitforcommit)
    {
        if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
        ISAKMPExchangeFinalize(node, nodeconfig, msg);
    }
}

//
// FUNCTION   :: ISAKMPValidatePayloadNotify
// LAYER      :: Network
// PURPOSE    :: Processing of Notify Payload received
// PARAMETERS :: ISAKMPStats* &stats - isakmp stats
//               ISAKMPPaylNotif* notify_payload - notify payload received
// RETURN     :: UInt16 - error or Notification type
// NOTE       ::

static
UInt16 ISAKMPValidatePayloadNotify(ISAKMPStats* &stats,
                                   ISAKMPPaylNotif* notify_payload)
{
    ISAKMPGenericHeader gen_header = notify_payload->h;

    stats->numOfInformExchRcv++;
    stats->numPayloadNotifyRcv++;

    //general header Processing
    if (gen_header.reserved != 0)
    {
        return ISAKMP_DROP_Message;
    }
    if (notify_payload->type == ISAKMP_NTYPE_CONNECTED)
    {
        return 0;
    }
    if (notify_payload->type < 1 || notify_payload->type >28)
    {
        return ISAKMP_DROP_Message;
    }
    return ISAKMP_DROP_EXchange;
}

//
// FUNCTION   :: ISAKMPValidatePayloadNonce
// LAYER      :: Network
// PURPOSE    :: Processing of Nonce Payload received
// PARAMETERS :: ISAKMPStats* &stats - isakmp stats
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylNotif* nonce_payload - nonce payload received
// RETURN     :: UInt16 - error or Notification type
// NOTE       ::

UInt16 ISAKMPValidatePayloadNonce(ISAKMPStats* &stats,
                              ISAKMPNodeConf* nodeconfig,
                              ISAKMPPaylNonce* nonce_payload)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    ISAKMPGenericHeader gen_header = nonce_payload->h;
    char* currentOffset = NULL;
    UInt16 notify_type = 0;
    UInt16 len_nonce = 0;

    stats->numPayloadNonceRcv++;

    //general header Processing
    if (gen_header.reserved != 0)
    {
        return ISAKMP_NTYPE_INVALID_RESERVED_FIELD;
    }

    currentOffset = (char*)nonce_payload;
    currentOffset = currentOffset + gen_header.len;

    notify_type = ISAKMPValidatepayload(
        stats, nodeconfig, gen_header.np_type, currentOffset);
    if (notify_type)
    {
        return notify_type;
    }

    len_nonce = nonce_payload->h.len - SIZE_NONCE_Payload;
    currentOffset = (char*)(nonce_payload + 1);
    if (exch->initiator == INITIATOR)
    {
       memcpy(exch->Nr, currentOffset, len_nonce);
        exch->Nr[len_nonce] = '\0';
    }
    else
    {
        memcpy(exch->Ni, currentOffset, len_nonce);
        exch->Ni[len_nonce] = '\0';
    }

    return notify_type;
}

//
// FUNCTION   :: ISAKMPValidatePayloadKE
// LAYER      :: Network
// PURPOSE    :: Processing of KE Payload received
// PARAMETERS :: ISAKMPStats* &stats - isakmp stats
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylNotif* ke_payload - key payload received
// RETURN     :: UInt16 - error or Notification type
// NOTE       ::

UInt16 ISAKMPValidatePayloadKE(ISAKMPStats* &stats,
                           ISAKMPNodeConf* nodeconfig,
                           ISAKMPPaylKeyEx* ke_payload)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    ISAKMPGenericHeader gen_header = ke_payload->h;
    char* currentOffset = NULL;
    UInt16 notify_type = 0;
    UInt16 len_ke = 0;

    stats->numPayloadKeyExRcv++;

    //general header Processing
    if (gen_header.reserved != 0)
    {
        return ISAKMP_NTYPE_INVALID_RESERVED_FIELD;
    }

    currentOffset = (char*)ke_payload;
    currentOffset = currentOffset + gen_header.len;

    notify_type = ISAKMPValidatepayload(
        stats, nodeconfig, gen_header.np_type, currentOffset);
    if (notify_type != 0)
    {
        return notify_type;
    }

    len_ke = ke_payload->h.len - SIZE_KE_Payload;

    currentOffset = (char*)(ke_payload + 1);

    if (exch->initiator == INITIATOR)
    {
        memcpy(exch->Key_r, currentOffset, len_ke);
        exch->Key_r[len_ke] = '\0';
    }
    else
    {
        memcpy(exch->Key_i, currentOffset, len_ke);
        exch->Key_i[len_ke] = '\0';
    }

    return notify_type;
}

//
// FUNCTION   :: ISAKMPRecvKENonce
// LAYER      :: Network
// PURPOSE    :: Processing of KE_NONCE message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvKENonce(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;

    UInt16    notify_type = 0;
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_KE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if ((exch->exchType == ISAKMP_ETYPE_IDENT
          ||exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PRE_SHARED
          ||exch->exchType == ISAKMP_IKE_ETYPE_MAIN_DIG_SIG)
        && exch->initiator == INITIATOR)
    {
        ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }

    exch->step++;
    (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}

//
// FUNCTION   :: GenNonceData
// LAYER      :: Network
// PURPOSE    :: To generate the nonce data to send
// PARAMETERS :: char* noncedata - nonce data pointer
//               UInt16 seed[] - isakmp seed
// RETURN     :: void
// NOTE       :: This function is not implement yet.
//               do we really need in Simulation ???

void GenNonceData(char* noncedata, UInt16 seed[])
{
    UInt32 value =     RANDOM_nrand(seed);
    *(UInt32*)noncedata = value;
}

//
// FUNCTION   :: ISAKMPAddNONCE
// LAYER      :: Network
// PURPOSE    :: To add the nonce payload to ISAKMP message
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylNonce* nonce_payload - nonce payload
// RETURN     :: void
// NOTE       ::

void ISAKMPAddNONCE(Node* node,
                      ISAKMPNodeConf* nodeconfig,
                      ISAKMPPaylNonce* nonce_payload)
{
    char* currentOffset = NULL;
    char noncedata[NONCE_SIZE + 1] = {'\0'};

    ISAKMPExchange* exch = nodeconfig->exchange;

    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];

    GenNonceData(noncedata, interfaceInfo->isakmpdata->seed);

    nonce_payload->h.np_type = ISAKMP_NPTYPE_NONE;
    nonce_payload->h.len = SIZE_NONCE_Payload + NONCE_SIZE;
    currentOffset = (char*)(nonce_payload + 1);
    memcpy(currentOffset, noncedata, NONCE_SIZE);

    if (exch->initiator == INITIATOR)
    {
        memcpy(exch->Ni, noncedata, NONCE_SIZE);
    }
    else
    {
        memcpy(exch->Nr, noncedata, NONCE_SIZE);
    }
}

//
// FUNCTION   :: ISAKMPAddKE
// LAYER      :: Network
// PURPOSE    :: To add the KE payload to ISAKMP message
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               ISAKMPPaylKeyEx* ke_payload - key payload
// RETURN     :: void
// NOTE       ::

static
void ISAKMPAddKE(Node* node,
                   ISAKMPNodeConf* nodeconfig,
                   ISAKMPPaylKeyEx* ke_payload)
{
    char* currentOffset = NULL;
    char keydata[KEY_SIZE + 1] = {'\0'};

    ISAKMPExchange* exch = nodeconfig->exchange;

    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    GenNonceData(keydata, interfaceInfo->isakmpdata->seed);

    ke_payload->h.np_type = ISAKMP_NPTYPE_NONE;
    ke_payload->h.len = SIZE_KE_Payload + KEY_SIZE;

    currentOffset = (char*)(ke_payload + 1);
    memcpy(currentOffset, keydata, KEY_SIZE);

    if (exch->initiator == INITIATOR)
    {
        memcpy(exch->Key_i, keydata, KEY_SIZE);
    }
    else
    {
        memcpy(exch->Key_r, keydata, KEY_SIZE);
    }
}

//
// FUNCTION   :: ISAKMPSendKENonce
// LAYER      :: Network
// PURPOSE    :: To send the KE_NONCE message
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendKENonce(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char*           currentOffset = NULL;
    Message*        newMsg = NULL;
    ISAKMPHeader*   isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;
    UInt16            len_packet = 0;
    UInt16            len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt16            len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    len_packet    = SIZE_ISAKMP_HEADER + len_ke + len_nonce;

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

     MESSAGE_PacketAlloc(
                    node,
                    newMsg,
                    len_packet,
                    TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie,  exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_KE;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)(isakmp_sendheader + 1);

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;
    ISAKMPPaylNonce* nonce_payload = (ISAKMPPaylNonce*)currentOffset;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, nonce_payload);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\n%s has sent KE,Nonce to %s at Simulation time = %s\n",
            srcStr, dstStr, timeStr);
    }

    stats->numPayloadKeyExSend++;
    stats->numPayloadNonceSend++;

    if ((exch->exchType == ISAKMP_ETYPE_IDENT
          ||exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PRE_SHARED
          ||exch->exchType == ISAKMP_IKE_ETYPE_MAIN_DIG_SIG)
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }
}

//
// FUNCTION   :: ISAKMPResponderReplySAKENonceIDAuth
// LAYER      :: Network
// PURPOSE    :: process SA_KE_NONCE_ID msg recieved and
//               send SA_KE_NONCE_ID_AUTH msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPResponderReplySAKENonceIDAuth(Node* node,
                                         ISAKMPNodeConf* nodeconfig,
                                         Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;

    char* id_data = NULL;
    char* sig_data = NULL;

    UInt32 len_id_data = 0;

    UInt16 notify_type;
    notify_type =
        ISAKMPValidateMessage(node, nodeconfig, msg, ISAKMP_NPTYPE_SA);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetSig(nodeconfig, sig_data);

    UInt32 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt32 len_id    = SIZE_ID_Payload + len_id_data;
    UInt32 len_sig     = SIZE_SIG_Payload + (int)strlen(sig_data);

    Message*        newMsg = NULL;
    ISAKMPHeader*    isakmp_sendheader, *isakmp_recvheader;
    UInt32            len_packet = 0;
    UInt16            len_SA = 0;
    UInt16            len_prop = 0;
    UInt16            len_trans = 0;
    char*            currentOffset;

    len_trans = exch->trans_selected->h.len;
    if (exch->phase == PHASE_1)
    {
        len_prop  = SIZE_PROPOSAL_Payload + len_trans;
    }
    else
    {
        len_prop  = SIZE_PROPOSAL_Payload + SIZE_SPI + len_trans;
    }
    len_SA = SIZE_SA_Payload + len_prop;

    len_packet = SIZE_ISAKMP_HEADER + len_SA + len_ke + len_nonce + len_id
                                                                  + len_sig;

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylSA* send_sa_payload = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(isakmp_recvheader + 1);

    memcpy((char*)send_sa_payload,
        (char*)recv_sa_payload, SIZE_SA_Payload);
    send_sa_payload->h.len = len_SA;
    send_sa_payload->h.np_type = ISAKMP_NPTYPE_KE;

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(send_sa_payload + 1);
    currentOffset = (char*)proposal;

    // copy proposal payload that is selected
    if (exch->phase == PHASE_1)
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload + SIZE_SPI);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload + SIZE_SPI;
    }
    proposal->h.len = len_prop;
    proposal->h.np_type = ISAKMP_NPTYPE_NONE;

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;

    // copy transform payload that is selected
    memcpy((char*)transform, (char*)exch->trans_selected, len_trans);

    currentOffset = (char*)transform;
    currentOffset = currentOffset + len_trans;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)currentOffset;

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;

    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)currentOffset;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);
    payload_nonce->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)payload_nonce;
    currentOffset = currentOffset + len_nonce;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);
    id_payload->h.np_type = ISAKMP_NPTYPE_SIG;

    currentOffset = (char*)(id_payload + 1);
    currentOffset = currentOffset + len_id_data;

    // add signature payload
    ISAKMPAddAUTH(nodeconfig, currentOffset, sig_data,
        (int)strlen(sig_data));

    UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    if (exch->phase == PHASE_1)
    {
        // temporarily save phase-1 SA negotiated
        SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    }
    else
    {
        // temporarily save phase-2 SA negotiated
        SetupIPSecSA(nodeconfig, attr, attr_size);
        nodeconfig->phase2->ipsec_sa = nodeconfig->ipsec_sa;
        nodeconfig->ipsec_sa = NULL;
    }

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags =
                                isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }

    MEM_free(id_data);
    MEM_free(sig_data);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\nResponder %s has sent SA,KE,Nonce,ID,Auth to %s"
            " at Simulation time = %s\n", srcStr, dstStr, timeStr);
    }

    stats->numPayloadSASend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadNonceSend++;
    stats->numPayloadIdSend++;
    stats->numPayloadAuthSend++;

    if (exch->exchType == ISAKMP_ETYPE_AGG
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }
}

//
// FUNCTION   :: ISAKMPResponderReplySANonceIDAuth
// LAYER      :: Network
// PURPOSE    :: send SA_NONCE_ID_AUTH msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPResponderReplySANonceIDAuth(Node* node,
                                             ISAKMPNodeConf* nodeconfig,
                                             Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;
    Message*        newMsg = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;
    char* id_data = NULL;
    char* sig_data = NULL;

    UInt32 len_id_data = 0;

    UInt16    notify_type;
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_SA);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetSig(nodeconfig, sig_data);

    UInt32 len_id    = SIZE_ID_Payload + len_id_data;
    UInt32 len_sig      = SIZE_SIG_Payload + (int)strlen(sig_data);

    ISAKMPHeader*    isakmp_sendheader, *isakmp_recvheader;
    UInt32            len_packet = 0;
    UInt16            len_SA = 0;
    UInt16            len_prop = 0;
    UInt16            len_trans = 0;
    char*            currentOffset;

    len_trans = exch->trans_selected->h.len;
    if (exch->phase == PHASE_1)
    {
        len_prop  = SIZE_PROPOSAL_Payload + len_trans;
    }
    else
    {
        len_prop  = SIZE_PROPOSAL_Payload + SIZE_SPI + len_trans;
    }
    len_SA = SIZE_SA_Payload + len_prop;

    len_packet = SIZE_ISAKMP_HEADER + len_SA + len_nonce + len_id + len_sig;

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylSA* send_sa_payload = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(isakmp_recvheader + 1);

    memcpy((char*)send_sa_payload,
        (char*)recv_sa_payload,
        SIZE_SA_Payload);
    send_sa_payload->h.len = len_SA;
    send_sa_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(send_sa_payload + 1);
    currentOffset = (char*)proposal;

    //copy proposal payload that is selected
    if (exch->phase == PHASE_1)
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload + SIZE_SPI);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload +SIZE_SPI;
    }
    proposal->h.len = len_prop;
    proposal->h.np_type = ISAKMP_NPTYPE_NONE;

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;

    //copy transform payload that is selected
    memcpy((char*)transform, (char*)exch->trans_selected,  len_trans);

    currentOffset = (char*)transform;
    currentOffset = currentOffset + len_trans;

    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)currentOffset;

     // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);
    payload_nonce->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)payload_nonce;
    currentOffset = currentOffset + len_nonce;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);
    id_payload->h.np_type = ISAKMP_NPTYPE_SIG;

    currentOffset = (char*)(id_payload + 1);
    currentOffset = currentOffset + len_id_data;

    //add signature payload
    ISAKMPAddAUTH(nodeconfig, currentOffset, sig_data,
        (int)strlen(sig_data));

    UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    if (exch->phase == PHASE_1)
    {
        // temporarily save phase-1 SA negotiated
        SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    }
    else
    {
        // temporarily save phase-2 SA negotiated
        SetupIPSecSA(nodeconfig, attr, attr_size);
    }
    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }

    MEM_free(id_data);
    MEM_free(sig_data);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\nResponder %s has sent SA,Nonce,ID,Auth to %s"
            " at Simulation time = %s\n", srcStr, dstStr, timeStr);
    }

    stats->numPayloadSASend++;
    stats->numPayloadNonceSend++;
    stats->numPayloadIdSend++;
    stats->numPayloadAuthSend++;
}

//
// FUNCTION   :: ISAKMPResponderReplySANonce
// LAYER      :: Network
// PURPOSE    :: send SA_NONCE msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPResponderReplySANonce(Node* node,
                                     ISAKMPNodeConf* nodeconfig,
                                     Message* msg)
{

    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    UInt16            len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;

    Message*        newMsg = NULL;
    ISAKMPHeader*    isakmp_sendheader, *isakmp_recvheader;
    UInt16            len_packet = 0;
    UInt16            len_SA = 0;
    UInt16            len_prop = 0;
    UInt16            len_trans = 0;
    char*            currentOffset;

    UInt16    notify_type;
    notify_type =
        ISAKMPValidateMessage(node, nodeconfig, msg,ISAKMP_NPTYPE_SA);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    len_trans = exch->trans_selected->h.len;
    if (exch->phase == PHASE_1)
    {
        len_prop  = SIZE_PROPOSAL_Payload + len_trans;
    }
    else
    {
        len_prop  = SIZE_PROPOSAL_Payload + SIZE_SPI + len_trans;
    }

    len_SA = SIZE_SA_Payload + len_prop;

    len_packet = SIZE_ISAKMP_HEADER + len_SA + len_nonce;

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);

    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);

    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylSA* send_sa_payload = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(isakmp_recvheader + 1);

    memcpy((char*)send_sa_payload,
        (char*)recv_sa_payload,
        SIZE_SA_Payload);
    send_sa_payload->h.len = len_SA;
    send_sa_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(send_sa_payload + 1);
    currentOffset = (char*)proposal;

    //copy proposal payload that is selected
    if (exch->phase == PHASE_1)
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload + SIZE_SPI);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload + SIZE_SPI;
    }
    proposal->h.len = len_prop;
    proposal->h.np_type = ISAKMP_NPTYPE_NONE;

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;

    // copy transform payload that is selected
    memcpy((char*)transform, (char*)exch->trans_selected,  len_trans);

    currentOffset = (char*)transform;
    currentOffset = currentOffset + len_trans;

    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)currentOffset;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);

    UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    if (exch->phase == PHASE_1)
    {
        // temporarily save phase-1 SA negotiated
        SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    }
    else
    {
        // temporarily save phase-2 SA negotiated
        SetupIPSecSA(nodeconfig, attr, attr_size);
    }

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\nResponder %s has sent SA,Nonce to %s"
            " at Simulation time = %s\n", srcStr, dstStr, timeStr);
    }

    stats->numPayloadSASend++;
    stats->numPayloadNonceSend++;
}

//
// FUNCTION   :: ISAKMPResponderReplySA
// LAYER      :: Network
// PURPOSE    :: send SA  msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPResponderReplySA(Node* node,
                               ISAKMPNodeConf* nodeconfig,
                               Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    UInt16    notify_type = 0;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    Message*        newMsg = NULL;
    ISAKMPHeader*    isakmp_sendheader, *isakmp_recvheader;
    UInt16            len_packet = 0;
    UInt16            len_SA = 0;
    UInt16            len_prop = 0;
    UInt16            len_trans = 0;
    char*            currentOffset;

    notify_type =
        ISAKMPValidateMessage(node, nodeconfig, msg, ISAKMP_NPTYPE_SA);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    len_trans = exch->trans_selected->h.len;
    if (exch->phase == PHASE_1)
    {
        len_prop  = SIZE_PROPOSAL_Payload + len_trans;
    }
    else
    {
        len_prop  = SIZE_PROPOSAL_Payload + SIZE_SPI + len_trans;
    }
    len_SA = SIZE_SA_Payload + len_prop;

    len_packet = SIZE_ISAKMP_HEADER + len_SA;

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylSA* send_sa_payload = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(isakmp_recvheader + 1);

    memcpy((char*)send_sa_payload,
        (char*)recv_sa_payload,
        SIZE_SA_Payload);
    send_sa_payload->h.len = len_SA;

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(send_sa_payload + 1);
    currentOffset = (char*)proposal;

    //copy proposal that is selected
    if (exch->phase == PHASE_1)
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected, SIZE_PROPOSAL_Payload);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload + SIZE_SPI);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload + SIZE_SPI;
    }
    proposal->h.len = len_prop;
    proposal->h.np_type = ISAKMP_NPTYPE_NONE;

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;

    //copy transform payload that is selected
    memcpy((char*)transform, (char*)exch->trans_selected,  len_trans);

    UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    if (exch->phase == PHASE_1)
    {
        // temporarily save phase-1 SA negotiated
        SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    }
    else
    {
        // temporarily save phase-2 SA negotiated
        SetupIPSecSA(nodeconfig, attr, attr_size);
    }

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\nResponder %s has sent SA to %s"
            " at Simulation time = %s\n", srcStr, dstStr, timeStr);
    }

    stats->numPayloadSASend++;
}

//
// FUNCTION   :: ISAKMPInitiatorRecvSAKENonceIDAuth
// LAYER      :: Network
// PURPOSE    :: process the SA_KE_NONCE_ID_AUTH msg  received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorRecvSAKENonceIDAuth(Node* node,
                                               ISAKMPNodeConf* nodeconfig,
                                               Message* msg)
{
    ISAKMPInitiatorRecvSA(node, nodeconfig, msg);
}

//
// FUNCTION   :: ISAKMPInitiatorRecvSANonceIDAuth
// LAYER      :: Network
// PURPOSE    :: process the SA_NONCE_ID_AUTH msg  received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorRecvSANonceIDAuth(Node* node,
                                            ISAKMPNodeConf* nodeconfig,
                                            Message* msg)
{
    ISAKMPInitiatorRecvSA(node, nodeconfig, msg);
}


// FUNCTION   :: ISAKMPInitiatorRecvSANonce
// LAYER      :: Network
// PURPOSE    :: process the SA_NONCE msg  received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorRecvSANonce(Node* node,
                                    ISAKMPNodeConf* nodeconfig,
                                    Message* msg)
{
     ISAKMPInitiatorRecvSA(node, nodeconfig, msg);
}

// FUNCTION   :: ISAKMPInitiatorRecvSA
// LAYER      :: Network
// PURPOSE    :: process the SA msg  received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorRecvSA(Node* node,
                              ISAKMPNodeConf* nodeconfig,
                              Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    char* currentOffset = NULL;

    UInt16 notify_type = 0;

    notify_type =
              ISAKMPValidateMessage(node, nodeconfig, msg, ISAKMP_NPTYPE_SA);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    ISAKMPHeader* isakmp_recvheader =
                                    (ISAKMPHeader*)MESSAGE_ReturnPacket(msg);

    if (isakmp_recvheader->np_type != ISAKMP_NPTYPE_SA)
    {
        // some unrecognized message
        return;
    }

    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(isakmp_recvheader + 1);
    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(recv_sa_payload + 1);
    currentOffset = (char*)proposal;

    if (exch->phase == PHASE_1)
    {
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload +SIZE_SPI;
    }

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;
    UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    if (exch->phase == PHASE_1)
    {
        // temporarily save phase-1 SA negotiated
        SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    }
    else
    {
        // temporarily save phase-2 SA negotiated
        SetupIPSecSA(nodeconfig, attr, attr_size);
    }

    if ((exch->exchType == ISAKMP_ETYPE_AGG
         || exch->exchType == ISAKMP_IKE_ETYPE_AGG_PRE_SHARED
         || exch->exchType == ISAKMP_IKE_ETYPE_AGG_DIG_SIG
         || exch->exchType == ISAKMP_IKE_ETYPE_AGG_PUB_KEY
         || exch->exchType == ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY)
        && exch->initiator == INITIATOR)
    {
        ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }

    exch->step++;
    (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}

//
// FUNCTION   :: ISAKMPGetSPI
// LAYER      :: Network
// PURPOSE    :: To Retrive SPI value based on Protocol and DOI.
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               IPsecProtocol protocolId - protocol id
//               UInt32 doi - domain of interpretation
// RETURN     :: SPI
// NOTE       :: This is just a stub function as exact implementation
//               is not required for simulation purpose

char* ISAKMPGetSPI(Node* node,
     ISAKMPNodeConf* nodeconfig, IPsecProtocol protocolId, UInt32 doi)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];

    // Please Make sure it gives a unique value
    UInt32 value = RANDOM_nrand(interfaceInfo->isakmpdata->seed) % 100;
    char* spi = (char*)MEM_malloc(SIZE_SPI + 1);
    sprintf(spi, "%u", 1000*protocolId + value + doi);
    return spi;
}

// FUNCTION   :: ISAKMPPhase2AddSA
// LAYER      :: Network
// PURPOSE    :: to add a SA Payload to an ISAKMP phase-2 msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* &newMsg - isakmp message to be send
//               char* &curr_pos - offset in message
//               UInt16 size_other_payloads - other payload size
// RETURN     :: void
// NOTE       ::

static
void ISAKMPPhase2AddSA(Node* node,
                                ISAKMPNodeConf* nodeconfig,
                                Message* &newMsg,
                                char* &curr_pos,
                                UInt16 size_other_payloads)
{
    UInt32  numofProposals = 0;
    UInt32  numofProtocols = 0;
    UInt32  numofTransforms = 0;
    UInt16  len_packet = 0;
    UInt16  len_SA = 0;
    UInt16  len_prop = 0;
    UInt16  len_proto = 0;
    UInt16  len_trans = 0;
    UInt32  np_type;
    char*   currentOffset = NULL;
    ISAKMPHeader* isakmp_sendheader = NULL;

    ISAKMPPaylProp* payload_prop = NULL;
    ISAKMPPaylTrans* payload_trans = NULL;

    ISAKMPProposal* p2_proposal = NULL;
    ISAKMPProtocol* p2_protocol = NULL;
    ISAKMPPhase2Transform* p2_transform = NULL;

    UInt32 i = 0;

    // calculating length of proposal payload beforehand to know how much
    // memory needed to allocate to the packet

    numofProposals = nodeconfig->phase2->numofProposals;
    p2_proposal = nodeconfig->phase2->proposal;
    for (; i < numofProposals; i++)
    {
        UInt32 j = 0;
        numofProtocols = p2_proposal->numofProtocols;
        p2_protocol = p2_proposal->protocol;
        for (; j < numofProtocols; j++)
        {
            UInt32 k = 0;
            numofTransforms = p2_protocol->numofTransforms;
            for (; k < numofTransforms; k++)
            {
                p2_transform = p2_protocol->transform[k];
                ISAKMPPhase2GetTransData(p2_transform);
                len_trans += SIZE_TRANSFORM_Payload + p2_transform->len_attr;
            }
            p2_protocol->len_transforms = len_trans;
            len_trans = 0;
            len_proto += SIZE_PROPOSAL_Payload + SIZE_SPI
                + p2_protocol->len_transforms;
            p2_protocol = p2_protocol->nextproto;
        }
        p2_proposal->len_protocols = len_proto;
        len_proto = 0;
        len_prop = len_prop + p2_proposal->len_protocols;
        p2_proposal = p2_proposal->nextproposal;
    }

    len_SA        = SIZE_SA_Payload + len_prop;
    len_packet    = SIZE_ISAKMP_HEADER + len_SA + size_other_payloads;

    newMsg = MESSAGE_Alloc(node,
                        MAC_LAYER,
                        IPSEC_ISAKMP,
                        MSG_MAC_FromNetwork);

     MESSAGE_PacketAlloc(
                node,
                newMsg,
                len_packet,
                TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylSA* payload_sa = (ISAKMPPaylSA*)(isakmp_sendheader + 1);

    // adding SA payload
    ISAKMPAddSecurityAssociationPayload(payload_sa,
        ISAKMP_NPTYPE_NONE,
        len_SA,IPSEC_DOI,
        IPSEC_SIT_IDENTITY_ONLY);

    currentOffset = (char*)(payload_sa + 1);

    // add all the avalible proposals
    numofProposals = nodeconfig->phase2->numofProposals;
    p2_proposal = nodeconfig->phase2->proposal;
    for (i = 0; i < numofProposals; i++)
    {
        UInt32 j = 0;
        numofProtocols = p2_proposal->numofProtocols;
        p2_protocol = p2_proposal->protocol;
        for (; j < numofProtocols; j++)
        {
            payload_prop = (ISAKMPPaylProp*)currentOffset;

            len_proto = SIZE_PROPOSAL_Payload + SIZE_SPI
                + p2_protocol->len_transforms ;

            if (numofProposals-1 > i || numofProtocols - 1 > j)
            {
                np_type = ISAKMP_NPTYPE_P;
            }
            else
            {
                np_type = ISAKMP_NPTYPE_NONE;
            }

            ISAKMPAddProposalPayload(
                payload_prop,
                np_type,
                len_proto,
                p2_proposal->proposalId,
                p2_protocol->protocolId,
                SIZE_SPI,
                numofTransforms,
                ISAKMPGetSPI(node, nodeconfig,
                p2_protocol->protocolId, nodeconfig->exchange->doi));

            UInt32 k = 0;
            payload_trans = (ISAKMPPaylTrans*)payload_prop;

            // add all the avalible transforms
            numofTransforms = p2_protocol->numofTransforms;
            for (; k < numofTransforms; k++)
            {
                if (numofTransforms - 1 > k)
                {
                    np_type = ISAKMP_NPTYPE_T;
                }
                else
                {
                    np_type = ISAKMP_NPTYPE_NONE;
                }

               p2_transform = p2_protocol->transform[k];

               ISAKMPAddTransformPayload(payload_trans,
                    np_type,
                    k + 1,
                    p2_transform->transformId,
                    p2_transform->len_attr,
                    p2_transform->attributes);

            }
            currentOffset = (char*)payload_trans;
            p2_protocol = p2_protocol->nextproto;
        }
        p2_proposal = p2_proposal->nextproposal;
    }

    curr_pos = (char*)payload_trans;
}



// FUNCTION   :: ISAKMPPhase2AddHashSA
// LAYER      :: Network
// PURPOSE    :: to add a Hash SA Payload to an ISAKMP phase-2 msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* &newMsg - isakmp message to be send
//               char* &curr_pos - offset in message
//               UInt16 size_other_payloads - other payload size
// RETURN     :: char* to SA payload starting offset
// NOTE       ::

static
char* ISAKMPPhase2AddHashSA(Node* node,
                           ISAKMPNodeConf* nodeconfig,
                           Message* &newMsg,
                           char* &curr_pos,
                           UInt16 size_other_payloads)
{
    UInt32  numofProposals = 0;
    UInt32  numofProtocols = 0;
    UInt32  numofTransforms = 0;
    UInt16  len_packet = 0;
    UInt32  len_hash  = 0;
    UInt32  len_hash_data = 0;
    UInt16  len_SA = 0;
    UInt16  len_prop = 0;
    UInt16  len_proto = 0;
    UInt16  len_trans = 0;
    UInt32  np_type;
    char*   currentOffset = NULL;
    char*   sa_payload_offset = NULL;
    char*   hash_data = NULL;
    ISAKMPHeader* isakmp_sendheader = NULL;

    ISAKMPPaylProp* payload_prop = NULL;
    ISAKMPPaylTrans* payload_trans = NULL;

    ISAKMPProposal* p2_proposal = NULL;
    ISAKMPProtocol* p2_protocol = NULL;
    ISAKMPPhase2Transform* p2_transform = NULL;

    UInt32 i = 0;

    // calculating length of proposal payload beforehand to know how much
    // memory needed to allocate to the packet

    numofProposals = nodeconfig->phase2->numofProposals;
    p2_proposal = nodeconfig->phase2->proposal;
    for (; i < numofProposals; i++)
    {
        UInt32 j = 0;
        numofProtocols = p2_proposal->numofProtocols;
        p2_protocol = p2_proposal->protocol;
        for (; j < numofProtocols; j++)
        {
            UInt32 k = 0;
            numofTransforms = p2_protocol->numofTransforms;
            for (; k < numofTransforms; k++)
            {
                p2_transform = p2_protocol->transform[k];
                ISAKMPPhase2GetTransData(p2_transform);
                len_trans += SIZE_TRANSFORM_Payload + p2_transform->len_attr;
            }
            p2_protocol->len_transforms = len_trans;
            len_trans = 0;
            len_proto += SIZE_PROPOSAL_Payload + SIZE_SPI
                + p2_protocol->len_transforms;
            p2_protocol = p2_protocol->nextproto;
        }
        p2_proposal->len_protocols = len_proto;
        len_proto = 0;
        len_prop = len_prop + p2_proposal->len_protocols;
        p2_proposal = p2_proposal->nextproposal;
    }

    //getting Hash data
    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);
    len_hash   = SIZE_HASH_Payload + len_hash_data;

    len_SA     = SIZE_SA_Payload + len_prop;
    len_packet = (UInt16)(SIZE_ISAKMP_HEADER + len_hash + len_SA
                                             + size_other_payloads);

    newMsg = MESSAGE_Alloc(node,
                        MAC_LAYER,
                        IPSEC_ISAKMP,
                        MSG_MAC_FromNetwork);

     MESSAGE_PacketAlloc(
                node,
                newMsg,
                len_packet,
                TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_sendheader->len = len_packet;

    // add hash payload
    ISAKMPPaylHash* payload_hash = (ISAKMPPaylHash*)(isakmp_sendheader + 1);
    currentOffset =  (char*)(isakmp_sendheader + 1);

    ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);
    payload_hash->h.np_type = ISAKMP_NPTYPE_SA;

    currentOffset = (char*)(payload_hash + 1);
    currentOffset = currentOffset + len_hash_data;

    ISAKMPPaylSA* payload_sa = (ISAKMPPaylSA*)(currentOffset);
    sa_payload_offset = (char*)(currentOffset);

    // adding SA payload
    ISAKMPAddSecurityAssociationPayload(payload_sa,
        ISAKMP_NPTYPE_NONE,
        len_SA,IPSEC_DOI,
        IPSEC_SIT_IDENTITY_ONLY);

    currentOffset = (char*)(payload_sa + 1);

    // add all the avalible proposals
    numofProposals = nodeconfig->phase2->numofProposals;
    p2_proposal = nodeconfig->phase2->proposal;
    for (i = 0; i < numofProposals; i++)
    {
        UInt32 j = 0;
        numofProtocols = p2_proposal->numofProtocols;
        p2_protocol = p2_proposal->protocol;
        for (; j < numofProtocols; j++)
        {
            payload_prop = (ISAKMPPaylProp*)currentOffset;

            len_proto = SIZE_PROPOSAL_Payload + SIZE_SPI
                + p2_protocol->len_transforms ;

            if (numofProposals-1 > i || numofProtocols - 1 > j)
            {
                np_type = ISAKMP_NPTYPE_P;
            }
            else
            {
                np_type = ISAKMP_NPTYPE_NONE;
            }

            ISAKMPAddProposalPayload(
                payload_prop,
                np_type,
                len_proto,
                p2_proposal->proposalId,
                p2_protocol->protocolId,
                SIZE_SPI,
                numofTransforms,
                ISAKMPGetSPI(node, nodeconfig,
                p2_protocol->protocolId, nodeconfig->exchange->doi));

            UInt32 k = 0;
            payload_trans = (ISAKMPPaylTrans*)payload_prop;

            // add all the avalible transforms
            numofTransforms = p2_protocol->numofTransforms;
            for (; k < numofTransforms; k++)
            {
                if (numofTransforms - 1 > k)
                {
                    np_type = ISAKMP_NPTYPE_T;
                }
                else
                {
                    np_type = ISAKMP_NPTYPE_NONE;
                }

               p2_transform = p2_protocol->transform[k];

               ISAKMPAddTransformPayload(payload_trans,
                    np_type,
                    k + 1,
                    p2_transform->transformId,
                    p2_transform->len_attr,
                    p2_transform->attributes);

            }
            currentOffset = (char*)payload_trans;
            p2_protocol = p2_protocol->nextproto;
        }
        p2_proposal = p2_proposal->nextproposal;
    }

    curr_pos = (char*)payload_trans;

    return sa_payload_offset;
}



// FUNCTION   :: ISAKMPPhase1AddSA
// LAYER      :: Network
// PURPOSE    :: to add a SA Payload to an ISAKMP phase-1 msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* &newMsg - isakmp message to be send
//               char* &curr_pos - offset in message
//               UInt16 size_other_payloads - other payload size
// RETURN     :: void
// NOTE       ::

static
void ISAKMPPhase1AddSA(Node* node,
                              ISAKMPNodeConf* nodeconfig,
                              Message* &newMsg,
                              char* &curr_pos,
                              UInt16 size_other_payloads)
{
    UInt32 numofTransforms = 0;
    UInt16 len_packet = 0;
    UInt16 len_SA = 0;
    UInt16 len_prop = 0;
    UInt16 len_trans = 0;
    ISAKMPHeader* isakmp_sendheader = NULL;
    UInt32 i;

    ISAKMPPhase1Transform* p1_transform;
    numofTransforms = nodeconfig->phase1->numofTransforms;

    for (i = 0; i < numofTransforms; i++)
    {
        p1_transform = nodeconfig->phase1->transform[i];
        ISAKMPPhase1GetTransData(p1_transform);
        len_trans += SIZE_TRANSFORM_Payload + p1_transform->len_attr;
    }

    len_prop    = SIZE_PROPOSAL_Payload + len_trans;
    len_SA      = SIZE_SA_Payload + len_prop;
    len_packet  = SIZE_ISAKMP_HEADER + len_SA + size_other_payloads;

    newMsg = MESSAGE_Alloc(node,
                        MAC_LAYER,
                        IPSEC_ISAKMP,
                        MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;

    isakmp_sendheader->len = len_packet;

    ISAKMPPaylSA* payload_sa = (ISAKMPPaylSA*)(isakmp_sendheader + 1);

    ISAKMPAddSecurityAssociationPayload(payload_sa,
        ISAKMP_NPTYPE_NONE,
        len_SA,
        ISAKMP_DOI,
        IPSEC_SIT_IDENTITY_ONLY);

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(payload_sa + 1);

    // only one proposal is sent during the phase1
    ISAKMPAddProposalPayload(proposal,
        ISAKMP_NPTYPE_NONE,
        len_prop,
        1,
        IPSEC_ISAKMP,
        0,
        numofTransforms,
        NULL);

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)proposal;

    UInt32 np_type;
    for (i = 0; i < numofTransforms; i++)
    {
        if (numofTransforms - 1 > i)
        {
            np_type = ISAKMP_NPTYPE_T;
        }
        else
        {
            np_type = ISAKMP_NPTYPE_NONE;
        }

        p1_transform = nodeconfig->phase1->transform[i];

        ISAKMPAddTransformPayload(transform,
            np_type,
            i + 1,
            p1_transform->transformId,
            p1_transform->len_attr,
            p1_transform->attributes);
    }

    curr_pos = (char*)transform;
}



// FUNCTION   :: ISAKMPPhase1AddHashSA
// LAYER      :: Network
// PURPOSE    :: to add a SA Payload to an ISAKMP phase-1 msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* &newMsg - isakmp message to be send
//               char* &curr_pos - offset in message
//               UInt16 size_other_payloads - other payload size
// RETURN     :: char* to SA payload starting offset
// NOTE       ::

static
char* ISAKMPPhase1AddHashSA(Node* node,
                              ISAKMPNodeConf* nodeconfig,
                              Message* &newMsg,
                              char* &curr_pos,
                              UInt16 size_other_payloads)
{
    UInt32 numofTransforms = 0;
    UInt16 len_packet = 0;
    UInt32 len_hash  = 0;
    UInt32 len_hash_data = 0;
    UInt16 len_SA = 0;
    UInt16 len_prop = 0;
    UInt16 len_trans = 0;
    ISAKMPHeader* isakmp_sendheader = NULL;
    UInt32 i;

    char* hash_data = NULL;
    char* currentOffset = NULL;
    char* sa_payload_offset = NULL;

    ISAKMPPhase1Transform* p1_transform;
    numofTransforms = nodeconfig->phase1->numofTransforms;

    for (i = 0; i < numofTransforms; i++)
    {
        p1_transform = nodeconfig->phase1->transform[i];
        ISAKMPPhase1GetTransData(p1_transform);
        len_trans += SIZE_TRANSFORM_Payload + p1_transform->len_attr;
    }

    //getting Hash data
    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);
    len_hash   = SIZE_HASH_Payload + len_hash_data;

    len_prop   = SIZE_PROPOSAL_Payload + len_trans;
    len_SA     = SIZE_SA_Payload + len_prop;
    len_packet = (UInt16)(SIZE_ISAKMP_HEADER + len_hash + len_SA
                                                      + size_other_payloads);

    newMsg = MESSAGE_Alloc(node,
                        MAC_LAYER,
                        IPSEC_ISAKMP,
                        MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;

    isakmp_sendheader->len = len_packet;

    // add hash payload
    ISAKMPPaylHash* payload_hash = (ISAKMPPaylHash*)(isakmp_sendheader + 1);
    currentOffset =  (char*)(isakmp_sendheader + 1);

    ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);
    payload_hash->h.np_type = ISAKMP_NPTYPE_SA;

    currentOffset = (char*)(payload_hash + 1);
    currentOffset = currentOffset + len_hash_data;

    ISAKMPPaylSA* payload_sa = (ISAKMPPaylSA*)(currentOffset);
    sa_payload_offset = (char*)(currentOffset);

    ISAKMPAddSecurityAssociationPayload(payload_sa,
        ISAKMP_NPTYPE_NONE,
        len_SA,
        ISAKMP_DOI,
        IPSEC_SIT_IDENTITY_ONLY);

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(payload_sa + 1);

    // only one proposal is sent during the phase1
    ISAKMPAddProposalPayload(proposal,
        ISAKMP_NPTYPE_NONE,
        len_prop,
        1,
        IPSEC_ISAKMP,
        0,
        numofTransforms,
        NULL);

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)proposal;

    UInt32 np_type;
    for (i = 0; i < numofTransforms; i++)
    {
        if (numofTransforms - 1 > i)
        {
            np_type = ISAKMP_NPTYPE_T;
        }
        else
        {
            np_type = ISAKMP_NPTYPE_NONE;
        }

        p1_transform = nodeconfig->phase1->transform[i];

        ISAKMPAddTransformPayload(transform,
            np_type,
            i + 1,
            p1_transform->transformId,
            p1_transform->len_attr,
            p1_transform->attributes);
    }

    curr_pos = (char*)transform;

    return sa_payload_offset;
}


// FUNCTION   :: ISAKMPInitiatorSendSAKENonceID
// LAYER      :: Network
// PURPOSE    :: to send SA_KE_NONCE_ID msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorSendSAKENonceID(Node* node,
                                          ISAKMPNodeConf* nodeconfig,
                                          Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    UInt16    notify_type = 0;
    Message*  newMsg = NULL;
    char*     curr_pos = NULL;
    char*     currentOffset = NULL;
    char*     id_data = NULL;

    ISAKMPHeader*  isakmp_sendheader = NULL;
    ISAKMPHeader*  isakmp_recvheader =
        (ISAKMPHeader*)MESSAGE_ReturnPacket(msg);

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    UInt16 len_id = 0;
    UInt32 len_id_data = 0;
    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;
    UInt16 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt16 total_len = 0;

    memcpy(nodeconfig->exchange->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);

    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_NONE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    len_id    = (UInt16)(SIZE_ID_Payload + len_id_data);

    total_len = len_ke + len_nonce + len_id;

    UInt32 phase = nodeconfig->exchange->phase;
    if (phase == PHASE_1)
    {
        ISAKMPPhase1AddSA(node, nodeconfig, newMsg, curr_pos, total_len);
    }
    else
    {
        ISAKMPPhase2AddSA(node, nodeconfig, newMsg, curr_pos, total_len);
    }

    isakmp_sendheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(newMsg);
    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;

    ISAKMPPaylSA* payload_sa = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    payload_sa->h.np_type = ISAKMP_NPTYPE_KE;

    ISAKMPPaylKeyEx* payload_ke = (ISAKMPPaylKeyEx*)curr_pos;

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, payload_ke);

    payload_ke->h.np_type = ISAKMP_NPTYPE_NONCE;

    currentOffset = (char*)(payload_ke + 1);
    currentOffset = currentOffset + KEY_SIZE;

    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)currentOffset;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);
    payload_nonce->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)payload_nonce;
    currentOffset = currentOffset + len_nonce;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);

    MEM_free(id_data);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    nodeconfig->exchange->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\nInitiator %s has sent SA,KE,Nonce,ID to %s"
            " at Simulation time = %s\n", srcStr, dstStr, timeStr);
    }

    stats->numPayloadSASend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadNonceSend++;
    stats->numPayloadIdSend++;
}


// FUNCTION   :: ISAKMPInitiatorSendSANonce
// LAYER      :: Network
// PURPOSE    :: to send SA_NONCE msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorSendSANonce(Node* node,
                                    ISAKMPNodeConf* nodeconfig,
                                    Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;
    UInt16    notify_type = 0;
    Message*  newMsg = NULL;
    char*     curr_pos = NULL;
    UInt32    phase;

    ISAKMPHeader* isakmp_sendheader = NULL;
    ISAKMPHeader* isakmp_recvheader =
        (ISAKMPHeader*)MESSAGE_ReturnPacket(msg);

    // Find source and Destination ISAKMP servers
    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    UInt16            len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;

    // save responder cookie
    memcpy(nodeconfig->exchange->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        printf("\n\nInitiator %s has recv resp cookie from %s",
            srcStr, dstStr);
    }

    //validate the received message
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_NONE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    phase = nodeconfig->exchange->phase;
    if (phase == PHASE_1)
    {
        ISAKMPPhase1AddSA(node, nodeconfig, newMsg, curr_pos, len_nonce);
    }
    else
    {
        ISAKMPPhase2AddSA(node, nodeconfig, newMsg, curr_pos, len_nonce);
    }

    isakmp_sendheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(newMsg);

    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);

    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);

    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;

    ISAKMPPaylSA* payload_sa = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    payload_sa->h.np_type = ISAKMP_NPTYPE_NONCE;

    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)curr_pos;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    nodeconfig->exchange->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\nInitiator %s has sent SA,Nonce to %s"
            " at Simulation time = %s\n", srcStr, dstStr, timeStr);
    }

    stats->numPayloadSASend++;
    stats->numPayloadNonceSend++;
}

// FUNCTION   :: ISAKMPInitiatorSendSA
// LAYER      :: Network
// PURPOSE    :: to send SA  msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorSendSA(Node* node,
                              ISAKMPNodeConf* nodeconfig,
                              Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    UInt32    phase;
    Message*  newMsg = NULL;
    char*     curr_pos = NULL;
    UInt16    notify_type = 0;
    ISAKMPHeader* isakmp_sendheader = NULL;
    ISAKMPHeader* isakmp_recvheader =
        (ISAKMPHeader*)MESSAGE_ReturnPacket(msg);

    //Find source and Destination ISAKMP servers
    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    // save Responder cookie
    memcpy(nodeconfig->exchange->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        printf("\n\nInitiator %s has recv resp cookie from %s",
            srcStr, dstStr);
    }

    // validate the received message
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_NONE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if (ISAKMP_DEBUG)
    {
        printf("\n after responder cookie validation");
    }

    phase = nodeconfig->exchange->phase;

    if (phase == PHASE_1)
    {
        ISAKMPPhase1AddSA(node, nodeconfig, newMsg, curr_pos, 0);
    }
    else
    {
        ISAKMPPhase2AddSA(node, nodeconfig, newMsg, curr_pos, 0);
    }

    isakmp_sendheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(newMsg);
    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    nodeconfig->exchange->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\nInitiator %s has sent SA to %s"
            " at Simulation time = %s\n", srcStr, dstStr, timeStr);
    }

    stats->numPayloadSASend++;
}

// FUNCTION   :: ISAKMPValidatepayload
// LAYER      :: Network
// PURPOSE    :: processing of all payloads in a msg received is done here
// PARAMETERS :: ISAKMPStats* &stats - isakmp stats
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               unsigned char payload_type - payload type
//               char* currentOffset - offset in message
// RETURN     :: UInt16 - error or notification type
// NOTE       ::

static
UInt16 ISAKMPValidatepayload(ISAKMPStats* &stats,
                        ISAKMPNodeConf* nodeconfig,
                        unsigned char payload_type,
                        char* currentOffset)
{
    UInt16 notify_type = 0;

    switch (payload_type)
    {
        case ISAKMP_NPTYPE_SA:
            notify_type = ISAKMPValidatePayloadSA(
                stats, nodeconfig, (ISAKMPPaylSA*)(currentOffset));
            break;
        case ISAKMP_NPTYPE_KE:
            notify_type = ISAKMPValidatePayloadKE(
                stats, nodeconfig, (ISAKMPPaylKeyEx*)(currentOffset));
            break;
        case ISAKMP_NPTYPE_ID:
            notify_type = ISAKMPValidatePayloadID(
                stats, nodeconfig, (ISAKMPPaylId*)(currentOffset));
            break;
        case ISAKMP_NPTYPE_CERT:
            notify_type = ISAKMPValidatePayloadCert(
                stats, nodeconfig, (ISAKMPPaylCert*)(currentOffset));
            break;
        case ISAKMP_NPTYPE_HASH:
            notify_type = ISAKMPValidatePayloadHash(
                stats, nodeconfig, (ISAKMPPaylHash*)(currentOffset));
            break;
        case ISAKMP_NPTYPE_SIG:
            notify_type = ISAKMPValidatePayloadSIG(
                stats, nodeconfig, (ISAKMPPaylSig*)(currentOffset));
            break;
        case ISAKMP_NPTYPE_NONCE:
            notify_type = ISAKMPValidatePayloadNonce(
                stats, nodeconfig, (ISAKMPPaylNonce*)(currentOffset));
            break;
        case ISAKMP_NPTYPE_N:
            notify_type = ISAKMPValidatePayloadNotify(
                stats, (ISAKMPPaylNotif*)(currentOffset));
        case ISAKMP_NPTYPE_D:
            break;
        default:
            break;
    }
    return notify_type;
}

// FUNCTION   :: ISAKMPHandleProtocolEvent
// LAYER      :: Network
// PURPOSE    :: Handler for a ISAKMP Protocol event
// PARAMETERS :: Node* node - node data
//               Message* msg - isakmp protocol event
// RETURN     :: void
// NOTE       ::

void ISAKMPHandleProtocolEvent(Node* node, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    ISAKMPTimerInfo* info = (ISAKMPTimerInfo*) MESSAGE_ReturnInfo(msg);
    ISAKMPNodeConf* nodeconfig = info->nodeconfig;

    switch (msg->eventType)
    {
        case MSG_NETWORK_ISAKMP_SchedulePhase1:
        {
            ISAKMPSetUp_Negotiation(node, nodeconfig, msg,
                nodeconfig->nodeAddress, nodeconfig->peerAddress,
                INITIATOR, PHASE_1);

            break;
        }

        case MSG_NETWORK_ISAKMP_ScheduleNextPhase:
        {
            ISAKMPSetUp_Negotiation(node, nodeconfig, msg, 0, 0,
                                    INITIATOR, PHASE_1);

            break;
        }

        case MSG_NETWORK_ISAKMP_SchedulePhase2:
        {
            ISAKMPSetUp_Negotiation(node, nodeconfig, msg, 0, 0,
                                    INITIATOR, PHASE_2);

            break;
        }

        // Check to see if need to retransmit any Packet.
        case MSG_NETWORK_ISAKMP_RxmtTimer:
        {
            if (ISAKMP_DEBUG)
            {
                char srcStr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
                char clockStr[100];
                ctoa(node->getNodeTime(), clockStr);
                printf("%s got RxmtTimer expired at time %s\n",
                        srcStr, clockStr);
                printf("step number is %u\n", info->value);
            }

            if (nodeconfig->exchange == NULL)
            {
                // no exchange is running
                MESSAGE_Free(node, msg);
                return;
            }

            if (nodeconfig->exchange->retrycounter == RETRY_LIMIT)
            {
                unsigned char phase = nodeconfig->exchange->phase;

                // drop the exchange
                ISAKMPDropExchange(node, nodeconfig);

                // restart exchange after some time
                if (phase == PHASE_1)
                {
                    ISAKMPSetTimer(
                            node,
                            nodeconfig,
                            MSG_NETWORK_ISAKMP_SchedulePhase1,
                            0,
                            RETRY_LIMIT * ISAKMP_RETRANS_INTERVAL);
                }
                else
                {
                    if (nodeconfig->current_pointer_list
                       && nodeconfig->current_pointer_list->phase2 ==
                       nodeconfig->phase2)
                    {
                        //set flag to retry the establishment
                        nodeconfig->current_pointer_list->reestabRequired =
                            TRUE;
                    }
                }
                return;
            }

            if (nodeconfig->exchange->step != info->value
                || nodeconfig->exchange->phase != info->phase)
            {
                MESSAGE_Free(node, msg);
                return;
            }

            nodeconfig->exchange->retrycounter++;

            Message* newMsg = MESSAGE_Duplicate(
                node, nodeconfig->exchange->lastSentPkt);

            ISAKMPSetTimer(node,
               nodeconfig,
               MSG_NETWORK_ISAKMP_RxmtTimer,
               nodeconfig->exchange->step);

            // Retransmit packet to specified peer.
            NetworkIpSendRawMessage(
                    node,
                    newMsg,
                    nodeconfig->nodeAddress,
                    nodeconfig->peerAddress,
                    ANY_INTERFACE,
                    IPTOS_PREC_INTERNETCONTROL,
                    IPPROTO_ISAKMP,
                    9);

                if (ISAKMP_DEBUG)
                {
                    char srcStr[MAX_STRING_LENGTH];
                    char dstStr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(
                        nodeconfig->nodeAddress, srcStr);
                    IO_ConvertIpAddressToString(
                        nodeconfig->peerAddress, dstStr);
                    char timeStr[100];
                    ctoa(node->getNodeTime(), timeStr);
                    printf("\n%s has Retransmitted msg to %s"
                      " at Simulation time = %s\n", srcStr, dstStr, timeStr);
                }

            NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
            IpInterfaceInfoType* interfaceInfo =
                ip->interfaceInfo[nodeconfig->interfaceIndex];
            ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

            stats->numOfRetransmissions++;
            break;
        }
        case MSG_NETWORK_ISAKMP_RefreshTimer:
        {
            if (ISAKMP_DEBUG)
            {
                char srcStr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
                char clockStr[100];
                ctoa(node->getNodeTime(), clockStr);
                printf("%s got Refresh Timer expired at time %s\n",
                        srcStr, clockStr);
                printf("SPI value is %u\n", info->value);
            }

            ISAKMPPhase2List* phase2_list = nodeconfig->phase2_list;

            while (phase2_list)
            {
                IPSEC_SA* &ipsec_sa = phase2_list->phase2->ipsec_sa;

                if (phase2_list->is_ipsec_sa
                && ipsec_sa->SPI == info->value)
                {
                    phase2_list->is_ipsec_sa = FALSE;

                    //if (ip->isIPsecEnabled == TRUE)
                    {
                        IpInterfaceInfoType* interfaceInfo =
                            ip->interfaceInfo[nodeconfig->interfaceIndex];
                        IPsecSecurityAssociationEntry* sa = NULL;
                        IPsecSecurityPolicyEntry* sp = NULL;

                        // Remove SA from database
                        sa = IPsecRemoveMatchingSAfromSAD(node,
                            ipsec_sa->proto,
                            nodeconfig->peerAddress,
                            ipsec_sa->SPI);

                        sp = IPsecGetMatchingSP(
                            phase2_list->phase2->localNetwork,
                            phase2_list->phase2->peerNetwork,
                            phase2_list->phase2->upperProtocol,
                            interfaceInfo->spdOUT->spd);

                        IPsecRemoveSAfromSP(sp, sa);

                        sa = IPsecRemoveMatchingSAfromSAD(node,
                                ipsec_sa->proto,
                                nodeconfig->nodeAddress,
                                ipsec_sa->SPI);

                        sp = IPsecGetMatchingSP(
                            phase2_list->phase2->peerNetwork,
                            phase2_list->phase2->localNetwork,
                            phase2_list->phase2->upperProtocol,
                            interfaceInfo->spdIN->spd);

                        IPsecRemoveSAfromSP(sp, sa);
                    }

                    // send notification of SA delete ,use delete payload
                    ISAKMPSendDeleteMessage(node, nodeconfig, ipsec_sa);

                    MEM_free(ipsec_sa);
                    ipsec_sa = NULL;
                    break;
                }
                phase2_list = phase2_list->next;
            }
            if (phase2_list == NULL)
            {
                break;
            }

            // start reestablishment
            if (nodeconfig->exchange == NULL)
            {
                nodeconfig->phase2 = phase2_list->phase2;
                nodeconfig->current_pointer_list = phase2_list;

                BOOL isIkeExchange = FALSE;
                unsigned char exchType = ISAKMP_ETYPE_NONE;

                //getting exchange type
                if (nodeconfig->phase2)
                {
                    exchType = nodeconfig->phase2->exchtype;
                }

                isIkeExchange = IsIKEExchange(exchType);

                if (isIkeExchange)
                {
                    //adding crypto delay caused for sending delete message
                    ISAKMPSetTimer(
                        node,
                        nodeconfig,
                        MSG_NETWORK_ISAKMP_SchedulePhase2,
                        0,
                        ISAKMPGetProcessDelay(node, nodeconfig));
                }
                else
                {
                    ISAKMPSetUp_Negotiation(
                           node, nodeconfig, NULL, 0, 0, INITIATOR, PHASE_2);
                }

                NetworkDataIp* ip =
                    (NetworkDataIp*)node->networkData.networkVar;
                IpInterfaceInfoType* interfaceInfo =
                    ip->interfaceInfo[nodeconfig->interfaceIndex];
                ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

                stats->numOfReestablishments++;
            }
            else
            {
                // set flag for later reestablishment
                phase2_list->reestabRequired = TRUE;
            }
            break;
        }

        default:
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr, "Node %u: Got invalid ISAKMP message\n",
                node->nodeId);
            ERROR_Assert(FALSE, errStr);
        }
    }// end switch

    MESSAGE_Free(node, msg);
}

// FUNCTION   :: ISAKMPHandleProtocolPacket
// LAYER      :: Network
// PURPOSE    :: Handler for a ISAKMP Protocol Packet
// PARAMETERS :: Node* node - node data
//               Message* msg - isakmp paccket received
//               NodeAddress source - isakmp paccket source
//               NodeAddress dest - isakmp paccket destination
// RETURN     :: void
// NOTE       ::

void ISAKMPHandleProtocolPacket(Node *node,
                                Message* msg,
                                NodeAddress source,
                                NodeAddress dest)
{
    UInt32 interfaceIndex =
        NetworkIpGetInterfaceIndexFromAddress(node, dest);

    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];
    ISAKMPHeader* isakmp_header;

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(dest, srcStr);
        IO_ConvertIpAddressToString(source, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\n%s has received a ISAKMP msg from %s"
                " at Simulation time = %s\n", dstStr, srcStr, timeStr);
    }

    if (interfaceInfo->isISAKMPEnabled)
    {
        ISAKMPNodeConf* nodeConfData =
            interfaceInfo->isakmpdata->nodeConfData;
        isakmp_header = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

        // if Phase 1 message
        if (isakmp_header->msgid == 0)
        {
            // message to setup an ISAKMP SA
            if (ISAKMP_IsZero(isakmp_header->resp_cookie, 8))
            {
                ISAKMPSetUp_Negotiation(
                    node, NULL, msg, dest, source, RESPONDER, PHASE_1);
            }
            else
            {
                nodeConfData = ISAKMPGetNodeConfig(node, dest, source);

                if (ISAKMP_DEBUG)
                {
                    ISAKMPNodeConf* tempConfData =
                        interfaceInfo->isakmpdata->nodeConfData;

                    FindExchConfigForCookie(
                        (char*)(isakmp_header->init_cookie),
                        (char*)(isakmp_header->resp_cookie),
                        tempConfData);

                    if (tempConfData != nodeConfData)
                    {
                        printf("PROBLEM: Cookie has got corruptted\n");
                    }
                }

                if (nodeConfData == NULL)
                {
                    MESSAGE_Free(node, msg);
                    return;
                }

                if (ISAKMP_DEBUG)
                {
                    char srcStr[MAX_STRING_LENGTH];
                    char dstStr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(
                        nodeConfData->nodeAddress, srcStr);
                    IO_ConvertIpAddressToString(
                        nodeConfData->peerAddress, dstStr);
                    printf("\nnodeConfData is present: nodeAddress %s,"
                        "peerAddress %s", srcStr, dstStr);
                }
                ISAKMPExchange* &exch    = nodeConfData->exchange;

                if (exch == NULL)
                {
                    // either this is information msg with delete payload
                    // or retransmission of last received packet for which
                    // info msg is been sent but not received at the peer
                    MESSAGE_Free(node, msg);
                    return;
                }

                (*(*exch->funcList)[exch->step])(node, nodeConfData, msg);
            }
        }
        else
        {
            // message to setup an IPSec SA
            if (ISAKMP_IsZero(isakmp_header->resp_cookie, 8))
            {
                ISAKMPSetUp_Negotiation(
                    node, NULL, msg, dest, source, RESPONDER, PHASE_2);
            }
            else
            {
                nodeConfData = ISAKMPGetNodeConfig(node, dest, source);

                if (ISAKMP_DEBUG)
                {
                    ISAKMPNodeConf* tempConfData =
                        interfaceInfo->isakmpdata->nodeConfData;
                    FindExchConfigForCookie(
                        (char*)(isakmp_header->init_cookie),
                        (char*)(isakmp_header->resp_cookie),
                        tempConfData);
                    if (tempConfData != nodeConfData)
                    {
                        printf("PROBLEM: Cookie has got corruptted\n");
                    }
                }

                if (nodeConfData == NULL)
                {
                    MESSAGE_Free(node, msg);
                    return;
                }

                ISAKMPExchange* &exch    = nodeConfData->exchange;

                if (exch == NULL)
                {
                    // either this is information msg with delete payload
                    // or retransmission of last received packet for which
                    // info msg is been sent bur not received to the peer

                    //check for delete message with hash payload
                    if (isakmp_header->np_type == ISAKMP_NPTYPE_HASH)
                    {
                        //extracting Hash payload from isakmp recv message
                        char* currentOffset = NULL;
                        ISAKMPPaylHash* recv_hash_payload =
                                        (ISAKMPPaylHash*)(isakmp_header + 1);
                        currentOffset = (char*)recv_hash_payload;
                        currentOffset = currentOffset +
                                                    recv_hash_payload->h.len;

                        //check for next message type
                        if (recv_hash_payload->h.np_type == ISAKMP_NPTYPE_D)
                        {
                            ISAKMPReceiveDeleteMessage(
                                node, msg, nodeConfData, ISAKMP_NPTYPE_HASH);
                        }
                    }
                    //check for simple delete message
                    else if (isakmp_header->np_type == ISAKMP_NPTYPE_D)
                    {
                        ISAKMPReceiveDeleteMessage(
                                   node, msg, nodeConfData, ISAKMP_NPTYPE_D);
                    }
                    MESSAGE_Free(node, msg);
                    return;
                }
                (*(*exch->funcList)[exch->step])(node, nodeConfData, msg);
            }
        }
    }
    MESSAGE_Free(node, msg);
}

// FUNCTION   :: ISAKMPFinalize
// LAYER      :: Network
// PURPOSE    :: Finalise function for ISAKMP, to Print Collected Statistics
// PARAMETERS :: Node* node - node data
//               UInt32 interfaceIndex - interface index
// RETURN     :: void
// NOTE       ::

void ISAKMPFinalize(Node* node, UInt32 interfaceIndex)
{
    char buf[BUFFER_SIZE];
    char addrStr[MAX_STRING_LENGTH];

    NodeAddress nodeIp = NetworkIpGetInterfaceAddress(node, interfaceIndex);
    IO_ConvertIpAddressToString(nodeIp, addrStr);

    if (node->networkData.networkStats)
    {
        NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
        IpInterfaceInfoType* interfaceInfo =
            ip->interfaceInfo[interfaceIndex];
        ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

        sprintf(buf, "Total Number of Aggressive Exchange = %u",
                            stats->numOfAggresExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Authentication Only Exchange = %u",
                            stats->numOfAuthOnlyExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Base Exchange = %u",
                                                       stats->numOfBaseExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Identity Protection Exchange = %u",
                            stats->numOfIdProtExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf,
               "Total Number of IKE Main Pre-Shared Key Exchange = %u",
               stats->numOfIkeMainPreSharedExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf,
                "Total Number of IKE Main Digital Signature Exchange = %u",
                stats->numOfIkeMainDigSigExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of IKE Main Public Key Exchange = %u",
                            stats->numOfIkeMainPubKeyExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf,
                "Total Number of IKE Main Revised Public Key Exchange = %u",
                stats->numOfIkeMainRevPubKeyExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf,
               "Total Number of IKE Aggressive Pre-Shared Key Exchange = %u",
               stats->numOfIkeAggresPreSharedExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf,
            "Total Number of IKE Aggressive Digital Signature Exchange = %u",
            stats->numOfIkeAggresDigSigExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf,
            "Total Number of IKE Aggressive Public Key Exchange = %u",
            stats->numOfIkeAggresPubKeyExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf,
           "Total Number of IKE Aggressive Revised Public Key Exchange = %u",
           stats->numOfIkeAggresRevPubKeyExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of IKE Quick Exchange = %u",
                            stats->numOfIkeQuickExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of IKE New Group Exchange = %u",
                            stats->numOfIkeNewGroupExch);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Information Exchange Send = %u",
                            stats->numOfInformExchSend);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Information Exchange Receive = %u",
                            stats->numOfInformExchRcv);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Exchange Dropped = %u",
                            stats->numOfExchDropped);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf,
                "Total Number of SA Payload Send = %u",
                stats->numPayloadSASend);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf,
               "Total Number of SA Payload Rcv = %u",
               stats->numPayloadSARcv);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Nonce Payload Send = %u",
                            stats->numPayloadNonceSend);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Nonce Payload Rcv = %u",
                            stats->numPayloadNonceRcv);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Key Exchange Payload Send = %u",
                            stats->numPayloadKeyExSend);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Key Exchange Payload Rcv = %u",
                            stats->numPayloadKeyExRcv);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Identity Payload Send = %u",
                            stats->numPayloadIdSend);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Identity Payload Rcv = %u",
                            stats->numPayloadIdRcv);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Signature Payload Send = %u",
                            stats->numPayloadAuthSend);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Signature Payload Rcv = %u",
                            stats->numPayloadAuthRcv);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Hash Payload Send = %u",
                            stats->numPayloadHashSend);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Hash Payload Rcv = %u",
                            stats->numPayloadHashRcv);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Certificate Payload Send = %u",
                            stats->numPayloadCertSend);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Certificate Payload Rcv = %u",
                            stats->numPayloadCertRcv);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Notify Payload Send = %u",
                            stats->numPayloadNotifySend);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Notify Payload Rcv = %u",
                            stats->numPayloadNotifyRcv);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Delete Payload Send = %u",
                            stats->numPayloadDeleteSend);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Delete Payload Rcv = %u",
                            stats->numPayloadDeleteRcv);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Retransmissions = %u",
                            stats->numOfRetransmissions);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);

        sprintf(buf, "Total Number of Reestablishments Initiated = %u",
                            stats->numOfReestablishments);
        IO_PrintStat(node, "Network", "ISAKMP", addrStr, -1, buf);
    }
}



//
// FUNCTION   :: ISAKMPSendIDHash
// LAYER      :: Network
// PURPOSE    :: To send the ID_Hash msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendIDHash(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char*           currentOffset = NULL;
    Message*        newMsg = NULL;
    ISAKMPHeader*   isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;
    clocktype       delay = 0;

    char* id_data = NULL;
    char* hash_data = NULL;

    UInt32 len_packet = 0;
    UInt32 len_id = 0;
    UInt32 len_id_data = 0;
    UInt32 len_hash = 0;
    UInt32 len_hash_data = 0;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);

    len_id     = SIZE_ID_Payload + len_id_data;
    len_hash   = SIZE_HASH_Payload + len_hash_data;

    len_packet = SIZE_ISAKMP_HEADER + len_id + len_hash;

    if (nodeconfig->exchange->phase == PHASE_1
        && exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PRE_SHARED
        && ((exch->flags & ISAKMP_FLAG_E) && !(exch->flags & ISAKMP_FLAG_C)))
    {
        // in Phase-1. Functionality like encrypting the ID, hash payloads
        // should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }

    // new message allocation
    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_ID;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)(isakmp_sendheader + 1);
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);
    id_payload->h.np_type = ISAKMP_NPTYPE_HASH;

    currentOffset = (char*)(id_payload + 1);
    currentOffset = currentOffset + len_id_data;

    // add hash payload
    ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags |ISAKMP_FLAG_C;
    }

    if ((exch->flags & ISAKMP_FLAG_E) && !(exch->flags & ISAKMP_FLAG_C))
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags | ISAKMP_FLAG_E;
    }

    MEM_free(id_data);
    MEM_free(hash_data);

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\n%s has sent ID,Auth to %s at Simulation time = %s"
               " with delay %s\n", srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadIdSend++;
    stats->numPayloadHashSend++;

    if (exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PRE_SHARED
        && exch->initiator == RESPONDER
        && !exch->waitforcommit)
    {
        if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
        ISAKMPExchangeFinalize(node, nodeconfig, msg);
    }
}


//
// FUNCTION   :: ISAKMPRecvIDHash
// LAYER      :: Network
// PURPOSE    :: Processing of a ID_Hash message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvIDHash(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;

    UInt16    notify_type;
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_ID);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if (exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PRE_SHARED
        && exch->initiator == INITIATOR)
    {
        if (exch->waitforcommit == TRUE)
        {
            exch->step++;
            return ;
        }
        else if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
     }

     exch->step++;
     (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}




//
// FUNCTION   :: ISAKMPSendIDCertSig
// LAYER      :: Network
// PURPOSE    :: To send the ID_Cert_Sig msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendIDCertSig(Node* node, ISAKMPNodeConf* nodeconfig,Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char*           currentOffset = NULL;
    Message*        newMsg = NULL;
    ISAKMPHeader*   isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;
    clocktype       delay = 0;

    char* id_data = NULL;
    char* cert_data = NULL;
    char* sig_data = NULL;

    UInt32 len_packet = 0;
    UInt32 len_id = 0;
    UInt32 len_id_data = 0;
    UInt32 len_cert = 0;
    UInt32 len_cert_data = 0;
    UInt32 len_sig = 0;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetCertData(nodeconfig, cert_data, len_cert_data);
    ISAKMPGetSig(nodeconfig, sig_data);

    len_id    = SIZE_ID_Payload + len_id_data;
    len_cert  = SIZE_CERT_Payload;
    len_sig   = SIZE_SIG_Payload + (int)strlen(sig_data);

    if (len_cert_data != 0)
    {
        len_packet = SIZE_ISAKMP_HEADER + len_id + len_cert + len_sig;
    }
    else
    {
        len_packet = SIZE_ISAKMP_HEADER + len_id + len_sig;
    }

    if (nodeconfig->exchange->phase == PHASE_1
        && exch->exchType == ISAKMP_IKE_ETYPE_MAIN_DIG_SIG
        && ((exch->flags & ISAKMP_FLAG_E) && !(exch->flags & ISAKMP_FLAG_C)))
    {
        // in Phase-1. Functionality like encrypting the ID, Cert, Signature
        // payloads should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }

    // new message allocation
    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    // Add virtual data if present
    int payloadSize = (Int32)len_cert_data;

    if (payloadSize > 0)
    {
        MESSAGE_AddVirtualPayload(node, newMsg, payloadSize);
    }

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_ID;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)(isakmp_sendheader + 1);
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);

    //if no certificate data then optional certificate payload is ignored
    if (len_cert_data)
    {
        id_payload->h.np_type = ISAKMP_NPTYPE_CERT;

        currentOffset = (char*)(id_payload + 1);
        currentOffset = currentOffset + len_id_data;

        // add certificate payload
        ISAKMPPaylCert* cert_payload = (ISAKMPPaylCert*) currentOffset;
        ISAKMPAddCert(nodeconfig, currentOffset, NULL, 0);

        currentOffset = (char*)(cert_payload + 1);

        cert_payload->h.np_type = ISAKMP_NPTYPE_SIG;
    }
    else
    {
        id_payload->h.np_type = ISAKMP_NPTYPE_SIG;

        currentOffset = (char*)(id_payload + 1);
        currentOffset = currentOffset + len_id_data;
    }

    // add signature payload
    ISAKMPAddAUTH(nodeconfig, currentOffset, sig_data,
        (int)strlen(sig_data));

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags |ISAKMP_FLAG_C;
    }

    if ((exch->flags & ISAKMP_FLAG_E) && !(exch->flags & ISAKMP_FLAG_C))
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags | ISAKMP_FLAG_E;
    }

    MEM_free(id_data);
    MEM_free(cert_data);
    MEM_free(sig_data);

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);

        if (len_cert_data)
        {
        printf("\n%s has sent ID, Cert,Auth to %s at Simulation time = %s"
               " with delay %s\n", srcStr, dstStr, timeStr, delayStr);
        }
        else
        {
        printf("\n%s has sent ID, Auth to %s at Simulation time = %s"
               " with delay %s\n", srcStr, dstStr, timeStr, delayStr);
        }
    }

    stats->numPayloadIdSend++;
    if (len_cert_data)
    {
        stats->numPayloadCertSend++;
    }
    stats->numPayloadAuthSend++;

    if (exch->exchType == ISAKMP_IKE_ETYPE_MAIN_DIG_SIG
        && exch->initiator == RESPONDER
        && !exch->waitforcommit)
    {
        if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
        ISAKMPExchangeFinalize(node, nodeconfig, msg);
    }
}



//
// FUNCTION   :: ISAKMPRecvIDCertSig
// LAYER      :: Network
// PURPOSE    :: Processing of a ID_Cert_Sig message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvIDCertSig(Node* node, ISAKMPNodeConf* nodeconfig,Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;

    UInt16    notify_type;
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_ID);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if ((exch->exchType == ISAKMP_IKE_ETYPE_MAIN_DIG_SIG
        && exch->initiator == INITIATOR))
    {
        if (exch->waitforcommit == TRUE)
        {
            exch->step++;
            return ;
        }
        else if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
     }

     exch->step++;
     (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}


//
// FUNCTION   :: ISAKMPSendKEHashIDNonce
// LAYER      :: Network
// PURPOSE    :: To send the KE_Hash_ID_Nonce msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendKEHashIDNonce(Node* node,
                             ISAKMPNodeConf* nodeconfig,
                             Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char*           currentOffset = NULL;
    Message*        newMsg = NULL;
    ISAKMPHeader*   isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;
    clocktype       delay = 0;

    char* hash_data = NULL;
    char* id_data  = NULL;

    UInt32 len_packet = 0;
    UInt16 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt32 len_hash = 0;
    UInt32 len_hash_data = 0;
    UInt32 len_id = 0;
    UInt32 len_id_data = 0;
    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);
    ISAKMPGetID(nodeconfig, id_data, len_id_data);

    len_hash  = SIZE_HASH_Payload + len_hash_data;
    len_id    = SIZE_ID_Payload + len_id_data;

    len_packet = SIZE_ISAKMP_HEADER + len_ke + len_hash + len_id + len_nonce;

    if (nodeconfig->exchange->phase == PHASE_1
        && exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PUB_KEY)
    {
        // in Phase-1. Functionality like encrypting the ID, Nonce
        // body payloads using Public key should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }

    // new message allocation
    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_KE;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)(isakmp_sendheader + 1);

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_HASH;

    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;

    // add hash payload
    ISAKMPPaylHash* hash_payload = (ISAKMPPaylHash*)currentOffset;
    ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);
    hash_payload->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)(hash_payload + 1);
    currentOffset = currentOffset + len_hash_data;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);
    id_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    currentOffset = (char*)(id_payload + 1);
    currentOffset = currentOffset + len_id_data;
    ISAKMPPaylNonce* nonce_payload = (ISAKMPPaylNonce*)currentOffset;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, nonce_payload);


    if (exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PUB_KEY
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(nodeconfig->exchange, exch->Key_i, exch->Key_r);
    }

    MEM_free(id_data);
    MEM_free(hash_data);

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\n%s has sent KE,Hash,ID,Nonce to %s at Simulation time = %s"
               " with delay %s\n", srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadKeyExSend++;
    stats->numPayloadHashSend++;
    stats->numPayloadIdSend++;
    stats->numPayloadNonceSend++;
}


//
// FUNCTION   :: ISAKMPRecvKEHashIDNonce
// LAYER      :: Network
// PURPOSE    :: Processing of KE_Hash_ID_Nonce message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvKEHashIDNonce(Node* node,
                             ISAKMPNodeConf* nodeconfig,
                             Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;

    UInt16    notify_type = 0;
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_KE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    exch->step++;
    (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}



//
// FUNCTION   :: ISAKMPSendKEIDNonce
// LAYER      :: Network
// PURPOSE    :: To send the KE_ID_Nonce msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendKEIDNonce(Node* node, ISAKMPNodeConf* nodeconfig,Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char*           currentOffset = NULL;
    Message*        newMsg = NULL;
    ISAKMPHeader*   isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;
    clocktype       delay = 0;

    char* id_data  = NULL;

    UInt32 len_packet = 0;
    UInt16 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt32 len_id = 0;
    UInt32 len_id_data = 0;
    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetID(nodeconfig, id_data, len_id_data);

    len_id    = SIZE_ID_Payload + len_id_data;

    len_packet    = SIZE_ISAKMP_HEADER + len_ke + len_id + len_nonce;

    if (nodeconfig->exchange->phase == PHASE_1
        && exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PUB_KEY)
    {
        // in Phase-1. Functionality like encrypting the ID, Nonce
        // body payloads with Public key should be added here.
        // Actual calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }

    // new message allocation
    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_KE;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)(isakmp_sendheader + 1);

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;

    //add ID payload
    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);
    id_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    currentOffset = (char*)(id_payload + 1);
    currentOffset = currentOffset + len_id_data;
    ISAKMPPaylNonce* nonce_payload = (ISAKMPPaylNonce*)currentOffset;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, nonce_payload);


    if (exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PUB_KEY
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(nodeconfig->exchange, exch->Key_i, exch->Key_r);
    }

    MEM_free(id_data);

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\n%s has sent KE,ID,Nonce to %s at Simulation time = %s"
               " with delay %s\n", srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadKeyExSend++;
    stats->numPayloadIdSend++;
    stats->numPayloadNonceSend++;
}


//
// FUNCTION   :: ISAKMPRecvKEIDNonce
// LAYER      :: Network
// PURPOSE    :: Processing of KE_ID_Nonce message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvKEIDNonce(Node* node, ISAKMPNodeConf* nodeconfig,Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;

    UInt16    notify_type = 0;
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_KE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if (exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PUB_KEY
        && exch->initiator == INITIATOR)
    {
        ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }

    exch->step++;
    (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}



//
// FUNCTION   :: ISAKMPSendHash
// LAYER      :: Network
// PURPOSE    :: To send the Hash msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendHash(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char*           currentOffset = NULL;
    Message*        newMsg = NULL;
    ISAKMPHeader*   isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;
    clocktype       delay = 0;

    char* hash_data = NULL;
    UInt32 len_packet = 0;
    UInt32 len_hash = 0;
    UInt32 len_hash_data = 0;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);

    len_hash  = SIZE_HASH_Payload + len_hash_data;

    len_packet  = SIZE_ISAKMP_HEADER + len_hash;

    if ((nodeconfig->exchange->phase == PHASE_1)
        &&
        (exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PUB_KEY
         || exch->exchType == ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY)
        &&
        ((exch->flags & ISAKMP_FLAG_E) && !(exch->flags & ISAKMP_FLAG_C)))
    {
        // in Phase-1. Functionality like calculation and encryption of
        // hash payload should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }

    // new message allocation
    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_HASH;
    isakmp_sendheader->len = len_packet;

    currentOffset = (char*)(isakmp_sendheader + 1);

    //add hash payload
    ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }
    if ((exch->flags & ISAKMP_FLAG_E) && !(exch->flags & ISAKMP_FLAG_C))
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags | ISAKMP_FLAG_E;
    }


    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1.

        if (exch->exchType == ISAKMP_IKE_ETYPE_QUICK
            && exch->flags & ISAKMP_FLAG_E)
        {
            isakmp_sendheader->flags = ISAKMP_FLAG_E;

            // Encrypt the hash payload using Phase-1 encryption
            // algorithm and key established.
            // Actual encryption not required for Simulation
            // Adding processing delay for encryption

            delay = nodeconfig->phase1->isakmp_sa->processdelay;
        }
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\n%s has sent Hash to %s at Simulation time = %s"
               " with delay %s\n", srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadHashSend++;

    if (((exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PUB_KEY
           || exch->exchType == ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY)
          && exch->initiator == RESPONDER
          && !exch->waitforcommit)
        ||
        ((exch->exchType == ISAKMP_IKE_ETYPE_AGG_PRE_SHARED
           || exch->exchType == ISAKMP_IKE_ETYPE_AGG_PUB_KEY
           || exch->exchType == ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY
           || exch->exchType == ISAKMP_IKE_ETYPE_QUICK)
         && exch->initiator == INITIATOR
         && !exch->waitforcommit))
    {
        if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
        ISAKMPExchangeFinalize(node, nodeconfig, msg);
    }
}



//
// FUNCTION   :: ISAKMPRecvHash
// LAYER      :: Network
// PURPOSE    :: Processing of a Hash message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvHash(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    UInt16    notify_type;
    ISAKMPExchange* exch = nodeconfig->exchange;

    notify_type = ISAKMPValidateMessage(node,
                                        nodeconfig,
                                        msg,
                                        ISAKMP_NPTYPE_HASH);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if (((exch->exchType == ISAKMP_IKE_ETYPE_MAIN_PUB_KEY
           || exch->exchType == ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY)
          && exch->initiator == INITIATOR)
        ||
        ((exch->exchType == ISAKMP_IKE_ETYPE_AGG_PRE_SHARED
           || exch->exchType == ISAKMP_IKE_ETYPE_AGG_PUB_KEY
           || exch->exchType == ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY
           || exch->exchType == ISAKMP_IKE_ETYPE_QUICK)
          && exch->initiator == RESPONDER))
    {
        if (exch->waitforcommit == TRUE)
        {
            exch->step++;
            return ;
        }
        else if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
    }

    exch->step++;
    (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}


//
// FUNCTION   :: ISAKMPSendHashNonceKEIDCert
// LAYER      :: Network
// PURPOSE    :: To send Hash_Nonce_KE_ID_Cert message
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendHashNonceKEIDCert(Node* node,
                                 ISAKMPNodeConf* nodeconfig,
                                 Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char*           currentOffset = NULL;
    Message*        newMsg = NULL;
    ISAKMPHeader*   isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;
    clocktype       delay = 0;

    char* hash_data = NULL;
    char* id_data  = NULL;
    char* cert_data = NULL;

    UInt32 len_packet = 0;
    UInt16 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt32 len_hash = 0;
    UInt32 len_hash_data = 0;
    UInt32 len_id = 0;
    UInt32 len_id_data = 0;
    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;
    UInt32 len_cert = 0;
    UInt32 len_cert_data = 0;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);
    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetCertData(nodeconfig, cert_data, len_cert_data);

    len_hash  = SIZE_HASH_Payload + len_hash_data;
    len_id    = SIZE_ID_Payload + len_id_data;
    len_cert  = SIZE_CERT_Payload;

    if (len_cert_data != 0)
    {
        len_packet = SIZE_ISAKMP_HEADER + len_hash + len_nonce + len_ke
                                                   + len_id + len_cert;
    }
    else
    {
        len_packet = SIZE_ISAKMP_HEADER + len_hash + len_nonce + len_ke
                                                   + len_id;
    }

    if (nodeconfig->exchange->phase == PHASE_1
        && exch->exchType == ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY)
    {
        // in Phase-1. Functionality like encrypting the Nonce body payload
        // using Public key, and KE, ID, Cert body payload with the key
        // derived from Nonce should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }

    // new message allocation
    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    // Add virtual data if present
    int payloadSize = (Int32)len_cert_data;

    if (payloadSize > 0)
    {
        MESSAGE_AddVirtualPayload(node, newMsg, payloadSize);
    }

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_HASH;
    isakmp_sendheader->len = len_packet;

    currentOffset = (char*)(isakmp_sendheader + 1);

    //add hash payload
    ISAKMPPaylHash* hash_payload = (ISAKMPPaylHash*)currentOffset;
    ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);

    hash_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    currentOffset = (char*)(hash_payload + 1);
    currentOffset = currentOffset + len_hash_data;
    ISAKMPPaylNonce* nonce_payload = (ISAKMPPaylNonce*)currentOffset;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, nonce_payload);

    nonce_payload->h.np_type = ISAKMP_NPTYPE_KE;

    currentOffset = (char*)(nonce_payload + 1);
    currentOffset = currentOffset + NONCE_SIZE;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)(currentOffset);

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_ID;
    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;

    //add ID payload
    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);

    //if no certificate data then optional certificate payload is ignored
    if (len_cert_data)
    {
        id_payload->h.np_type = ISAKMP_NPTYPE_CERT;

        currentOffset = (char*)(id_payload + 1);
        currentOffset = currentOffset + len_id_data;

        // add certificate payload
        //ISAKMPPaylCert* cert_payload = (ISAKMPPaylCert*) currentOffset;
        ISAKMPAddCert(nodeconfig, currentOffset, NULL, 0);
    }

    if (exch->exchType == ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(nodeconfig->exchange, exch->Key_i, exch->Key_r);
    }

    MEM_free(id_data);
    MEM_free(hash_data);
    MEM_free(cert_data);

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);

        if (len_cert_data)
        {
        printf("\n%s has sent Hash,Nonce,KE,ID,Cert to %s at Simulation time"
               " = %s with delay %s\n", srcStr, dstStr, timeStr, delayStr);
        }
        else
        {
        printf("\n%s has sent Hash,Nonce,KE,ID to %s at Simulation time = %s"
               " with delay %s\n", srcStr, dstStr, timeStr, delayStr);
        }
    }

    stats->numPayloadHashSend++;
    stats->numPayloadNonceSend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadIdSend++;

    if (len_cert_data)
    {
        stats->numPayloadCertSend++;
    }
}



//
// FUNCTION   :: ISAKMPRecvHashNonceKEIDCert
// LAYER      :: Network
// PURPOSE    :: Processing of a Hash Nonce KE ID Cert message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvHashNonceKEIDCert(Node* node,
                                 ISAKMPNodeConf* nodeconfig,
                                 Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;

    UInt16    notify_type;
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_HASH);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

     exch->step++;
     (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}


//
// FUNCTION   :: ISAKMPSendNonceKEID
// LAYER      :: Network
// PURPOSE    :: To
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendNonceKEID(Node* node, ISAKMPNodeConf* nodeconfig,Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char*           currentOffset = NULL;
    Message*        newMsg = NULL;
    ISAKMPHeader*   isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;
    clocktype       delay = 0;

    char* id_data  = NULL;

    UInt32 len_packet = 0;
    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;
    UInt16 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt32 len_id = 0;
    UInt32 len_id_data = 0;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetID(nodeconfig, id_data, len_id_data);

    len_id    = SIZE_ID_Payload + len_id_data;

    len_packet = SIZE_ISAKMP_HEADER + len_nonce + len_ke + len_id;

    if (nodeconfig->exchange->phase == PHASE_1
        && exch->exchType == ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY)
    {
        // in Phase-1. Functionality like encrypting the Nonce body payload
        // using Public key, and KE, ID body payload with the key
        // derived from Nonce should be added here.
        // Actual calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }

    // new message allocation
    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_NONCE;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylNonce* nonce_payload =
                                   (ISAKMPPaylNonce*)(isakmp_sendheader + 1);

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, nonce_payload);

    nonce_payload->h.np_type = ISAKMP_NPTYPE_KE;

    currentOffset = (char*)(nonce_payload + 1);
    currentOffset = currentOffset + NONCE_SIZE;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)(currentOffset);

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_ID;
    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;

    //add ID payload
    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);

    if (exch->exchType == ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(nodeconfig->exchange, exch->Key_i, exch->Key_r);
    }

    MEM_free(id_data);

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);

        printf("\n%s has sent Nonce,KE,ID to %s at Simulation time = %s"
               " with delay %s\n", srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadNonceSend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadIdSend++;
}



//
// FUNCTION   :: ISAKMPRecvNonceKEID
// LAYER      :: Network
// PURPOSE    :: Processing of a Nonce_KE_ID message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvNonceKEID(Node* node, ISAKMPNodeConf* nodeconfig,Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;

    UInt16    notify_type;
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_NONCE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

     exch->step++;
     (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}




//
// FUNCTION   :: ISAKMPResponderReplySAKENonceIDHash
// LAYER      :: Network
// PURPOSE    :: process SA_KE_NONCE_ID msg recieved and
//               send SA_KE_NONCE_ID_Hash msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPResponderReplySAKENonceIDHash(Node* node,
                                         ISAKMPNodeConf* nodeconfig,
                                         Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;

    char* id_data = NULL;
    char* hash_data = NULL;

    UInt32 len_id_data = 0;
    UInt32 len_hash_data = 0;

    UInt16 notify_type;
    notify_type = ISAKMPValidateMessage(node,
                                        nodeconfig,
                                        msg,
                                        ISAKMP_NPTYPE_SA);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);

    UInt32 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt32 len_id    = SIZE_ID_Payload + len_id_data;
    UInt32 len_hash  = SIZE_HASH_Payload + len_hash_data;

    Message*        newMsg = NULL;
    ISAKMPHeader*   isakmp_sendheader, *isakmp_recvheader;
    UInt32          len_packet = 0;
    UInt16          len_SA = 0;
    UInt16          len_prop = 0;
    UInt16          len_trans = 0;
    char*           currentOffset = NULL;

    len_trans = exch->trans_selected->h.len;
    if (exch->phase == PHASE_1)
    {
        len_prop  = SIZE_PROPOSAL_Payload + len_trans;
    }
    else
    {
        len_prop  = SIZE_PROPOSAL_Payload + SIZE_SPI + len_trans;
    }

    len_SA = SIZE_SA_Payload + len_prop;

    len_packet = SIZE_ISAKMP_HEADER + len_SA + len_ke + len_nonce + len_id
                + len_hash;

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylSA* send_sa_payload = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(isakmp_recvheader + 1);

    memcpy((char*)send_sa_payload,
        (char*)recv_sa_payload, SIZE_SA_Payload);
    send_sa_payload->h.len = len_SA;
    send_sa_payload->h.np_type = ISAKMP_NPTYPE_KE;

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(send_sa_payload + 1);
    currentOffset = (char*)proposal;

    // copy proposal payload that is selected
    if (exch->phase == PHASE_1)
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload + SIZE_SPI);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload + SIZE_SPI;
    }
    proposal->h.len = len_prop;
    proposal->h.np_type = ISAKMP_NPTYPE_NONE;

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;

    // copy transform payload that is selected
    memcpy((char*)transform, (char*)exch->trans_selected, len_trans);

    currentOffset = (char*)transform;
    currentOffset = currentOffset + len_trans;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)currentOffset;

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;

    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)currentOffset;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);
    payload_nonce->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)payload_nonce;
    currentOffset = currentOffset + len_nonce;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);
    id_payload->h.np_type = ISAKMP_NPTYPE_HASH;

    currentOffset = (char*)(id_payload + 1);
    currentOffset = currentOffset + len_id_data;

    // add hash payload
    ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);

    UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    if (exch->phase == PHASE_1)
    {
        // temporarily save phase-1 SA negotiated
        SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    }
    else
    {
        // temporarily save phase-2 SA negotiated
        SetupIPSecSA(nodeconfig, attr, attr_size);
        nodeconfig->phase2->ipsec_sa = nodeconfig->ipsec_sa;
        nodeconfig->ipsec_sa = NULL;
    }

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags =
                                isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }

    MEM_free(id_data);
    MEM_free(hash_data);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);
        printf("\nResponder %s has sent SA,KE,Nonce,ID,Hash to %s"
            " at Simulation time = %s\n", srcStr, dstStr, timeStr);
    }

    stats->numPayloadSASend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadNonceSend++;
    stats->numPayloadIdSend++;
    stats->numPayloadHashSend++;

    if (exch->exchType == ISAKMP_IKE_ETYPE_AGG_PRE_SHARED
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }
}



//
// FUNCTION   :: ISAKMPInitiatorRecvSAKENonceIDHash
// LAYER      :: Network
// PURPOSE    :: process the SA_KE_NONCE_ID_Hash msg received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorRecvSAKENonceIDHash(Node* node,
                                        ISAKMPNodeConf* nodeconfig,
                                        Message* msg)
{
    ISAKMPInitiatorRecvSA(node, nodeconfig, msg);
}



//
// FUNCTION   :: ISAKMPResponderReplySAKENonceIDCertSig
// LAYER      :: Network
// PURPOSE    :: process SA_KE_NONCE_ID msg recieved and
//               send SA_KE_NONCE_ID_Cert_Sig msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPResponderReplySAKENonceIDCertSig(Node* node,
                                            ISAKMPNodeConf* nodeconfig,
                                            Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;

    char* id_data = NULL;
    char* cert_data = NULL;
    char* sig_data = NULL;

    UInt32 len_id_data = 0;
    UInt32 len_cert_data = 0;

    UInt16 notify_type;
    notify_type =
        ISAKMPValidateMessage(node, nodeconfig, msg, ISAKMP_NPTYPE_SA);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetCertData(nodeconfig, cert_data, len_cert_data);
    ISAKMPGetSig(nodeconfig, sig_data);

    UInt32 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt32 len_id    = SIZE_ID_Payload + len_id_data;
    UInt32 len_cert  = SIZE_CERT_Payload;
    UInt32 len_sig   = SIZE_SIG_Payload + (int)strlen(sig_data);

    Message*        newMsg = NULL;
    ISAKMPHeader*    isakmp_sendheader, *isakmp_recvheader;
    UInt32            len_packet = 0;
    UInt16            len_SA = 0;
    UInt16            len_prop = 0;
    UInt16            len_trans = 0;
    char*            currentOffset;

    len_trans = exch->trans_selected->h.len;

    if (exch->phase == PHASE_1)
    {
        len_prop  = SIZE_PROPOSAL_Payload + len_trans;
    }
    else
    {
        len_prop  = SIZE_PROPOSAL_Payload + SIZE_SPI + len_trans;
    }

    len_SA = SIZE_SA_Payload + len_prop;

    if (len_cert_data != 0)
    {
        len_packet = SIZE_ISAKMP_HEADER + len_SA + len_ke + len_nonce
                                        + len_id + len_cert + len_sig;
    }
    else
    {
        len_packet = SIZE_ISAKMP_HEADER + len_SA + len_ke + len_nonce
                                        + len_id + len_sig;
    }

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    // Add virtual data if present
    int payloadSize = (Int32)len_cert_data;

    if (payloadSize > 0)
    {
        MESSAGE_AddVirtualPayload(node, newMsg, payloadSize);
    }

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylSA* send_sa_payload = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(isakmp_recvheader + 1);

    memcpy((char*)send_sa_payload,
        (char*)recv_sa_payload, SIZE_SA_Payload);
    send_sa_payload->h.len = len_SA;
    send_sa_payload->h.np_type = ISAKMP_NPTYPE_KE;

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(send_sa_payload + 1);
    currentOffset = (char*)proposal;

    // copy proposal payload that is selected
    if (exch->phase == PHASE_1)
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload + SIZE_SPI);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload + SIZE_SPI;
    }
    proposal->h.len = len_prop;
    proposal->h.np_type = ISAKMP_NPTYPE_NONE;

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;

    // copy transform payload that is selected
    memcpy((char*)transform, (char*)exch->trans_selected, len_trans);

    currentOffset = (char*)transform;
    currentOffset = currentOffset + len_trans;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)currentOffset;

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;

    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)currentOffset;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);
    payload_nonce->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)payload_nonce;
    currentOffset = currentOffset + len_nonce;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);

    //if no certificate data then optional certificate payload is ignored
    if (len_cert_data)
    {
        id_payload->h.np_type = ISAKMP_NPTYPE_CERT;

        currentOffset = (char*)(id_payload + 1);
        currentOffset = currentOffset + len_id_data;

        // add certificate payload
        ISAKMPPaylCert* cert_payload = (ISAKMPPaylCert*) currentOffset;
        ISAKMPAddCert(nodeconfig, currentOffset, NULL, 0);

        currentOffset = (char*)(cert_payload + 1);
        //currentOffset = currentOffset + SIZE_CERT_Payload;

        cert_payload->h.np_type = ISAKMP_NPTYPE_SIG;
    }
    else
    {
        id_payload->h.np_type = ISAKMP_NPTYPE_SIG;

        currentOffset = (char*)(id_payload + 1);
        currentOffset = currentOffset + len_id_data;
    }

    // add signature payload
    ISAKMPAddAUTH(nodeconfig, currentOffset, sig_data,
        (int)strlen(sig_data));

    UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    if (exch->phase == PHASE_1)
    {
        // temporarily save phase-1 SA negotiated
        SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    }
    else
    {
        // temporarily save phase-2 SA negotiated
        SetupIPSecSA(nodeconfig, attr, attr_size);
        nodeconfig->phase2->ipsec_sa = nodeconfig->ipsec_sa;
        nodeconfig->ipsec_sa = NULL;
    }

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags =
                                isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }

    MEM_free(id_data);
    MEM_free(cert_data);
    MEM_free(sig_data);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);

        if (len_cert_data)
        {
            printf("\nResponder %s has sent SA,KE,Nonce,ID,Cert,Sig to %s"
                " at Simulation time = %s\n", srcStr, dstStr, timeStr);
        }
        else
        {
            printf("\nResponder %s has sent SA,KE,Nonce,ID,Sig to %s"
                " at Simulation time = %s\n", srcStr, dstStr, timeStr);
        }
    }

    stats->numPayloadSASend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadNonceSend++;
    stats->numPayloadIdSend++;
    if (len_cert_data)
    {
        stats->numPayloadCertSend++;
    }
    stats->numPayloadAuthSend++;

    if (exch->exchType == ISAKMP_IKE_ETYPE_MAIN_DIG_SIG
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }
}



//
// FUNCTION   :: ISAKMPInitiatorRecvSAKENonceIDCertSig
// LAYER      :: Network
// PURPOSE    :: process the SA_KE_NONCE_ID_Hash_Cert msg received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorRecvSAKENonceIDCertSig(Node* node,
                                           ISAKMPNodeConf* nodeconfig,
                                           Message* msg)
{
    ISAKMPInitiatorRecvSA(node, nodeconfig, msg);
}



//
// FUNCTION   :: ISAKMPSendCertSig
// LAYER      :: Network
// PURPOSE    :: To send the Cert_Sig msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPSendCertSig(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    char* currentOffset = NULL;
    Message*        newMsg = NULL;
    ISAKMPHeader*    isakmp_sendheader = NULL;
    ISAKMPExchange* exch = nodeconfig->exchange;

    char* cert_data = NULL;
    char* sig_data = NULL;

    UInt32 len_packet = 0;
    UInt32 len_cert = 0;
    UInt32 len_cert_data = 0;
    UInt32 len_sig = 0;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetCertData(nodeconfig, cert_data, len_cert_data);
    ISAKMPGetSig(nodeconfig, sig_data);

    len_cert  = SIZE_CERT_Payload;
    len_sig   = SIZE_SIG_Payload + (int)strlen(sig_data);

    if (len_cert_data != 0)
    {
        len_packet = SIZE_ISAKMP_HEADER + len_cert + len_sig;
    }
    else
    {
        len_packet = SIZE_ISAKMP_HEADER + len_sig;
    }

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    // Add virtual data if present
    int payloadSize = (Int32)len_cert_data;

    if (payloadSize > 0)
    {
        MESSAGE_AddVirtualPayload(node, newMsg, payloadSize);
    }

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;

    memcpy(isakmp_sendheader->init_cookie, exch->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie, exch->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = exch->exchType;
    isakmp_sendheader->msgid = exch->msgid;
    isakmp_sendheader->len = len_packet;

    currentOffset = (char *)(isakmp_sendheader + 1);

    //if no certificate data then optional certificate payload is ignored
    if (len_cert_data)
    {
        isakmp_sendheader->np_type = ISAKMP_NPTYPE_CERT;

        // add certificate payload
        ISAKMPPaylCert* cert_payload = (ISAKMPPaylCert*) currentOffset;
        ISAKMPAddCert(nodeconfig, currentOffset, NULL, 0);

        currentOffset = (char*)(cert_payload + 1);
        //currentOffset = currentOffset + SIZE_CERT_Payload;

        cert_payload->h.np_type = ISAKMP_NPTYPE_SIG;
    }
    else
    {
        isakmp_sendheader->np_type = ISAKMP_NPTYPE_SIG;
    }

    // add signature payload
    ISAKMPAddAUTH(nodeconfig, currentOffset, sig_data,
        (int)strlen(sig_data));

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags |ISAKMP_FLAG_C;
    }

    MEM_free(cert_data);
    MEM_free(sig_data);

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step);

    NetworkIpSendRawMessage(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        ctoa(node->getNodeTime(), timeStr);

        if (len_cert_data)
        {
        printf("\n%s has sent Cert,Sig to %s at Simulation time = %s\n",
            srcStr, dstStr, timeStr);
        }
        else
        {
        printf("\n%s has sent Sig to %s at Simulation time = %s\n",
            srcStr, dstStr, timeStr);
        }
    }

    if (len_cert_data)
    {
        stats->numPayloadCertSend++;
    }
    stats->numPayloadAuthSend++;

    if (exch->exchType == ISAKMP_IKE_ETYPE_AGG_DIG_SIG
        && exch->initiator == INITIATOR
        && !exch->waitforcommit)
    {
        if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
        ISAKMPExchangeFinalize(node, nodeconfig, msg);
    }
}



//
// FUNCTION   :: ISAKMPRecvCertSig
// LAYER      :: Network
// PURPOSE    :: Processing of a Cert_Sig message received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPRecvCertSig(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;

    ISAKMPHeader*   isakmp_recvheader;
    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    UInt16 notify_type;

    if (isakmp_recvheader->np_type == ISAKMP_NPTYPE_CERT)
    {
        notify_type = ISAKMPValidateMessage(
            node, nodeconfig, msg, ISAKMP_NPTYPE_CERT);
    }
    else
    {
        notify_type = ISAKMPValidateMessage(
            node, nodeconfig, msg, ISAKMP_NPTYPE_SIG);
    }

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if (exch->exchType == ISAKMP_IKE_ETYPE_AGG_DIG_SIG
        && exch->initiator == RESPONDER)
    {
        if (exch->waitforcommit == TRUE)
        {
            exch->step++;
            return ;
        }
        else if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
     }

     exch->step++;
     (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}



//
// FUNCTION   :: ISAKMPInitiatorSendSAHashKEIDNonce
// LAYER      :: Network
// PURPOSE    :: To send SA_Hash_KE_ID_Nonce msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorSendSAHashKEIDNonce(Node* node,
                                        ISAKMPNodeConf* nodeconfig,
                                        Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    clocktype delay = 0;
    UInt16    notify_type = 0;
    Message*  newMsg = NULL;
    char*     curr_pos = NULL;
    char*     hash_data = NULL;
    char*     id_data = NULL;

    ISAKMPHeader*  isakmp_sendheader = NULL;
    ISAKMPHeader*  isakmp_recvheader =
                                    (ISAKMPHeader*)MESSAGE_ReturnPacket(msg);

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    UInt16 len_id = 0;
    UInt32 len_id_data = 0;
    UInt32 len_hash = 0;
    UInt32 len_hash_data = 0;
    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;
    UInt16 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt16 total_len = 0;

    memcpy(nodeconfig->exchange->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);

    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_NONE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);
    ISAKMPGetID(nodeconfig, id_data, len_id_data);

    len_hash  = SIZE_HASH_Payload + len_hash_data;
    len_id    = (UInt16)(SIZE_ID_Payload + len_id_data);

    total_len = (UInt16)(len_hash + len_ke + len_id + len_nonce);

    if (nodeconfig->exchange->phase == PHASE_1
        && exch->exchType == ISAKMP_IKE_ETYPE_AGG_PUB_KEY)
    {
        // in Phase-1. Functionality like encrypting the ID, Nonce
        // body payloads using Public key should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }

    UInt32 phase = nodeconfig->exchange->phase;
    if (phase == PHASE_1)
    {
        ISAKMPPhase1AddSA(node, nodeconfig, newMsg, curr_pos, total_len);
    }
    else
    {
        ISAKMPPhase2AddSA(node, nodeconfig, newMsg, curr_pos, total_len);
    }

    isakmp_sendheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(newMsg);
    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;

    ISAKMPPaylSA* payload_sa = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    payload_sa->h.np_type = ISAKMP_NPTYPE_HASH;

    // add hash payload
    ISAKMPPaylHash* payload_hash = (ISAKMPPaylHash*)curr_pos;
    ISAKMPAddHash(nodeconfig, curr_pos, hash_data, len_hash_data);
    payload_hash->h.np_type = ISAKMP_NPTYPE_KE;

    curr_pos = (char*)(payload_hash + 1);
    curr_pos = curr_pos + len_hash_data;

    ISAKMPPaylKeyEx* payload_ke = (ISAKMPPaylKeyEx*)curr_pos;

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, payload_ke);

    payload_ke->h.np_type = ISAKMP_NPTYPE_ID;

    curr_pos = (char*)(payload_ke + 1);
    curr_pos = curr_pos + KEY_SIZE;

    //add ID payload
    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)curr_pos;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);
    id_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    curr_pos = (char*)(id_payload + 1);
    curr_pos = curr_pos + len_id_data;

    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)curr_pos;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);

    MEM_free(hash_data);
    MEM_free(id_data);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    nodeconfig->exchange->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
                node,
                newMsg,
                source,
                dest,
                ANY_INTERFACE,
                IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_ISAKMP,
                9,
                delay);
    }
    else
    {
        NetworkIpSendRawMessage(
                node,
                newMsg,
                source,
                dest,
                ANY_INTERFACE,
                IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_ISAKMP,
                9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\nInitiator %s has sent SA,Hash,KE,ID,Nonce to %s"
            " at Simulation time = %s with delay %s\n",
            srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadSASend++;
    stats->numPayloadHashSend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadIdSend++;
    stats->numPayloadNonceSend++;
}




//
// FUNCTION   :: ISAKMPResponderReplySAKEIDNonceHash
// LAYER      :: Network
// PURPOSE    :: process SA_Hash_KE_ID_NONCE msg recieved and
//               send SA_KE_ID_NONCE_Hash msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPResponderReplySAKEIDNonceHash(Node* node,
                                         ISAKMPNodeConf* nodeconfig,
                                         Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    clocktype delay = 0;

    char* id_data = NULL;
    char* hash_data = NULL;

    UInt32 len_id_data = 0;
    UInt32 len_hash_data = 0;

    UInt16 notify_type;
    notify_type =
        ISAKMPValidateMessage(node, nodeconfig, msg, ISAKMP_NPTYPE_SA);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);

    UInt32 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt32 len_id    = SIZE_ID_Payload + len_id_data;
    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;
    UInt32 len_hash  = SIZE_HASH_Payload + len_hash_data;

    Message*        newMsg = NULL;
    ISAKMPHeader*    isakmp_sendheader, *isakmp_recvheader;
    UInt32            len_packet = 0;
    UInt16            len_SA = 0;
    UInt16            len_prop = 0;
    UInt16            len_trans = 0;
    char*            currentOffset;

    len_trans = exch->trans_selected->h.len;
    if (exch->phase == PHASE_1)
    {
        len_prop  = SIZE_PROPOSAL_Payload + len_trans;
    }
    else
    {
        len_prop  = SIZE_PROPOSAL_Payload + SIZE_SPI + len_trans;
    }
    len_SA = SIZE_SA_Payload + len_prop;

    len_packet = SIZE_ISAKMP_HEADER + len_SA + len_ke + len_nonce + len_id
                + len_hash;

    if (nodeconfig->exchange->phase == PHASE_1
        && exch->exchType == ISAKMP_IKE_ETYPE_AGG_PUB_KEY)
    {
        // in Phase-1. Functionality like encrypting the ID, Nonce
        // body payloads using Public key should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }

    // new message allocation
    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylSA* send_sa_payload = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(isakmp_recvheader + 1);

    memcpy((char*)send_sa_payload,
        (char*)recv_sa_payload, SIZE_SA_Payload);
    send_sa_payload->h.len = len_SA;
    send_sa_payload->h.np_type = ISAKMP_NPTYPE_KE;

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(send_sa_payload + 1);
    currentOffset = (char*)proposal;

    // copy proposal payload that is selected
    if (exch->phase == PHASE_1)
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload + SIZE_SPI);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload + SIZE_SPI;
    }
    proposal->h.len = len_prop;
    proposal->h.np_type = ISAKMP_NPTYPE_NONE;

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;

    // copy transform payload that is selected
    memcpy((char*)transform, (char*)exch->trans_selected, len_trans);

    currentOffset = (char*)transform;
    currentOffset = currentOffset + len_trans;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)currentOffset;

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);
    id_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    currentOffset = (char*)(id_payload + 1);
    currentOffset = currentOffset + len_id_data;

    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)currentOffset;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);
    payload_nonce->h.np_type = ISAKMP_NPTYPE_HASH;

    currentOffset = (char*)payload_nonce;
    currentOffset = currentOffset + len_nonce;

    // add hash payload
    ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);

    UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    if (exch->phase == PHASE_1)
    {
        // temporarily save phase-1 SA negotiated
        SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    }
    else
    {
        // temporarily save phase-2 SA negotiated
        SetupIPSecSA(nodeconfig, attr, attr_size);
        nodeconfig->phase2->ipsec_sa = nodeconfig->ipsec_sa;
        nodeconfig->ipsec_sa = NULL;
    }

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }

    MEM_free(id_data);
    MEM_free(hash_data);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\nResponder %s has sent SA,KE,ID,Nonce,Hash to %s"
            " at Simulation time = %s with delay %s\n",
            srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadSASend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadIdSend++;
    stats->numPayloadNonceSend++;
    stats->numPayloadHashSend++;

    if (exch->exchType == ISAKMP_IKE_ETYPE_AGG_PUB_KEY
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }
}




//
// FUNCTION   :: ISAKMPInitiatorRecvSAKEIDNonceHash
// LAYER      :: Network
// PURPOSE    :: process the SA_KE_ID_NONCE_Hash msg received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorRecvSAKEIDNonceHash(Node* node,
                                        ISAKMPNodeConf* nodeconfig,
                                        Message* msg)
{
    ISAKMPInitiatorRecvSA(node, nodeconfig, msg);
}



//
// FUNCTION   :: ISAKMPInitiatorSendSAHashNonceKEIDCert
// LAYER      :: Network
// PURPOSE    :: To send SA_Hash_Nonce_KE_ID_Cert msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorSendSAHashNonceKEIDCert(Node* node, ISAKMPNodeConf* nodeconfig, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    clocktype delay = 0;
    UInt16    notify_type = 0;
    Message*  newMsg = NULL;
    char*     curr_pos = NULL;
    char*     hash_data = NULL;
    char*     id_data = NULL;
    char*     cert_data = NULL;

    ISAKMPHeader*  isakmp_sendheader = NULL;
    ISAKMPHeader*  isakmp_recvheader =
        (ISAKMPHeader*)MESSAGE_ReturnPacket(msg);

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    UInt16 len_id = 0;
    UInt32 len_id_data = 0;
    UInt32 len_hash = 0;
    UInt32 len_hash_data = 0;
    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;
    UInt16 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt32 len_cert = 0;
    UInt32 len_cert_data = 0;
    UInt16 total_len = 0;

    memcpy(nodeconfig->exchange->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);

    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_NONE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);
    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetCertData(nodeconfig, cert_data, len_cert_data);

    len_hash  = SIZE_HASH_Payload + len_hash_data;
    len_id    = (UInt16)(SIZE_ID_Payload + len_id_data);
    len_cert  = SIZE_CERT_Payload;

    if (len_cert_data != 0)
    {
        total_len = UInt16(len_hash + len_nonce + len_ke + len_id +len_cert);
    }
    else
    {
        total_len = UInt16(len_hash + len_nonce + len_ke + len_id);
    }

    if (nodeconfig->exchange->phase == PHASE_1
        && exch->exchType == ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY)
    {
        // in Phase-1. Functionality like encrypting the Nonce body payload
        // using Public key, and KE, ID, Cert body payload with the key
        // derived from Nonce should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }

    UInt32 phase = nodeconfig->exchange->phase;
    if (phase == PHASE_1)
    {
        ISAKMPPhase1AddSA(node, nodeconfig, newMsg, curr_pos, total_len);
    }
    else
    {
        ISAKMPPhase2AddSA(node, nodeconfig, newMsg, curr_pos, total_len);
    }

    isakmp_sendheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(newMsg);
    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;

    ISAKMPPaylSA* payload_sa = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    payload_sa->h.np_type = ISAKMP_NPTYPE_HASH;

    // add hash payload
    ISAKMPPaylHash* payload_hash = (ISAKMPPaylHash*)curr_pos;
    ISAKMPAddHash(nodeconfig, curr_pos, hash_data, len_hash_data);
    payload_hash->h.np_type = ISAKMP_NPTYPE_NONCE;

    curr_pos = (char*)(payload_hash + 1);
    curr_pos = curr_pos + len_hash_data;

    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)curr_pos;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);
    payload_nonce->h.np_type = ISAKMP_NPTYPE_KE;

    curr_pos = (char*)payload_nonce;
    curr_pos = curr_pos + len_nonce;

    // add KE Payload
    ISAKMPPaylKeyEx* payload_ke = (ISAKMPPaylKeyEx*)curr_pos;
    ISAKMPAddKE(node, nodeconfig, payload_ke);

    payload_ke->h.np_type = ISAKMP_NPTYPE_ID;

    curr_pos = (char*)(payload_ke + 1);
    curr_pos = curr_pos + KEY_SIZE;

    //add ID payload
    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)curr_pos;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);

    //if no certificate data then optional certificate payload is ignored
    if (len_cert_data)
    {
        id_payload->h.np_type = ISAKMP_NPTYPE_CERT;

        curr_pos = (char*)(id_payload + 1);
        curr_pos = curr_pos + len_id_data;

        // add certificate payload
        //ISAKMPPaylCert* cert_payload = (ISAKMPPaylCert*) curr_pos;
        ISAKMPAddCert(nodeconfig, curr_pos, NULL, 0);
    }

    MEM_free(hash_data);
    MEM_free(id_data);
    MEM_free(cert_data);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    nodeconfig->exchange->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
                node,
                newMsg,
                source,
                dest,
                ANY_INTERFACE,
                IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_ISAKMP,
                9,
                delay);
    }
    else
    {
        NetworkIpSendRawMessage(
                node,
                newMsg,
                source,
                dest,
                ANY_INTERFACE,
                IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_ISAKMP,
                9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);

        if (len_cert_data)
        {
            printf("\nInitiator %s has sent SA,Hash,Nonce,KE,ID,Cert to %s"
                " at Simulation time = %s with delay %s\n",
                srcStr, dstStr, timeStr, delayStr);
        }
        else
        {
            printf("\nInitiator %s has sent SA,Hash,Nonce,KE,ID to %s"
                " at Simulation time = %s with delay %s\n",
                srcStr, dstStr, timeStr, delayStr);
        }
    }

    stats->numPayloadSASend++;
    stats->numPayloadHashSend++;
    stats->numPayloadNonceSend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadIdSend++;
    if (len_cert_data)
    {
        stats->numPayloadCertSend++;
    }
}




//
// FUNCTION   :: ISAKMPResponderReplySANonceKEIDHash
// LAYER      :: Network
// PURPOSE    :: process SA_Nonce_KE_ID_Cert msg recieved and
//               send SA_Nonce_KE_ID_Hash msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPResponderReplySANonceKEIDHash(Node* node,
                                         ISAKMPNodeConf* nodeconfig,
                                         Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    clocktype delay = 0;

    char* id_data = NULL;
    char* hash_data = NULL;

    UInt32 len_id_data = 0;
    UInt32 len_hash_data = 0;

    UInt16 notify_type = 0;
    notify_type =
        ISAKMPValidateMessage(node, nodeconfig, msg, ISAKMP_NPTYPE_SA);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    ISAKMPGetID(nodeconfig, id_data, len_id_data);
    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);

    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;
    UInt32 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt32 len_id    = SIZE_ID_Payload + len_id_data;
    UInt32 len_hash  = SIZE_HASH_Payload + len_hash_data;

    Message*        newMsg = NULL;
    ISAKMPHeader*    isakmp_sendheader, *isakmp_recvheader;
    UInt32            len_packet = 0;
    UInt16            len_SA = 0;
    UInt16            len_prop = 0;
    UInt16            len_trans = 0;
    char*            currentOffset;

    len_trans = exch->trans_selected->h.len;
    if (exch->phase == PHASE_1)
    {
        len_prop  = SIZE_PROPOSAL_Payload + len_trans;
    }
    else
    {
        len_prop  = SIZE_PROPOSAL_Payload + SIZE_SPI + len_trans;
    }
    len_SA = SIZE_SA_Payload + len_prop;

    len_packet = SIZE_ISAKMP_HEADER + len_SA + len_ke + len_nonce + len_id
                                                                  + len_hash;

    if (nodeconfig->exchange->phase == PHASE_1
        && exch->exchType == ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY)
    {
        // in Phase-1. Functionality like encrypting the Nonce body payload
        // using Public key, and KE, ID body payload with the key
        // derived from Nonce should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = ISAKMPGetProcessDelay(node, nodeconfig);
    }

    // new message allocation
    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
    memset(packet, 0, len_packet);
    isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_SA;
    isakmp_sendheader->len = len_packet;

    ISAKMPPaylSA* send_sa_payload = (ISAKMPPaylSA*)(isakmp_sendheader + 1);
    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(isakmp_recvheader + 1);

    memcpy((char*)send_sa_payload,
        (char*)recv_sa_payload, SIZE_SA_Payload);
    send_sa_payload->h.len = len_SA;
    send_sa_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(send_sa_payload + 1);
    currentOffset = (char*)proposal;

    // copy proposal payload that is selected
    if (exch->phase == PHASE_1)
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload + SIZE_SPI);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload + SIZE_SPI;
    }
    proposal->h.len = len_prop;
    proposal->h.np_type = ISAKMP_NPTYPE_NONE;

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;

    // copy transform payload that is selected
    memcpy((char*)transform, (char*)exch->trans_selected, len_trans);

    currentOffset = (char*)transform;
    currentOffset = currentOffset + len_trans;

    // add Nonce Payload
    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)currentOffset;
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);
    payload_nonce->h.np_type = ISAKMP_NPTYPE_KE;

    currentOffset = (char*)payload_nonce;
    currentOffset = currentOffset + len_nonce;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)currentOffset;

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;

    ISAKMPPaylId* id_payload = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload, id_data, len_id_data);
    id_payload->h.np_type = ISAKMP_NPTYPE_HASH;

    currentOffset = (char*)(id_payload + 1);
    currentOffset = currentOffset + len_id_data;

    // add hash payload
    ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);

    UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    if (exch->phase == PHASE_1)
    {
        // temporarily save phase-1 SA negotiated
        SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    }
    else
    {
        // temporarily save phase-2 SA negotiated
        SetupIPSecSA(nodeconfig, attr, attr_size);
        nodeconfig->phase2->ipsec_sa = nodeconfig->ipsec_sa;
        nodeconfig->ipsec_sa = NULL;
    }

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags =
                                isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }

    MEM_free(id_data);
    MEM_free(hash_data);

    if (nodeconfig->exchange->phase == PHASE_2)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functialanity like creating hash and adding
        // hash payload or encrypting the payloads should be added here.
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\nResponder %s has sent SA,Nonce,KE,ID,Hash to %s"
            " at Simulation time = %s with delay %s\n",
            srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadSASend++;
    stats->numPayloadNonceSend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadIdSend++;
    stats->numPayloadHashSend++;

    if (exch->exchType == ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }
}



//
// FUNCTION   :: ISAKMPInitiatorRecvSANonceKEIDHash
// LAYER      :: Network
// PURPOSE    :: process the SA_Nonce_KE_ID_Hash msg received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorRecvSANonceKEIDHash(Node* node,
                                        ISAKMPNodeConf* nodeconfig,
                                        Message* msg)
{
    ISAKMPInitiatorRecvSA(node, nodeconfig, msg);
}



//
// FUNCTION   :: ISAKMPInitiatorSendHashSANonceKEIDID
// LAYER      :: Network
// PURPOSE    :: To send Hash_SA_Nonce_KE_ID_ID msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorSendHashSANonceKEIDID(Node* node,
                                          ISAKMPNodeConf* nodeconfig,
                                          Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    UInt32    phase;
    Message*  newMsg = NULL;
    char*     curr_pos = NULL;
    char*     currentOffset = NULL;
    char*     sa_payload_offset = NULL;
    char*     id_data1 = NULL;
    char*     id_data2 = NULL;
    UInt16    notify_type = 0;
    clocktype delay = 0;

    ISAKMPHeader* isakmp_sendheader = NULL;
    ISAKMPHeader* isakmp_recvheader =
        (ISAKMPHeader*)MESSAGE_ReturnPacket(msg);

    //Find source and Destination ISAKMP servers
    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    UInt16 len_id1 = 0;
    UInt32 len_id_data1 = 0;
    UInt16 len_id2 = 0;
    UInt32 len_id_data2 = 0;
    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;
    UInt16 len_ke    = SIZE_KE_Payload + KEY_SIZE;
    UInt16 total_len = 0;

    // save Responder cookie
    memcpy(nodeconfig->exchange->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        printf("\n\nInitiator %s has recv resp cookie from %s",
            srcStr, dstStr);
    }

    // validate the received message
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_NONE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if (ISAKMP_DEBUG)
    {
        printf("\n after responder cookie validation");
    }

    // getting first ID data
    ISAKMPGetID(nodeconfig, id_data1, len_id_data1);
    len_id1    = (UInt16)(SIZE_ID_Payload + len_id_data1);

    // getting second ID data
    ISAKMPGetID(nodeconfig, id_data2, len_id_data2);
    len_id2    = (UInt16)(SIZE_ID_Payload + len_id_data2);

    total_len = len_nonce + len_ke + len_id1 + len_id2;

    phase = nodeconfig->exchange->phase;

    if (phase == PHASE_2 && exch->exchType == ISAKMP_IKE_ETYPE_QUICK)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functionality like encrypting the SA, Nonce, KE, IDci,
        // IDcr payloads should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = nodeconfig->phase1->isakmp_sa->processdelay;
    }


    // add Hash SA payloads
    sa_payload_offset = ISAKMPPhase2AddHashSA(node,
                                              nodeconfig,
                                              newMsg,
                                              curr_pos,
                                              total_len);

    isakmp_sendheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(newMsg);
    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_HASH;

    if (nodeconfig->exchange->phase == PHASE_2
        && exch->exchType == ISAKMP_IKE_ETYPE_QUICK)
    {
        isakmp_sendheader->flags = ISAKMP_FLAG_E;
    }

    ISAKMPPaylSA* payload_sa = (ISAKMPPaylSA*)(sa_payload_offset);
    payload_sa->h.np_type = ISAKMP_NPTYPE_NONCE;

    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)curr_pos;

    // add Nonce Payload
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);
    payload_nonce->h.np_type = ISAKMP_NPTYPE_KE;

    currentOffset = (char*)payload_nonce;
    currentOffset = currentOffset + len_nonce;

    ISAKMPPaylKeyEx* payload_ke = (ISAKMPPaylKeyEx*)currentOffset;

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, payload_ke);
    payload_ke->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)(payload_ke + 1);
    currentOffset = currentOffset + KEY_SIZE;

    // add first ID payload
    ISAKMPPaylId* id_payload1 = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload1, id_data1, len_id_data1);
    id_payload1->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)(id_payload1 + 1);
    currentOffset = currentOffset + len_id_data1;

    // add second ID payload
    ISAKMPPaylId* id_payload2 = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload2, id_data2, len_id_data2);

    MEM_free(id_data1);
    MEM_free(id_data2);

    nodeconfig->exchange->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
                node,
                newMsg,
                source,
                dest,
                ANY_INTERFACE,
                IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_ISAKMP,
                9,
                delay);
    }
    else
    {
        NetworkIpSendRawMessage(
                node,
                newMsg,
                source,
                dest,
                ANY_INTERFACE,
                IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_ISAKMP,
                9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\nInitiator %s has sent Hash SA Nonce KE ID ID to %s"
            " at Simulation time = %s with delay %s\n",
            srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadHashSend++;
    stats->numPayloadSASend++;
    stats->numPayloadNonceSend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadIdSend++;
    stats->numPayloadIdSend++;
}



//
// FUNCTION   :: ISAKMPResponderReplyHashSANonceKEIDID
// LAYER      :: Network
// PURPOSE    :: To send Hash SA Nonce KE ID ID message
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPResponderReplyHashSANonceKEIDID(Node* node,
                                           ISAKMPNodeConf* nodeconfig,
                                           Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    clocktype delay = 0;

    char* hash_data = NULL;
    char* id_data1 = NULL;
    char* id_data2 = NULL;
    UInt32 len_hash = 0;
    UInt32 len_hash_data = 0;
    UInt32 len_id1 = 0;
    UInt32 len_id2 = 0;
    UInt32 len_id_data1 = 0;
    UInt32 len_id_data2 = 0;
    UInt16 len_nonce = SIZE_NONCE_Payload + NONCE_SIZE;
    UInt32 len_ke    = SIZE_KE_Payload + KEY_SIZE;

    UInt16 notify_type = 0;

    notify_type =
        ISAKMPValidateMessage(node, nodeconfig, msg, ISAKMP_NPTYPE_HASH);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    //get hash data
    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);
    len_hash  = SIZE_HASH_Payload + len_hash_data;

    ISAKMPGetID(nodeconfig, id_data1, len_id_data1);
    len_id1 = SIZE_ID_Payload + len_id_data1;

    ISAKMPGetID(nodeconfig, id_data2, len_id_data2);
    len_id2 = SIZE_ID_Payload + len_id_data2;

    Message*        newMsg = NULL;
    ISAKMPHeader*   isakmp_sendheader, *isakmp_recvheader;
    UInt16          len_packet = 0;
    UInt16          len_SA = 0;
    UInt16          len_prop = 0;
    UInt16          len_trans = 0;
    char*           currentOffset = NULL;
    char*           recv_currentOffset = NULL;

    len_trans = exch->trans_selected->h.len;
    if (exch->phase == PHASE_1)
    {
        len_prop  = SIZE_PROPOSAL_Payload + len_trans;
    }
    else
    {
        len_prop  = SIZE_PROPOSAL_Payload + SIZE_SPI + len_trans;
    }
    len_SA = SIZE_SA_Payload + len_prop;

    len_packet = (UInt16)(SIZE_ISAKMP_HEADER + len_hash + len_SA + len_nonce
                                            + len_ke + len_id1 + len_id2);

    if (nodeconfig->exchange->phase == PHASE_2
        && exch->exchType == ISAKMP_IKE_ETYPE_QUICK)
    {
        // Provide Security to Phase-2 message using ISAKMP SA established
        // in Phase-1. Functionality like encrypting the SA, Nonce, KE, IDci,
        // IDcr payloads should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = nodeconfig->phase1->isakmp_sa->processdelay;
    }

    // new message allocation
    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_HASH;
    isakmp_sendheader->len = len_packet;

    if (nodeconfig->exchange->phase == PHASE_2
        && exch->exchType == ISAKMP_IKE_ETYPE_QUICK)
    {
        isakmp_sendheader->flags = ISAKMP_FLAG_E;
    }

    currentOffset = (char*)(isakmp_sendheader + 1);

    //add hash payload
    ISAKMPPaylHash* hash_payload = (ISAKMPPaylHash*)currentOffset;
    ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);
    hash_payload->h.np_type = ISAKMP_NPTYPE_SA;

    currentOffset = (char*)(hash_payload + 1);
    currentOffset = currentOffset + len_hash_data;

    ISAKMPPaylSA* send_sa_payload = (ISAKMPPaylSA*)(currentOffset);

    //extracting Hash payload from isakmp recv message
    ISAKMPPaylHash* recv_hash_payload =
                                    (ISAKMPPaylHash*)(isakmp_recvheader + 1);
    recv_currentOffset = (char*)recv_hash_payload;
    recv_currentOffset = recv_currentOffset + recv_hash_payload->h.len;
    //now getting recv SA payload
    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(recv_currentOffset);

    memcpy((char*)send_sa_payload,
        (char*)recv_sa_payload,
        SIZE_SA_Payload);
    send_sa_payload->h.len = len_SA;
    send_sa_payload->h.np_type = ISAKMP_NPTYPE_NONCE;

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(send_sa_payload + 1);
    currentOffset = (char*)proposal;

    //copy proposal that is selected
    if (exch->phase == PHASE_1)
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected, SIZE_PROPOSAL_Payload);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload + SIZE_SPI);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload + SIZE_SPI;
    }
    proposal->h.len = len_prop;
    proposal->h.np_type = ISAKMP_NPTYPE_NONE;

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;

    //copy transform payload that is selected
    memcpy((char*)transform, (char*)exch->trans_selected,  len_trans);

    currentOffset = (char*)transform;
    currentOffset = currentOffset + len_trans;

    // add Nonce Payload
    ISAKMPPaylNonce* payload_nonce = (ISAKMPPaylNonce*)currentOffset;
    ISAKMPAddNONCE(node, nodeconfig, payload_nonce);
    payload_nonce->h.np_type = ISAKMP_NPTYPE_KE;

    currentOffset = (char*)payload_nonce;
    currentOffset = currentOffset + len_nonce;

    ISAKMPPaylKeyEx* ke_payload = (ISAKMPPaylKeyEx*)currentOffset;

    // add KE Payload
    ISAKMPAddKE(node, nodeconfig, ke_payload);

    ke_payload->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)(ke_payload + 1);
    currentOffset = currentOffset + KEY_SIZE;

    // add first ID payload
    ISAKMPPaylId* id_payload1 = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload1, id_data1, len_id_data1);
    id_payload1->h.np_type = ISAKMP_NPTYPE_ID;

    currentOffset = (char*)(id_payload1 + 1);
    currentOffset = currentOffset + len_id_data1;

    // add second ID payload
    ISAKMPPaylId* id_payload2 = (ISAKMPPaylId*)currentOffset;
    ISAKMPAddID(nodeconfig, id_payload2, id_data2, len_id_data2);


    UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    if (exch->phase == PHASE_1)
    {
        // temporarily save phase-1 SA negotiated
        SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    }
    else
    {
        // temporarily save phase-2 SA negotiated
        SetupIPSecSA(nodeconfig, attr, attr_size);
        nodeconfig->phase2->ipsec_sa = nodeconfig->ipsec_sa;
        nodeconfig->ipsec_sa = NULL;
    }

    if (!exch->waitforcommit && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags =
                                isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }

    MEM_free(id_data1);
    MEM_free(id_data2);

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9,
            delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\nResponder %s has sent Hash SA Nonce KE ID ID to %s"
            " at Simulation time = %s with delay %s\n",
            srcStr, dstStr, timeStr, delayStr);
    }

    if (exch->exchType == ISAKMP_IKE_ETYPE_QUICK
        && exch->initiator == RESPONDER)
    {
        ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }

    stats->numPayloadHashSend++;
    stats->numPayloadSASend++;
    stats->numPayloadNonceSend++;
    stats->numPayloadKeyExSend++;
    stats->numPayloadIdSend++;
    stats->numPayloadIdSend++;
}


//
// FUNCTION   :: ISAKMPInitiatorRecvHashSANonceKEIDID
// LAYER      :: Network
// PURPOSE    :: process the Hash_SA_Nonce_KE_ID_ID msg received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorRecvHashSANonceKEIDID(Node* node,
                                          ISAKMPNodeConf* nodeconfig,
                                          Message* msg)
{
    ISAKMPInitiatorRecvHashSA(node, nodeconfig, msg);
}



//
// FUNCTION   :: ISAKMPInitiatorSendHashSA
// LAYER      :: Network
// PURPOSE    :: To send Hash_SA msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorSendHashSA(Node* node,
                               ISAKMPNodeConf* nodeconfig,
                               Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;
    ISAKMPExchange* exch = nodeconfig->exchange;

    Message*  newMsg = NULL;
    char*     curr_pos = NULL;
    UInt16    notify_type = 0;
    clocktype delay = 0;

    ISAKMPHeader* isakmp_sendheader = NULL;
    ISAKMPHeader* isakmp_recvheader =
        (ISAKMPHeader*)MESSAGE_ReturnPacket(msg);

    //Find source and Destination ISAKMP servers
    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    // save Responder cookie
    memcpy(nodeconfig->exchange->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        printf("\n\nInitiator %s has recv resp cookie from %s",
            srcStr, dstStr);
    }

    // validate the received message
    notify_type = ISAKMPValidateMessage(
        node, nodeconfig, msg, ISAKMP_NPTYPE_NONE);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    if (ISAKMP_DEBUG)
    {
        printf("\n after responder cookie validation");
    }

    ISAKMPPhase1AddHashSA(node, nodeconfig, newMsg, curr_pos, 0);

    isakmp_sendheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(newMsg);
    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_HASH;

    if (nodeconfig->exchange->phase == PHASE_1)
    {
        // Provide Security to new group mode message using ISAKMP SA
        // established in Phase-1. Functionality like encrypting the
        // payloads should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = nodeconfig->phase1->isakmp_sa->processdelay;
    }

    if (exch->exchType == ISAKMP_IKE_ETYPE_NEW_GROUP
        && !exch->waitforcommit
        && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }


    nodeconfig->exchange->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
        NetworkIpSendRawMessageWithDelay(
                node,
                newMsg,
                source,
                dest,
                ANY_INTERFACE,
                IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_ISAKMP,
                9,
                delay);
    }
    else
    {
        NetworkIpSendRawMessage(
                node,
                newMsg,
                source,
                dest,
                ANY_INTERFACE,
                IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_ISAKMP,
                9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\nInitiator %s has sent Hash SA to %s at Simulation time ="
            " %s with delay %s\n", srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadHashSend++;
    stats->numPayloadSASend++;
}


//
// FUNCTION   :: ISAKMPResponderReplyHashSA
// LAYER      :: Network
// PURPOSE    :: send Hash_SA  msg
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPResponderReplyHashSA(Node* node,
                                ISAKMPNodeConf* nodeconfig,
                                Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
        ip->interfaceInfo[nodeconfig->interfaceIndex];
    ISAKMPStats* stats = interfaceInfo->isakmpdata->stats;

    ISAKMPExchange* exch = nodeconfig->exchange;

    char* hash_data = NULL;
    UInt32 len_hash = 0;
    UInt32 len_hash_data = 0;

    UInt16 notify_type = 0;

    NodeAddress source  = nodeconfig->nodeAddress;
    NodeAddress dest    = nodeconfig->peerAddress;

    ISAKMPGetHash(nodeconfig, hash_data, len_hash_data);
    len_hash  = SIZE_HASH_Payload + len_hash_data;

    Message*       newMsg = NULL;
    ISAKMPHeader*  isakmp_sendheader, *isakmp_recvheader;
    UInt16         len_packet = 0;
    UInt16         len_SA = 0;
    UInt16         len_prop = 0;
    UInt16         len_trans = 0;
    char*          currentOffset = NULL;
    char*          recv_currentOffset = NULL;
    clocktype      delay = 0;

    notify_type =
        ISAKMPValidateMessage(node, nodeconfig, msg, ISAKMP_NPTYPE_HASH);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    len_trans = exch->trans_selected->h.len;
    if (exch->phase == PHASE_1)
    {
        len_prop  = SIZE_PROPOSAL_Payload + len_trans;
    }
    else
    {
        len_prop  = SIZE_PROPOSAL_Payload + SIZE_SPI + len_trans;
    }
    len_SA = SIZE_SA_Payload + len_prop;

    len_packet = UInt16(SIZE_ISAKMP_HEADER + len_hash + len_SA);

    newMsg = MESSAGE_Alloc(node,
                            MAC_LAYER,
                            IPSEC_ISAKMP,
                            MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        len_packet,
        TRACE_ISAKMP);

    char* packet = MESSAGE_ReturnPacket(newMsg);
        memset(packet, 0, len_packet);
        isakmp_sendheader = (ISAKMPHeader*)packet;
    isakmp_recvheader = (ISAKMPHeader*) MESSAGE_ReturnPacket(msg);

    memcpy(isakmp_sendheader->init_cookie,
        isakmp_recvheader->init_cookie, COOKIE_SIZE);
    memcpy(isakmp_sendheader->resp_cookie,
        isakmp_recvheader->resp_cookie, COOKIE_SIZE);
    isakmp_sendheader->exch_type = isakmp_recvheader->exch_type;
    isakmp_sendheader->msgid = isakmp_recvheader->msgid;
    isakmp_sendheader->np_type = ISAKMP_NPTYPE_HASH;
    isakmp_sendheader->len = len_packet;

    currentOffset = (char*)(isakmp_sendheader + 1);

    //add hash payload
    ISAKMPPaylHash* hash_payload = (ISAKMPPaylHash*)currentOffset;
    ISAKMPAddHash(nodeconfig, currentOffset, hash_data, len_hash_data);
    hash_payload->h.np_type = ISAKMP_NPTYPE_SA;

    currentOffset = (char*)(hash_payload + 1);
    currentOffset = currentOffset + len_hash_data;

    ISAKMPPaylSA* send_sa_payload = (ISAKMPPaylSA*)(currentOffset);

    //extracting Hash payload from isakmp recv message
    ISAKMPPaylHash* recv_hash_payload =
                                    (ISAKMPPaylHash*)(isakmp_recvheader + 1);
    recv_currentOffset = (char*)recv_hash_payload;
    recv_currentOffset = recv_currentOffset + recv_hash_payload->h.len;
    //now getting recv SA payload
    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(recv_currentOffset);

    memcpy((char*)send_sa_payload,
        (char*)recv_sa_payload,
        SIZE_SA_Payload);
    send_sa_payload->h.len = len_SA;

    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(send_sa_payload + 1);
    currentOffset = (char*)proposal;

    //copy proposal that is selected
    if (exch->phase == PHASE_1)
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected, SIZE_PROPOSAL_Payload);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        memcpy(currentOffset,
            (char*)exch->prop_selected,
            SIZE_PROPOSAL_Payload + SIZE_SPI);
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload + SIZE_SPI;
    }
    proposal->h.len = len_prop;
    proposal->h.np_type = ISAKMP_NPTYPE_NONE;

    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;

    //copy transform payload that is selected
    memcpy((char*)transform, (char*)exch->trans_selected,  len_trans);

    //UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    //ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    //if (exch->phase == PHASE_1)
    //{
    //    // temporarily save phase-1 SA negotiated
    //    // Not required for Simulation.
    //    // Its just a dummy exchange for New group mode.
    //    // No need to update the already configured ISAKMPSA.
    //    //SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    //}
    //else
    //{
    //    // temporarily save phase-2 SA negotiated
    //    SetupIPSecSA(nodeconfig, attr, attr_size);
    //}

    if (nodeconfig->exchange->phase == PHASE_1)
    {
        // Provide Security to new group mode message using ISAKMP SA
        // established in Phase-1. Functionality like encrypting the
        // payloads should be added here.
        // Actual Hash calculation and encryption not required for Simulation
        // Adding processing delay for encryption

        delay = nodeconfig->phase1->isakmp_sa->processdelay;
    }

    if (exch->exchType == ISAKMP_IKE_ETYPE_NEW_GROUP
        && !exch->waitforcommit
        && exch->flags & ISAKMP_FLAG_C)
    {
        isakmp_sendheader->flags = isakmp_sendheader->flags | ISAKMP_FLAG_C;
    }

    exch->step++;

    // Add to retransmission list
    if (nodeconfig->exchange->lastSentPkt != NULL)
    {
        MESSAGE_Free(node, nodeconfig->exchange->lastSentPkt);
    }

    nodeconfig->exchange->lastSentPkt = MESSAGE_Duplicate(node, newMsg);

    ISAKMPSetTimer(node,
                   nodeconfig,
                   MSG_NETWORK_ISAKMP_RxmtTimer,
                   nodeconfig->exchange->step,
                   delay);

    if (delay)
    {
    NetworkIpSendRawMessageWithDelay(
        node,
        newMsg,
        source,
        dest,
        ANY_INTERFACE,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ISAKMP,
        9,
        delay);
    }
    else
    {
        NetworkIpSendRawMessage(
            node,
            newMsg,
            source,
            dest,
            ANY_INTERFACE,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_ISAKMP,
            9);
    }

    if (ISAKMP_DEBUG)
    {
        char srcStr[MAX_STRING_LENGTH];
        char dstStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
        IO_ConvertIpAddressToString(nodeconfig->peerAddress, dstStr);
        char timeStr[100];
        char delayStr[100];
        ctoa(node->getNodeTime(), timeStr);
        ctoa(delay, delayStr);
        printf("\nResponder %s has sent Hash SA to %s at Simulation time ="
            " %s with delay %s\n", srcStr, dstStr, timeStr, delayStr);
    }

    stats->numPayloadHashSend++;
    stats->numPayloadSASend++;

    if (exch->exchType == ISAKMP_IKE_ETYPE_NEW_GROUP
        && exch->initiator == RESPONDER
        && !(exch->flags & ISAKMP_FLAG_C))
    {
        (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
    }
}


//
// FUNCTION   :: ISAKMPInitiatorRecvHashSA
// LAYER      :: Network
// PURPOSE    :: process the Hash SA msg  received
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp node-peer configuration
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInitiatorRecvHashSA(Node* node,
                               ISAKMPNodeConf* nodeconfig,
                               Message* msg)
{
    ISAKMPExchange* exch = nodeconfig->exchange;
    char* currentOffset = NULL;

    UInt16    notify_type = 0;
    notify_type =
        ISAKMPValidateMessage(node, nodeconfig, msg, ISAKMP_NPTYPE_HASH);

    // if validation fails
    if (notify_type != 0)
    {
        ISAKMPProcessValidationResult(node, nodeconfig, notify_type);
        return ;
    }

    ISAKMPHeader* isakmp_recvheader =
        (ISAKMPHeader*)MESSAGE_ReturnPacket(msg);
    if (isakmp_recvheader->np_type != ISAKMP_NPTYPE_HASH)
    {
        // some unrecognized message
        return;
    }

    //extracting Hash payload
    ISAKMPPaylHash* recv_hash_payload =
                                    (ISAKMPPaylHash*)(isakmp_recvheader + 1);
    currentOffset = (char*)recv_hash_payload;
    currentOffset = currentOffset + recv_hash_payload->h.len;

    //getting SA payload
    ISAKMPPaylSA* recv_sa_payload = (ISAKMPPaylSA*)(currentOffset);
    ISAKMPPaylProp* proposal = (ISAKMPPaylProp*)(recv_sa_payload + 1);
    currentOffset = (char*)proposal;
    if (exch->phase == PHASE_1)
    {
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload;
    }
    else
    {
        currentOffset = currentOffset + SIZE_PROPOSAL_Payload +SIZE_SPI;
    }
    ISAKMPPaylTrans* transform = (ISAKMPPaylTrans*)currentOffset;
    UInt32 attr_size = transform->h.len - SIZE_TRANSFORM_Payload;

    ISAKMPDataAttr*    attr = (ISAKMPDataAttr*)(transform + 1);

    if (exch->phase == PHASE_1)
    {
        // temporarily save phase-1 SA negotiated
        // Not required for Simulation.
        // Its just a dummy exchange for New group mode.
        // No need to update the already configured ISAKMPSA.
        //SetupISAKMPSA(node, nodeconfig, attr, attr_size);
    }
    else
    {
        // temporarily save phase-2 SA negotiated
        SetupIPSecSA(nodeconfig, attr, attr_size);
    }

    if (exch->exchType == ISAKMP_IKE_ETYPE_QUICK
        && exch->initiator == INITIATOR)
    {
        ISAKMP_GenKey(exch, exch->Key_i, exch->Key_r);
    }


        if (ISAKMP_DEBUG)
        {
            char srcStr[MAX_STRING_LENGTH];
            char timeStr[100];
            IO_ConvertIpAddressToString(nodeconfig->nodeAddress, srcStr);
            ctoa(node->getNodeTime(), timeStr);
            printf("\n%s has receive Hash SA at Simulation time = %s\n",
                srcStr, timeStr);
        }


    if (exch->exchType == ISAKMP_IKE_ETYPE_NEW_GROUP
        && exch->initiator == INITIATOR)
    {
        if (exch->flags & ISAKMP_FLAG_C)
        {
            // send info msg here
            ISAKMPInfoExchange(node, nodeconfig, ISAKMP_NTYPE_CONNECTED);
        }
    }

    exch->step++;
    (*(*exch->funcList)[exch->step])(node, nodeconfig, msg);
}
