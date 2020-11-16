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

#include "api.h"
#include "app_util.h"
#include "partition.h"
#include "phy.h"
#include "mac.h"
#include "channel_scanner.h"
#include "network_ip.h"
#include "app_eaves.h"

void Eaves_ProcessEvent(Node *node, Message *msg)
{
    Node *eavesNode;
    EavesInfo* eInfo;

    eavesNode = MAPPING_GetNodePtrFromHash(node->partitionData->nodeIdHash,
        msg->originatingNodeId);

    if (eavesNode == NULL)
    {
        printf("** [EavesDropper] ERROR: Node %d does not exist!\n",
            msg->originatingNodeId);
        MESSAGE_Free(node, msg);
        return;
    }
    eInfo = (EavesInfo *) MESSAGE_ReturnInfo(msg);
    ERROR_Assert(eInfo != NULL, "Eavesdrop Info field is NULL!");

    if (msg->eventType == MSG_EAVES_Start)
    {
        if (eInfo->eavesAddress != INVALID_ADDRESS)
        {
            int interfaceIndex = NetworkIpGetInterfaceIndexFromAddress
                (eavesNode, eInfo->eavesAddress);
            eavesNode->macData[interfaceIndex]->promiscuousMode = TRUE;
            if (eInfo->switchHeader == TRUE)
            {
                eavesNode->macData[interfaceIndex]->promiscuousModeWithHeaderSwitch = TRUE;
            }
            if (eInfo->hla == TRUE)
            {
                eavesNode->macData[interfaceIndex]->promiscuousModeWithHLA = TRUE;
            }
        }
        else
        {
            for (int interfaceIndex = 0; interfaceIndex < eavesNode->numberInterfaces; interfaceIndex++)
            {
                //check for virtual interface created by dual-ip, this is not supported
                NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
                if (ip->interfaceInfo[interfaceIndex]->isVirtualInterface)
                {
                    continue;
                }
                eavesNode->macData[interfaceIndex]->promiscuousMode = TRUE;
                if (eInfo->switchHeader == TRUE)
                {
                    eavesNode->macData[interfaceIndex]->promiscuousModeWithHeaderSwitch = TRUE;
                }
                if (eInfo->hla == TRUE)
                {
                    eavesNode->macData[interfaceIndex]->promiscuousModeWithHLA = TRUE;
                }
            }
        }

    }
    else if (msg->eventType == MSG_EAVES_Stop)
    {
        if (eInfo->eavesAddress != INVALID_ADDRESS)
        {
            int interfaceIndex = NetworkIpGetInterfaceIndexFromAddress
                (eavesNode, eInfo->eavesAddress);
            eavesNode->macData[interfaceIndex]->promiscuousMode = FALSE;
            eavesNode->macData[interfaceIndex]->promiscuousModeWithHeaderSwitch = FALSE;
            eavesNode->macData[interfaceIndex]->promiscuousModeWithHLA = FALSE;
        }
        else
        {
            for (int interfaceIndex = 0; interfaceIndex < eavesNode->numberInterfaces; interfaceIndex++)
            {
                //check for virtual interface created by dual-ip, this is not supported
                NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
                if (ip->interfaceInfo[interfaceIndex]->isVirtualInterface)
                {
                    continue;
                }
                eavesNode->macData[interfaceIndex]->promiscuousMode = FALSE;
                eavesNode->macData[interfaceIndex]->promiscuousModeWithHeaderSwitch = FALSE;
                eavesNode->macData[interfaceIndex]->promiscuousModeWithHLA = FALSE;

            }
        }

    }
    MESSAGE_Free(node, msg);
}
