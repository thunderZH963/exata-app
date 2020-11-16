#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "node.h"
#include "network_ip.h"
#include "transport_udp.h"
#include "transport_tcp_hdr.h"
#include "partition.h"
#include "external.h"
#include "api.h"
#include "fixed_comms.h"


void FixedComms_Initialize(Node* node, const NodeInput* nodeInput)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    BOOL wasFound;
    clocktype commsVal;
    int i;
    double drop = 0.0;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        IO_ReadTimeInstance(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, i),
            nodeInput,
            "FIXED-COMMS-DELAY",
            i,
            TRUE,
            &wasFound,
            &commsVal);

        if (!wasFound)
        {
            commsVal = -1;
        }
        ip->interfaceInfo[i]->commsDelay = commsVal;

        IO_ReadDoubleInstance(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, i),
            nodeInput,
            "FIXED-COMMS-DROP-PROBABILITY",
            i,
            TRUE,
            &wasFound,
            &drop);
    
        if (!wasFound)
        {
            ip->interfaceInfo[i]->commsDrop = -1;
        }
        else if (drop < 0 || drop > 1)
        {
            ERROR_ReportError("Drop probability should be between 0 and 1 "
                "(both inclusive)\n");
        }
        else
        {
            ip->interfaceInfo[i]->commsDrop = drop;
            RANDOM_SetSeed (ip->interfaceInfo[i]->dropSeed,
                node->globalSeed,
                node->nodeId,
                0,i);
        }
    }
}

static 
void FixedComms_SendDelay(Node* node, Message* msg, BOOL* wasSentDelay)
{
    Message* delayMsg;
    Node* dstNode;
    NodeAddress dstnodeId;
    int interfaceIndex;
    clocktype fixedDelay;
    
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    interfaceIndex = NetworkIpGetInterfaceIndexFromAddress(node, ipHeader->ip_src);
    fixedDelay = ip->interfaceInfo[interfaceIndex]->commsDelay;
    if (fixedDelay > -1)
    {
        if (!NetworkIpIsMulticastAddress(node,ipHeader->ip_dst) && 
            (ipHeader->ip_dst != ANY_DEST))
        {
            dstnodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                node,
                ipHeader->ip_dst);
            
            if (dstnodeId != INVALID_MAPPING)
            {
                assert(dstnodeId != INVALID_MAPPING);
                delayMsg = MESSAGE_Duplicate(node, msg);
                MESSAGE_SetEvent(delayMsg, MSG_NETWORK_DelayFunc);
                MESSAGE_SetLayer(delayMsg, NETWORK_LAYER,NETWORK_PROTOCOL_IP);
                MESSAGE_RemoteSendSafely(node, dstnodeId, 
                    delayMsg,fixedDelay);

                *wasSentDelay=TRUE;
            }
        }
        else //This is a multicast or broadcast packet so send it to all nodes 
        {
            for (int i = 0; i < node->partitionData->getNumPartitions(); i++)
            {
                delayMsg = MESSAGE_Duplicate(node, msg);
                MESSAGE_SetEvent(delayMsg, MSG_NETWORK_DelayFunc);
                MESSAGE_SetLayer(delayMsg, NETWORK_LAYER,NETWORK_PROTOCOL_IP);

                if (i == node->partitionData->partitionId)
                {
                    MESSAGE_Send(node->partitionData->firstNode, delayMsg, 
                        fixedDelay);
                }
                else
                {
#ifdef PARALLEL //Parallel
                    delayMsg->nodeId    = ANY_DEST;
                    if (node->partitionData->isRunningInParallel())                                                             
                    {
                        if (node->getNodeTime() + fixedDelay 
                            < node->partitionData->safeTime + 1)
                        {
                            fixedDelay = node->partitionData->safeTime + 1 
                                - node->getNodeTime();
                        }
                    }
                    delayMsg->eventTime = node->getNodeTime() + fixedDelay;
                    PARALLEL_SendRemoteMessages(delayMsg,
                                    node->partitionData,
                                    i);
#ifdef USE_MPI
                    MESSAGE_Free(node, delayMsg);
#endif
#endif //endParallel
                }
            }
            *wasSentDelay=TRUE;
        }
    }
    return;
}

static
BOOL FixedComms_DetermineDrop(double dropVal, RandomSeed seed)
{
    double randNum;
    double max;

    max = (double)(pow(2.0, 31));
    randNum = (RANDOM_nrand(seed)/max);

    if (randNum < dropVal)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

void FixedComms_DelayDrop(Node * node, Message * msg, BOOL * wasProcessed)
{
    
    int interfaceIndex;

    //check for case when external interfaces are defined and we are in warm-up
    if (node->partitionData->interfaceList.numInterfaces > 0)
    {
        if (EXTERNAL_IsInWarmup(node->partitionData))
        {
            wasProcessed = FALSE;
            return;
        }
    }

    BOOL wasSentDelay = FALSE;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    interfaceIndex = NetworkIpGetInterfaceIndexFromAddress(node, ipHeader->ip_src);

    if (ip->interfaceInfo[interfaceIndex]->commsDrop != -1)
    {
        if (FixedComms_DetermineDrop(ip->interfaceInfo[interfaceIndex]->commsDrop,
            ip->interfaceInfo[interfaceIndex]->dropSeed))
        {
            *wasProcessed = TRUE;
            ip->stats.ipCommsDropped++;
            return;
        }
    }
    //Send the packet with user-specified delay if not dropped
    FixedComms_SendDelay(node,msg,&wasSentDelay);

    if (wasSentDelay)
    {
        *wasProcessed = TRUE;
        return;
    }
}
