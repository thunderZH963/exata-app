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

// This file contains the MdpSession & MdpObject methods
// for handling recv'd MDPv2 protocol messages

#include "mdpSession.h"
#include "app_mdp.h"
#include <time.h>  // for gmtime()
#include <errno.h>

#ifdef MDP_FOR_WINDOWS
#include <windows.h>
#include <direct.h>
#else
// for unix
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#endif

#define MDP_DEBUG_MSG_FLOW 0

bool MdpSession::HandleRecvPacket(char* buffer,
                                  UInt32 len,
                                  MdpProtoAddress* src,
                                  BOOL isUnicast,
                                  char* info,
                                  Message* theMsgPtr,
                                  Int32 virtualSize)
{
    MdpMessage msg; // This doesn't have to be static
    bool isServerPacket = true;

    if (!msg.Unpack(buffer,
                   len,
                   theMsgPtr->virtualPayloadSize,
                   &isServerPacket))
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "mdp: node:%u Recv'd bad message.\n",LocalNodeId());
        ERROR_ReportWarning(errStr);

        // free qualnet message
        MESSAGE_Free(node, theMsgPtr);
        return true;
    }

    if (isServerPacket
       && MdpIsExataIncomingPort(node, ((UdpToAppRecv *)info)->destPort))
    {
        // need to add the source port and source address of the
        // external application in mdp out port list so that
        // unicast ACK, NACK, REPORT by the client can go through
        // hton process
        // below call will add the sourceport and source address
        // in the list if not exist
        if (((UdpToAppRecv *)info)->sourceAddr.networkType == NETWORK_IPV4)
        {
            MdpAddPortInExataOutPortList(node,
                     ((UdpToAppRecv *)info)->sourcePort,
                     ((UdpToAppRecv *)info)->sourceAddr.interfaceAddr.ipv4);
        }
    }

    // Some machines or OS's (Win32) don't ever disable mcast loopback
    // Only receive your own packets if "loopback" is enabled
    if (!loopback && (LocalNodeId() == msg.sender))
    {
        // free qualnet message
        MESSAGE_Free(node, theMsgPtr);
        return true;
    }
    else if (loopback && (LocalNodeId() == msg.sender))
    {
        // opening MDP server if not open
        if (!IsClient())
        {
            MdpError err = OpenClient(GetSessionRxBufferSize());

            if (err != MDP_ERROR_NONE)
            {
                char errStr[MAX_STRING_LENGTH];
                sprintf(errStr,"Error in opening MDP receiver for loopback. "
                               "(Error = %d)\n",err);
                ERROR_ReportWarning(errStr);
            }
        }
    }


    if (MDP_REPORT != msg.type)
    {
        client_stats.rx_rate += (len + theMsgPtr->virtualPayloadSize);  // for client rx_rate reporting
    }

    if (msg.version != MDP_PROTOCOL_VERSION)
    {
        if (MDP_DEBUG)
        {
            printf("mdp: node:%u Received packet type:%d with wrong "
                   "protocol version.\n", this->GetNode()->nodeId, msg.type);
        }
        // free qualnet message
        MESSAGE_Free(node, theMsgPtr);
        return true;
    }

    switch (msg.type)
    {
        case MDP_REPORT:
            HandleMdpReport(&msg, src);
            break;

        case MDP_INFO:
        case MDP_DATA:
        case MDP_PARITY:
            // Only clients care about MDP_PARITY
            if (IsClient()) HandleObjectMessage(&msg,
                                                src,
                                                info,
                                                theMsgPtr,
                                                virtualSize);
            break;

        case MDP_CMD:
            // Only clients care about MDP_CMD
            if (IsClient()) HandleMdpServerCmd(&msg, src);
            break;

        case MDP_NACK:
            // Both clients and servers care about MDP_NACKs
            if (IsServer()) ServerHandleMdpNack(&msg, isUnicast);
            if (IsClient()) ClientHandleMdpNack(&msg);
            break;

        case MDP_ACK:
            // Servers only for now
            if (IsServer())
            {
                if (MDP_DEBUG_MSG_FLOW)
                {
                    printf("MdpSession::HandleRecvPacket: "
                           "Node %d Receiving MDP_ACK\n",
                            node->nodeId);
                }
                ServerHandleMdpAck(&msg);
            }
            break;

        default:
            // should never get here
            printf("mdp: node:%u Recv'd unsupported message type %d.\n",
                                this->GetNode()->nodeId, msg.type);
            break;
    }
    // If the application has deleted/aborted the session in
    // a notify callback during this event, we must do housekeeping
    if (notify_abort) mgr->DeleteSession(this);

    //free qualnet message
    MESSAGE_Free(node, theMsgPtr);
    return true;
}  // end MdpSession::HandleRecvPacket()

void MdpSession::HandleMdpReport(MdpMessage *theMsg, MdpProtoAddress *src)
{
    // Update Positive Acknowledgement List as needed
    // (TBD) Manage acking node list better .remove nodes that have timed out
    if (theMsg->report.status & MDP_ACKING)
    {
        AddAckingNode(theMsg->sender);
    }
    else
    {
        RemoveAckingNode(theMsg->sender);
    }

    if (theMsg->report.status & MDP_CLIENT)
    {
        // (TBD) In the future we might use "NotifyUser" to post
        // report info to application.  Meanwhile we'll just output
        // a debug message
        // incrementing REPORT receive msg stat count at sender
        commonStats.numReportMsgRecCount++;

#ifdef PROTO_DEBUG
    if (MDP_DEBUG)
    {
        MdpClientStats *stat = &theMsg->report.client_stats;
        printf("*******************************************************\n");
        printf("MDP_REPORT from client: \"%d\"\n", theMsg->sender);
        struct timevalue  rxTime;
        ProtoSystemTime(rxTime, this->GetNode()->getNodeTime());
        printf("   Session duration : %lu sec.\n", stat->duration);
        printf("   Objects completed: %lu\n", stat->success);
        printf("   Objects pending  : %lu\n", stat->active);
        printf("   Objects failed   : %lu\n", stat->fail);
        printf("   Server resyncs   : %lu\n", stat->resync);
        printf("   Current goodput  : %.3f kbps\n",
                        ((double)stat->goodput * 8.0)/1000.0);
        printf("   Current rx rate  : %.3f kbps\n",
                        ((double)stat->rx_rate * 8.0)/1000.0);
        printf("   Current tx rate  : %.3f kbps\n",
                        ((double)stat->tx_rate * 8.0)/1000.0);
        printf("   NACKs transmitted: %lu\n", stat->nack_cnt);
        printf("   NACKs suppressed : %lu\n", stat->supp_cnt);
        printf("   Block loss stats : %lu, %lu, %lu, %lu, %lu, %lu\n",
                        stat->blk_stat.lost_00, stat->blk_stat.lost_05,
                        stat->blk_stat.lost_10, stat->blk_stat.lost_20,
                        stat->blk_stat.lost_40, stat->blk_stat.lost_50);
        printf("   Buffer usage     : peak>%luK overruns>%lu\n",
                        (stat->buf_stat.peak+500)/1000,
                        stat->buf_stat.overflow);
        printf("*******************************************************\n");
    }
#endif // PROTO_DEBUG
    }
    return;
}  // end MdpSession::HandleMdpReport()


void MdpSession::HandleObjectMessage(MdpMessage* theMsg,
                                     MdpProtoAddress* src,
                                     char* info,
                                     Message* theMsgPtr,
                                     Int32 virtualSize)
{
    // Find state for the server
    MdpServerNode* theServer =
        (MdpServerNode*) server_list.FindNodeById(theMsg->sender);
    if (!theServer)
    {
        theServer = NewRemoteServer(theMsg->sender);
        if (!theServer)
        {
            if (MDP_DEBUG)
            {
                printf("mdp: node:%u Error allocating new Mdp Server state!\n",
                        LocalNodeId());
            }
            return;
        }
    }
    // Update general server state
    theServer->UpdateGrtt(theMsg->object.grtt);
    theServer->ResetActivityTimer();
    theServer->SetAddress(src);
    theServer->UpdateLossEstimate(theMsg->object.sequence, ecn_status);

    unsigned short segmentSize;
    unsigned char numData = theMsg->object.ndata;
    unsigned char numParity = theMsg->object.nparity;
    UInt32 blockId;
    char* infoPtr = NULL;
    unsigned short infoLen = 0;

    MdpMessageType msgType = (MdpMessageType) theMsg->type;
    switch (msgType)
    {
        case MDP_INFO:
            if (MDP_DEBUG_MSG_FLOW)
            {
                printf("MdpSession::HandleObjectMessage: "
                       "Node %d Receiving MDP_INFO\n", node->nodeId);
            }
            segmentSize = theMsg->object.info.segment_size;
            blockId = 0;
            infoPtr = theMsg->object.info.data;
            infoLen = theMsg->object.info.len;

            // Right now object.info.len and object.info.actual_data_len are
            // same so below commented statement does not have any affect

            //infoLen = theMsg->object.info.actual_data_len;

            // incrementing INFO receive msg stat count
            commonStats.numInfoMsgRecCount++;
            break;

        case MDP_DATA:
            if (MDP_DEBUG_MSG_FLOW)
            {
                printf("MdpSession::HandleObjectMessage: "
                       "Node %d Receiving MDP_DATA\n", node->nodeId);
            }
            if (theMsg->object.flags & MDP_DATA_FLAG_RUNT)
                segmentSize = theMsg->object.data.segment_size;
            else
                segmentSize = theMsg->object.data.len;
            blockId = theMsg->object.data.offset / (numData * segmentSize);
            // incrementing DATA receive msg stat count
            commonStats.numDataMsgRecCount++;
            break;

        case MDP_PARITY:
            if (MDP_DEBUG_MSG_FLOW)
            {
                printf("MdpSession::HandleObjectMessage: "
                       "Node %d Receiving MDP_PARITY\n", node->nodeId);
            }
            segmentSize = theMsg->object.parity.len;
            blockId = theMsg->object.parity.offset / (numData * segmentSize);
            // incrementing PARITY receive msg stat count
            commonStats.numParityMsgRecCount++;
            break;

        default:
            // This should _never_ occur
            ASSERT(0);
            return;
    }

    // Check to make sure server hasn't restarted with new coding parameters
    if (!theServer->VerifyCoding(segmentSize, numData, numParity))
    {
        // Reset server for new activation
        if (theServer->IsActive()) theServer->Deactivate();
        theServer->SetCoding(segmentSize, numData, numParity);
    }

    // Find/create the appropriate object state
    UInt32 objectId = theMsg->object.object_id;
    MdpObject* theObject = theServer->FindRecvObjectById(objectId);
    if (!theObject)
    {
        if (MDP_DEBUG)
        {
            char clockStr[MAX_CLOCK_STRING_LENGTH];
            ctoa(node->getNodeTime(), clockStr);
            printf("mdp: node: %u Receiving new object:%u from "
                   "server:%u at time %s\n",
                    LocalNodeId(), objectId, theServer->Id(), clockStr);
        }
        // Pick up new objects only if already synchronized or
        // if it's _not_ a repair transmission _and_ it's in the first
        // coding block
        if (theServer->ServerSynchronized() ||
            (!(theMsg->object.flags & MDP_DATA_FLAG_REPAIR) && (0 == blockId)))
        {
            // Is it in range
            MdpRecvObjectStatus objectStatus =
                theServer->ObjectSequenceCheck(objectId);


            switch (objectStatus)
            {
                case  MDP_RECV_OBJECT_INVALID:
                    if (MDP_DEBUG)
                    {
                        char clockStr[MAX_CLOCK_STRING_LENGTH];
                        ctoa(node->getNodeTime(), clockStr);
                        printf("mdp: node: %u New object status: "
                               "MDP_RECV_OBJECT_INVALID at time %s\n",
                                LocalNodeId(), clockStr);
                    }
                    theServer->Sync(objectId);
                    ASSERT(MDP_RECV_OBJECT_NEW == theServer->ObjectSequenceCheck(objectId));
                    client_stats.resync++;
                    objectStatus = MDP_RECV_OBJECT_NEW;
                    break;

                case MDP_RECV_OBJECT_NEW:
                    if (MDP_DEBUG)
                    {
                        char clockStr[MAX_CLOCK_STRING_LENGTH];
                        ctoa(node->getNodeTime(), clockStr);
                        printf("mdp: node: %u New object status: "
                               "MDP_RECV_OBJECT_NEW at time %s\n",
                         LocalNodeId(), clockStr);
                    }
                    // New object in valid range
                    break;

                case MDP_RECV_OBJECT_PENDING:
                    if (MDP_DEBUG)
                    {
                        char clockStr[MAX_CLOCK_STRING_LENGTH];
                        ctoa(node->getNodeTime(), clockStr);
                        printf("mdp: node: %u New object status: "
                               "MDP_RECV_OBJECT_PENDING at time %s\n",
                         LocalNodeId(), clockStr);
                    }
                    break;

                case MDP_RECV_OBJECT_COMPLETE :
                    if (MDP_DEBUG)
                    {
                        char clockStr[MAX_CLOCK_STRING_LENGTH];
                        ctoa(node->getNodeTime(), clockStr);
                        printf("mdp: node: %u New object status: "
                               "MDP_RECV_OBJECT_COMPLETE at time %s\n",
                         LocalNodeId(), clockStr);
                    }
                    // We have already received this object
                    break;
            }


            if (MDP_RECV_OBJECT_COMPLETE != objectStatus
                && MDP_RECV_OBJECT_INVALID != objectStatus)
            {
                // Allocate buffers if not already allocated
                if (!theServer->IsActive())
                {
                    if (!theServer->Activate(client_window_size,
                                             segment_pool_depth))
                    {
                        if (MDP_DEBUG)
                        {
                            printf("MdpSession::UpdateServer() Error activating server!\n");
                        }
                        return;
                    }
                }

                MdpObjectType objectType = ((theMsg->object.flags & MDP_DATA_FLAG_FILE) ?
                                        MDP_OBJECT_FILE : MDP_OBJECT_DATA);

                // now before creating File Object ensure that
                // archive directory must exist
                if (objectType == MDP_OBJECT_FILE)
                {
#ifdef MDP_FOR_WINDOWS
                    // making node name directory
                    if (_mkdir(archive_path))
                    {
                        if (MDP_DEBUG)
                        {
                            char errStr[MAX_STRING_LENGTH];
                            sprintf(errStr,"Failed to create archive "
                                       "directory \"%s\": %s\n",
                                       archive_path, strerror(errno));
                            ERROR_ReportWarning(errStr);
                        }
                    }
#else
                    if (mkdir(archive_path, 0777))
                    {
                        if (MDP_DEBUG)
                        {
                            char errStr[MAX_STRING_LENGTH];
                            sprintf(errStr,"Failed to create dir \"%s\": "
                                      "%s\n",archive_path, strerror(errno));
                            ERROR_ReportWarning(errStr);
                        }
                    }
#endif
                    // first check the archive dir state
                    if (!MdpFileIsWritable(archive_path))
                    {
                        char errStr[MAX_STRING_LENGTH];
                        sprintf(errStr,"Error in accessing the archive "
                                       "path %s for writable state. \n",
                                       archive_path);
                        ERROR_ReportError(errStr);
                    }
                }

                theObject = theServer->NewRecvObject(objectId,
                                                 objectType,
                                                 theMsg->object.object_size,
                                                 virtualSize,
                                                 infoPtr,
                                                 infoLen);

                if (msgType == MDP_DATA || msgType == MDP_PARITY)
                {
                    theObject->SetVirtualSize(virtualSize);
                }
                // If no info is available, don't ask for it
                if (theObject && !(theMsg->object.flags & MDP_DATA_FLAG_INFO))
                    theObject->SetHaveInfo(true);
            }
        }  // end if ("it's a good object to pick up on");
    }  // end if (!theObject)

    if (theObject)
    {
        ASSERT(theServer->ServerSynchronized());
        bool result = true;
        switch (msgType)
        {
            case MDP_INFO:
                if (!theObject->HaveInfo())
                {

                    ASSERT(theObject->IsOpen());
                    theObject->SetHaveInfo(true);
                    theObject->SetInfo(theMsg->object.info.data,
                                       theMsg->object.info.len);
                    theObject->Notify(MDP_NOTIFY_RX_OBJECT_INFO, MDP_ERROR_NONE);
                }
                else
                {
                    // received redundant info pkt
                    // (TBD) we may want to verify that the info hasn't changed ??
                }
                if (!theServer->WasDeleted())
                    theServer->ObjectRepairCheck(objectId, 0);
                break;

            case MDP_DATA:
                // Now update the object with received MDP_DATA content
                result = theObject->HandleRecvData(theMsg->object.data.offset, 0,
                                              (0 != (theMsg->object.flags & MDP_DATA_FLAG_BLOCK_END)),
                                              theMsg->object.data.data,
                                              theMsg->object.data.len,
                                              (unsigned short)theMsg->object.data.actual_data_len);
                break;

            case MDP_PARITY:
                // Now update the object with received MDP_PARITY content
                result = theObject->HandleRecvData(theMsg->object.parity.offset,
                                              theMsg->object.parity.id,
                                              (0 != (theMsg->object.flags & MDP_DATA_FLAG_BLOCK_END)),
                                              theMsg->object.parity.data,
                                              theMsg->object.parity.len,
                                              (unsigned short)theMsg->object.parity.actual_data_len);
                break;

            default:
                // This should _never_ occur
                ASSERT(0);
                break;
        }  // end switch (msgType)

        // Check for object/remote server termination by app during callback
        if (theServer->WasDeleted())
        {
            theServer->Delete();
            return;
        }
        else if (theObject->WasAborted())
        {
            theObject->RxAbort();
            theServer->ObjectRepairCheck(objectId, 0);
            return;
        }

        if (result)
        {
            // Is the object finished?
            if (!theObject->RxPending())
            {
                MdpObjectType objectType = ((theMsg->object.flags & MDP_DATA_FLAG_FILE) ?
                                        MDP_OBJECT_FILE : MDP_OBJECT_DATA);
                AppType appType;

                //check for loopback packets
                if (mgr->LocalNodeId() == theMsg->sender)
                {
                    appType = MdpGetAppTypeForServer(
                                        theObject->Session()->GetAppType());
                }
                else
                {
                    appType = theObject->Session()->GetAppType();
                }

                if (objectType == MDP_OBJECT_DATA)
                {
                    UInt32 actualObjectDataSize = 0;
                    char* object_data = ((MdpDataObject*)theObject)->
                                        GetActualData(&actualObjectDataSize);

                    MdpSendDataToApp(theObject->Session()->GetNode(),
                                     info,                     //UdpToAppRecv info
                                     object_data,
                                     appType,
                                     (Int32)theObject->Size(), //for complete objectsize
                                     (Int32)actualObjectDataSize,
                                     theMsgPtr,
                                     objectType,
                                     (char*)theObject->Info(),
                                     (Int32)theObject->InfoSize(),
                                     theObject->Session());

                    MEM_free(object_data);
                }
                else if (objectType == MDP_OBJECT_FILE)
                {
                    // need to send notification to upper Application
                    // TBD which application need to use below call. Below
                    // commented code is sending the path with file name
                    // as data of the packet and object info as packet info
                    char name[MDP_PATH_MAX + 1];
                    memset(name, 0, (MDP_PATH_MAX + 1));
                    UInt16 maxLen = MDP_PATH_MAX;
                    MdpFileObject* fileObject = (MdpFileObject*)theObject;

                    UInt32 maxNameLen = MDP_PATH_MAX;
                                        //MAX(strlen(fileObject->GetPath()),
                                        //    MDP_PATH_MAX);
                    strncpy(name, fileObject->GetPath(), maxNameLen);
                    UInt32 path_len = MIN(maxNameLen, strlen(name));
                    UInt32 name_len = MIN((maxNameLen-path_len),
                                           fileObject->InfoSize());
                    strncpy(name+path_len, fileObject->Info(), name_len);
                    maxNameLen = strlen(name);
                    maxNameLen = MIN(maxLen, maxNameLen);
                    if (maxNameLen < maxLen) name[maxNameLen] = '\0';

                    MdpSendDataToApp(theObject->Session()->GetNode(),
                                     info,
                                     name,
                                     appType,
                                     (Int32)maxNameLen, // for the packet data size
                                     (Int32)maxNameLen,
                                     theMsgPtr,
                                     objectType,
                                     (char*)fileObject->Info(),
                                     (Int32)fileObject->InfoSize(),
                                     theObject->Session());
                }

                ASSERT(!theObject->HaveBuffers());
                client_stats.success++;
                theServer->DeactivateRecvObject(theObject->TransportId(), theObject);
                if (MDP_DEBUG)
                {
                    char clockStr[MAX_CLOCK_STRING_LENGTH];
                    ctoa(node->getNodeTime(), clockStr);
                    printf("mdp: node:%u Client recv object:%u "
                           "complete at time %s.\n",
                        LocalNodeId(), objectId, clockStr);
                }
                theObject->Notify(MDP_NOTIFY_RX_OBJECT_COMPLETE, MDP_ERROR_NONE);
                delete theObject;
            }

        }
        else  // Fatal DATA/PARITY handling error for this object
        {
            client_stats.fail++;
            if (MDP_DEBUG)
            {
                printf("mdp: node:%u Client error handling reception of object:%u\n",
                            LocalNodeId(), objectId);
            }
            theObject->RxAbort();
        }
    }
    else  // if (!theObject)
    {
        if (theServer->ServerSynchronized())
            theServer->ObjectRepairCheck(objectId, 0);
    }  // end if/else(theObject)
}  // end MdpSession::HandleObjectMessage()


// This handles received data or parity for an object
// (TBD) Rewrite this to be a member of MdpServerNode ???
bool MdpObject::HandleRecvData(UInt32           dataOffset,
                               int              parityId,
                               bool             blockEnd,
                               char*            theData,
                               UInt16           dataLen,
                               UInt16           actualDataLen)
{
    ASSERT(IsOpen());
    UInt32 blockId = dataOffset/block_size;
    MdpBlock* theBlock = block_buffer.GetBlock(blockId);
    if (!theBlock)
    {
        // Make sure we haven't already received this block
        if (!transmit_mask.Test(blockId))
        {
            if (MDP_DEBUG)
            {
                printf("mdp: node:%u Client receiving redundant %s", LocalNodeId(),
                    parityId ? "parity " : "data ");
                printf("for object:%u block:%03u\n", transport_id, blockId);
            }
            sender->ObjectRepairCheck(transport_id,
                            (blockEnd ? (blockId+1) : blockId));
            return true;
        }
        // Create new block
        theBlock = sender->BlockGetFromPool();
        if (!theBlock)
        {
            if (sender->ReclaimResources(this, blockId))
            {
                theBlock = sender->BlockGetFromPool();
                ASSERT(theBlock);
            }
            else
            {
                if (MDP_DEBUG)
                {
                    printf("mdp: node:%u No buffers for recv data block of object:%u block:%u\n",
                        LocalNodeId(), transport_id, blockId);
                }
                sender->ObjectRepairCheck(transport_id,
                                (blockEnd ? (blockId+1) : blockId));
                return true;
            }
        }
        // Properly rx init the block (Note that last block may be short)
        if (blockId != last_block_id)
            theBlock->RxInit(blockId, ndata, nparity);
        else
            theBlock->RxInit(blockId, last_block_len, nparity);
        // Put it in our object's block_buffer
        block_buffer.Prepend(theBlock);
    }  // end if (!theBlock)

    // Which vector is this??
    unsigned int vectorId;
    if (parityId)
    {
        vectorId = parityId;
        if (MDP_DEBUG)
        {
            printf("mdp: node:%u Client recv'd MDP_PARITY object:%u block:%02u vector:%u\n",
                    LocalNodeId(), transport_id, blockId, vectorId);
        }
    }
    else
    {
        vectorId = (dataOffset / segment_size) - (blockId * ndata);
        if (MDP_DEBUG)
        {
            char clockStr[MAX_CLOCK_STRING_LENGTH];
            ctoa(session->node->getNodeTime(), clockStr);
            printf("mdp: node:%u Client recv'd MDP_DATA  object:%u "
                   "block:%02u vector:%u at time %s\n",
                   LocalNodeId(), transport_id, blockId, vectorId, clockStr);
        }
    }
    // Check to see if we already have it
    if (theBlock->Vector(vectorId) || theBlock->IsVectorExist(vectorId))
    {
        if (MDP_DEBUG)
        {
            printf("mdp: node:%u Client recv'd redundant %s.\n",
                LocalNodeId(), (parityId ? "MDP_PARITY" : "MDP_DATA"));
        }
        sender->ObjectRepairCheck(transport_id,
                        (blockEnd ? (blockId+1) : blockId));
        return true;
    }

    // Copy data to a vector from the server's pool and attach to block
    char* vector = sender->VectorGetFromPool();
    if (!vector)
    {
        if (sender->ReclaimResources(this, blockId))
        {
            vector = sender->VectorGetFromPool();
            ASSERT(vector);
        }
        else
        {
            if (MDP_DEBUG)
            {
                printf("mdp: node:%u No buffers for recv data vector of object:%u block:%u\n",
                        LocalNodeId(), transport_id, blockId);
            }
            sender->ObjectRepairCheck(transport_id,
                            (blockEnd ? (blockId+1) : blockId));
            return true;
        }
    }
    memcpy(vector, theData, actualDataLen);
    if (actualDataLen < segment_size)
        memset(&vector[actualDataLen], 0, segment_size - actualDataLen);

    theBlock->AttachVector(vector, vectorId);
    theBlock->SetVectorSize(actualDataLen, vectorId);

    // It's non-redundant data or parity, call it "goodput" for client reporting
    session->client_stats.goodput += dataLen;

    if (parityId)
        theBlock->IncrementParityCount();
    else
        theBlock->DecrementErasureCount();

    theBlock->UnsetMask(vectorId);  // "unmark" erasure

    if (!parityId)
    {
        if (!WriteSegment(dataOffset, theData, actualDataLen))
        {
            // fatal error for this object
            if (MDP_DEBUG)
            {
                printf("mdp: node:%u Error writing object data vector\n",
                        LocalNodeId());
            }
            sender->ObjectRepairCheck(transport_id,
                            ((blockEnd) ? (blockId+1) : blockId));
            return false; // error writing to object
        }
        theBlock->SetVectorSize(actualDataLen, vectorId);
    }
    data_recvd += dataLen;  // track recv progress

    session->client_stats.bytes_recv += dataLen;

    Notify(MDP_NOTIFY_RX_OBJECT_UPDATE, MDP_ERROR_NONE);
    if (sender->WasDeleted() || WasAborted()) return true;

    if (theBlock->ErasureCount() <= theBlock->ParityCount())
    {
        // Block fully received
        transmit_mask.Unset(blockId);  // block transmission complete

        session->client_stats.blk_stat.count++;

            unsigned int numData;
        if (blockId != last_block_id)
            numData = ndata;
        else
            numData = last_block_len;
        // Decode if necessary
        if (theBlock->FirstSet() < numData)
        {
            if (MDP_DEBUG)
            {
                printf("mdp: node:%u Client decoding object:%u block:%u with %d erasure(s).\n",
                    LocalNodeId(), transport_id, blockId, theBlock->ErasureCount());
            }
            // Fill missing (erased) vectors with zero filled vectors
            if (!theBlock->FillZero(sender->VectorPool(), segment_size, numData+nparity))
            {
                // This shouldn't happen since receiver allocate some extra vectors
                // for this job among others
                if (MDP_DEBUG)
                 {
                    printf("mdp: node:%u Error zero filling coding block!\n", LocalNodeId());
                }
                sender->ObjectRepairCheck(transport_id,
                                ((blockEnd) ? (blockId+1) : blockId));
                return false; // error writing to object
            }
            sender->Decode(theBlock->VectorList(), numData, theBlock->Mask());
        }
        // Write filled erasures to object (erasures marked in block vector_mask)
        vectorId = theBlock->FirstSet();
        UInt32 blockOffset = blockId * block_size;
        dataLen = (unsigned short)segment_size;
        while (vectorId < numData)
        {
            dataOffset = blockOffset + (vectorId * dataLen);
            if (last_offset == dataOffset)
                dataLen = (unsigned short)(object_size - last_offset);

            if (!WriteSegment(dataOffset, theBlock->Vector(vectorId), dataLen))
            {
                // fatal error for this object
                if (MDP_DEBUG)
                {
                    printf("mdp: node:%u Error writing object data vector\n",
                            LocalNodeId());
                }
                sender->ObjectRepairCheck(transport_id,
                                ((blockEnd) ? (blockId+1) : blockId));
                return false; // error writing to object
            }
            vectorId = theBlock->NextSet(++vectorId);
        }
        // Record first pass block loss statistics for full-size blocks
        // Note: Out of order packet reception at block boundaries
        //       can cause these estimated stat's to be skewed a little
        if (!theBlock->InRepair() && (numData == ndata))
        {
            if (0 == theBlock->ErasureCount())
            {
                session->client_stats.blk_stat.lost_00++;
            }
            else
            {
                double loss = (double)theBlock->ErasureCount() /
                             (double)(numData);
                if (loss <= 0.05)
                    session->client_stats.blk_stat.lost_05++;
                else if (loss <= 0.10)
                    session->client_stats.blk_stat.lost_10++;
                else if (loss <= 0.20)
                    session->client_stats.blk_stat.lost_20++;
                else if (loss <= 0.40)
                    session->client_stats.blk_stat.lost_40++;
                else
                    session->client_stats.blk_stat.lost_50++;
            }
        }
        // Since we're finished with the block, return block resources to pools
        block_buffer.Remove(theBlock);
        sender->BlockReturnToPool(theBlock);
    }
    sender->ObjectRepairCheck(transport_id,
                        ((blockEnd) ? (blockId+1) : blockId));
    return true;  // Everything OK
}  // end MdpObject::HandleRecvData()


void MdpSession::HandleMdpServerCmd(MdpMessage *theMsg,
                                    MdpProtoAddress *src)
{
    MdpServerNode* theServer = (MdpServerNode*) server_list.FindNodeById(theMsg->sender);
    if (!theServer)
    {
        theServer = NewRemoteServer(theMsg->sender);
        if (!theServer)
        {
            if (MDP_DEBUG)
            {
                printf("mdp: node:%u Error allocating new MdpServer state!\n", LocalNodeId());
            }
            return;
        }
    }
    // Update general server state
    theServer->UpdateGrtt(theMsg->cmd.grtt);
    theServer->ResetActivityTimer();
    theServer->SetAddress(src);
    theServer->UpdateLossEstimate(theMsg->cmd.sequence, ecn_status);

    // incrementing total CMD msg sent stat count
    commonStats.numCmdMsgRecCount++;

    switch (theMsg->cmd.flavor)
    {
        case MDP_CMD_FLUSH:
            if (MDP_DEBUG_MSG_FLOW)
            {
                printf("MdpSession::HandleMdpServerCmd: "
                       "Node %d Receiving MDP_CMD_FLUSH\n", node->nodeId);
            }
            if (theMsg->cmd.flush.flags & MDP_CMD_FLAG_EOT)
            {
                theServer->Deactivate();
                theServer->Close();
                DeleteRemoteServer(theServer);
            }
            else
            {
                if (theServer->ServerSynchronized())
                    theServer->FlushServer(theMsg->cmd.flush.object_id);
            }
            // incrementing total CMD FLUSH msg receive stat count
            commonStats.numCmdFlushMsgRecCount++;
            break;

        case MDP_CMD_SQUELCH:
            if (MDP_DEBUG_MSG_FLOW)
            {
                printf("MdpSession::HandleMdpServerCmd: "
                       "Node %d Receiving MDP_CMD_SQUELCH\n", node->nodeId);
            }
            theServer->HandleSquelchCmd(theMsg->cmd.squelch.sync_id,
                                        theMsg->cmd.squelch.data,
                                        theMsg->cmd.squelch.len);
            // incrementing total CMD SQUELCH msg receive stat count
            commonStats.numCmdSquelchMsgRecCount++;
            break;

        case MDP_CMD_ACK_REQ:
        {
            if (MDP_DEBUG_MSG_FLOW)
            {
                 printf("MdpSession::HandleMdpServerCmd: "
                        "Node %d Receiving MDP_CMD_ACK_REQ\n", node->nodeId);
            }
            // Are we in the list ?
            UInt32 objectId = theMsg->cmd.ack_req.object_id;
            if (theMsg->cmd.ack_req.FindAckingNode(LocalNodeId()))
            {
                // If object is complete, acknowledge it
                // Note this does not mean we actually received it,
                // but rather that the MdpClient is no longer interested
                // in it for whatever reason.
                if (MDP_RECV_OBJECT_COMPLETE == theServer->ObjectSequenceCheck(objectId))
                {
                    if (!EmconClient())
                    {
                        if (MDP_DEBUG_MSG_FLOW)
                        {
                             printf("MdpSession::HandleMdpServerCmd: "
                                    "Node %d Initiating porcess for MDP_ACK\n",
                                     node->nodeId);
                        }
                        theServer->AcknowledgeRecvObject(objectId);
                    }
                }
                else
                {
                    // Being asked to ACK will wake us up
                    theServer->FlushServer(objectId);
                }
            }
            else
            {
                // "FlushServer()" will activate new objects as needed
                if (theServer->ServerSynchronized())
                        theServer->FlushServer(objectId);
            }
            // incrementing total CMD ACK msg receive stat count
            commonStats.numCmdAckReqMsgRecCount++;
        }
        break;

        case MDP_CMD_GRTT_REQ:
            theServer->HandleGrttRequest(theMsg);
            // incrementing total CMD GRTT REQ msg receive stat count
            commonStats.numCmdGrttReqMsgRecCount++;
            break;

        case MDP_CMD_NACK_ADV:
            if (MDP_DEBUG_MSG_FLOW)
            {
                 printf("MdpSession::HandleMdpServerCmd: "
                        "Node %d Receiving MDP_CMD_NACK_ADV\n",
                         node->nodeId);
            }
            theServer->HandleRepairNack(theMsg->cmd.nack_adv.data,
                                        theMsg->cmd.nack_adv.len);
            // incrementing total CMD NACK ADV msg receive stat count
            commonStats.numCmdNackAdvMsgRecCount++;
            break;

        default:
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr,"mdp: node:%u Client recv'd invalid server "
                           "command from node \"%u\"\n",
                           LocalNodeId(), theServer->Id());
            ERROR_ReportError(errStr);
            //break;
    }
}  // end MdpSession::HandleMdpServerCmd()


void MdpSession::ServerHandleMdpNack(MdpMessage *theMsg, BOOL isUnicast)
{
    //if (isUnicast) printf("mdp: Server received unicast NACK.\n");
    // Is the message for me ??
    if (LocalNodeId() != theMsg->nack.server_id) return;

    //incrementing NACK msg receive stat count
    commonStats.numNackMsgRecCount++;

//#if defined(PROTO_DEBUG)
//    if (theMsg->nack.grtt_response.tv_sec || theMsg->nack.grtt_response.tv_usec)
//    {
//        struct in_addr theClient;
//        theClient.s_addr = theMsg->sender;
//        printf("mdp: node:%lu Server recv'd MDP_NACK with GRTT response from \"%s\"\n",
//              LocalNodeId(), inet_ntoa(theClient));
//    }
//#endif // PROTO_DEBUG

    // Process embedded GRTT_REQ response
    ServerProcessClientResponse(theMsg->sender,
                                &theMsg->nack.grtt_response,
                                theMsg->nack.loss_estimate,
                                theMsg->nack.grtt_req_sequence);

    // Variables to deal with potential need to SQUELCH
    MdpMessage* squelchMsg = NULL;
    unsigned short squelchLen = 0;
    char* squelchPtr = NULL;
    UInt32 pendingLow = 0, pendingRange = 0;


    // For unicast nack suppression: If the "increaseRepairState"
    // gets set to "true" while processing this NACK, the server
    // will advertise its current repair state in the form of
    // a pseudo-nack sent to the group to suppress receivers with
    // equal or less repair needs
    bool increasedRepairState = false;

    // Unpack the concatenated Object/Repair Nacks and process them
    char* optr = theMsg->nack.data;
    char* nack_end = optr + theMsg->nack.nack_len;
    while (optr < nack_end)
    {
        MdpObjectNack onack;
        optr += onack.Unpack(optr);
        UInt32 objectId = onack.object_id;
        MdpObject* theObject = tx_repair_queue.FindFromHead(objectId);
        if (!theObject)
        {
            theObject = tx_hold_queue.FindFromTail(objectId);
            if (theObject)
            {
                // Put object onto session's (active) tx_repair_queue
                ReactivateTxObject(theObject);
            }
            else
            {
                if (MDP_DEBUG)
                {
                    printf("mdp: node:%u Server couldn't find state for repair object: %u "
                           "(squelching it)\n", LocalNodeId(), objectId);
                }
                if (!squelchMsg)
                {
                    squelchMsg = msg_pool.Get();
                    if (squelchMsg)
                    {
                        squelchMsg->type = MDP_CMD;
                        squelchMsg->version = MDP_PROTOCOL_VERSION;
                        squelchMsg->sender = LocalNodeId();
                        squelchMsg->cmd.flavor = MDP_CMD_SQUELCH;
                        squelchMsg->cmd.squelch.data = squelchPtr = server_vector_pool.Get();
                        if (!squelchMsg->cmd.squelch.data)
                        {
                            if (MDP_DEBUG)
                            {
                                printf("mdp: Server error getting vector for SquelchCmd!");
                            }
                            msg_pool.Put(squelchMsg);
                            squelchMsg = NULL;
                            return;
                        }
                        // Init range of objects we're currently servicing
                        MdpObject* theHead = tx_hold_queue.Head();
                        if (theHead)
                        {
                            pendingLow = theHead->TransportId();
                            theHead = tx_repair_queue.Head();
                            if (theHead)
                            {
                                UInt32 tempId = theHead->TransportId();
                                // if tempId < pendingLow
                                UInt32 diff = tempId - pendingLow;
                                if ((diff > MDP_SIGNED_BIT_INTEGER) ||
                                    ((diff == MDP_SIGNED_BIT_INTEGER) && (tempId > pendingLow)))
                                {
                                    pendingLow = tempId;
                                }
                            }
                        }
                        else
                        {
                            theHead = tx_repair_queue.Head();
                            if (theHead)
                                pendingLow = theHead->TransportId();
                            else
                                pendingLow = current_tx_object_id;
                        }  // end if/else(theHead)
                        squelchMsg->cmd.squelch.sync_id = pendingLow;
                        pendingRange = current_tx_object_id - pendingLow;
                    }
                    else
                    {
                        if (MDP_DEBUG)
                        {
                            printf("mdp: node:%u Server msg_pool empty, can't send MDP_SQUELCH!\n",
                                    LocalNodeId());
                        }
                    }
                }
                if (squelchMsg)
                {
                    // Is the object in question in the valid range of objects
                    // we're currently servicing?
                    if ((objectId - pendingLow) <= pendingRange)
                    {
                        // Is there room in our "squelchVector"?
                        if ((unsigned int)segment_size >= (squelchLen + sizeof(UInt32)))
                        {
                            UInt32 tempId = objectId;
                            memcpy(squelchPtr, &tempId, sizeof(UInt32));
                            squelchLen += sizeof(UInt32);
                            squelchPtr += sizeof(UInt32);
                        }
                    }
                }
                continue;
            }
        }  // end if (!theObject)
        char* rptr = onack.data;
        char* onack_end = rptr + onack.nack_len;
        while (rptr < onack_end)
        {
            MdpRepairNack rnack;
            rptr += rnack.Unpack(rptr);
            increasedRepairState |= theObject->ServerHandleRepairNack(&rnack);
        }
        // If nack was obsolete or unable to activate repair cycle for
        // any reason, temporarily deactivate the TxObject (move to tx_hold_queue)
        if (!(theObject->TxPending() || theObject->RepairPending()))
            DeactivateTxObject(theObject);
    }  // end while (optr < nack_end)

    if (squelchMsg)
    {
        squelchMsg->cmd.squelch.len = squelchLen;
        // (TBD) fill in sync point
        QueueMessage(squelchMsg);
    }

    // Here's where we suppress non-multicast NACKs by advertising our
    // current repair state in the form of a NACK
    // Only do this when destination address is multicast
    if (isUnicast && Address()->IsMulticast())// && increasedRepairState)
    {
        MdpMessage* nackAdv = NULL;
        nackAdv = tx_queue.FindNackAdv();
        bool enqueue;
        if (nackAdv)
        {
            enqueue = false;
            if (!increasedRepairState) nackAdv = NULL;
        }
        else
        {
            enqueue = true;
            nackAdv = msg_pool.Get();
            if (nackAdv)
            {
                char* vector = server_vector_pool.Get();
                if (vector)
                {
                    nackAdv->cmd.nack_adv.data = vector;
                }
                else
                {
                    msg_pool.Put(nackAdv);
                    nackAdv = NULL;
                    if (MDP_DEBUG)
                    {
                        printf("mdp: Server Warning! vector_pool empty. Couldn't"
                            "re-advertise unicast NACK ...\n");
                    }
                }
            }
        }
        if (nackAdv)
        {
            nackAdv->type = MDP_CMD;
            nackAdv->version = MDP_PROTOCOL_VERSION;
            nackAdv->sender = LocalNodeId();
            nackAdv->cmd.flavor = MDP_CMD_NACK_ADV;
            nackAdv->cmd.nack_adv.len = (unsigned short)MIN(theMsg->nack.nack_len, segment_size);
            memcpy(nackAdv->cmd.nack_adv.data, theMsg->nack.data, nackAdv->cmd.nack_adv.len);
            if (enqueue) QueueMessage(nackAdv);
            if (MDP_DEBUG)
            {
                printf("mdp: Server Re-advertising unicast NACK ...\n");
            }
        }
        else
        {
            if (MDP_DEBUG)
            {
                if (increasedRepairState)
                    printf("mdp: Server Warning! msg_pool empty. Couldn't "
                            "re-advertise unicast NACK ...\n");
            }
        }
    }
    else
    {
        if (MDP_DEBUG)
        {
            if (isUnicast && Address()->IsMulticast())
                printf("mdp: Server non-increasing NACK adv ...\n");
        }
    }

    // Wake up the server in case immediate reaction is required
    if (tx_queue.IsEmpty()) Serve();
}  // end MdpSession::ServerHandleMdpNack()

void MdpSession::ServerHandleMdpAck(MdpMessage* theMsg)
{
    // Is the message for me?
    if (LocalNodeId() != theMsg->ack.server_id) return;

//#if defined(PROTO_DEBUG)
//    if (theMsg->ack.grtt_response.tv_sec || theMsg->ack.grtt_response.tv_usec)
//    {
//        struct in_addr theClient;
//        theClient.s_addr = theMsg->sender;
//        printf("mdp: node:%lu Server recv'd MDP_ACK with GRTT response\n",
//              LocalNodeId());
//    }
//#endif // PROTO_DEBUG

    // Process embedded GRTT_REQ response
    ServerProcessClientResponse(theMsg->sender,
                                &theMsg->ack.grtt_response,
                                theMsg->ack.loss_estimate,
                                theMsg->ack.grtt_req_sequence);
    switch (theMsg->ack.type)
    {
        case MDP_ACK_GRTT:
            if (MDP_DEBUG_MSG_FLOW)
            {
                 printf("MdpSession::ServerHandleMdpAck: "
                        "Node %d Receiving MDP_ACK_GRTT\n", node->nodeId);
            }
            // it was just a GRTT ack
            // incrementing stat count of the response received for
            // Mdp GRTT Req Command msg sent
            commonStats.numGrttAckMsgRecCount++;
            break;

        case MDP_ACK_OBJECT:
        {
            if (MDP_DEBUG_MSG_FLOW)
            {
                 printf("MdpSession::ServerHandleMdpAck: "
                        "Node %d Receiving MDP_ACK_OBJECT\n", node->nodeId);
            }
            MdpAckingNode* theAcker = (MdpAckingNode*) pos_ack_list.FindNodeById(theMsg->sender);
            if (theAcker)
                theAcker->SetLastAckObject(theMsg->ack.object_id);
            // incrementing stat count of the response received for
            // Mdp Positive Ack Request Command msg sent
            commonStats.numPosAckMsgRecCount++;
        }
        break;

        default:
        {
//#if defined(PROTO_DEBUG)
//            struct in_addr theClient;
//            theClient.s_addr = theMsg->sender;
//            printf("mdp: node:%lu Server recv'd invalid MDP_ACK from \"%s\"\n", LocalNodeId(),
//                  inet_ntoa(theClient));
//#endif
        }
        break;
    }
}  // end MdpSession::ServerHandleMdpAck()

void MdpSession::ClientHandleMdpNack(MdpMessage* theMsg)
{
    // Do we know this server ??
    MdpServerNode* theServer = (MdpServerNode*) server_list.FindNodeById(theMsg->nack.server_id);
    if (theServer)
    {
        theServer->HandleRepairNack(theMsg->nack.data, theMsg->nack.nack_len);
        // incrementing NACK msg receive stat count for known server
        commonStats.numNackMsgRecCount++;
    }
    else
        if (MDP_DEBUG)
        {
            printf("mdp: node:%u Heard NACK destined for unknown server ...\n", LocalNodeId());
        }
}  // end MdpSession::ClientHandleMdpNack()


/* Note  - I need to figure out how to get current object/block info
         - from another client's NACK so we can properly start up
         - repair_timer ... I suggest clients provide their "current_object_id"
         - and "current_block_id" in their NACK content ... Then we can
         - do an "ObjectRepairCheck()" prior to parsing the NACK, the alternative
         - is to parse the NACK twice ... once to get the current obj/block info
         - and a second time to incorporate the NACK content into our
         - "repair_masks" ... Be wary of NACK race condition when GRTT estimate
         - is off!!! ... Think about this !!!

        -> For now, we won't let other client's NACKs trigger a new repair cycle
        -> Only messages from the server will trigger client repair cycles ?!
        -> Client triggering of repair can lead to all sorts of problems ??
*/

void MdpServerNode::HandleRepairNack(char* nackData, unsigned short nackLen)
{
    // Clients only care about NACKs for NACK suppression purposes
    if (repair_timer.IsActive(session->GetNode()->getNodeTime())
        && repair_timer.GetRepeatCount())
    {
        char* optr = nackData;
        char* nack_end = optr + nackLen;
        while (optr < nack_end)
        {
            MdpObjectNack onack;
            optr += onack.Unpack(optr);
            char* rptr = onack.data;
            char* onack_end = rptr + onack.nack_len;
            MdpRepairNack rnack;
            MdpObject* theObject = FindRecvObjectById(onack.object_id);
            while (rptr < onack_end)
            {
                rptr += rnack.Unpack(rptr);
                if (theObject)
                {
                    theObject->ClientHandleRepairNack(&rnack);
                    if (MDP_DEBUG)
                    {
                        printf("mdp: node:%u Client heard MDP_NACK_REPAIR for object:%u\n",
                            session->LocalNodeId(), theObject->TransportId());
                    }
                }
                else
                {
                    if (MDP_RECV_OBJECT_PENDING == ObjectSequenceCheck(onack.object_id))
                    {
                        if (MDP_REPAIR_OBJECT == rnack.type)
                        {
                            if (object_repair_mask.IsSet())
                            {
                                session->SetNackRequired(TRUE);
                            }
                            object_repair_mask.Unset(onack.object_id);
                        }
                    }
                }
            }  // end while (rptr < onack_end)
        }  // end while (optr < nack_end)
    }  // end if (repair_timer.IsActive())
}  // end MdpServerNode::ClientHandleRepairNack()

