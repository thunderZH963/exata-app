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
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "app_util.h"
#include "mac.h"
#include "transport_tcp.h"

#include "os_resource_manager.h"

#define EPSILON 1.0e-5

OSResourceManager::OSResourceManager(Node* node)
{
    this->node = node;
}

void OSResourceManager::init(const NodeInput* nodeInput)
{
    BOOL wasFound;
    char buf[MAX_STRING_LENGTH];

    memoryUsage = 0;
    _peakMemoryUsage = 0;
    _peakMemoryUsage = 0;

    _peakCPUBacklog = 0 * SECOND;
    backlogLastUpdatedAt = 0 * SECOND;
    backloggedLoads = 0;

    numMemoryFailures = 0;
    numCPUFailures = 0;

    isShutdown = FALSE;

    // Memory resource modeling
    memoryCapacity = readDoubleParameter(
            "OS-MEMORY-CAPACITY",
            nodeInput);

    packetMemoryOverhead = readDoubleParameter(
            "OS-MEMORY-PACKET-OVERHEAD",
            nodeInput);

    connectionMemoryUsage = readDoubleParameter(
            "OS-MEMORY-CONNECTION-USAGE",
            nodeInput);

    // CPU resource modeling
    maxCPUBacklog = readTimeParameter(
            "OS-CPU-MAX-BACKLOG",
            nodeInput);

    double eventsPerSec = readDoubleParameter(
            "OS-CPU-PROCESSING-SPEED",
            nodeInput);

    if (eventsPerSec < EPSILON)
    {
        cpuLoadPerEvent = 0;
    }
    else
    {
        cpuLoadPerEvent = (clocktype) (SECOND / eventsPerSec);
    }

    // Failure modeling
    IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "OS-RESOURCE-FAILURE-MODE",
            &wasFound,
            buf);

    failureMode = FAILURE_MODE_RECOVER;

    if (wasFound)
    {
        if (!strcmp(buf, "SHUTDOWN"))
        {
            failureMode = FAILURE_MODE_SHUTDOWN;
        }
        else if (!strcmp(buf, "RECOVER"))
        {
            failureMode = FAILURE_MODE_RECOVER;
        }
        else
        {
            ERROR_ReportError("Supported values for OS-FAILURE-MODE "
                    "are SHUTDOWN and RECOVER.");
        }
    }


    // Define GUI run time stats
    memoryGUIDisplayId = GUI_DefineMetric(
            "Current Memory Usage",
            node->nodeId,
            GUI_APP_LAYER,
            0,
            GUI_DOUBLE_TYPE,
            GUI_AVERAGE_METRIC);

    cpuGUIDisplayId = GUI_DefineMetric(
            "Current CPU Backlog",
            node->nodeId,
            GUI_APP_LAYER,
            0,
            GUI_DOUBLE_TYPE,
            GUI_AVERAGE_METRIC);

}

void OSResourceManager::finalize()
{
    // TODO
    printf("[%d] Peak memory = %f\n",
            node->nodeId, _peakMemoryUsage);
    printf("[%d] Current memory=%f\n",
            node->nodeId, currentMemory());
}


void OSResourceManager::runTimeStats()
{
    if (node->guiOption)
    {
        clocktype now = node->getNodeTime();

        GUI_SendRealData(node->nodeId,
                memoryGUIDisplayId,
                currentMemory(),
                now);

        GUI_SendRealData(node->nodeId,
                cpuGUIDisplayId,
                currentCPU(),
                now);
    }
}

void OSResourceManager::packetAllocated(const Message *msg)
{
    useMemory(MESSAGE_ReturnPacketSize(msg) + packetMemoryOverhead);
}


void OSResourceManager::packetFree(const Message *msg)
{
    freeMemory(MESSAGE_ReturnPacketSize(msg) + packetMemoryOverhead);
}

void OSResourceManager::connectionEstablished()
{
    useMemory(connectionMemoryUsage);
}


void OSResourceManager::connectionTeardown()
{
    freeMemory(connectionMemoryUsage);
}

void OSResourceManager::timerExpired()
{
    if ((maxCPUBacklog == 0) || (cpuLoadPerEvent == 0)) {
        return;
    }
    useCPU(cpuLoadPerEvent);
}

void OSResourceManager::processPacket()
{
    if ((maxCPUBacklog == 0) || (cpuLoadPerEvent == 0)) {
        return;
    }
    useCPU(cpuLoadPerEvent);
}

double OSResourceManager::currentMemory()
{
    return memoryUsage;
}

clocktype OSResourceManager::currentCPU()
{
    if ((maxCPUBacklog == 0) || (cpuLoadPerEvent == 0)) {
        return 0;
    }

    clocktype now = node->getNodeTime();
    clocktype interval = now - backlogLastUpdatedAt;
    double loadsFinished = interval * 1.0 / cpuLoadPerEvent;

    if (loadsFinished > backloggedLoads) {
        loadsFinished = backloggedLoads;
    }

    backloggedLoads -= loadsFinished;

    backlogLastUpdatedAt = now;

    return (clocktype) backloggedLoads * cpuLoadPerEvent;
}


void OSResourceManager::useMemory(double amount)
{
    if (memoryCapacity < EPSILON) {
        // memory resource not enabled
        return;
    }

    memoryUsage += amount;
    if (memoryUsage > _peakMemoryUsage)
    {
        _peakMemoryUsage = memoryUsage;
    }

    if (memoryUsage >= memoryCapacity)
    {
        if (failureMode == FAILURE_MODE_SHUTDOWN)
        {
            shutdown();
            memoryUsage = 0;
        }
        else
        {
            recoverMemoryFailure();
        }
    }
}

void OSResourceManager::freeMemory(double amount)
{
    if (memoryCapacity < EPSILON) {
        // memory resource not enabled
        return;
    }

    memoryUsage -= amount;

    if (memoryUsage < 0) {
        memoryUsage = 0;
    }
}

void OSResourceManager::useCPU(clocktype amount)
{
    if (isShutdown)
    {
        return;
    }
    else
    {
        backloggedLoads ++;
        clocktype currentCPULoad = currentCPU();
        if (currentCPULoad >= maxCPUBacklog)
        {
            if (failureMode == FAILURE_MODE_SHUTDOWN)
            {
                shutdown();
            }
            else
            {
                recoverCPUFailure();
            }
        }
    }
}


void OSResourceManager::shutdown()
{
    // Shut down all interfaces on this node
    for (int interfaceIndex = 0; interfaceIndex < node->numberInterfaces; interfaceIndex++)
    {
        if (!MAC_InterfaceIsEnabled(node, interfaceIndex))
        {
            continue;
        }
        Message* msg = MESSAGE_Alloc(node, MAC_LAYER, 0, MSG_MAC_StartFault);
        MESSAGE_SetInstanceId(msg, interfaceIndex);

        MESSAGE_InfoAlloc(node, msg, sizeof(MacFaultInfo));
        MacFaultInfo* fault = (MacFaultInfo *) MESSAGE_ReturnInfo(msg);
        fault->faultType = STATIC_FAULT;
        fault->interfaceCardFailed = TRUE;

        MESSAGE_Send(node, msg, 0);
        isShutdown = TRUE;
    }

}

void OSResourceManager::recoverMemoryFailure()
{
    // Drop all packets in the network_ip queue
    Message* msg;
    int networkType;
    TosType priority;
    MacHWAddress hwAddr;

    for (int interface = 0; interface < node->numberInterfaces; interface++)
    {
        while (true)
        {
            MAC_OutputQueueDequeuePacket(
                    node,
                    interface,
                    &msg,
                    &hwAddr,
                    &networkType,
                    &priority);

            if (msg == NULL) {
                break;
            }
            MESSAGE_Free(node, msg);
        }
    }


    // Drop all fragments in network_ip
    // Drop all TCP connections
    TransportDataTcp* tcpLayer = (TransportDataTcp*)
                                        node->transportData.tcp;

    struct inpcb *ptr = &tcpLayer->head;

    ptr = ptr->inp_next;

    while (ptr != ptr->inp_head)
    {
        if ((ptr->inp_remote_port <= 0) || (ptr->inp_local_port <= 0)) {
            ptr = ptr->inp_next;
            continue;
        }
/*
        printf("connectionid = %d  %x:%d -> %x:%d\n",
                ptr->con_id,
                ptr->inp_local_addr.interfaceAddr.ipv4,
                ptr->inp_local_port,
                ptr->inp_remote_addr.interfaceAddr.ipv4,
                ptr->inp_remote_port);
 */
       APP_TcpCloseConnection(node, ptr->con_id);
        ptr = ptr->inp_next;
    }

    memoryUsage = 0;

}

void OSResourceManager::recoverCPUFailure()
{
    backloggedLoads = 0;
    // Shutdown interfaces for CPU Backlog threshold duration
    for (int interfaceIndex = 0; interfaceIndex < node->numberInterfaces; interfaceIndex++)
    {
        // Start Fault
        Message* startFaultMsg = MESSAGE_Alloc(node, MAC_LAYER, 0, MSG_MAC_StartFault);
        MESSAGE_SetInstanceId(startFaultMsg, interfaceIndex);

        MESSAGE_InfoAlloc(node, startFaultMsg, sizeof(MacFaultInfo));
        MacFaultInfo* fault = (MacFaultInfo *) MESSAGE_ReturnInfo(startFaultMsg);
        fault->faultType = STATIC_FAULT;
        fault->interfaceCardFailed = TRUE;

        MESSAGE_Send(node, startFaultMsg, 0);

        // End fault
        Message* endFaultMsg = MESSAGE_Alloc(node, MAC_LAYER, 0, MSG_MAC_EndFault);
        MESSAGE_SetInstanceId(endFaultMsg, interfaceIndex);

        MESSAGE_InfoAlloc(node, endFaultMsg, sizeof(MacFaultInfo));
        fault = (MacFaultInfo *) MESSAGE_ReturnInfo(endFaultMsg);
        fault->faultType = STATIC_FAULT;
        fault->interfaceCardFailed = TRUE;

        clocktype duration = maxCPUBacklog;
        MESSAGE_Send(node, endFaultMsg, duration);
    }
}

double OSResourceManager::readDoubleParameter(
        const char* parameterName,
        const NodeInput* nodeInput)
{
    BOOL wasFound;
    double value;

    IO_ReadDouble(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            parameterName,
            &wasFound,
            &value);

    if (!wasFound) {
        value = 0;
    }

    if (value < 0)
    {
        char errorString[MAX_STRING_LENGTH];
        sprintf(errorString, "Value of %s should not be negative.",
                parameterName);
        ERROR_ReportError(errorString);
    }

    return value;
}

clocktype OSResourceManager::readTimeParameter(
        const char* parameterName,
        const NodeInput* nodeInput)
{
    BOOL wasFound;
    clocktype value;

    IO_ReadTime(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            parameterName,
            &wasFound,
            &value);

    if (!wasFound) {
        value = 0 * SECOND;
    }

    if (value < 0)
    {
        char errorString[MAX_STRING_LENGTH];
        sprintf(errorString, "Value of %s should not be negative.",
                parameterName);
        ERROR_ReportError(errorString);
    }

    return value;
}
