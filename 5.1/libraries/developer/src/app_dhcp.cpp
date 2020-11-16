// Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.
//                          600 Corporate Pointe
//                          Suite 1200
//                          Culver City, CA 90230
//                          info@scalable-networks.com
//
// This source code is licensed, not sold, and is subject to a written
// license agreement.  Among other things, no portion of this source
// code may be copied, transmitted, disclosed, displayed, distributed,
// translated, used as the basis for  a derivative work, or used, in
// whole or in part, for  any program or purpose other than its intended
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for  any other
// software, hardware, product or service.


// /**
// PROTOCOL :: Dynamic Host Configuration Protocol
// LAYER :: Application Layer
// REFERENCES :: [RFC 2131] “Dynamic Host Configuration Protocol,”
//               RFC 2131, Mar 1997.
//               http://www.ietf.org/rfc/rfc2131.txt
//               [RFC 2132] “DHCP Options and BOOTP Vendor Extensions,
//               RFC 2132, Mar 1997.
//               http://www.ietf.org/rfc/rfc2132.txt
// COMMENTS :: DHCPRELEASE can be triggered from client externally.
//             Assumptions:
//             1.BOOT file name parameter to be left null as the
//               BOOTP protocol is not implemented in QualNet.
//             2 The key for  storage of IP address and configuration
//               parameters at server side will be subnet number and hardware
//               address unless the client explicitly supplies an identifier
//               using the ‘client identifier’ option.
//             3.DHCP messages shall always be broadcasted before
//               an IP address is configured.
// **/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "api.h"
#include "mapping.h"
#include "partition.h"
#include "app_util.h"
#include "app_dhcp.h"
#include "network_ip.h"
#include "mac_arp.h"
#include "mac.h"

#define IPV4    interfaceAddr.ipv4


//--------------------DHCP static functions implementataion starts---------

//--------------------------------------------------------------------------
// NAME             : dhcpGetOption
// PURPOSE          : This function gets the sepcified parameter from
//                    option field of DHCP packet
// PARAMETERS       :
// + options        : unsigned char* : option field of DHCP packet
// + optcode        : UInt8          : code of parameter that is to be
//                                     reterieved from option
// + optlen         : UInt8          : length of parameter to be reterieved
// + optvalPtr      : UInt8          : pointer to store the value of
//                                     required parameter
// RETURN           :
// unsigned char*   : pointer to options
//                    NULL if desired option not found
//--------------------------------------------------------------------------

static
unsigned char* dhcpGetOption(
    unsigned char* options,
    UInt8 optcode,
    UInt8 optlen,
    void* optvalptr)
{
    UInt8 i;

    // parse for  desired option
    for (;;)
    {
        // skip pad characters
        if (*options == DHO_PAD)
        {
            options++;
        }

        // break if end reached
        else if (*options == DHO_END)
        {
            break;
        }

        // check for  desired option
        else if (*options == optcode)
        {
            // found desired option
            // limit size to actual option length

            optlen = MIN(optlen, *(options + 1));

            // copy contents of option
            for (i = 0; i < optlen; i++)
            {
                *(((UInt8*)optvalptr) + i) = *(options + i + 2);
            }

            // return length of option
            return (options + 1);
        }
        else
        {
            // skip to next option
             options++;
             options += *options;
             options++;
        }
    }

    // failed to find desired option
    return NULL;
}
//--------------------------------------------------------------------------
// NAME         : dhcpGetOptionLength
// PURPOSE      : This function gets the length of specified parameter
//                in option field of DHCP packet
// PARAMETERS   :
// + options    : unsigned char* :  option field of DHCP packet
// + optcode    : UInt8          : code of parameter
// RETURN       :
// UInt8        : size of option if found
//                NULL if not found
//--------------------------------------------------------------------------
static
UInt8 dhcpGetOptionLength(
    unsigned char* options,
    UInt8 optcode)
{
    // parse for desired option
    for (;;)
    {
        // skip pad characters
        if (*options == DHO_PAD)
        {
            options++;
        }
        // break if end reached
        else if (*options == DHO_END)
        {
            break;
        }
        // check for  desired option
        else if (*options == optcode)
        {
            return (*(options + 1));
        }
        else
        {
            // skip to next option
            options++;
            options += *options;
            options++;
        }
    }

    // failed to find desired option
    return 0;
}
//--------------------------------------------------------------------------
// NAME             : dhcpSetOption
// PURPOSE          : This function sets the sepcified parameter in
//                    option field of DHCP packet
// PARAMETERS       :
// + options        : unsigned char* : option field of DHCP packet
// + optcode        : UInt8          : code of parameter that is to be set
//                                     in option
// +optlen          : UInt8          : length of parameter to be reterieved
// +optvalPtr       : void*          : value of options that is to be set
// RETURN           :
// unsigned char*   : pointer to options if found NULL if not found
//--------------------------------------------------------------------------
static
unsigned char* dhcpSetOption(
    unsigned char* options,
    UInt8 optcode,
    UInt8 optlen,
    void* optvalptr)
{
    if (strlen((const char*)options) != 0)
    {
        while ((*options) != DHO_END)
        {
            options++;
            // get the option length and advance options by length
            options = options + (*options);
            options++;
        }
    }

    // use current options address as write point
    memcpy(options, &optcode, sizeof(UInt8));
    options++;
    memcpy(options, &optlen, sizeof(UInt8));
    options++;
    memcpy(options, optvalptr, optlen);
    while (optlen--)
    {
        options++;
    }

    // write end marker
    *options = DHO_END;
    return options;
}
//--------------------------------------------------------------------------
// NAME              :AppDhcpCheckIfSameClientId
// PURPOSE           : This function checks if client id is same or not
// PARAMETERS        :
// + lease           : struct dhcpLease* : lease which needs to be compared,
// + clientIdentifier: char*             :clientIdentifier
// + data            : struct dhcpData   : dhcp data packet
// RETURN:
// bool              : TRUE  : if client id matched
//                     FALSE : if client id are different
//--------------------------------------------------------------------------
static bool
AppDhcpCheckIfSameClientId(struct dhcpLease* lease,
                           char* clientIdentifier,
                           struct dhcpData data)
{
    if (strlen(clientIdentifier) > 0 &&
        strcmp(clientIdentifier, lease->clientIdentifier) == 0)
    {
        return TRUE;
    }
    else if (lease->macAddress.byte &&
             memcmp(lease->macAddress.byte, data.chaddr, data.hlen) == 0)
    {
        if (data.ciaddr == 0)
        {
            return TRUE;
        }
        else if (data.ciaddr != 0 && (data.ciaddr & lease->subnetMask.IPV4)
                        == lease->subnetNumber.IPV4)
        {
            return TRUE;
        }
    }

    return FALSE;
}
//---------------------------------------------------------------------------
// NAME         : AppDhcpCheckIfIpInManualAllocationList
// PURPOSE      : This function checks if any ip is present in manual
//                allocation list of server
// PARAMETERS:
// + serverPtr  : struct appDataDhcpServer* : pointer to dhcp server
// + ipAddress  : Address                   : ipaddress to check
// RETURN       :
// bool         :TRUE  : if ip present
//               FALSE : if ip not present
//---------------------------------------------------------------------------
static bool
AppDhcpCheckIfIpInManualAllocationList(
                    struct appDataDhcpServer* serverPtr,
                    Address ipAddress)
{
    if (!serverPtr->manualAllocationList->empty())
    {
        std::list<struct appDhcpServerManualAlloc*>::iterator it;
        for (it = serverPtr->manualAllocationList->begin();
             it != serverPtr->manualAllocationList->end();
             it++)
        {
            if (MAPPING_CompareAddress(
                                    (*it)->ipAddress,
                                     ipAddress) == 0)
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}
//--------------------------------------------------------------------------
// NAME                : AppDhcpServerCheckClientForManualLease
// PURPOSE             : This function checks for  manual lease allocation
//                       for  client at server side
// PARAMETERS          :
// + node              : Node*                     : pointer to the node.
// + serverPtr         : struct appDataDhcpServer* : pointer to DHCP server
// + originatingNodeId : NodeId                    : node id of dhcp client
// + incomingInterface : Int32                     : incoming interface index
//                                                   of server
// + data              : struct dhcpData           : DHCP Discover packet
// RETURN              :
// struct dhcpLease*   : lease if valid for  manual allocation else NULL.
//--------------------------------------------------------------------------
static
struct dhcpLease* AppDhcpServerCheckClientForManualLease(
    Node* node,
    struct appDataDhcpServer* serverPtr,
    NodeId originatingNodeId,
    Int32 incomingInterface,
    struct dhcpData data)
{
    UInt32 requestedIp = 0;
    char clientIdentifier[MAX_STRING_LENGTH] = "";
    UInt8 clientIdLength = 0;
    struct dhcpLease* lease = NULL;
    struct appDhcpServerManualAlloc* manualAlloc = NULL;

    // Parse the option field of DISCOVER packet
    // to get Requested IP and client identifier

    dhcpGetOption(
            data.options,
            DHO_DHCP_REQUESTED_ADDRESS,
            DHCP_ADDRESS_OPTION_LENGTH,
            &requestedIp);

    // Get the client identifier
    clientIdLength = dhcpGetOptionLength(
                            data.options,
                            DHO_DHCP_CLIENT_IDENTIFIER);
    if (clientIdLength != 0)
    {
        dhcpGetOption(data.options,
                      DHO_DHCP_CLIENT_IDENTIFIER,
                      clientIdLength,
                      clientIdentifier);
        clientIdentifier[clientIdLength] = '\0';
    }

    // Check if Manual  allocation is configured at server
    // If configured then check if the client is to
    // be offered lease manually

    if (!serverPtr->manualAllocationList->empty())
    {
        std::list<struct appDhcpServerManualAlloc*>::iterator it;
        for (it = serverPtr->manualAllocationList->begin();
             it != serverPtr->manualAllocationList->end();
             it++)
        {
            manualAlloc = *it;
            if ((*it)->nodeId == originatingNodeId &&
                (*it)->incomingInterface == incomingInterface)
            {
                // The client is matching any lease of manual allocation
                // Find if any old lease present for  this client in
                // the linked list. If present and the status is available
                // then allocate that lease

                if (DHCP_DEBUG)
                {
                    printf(
                       "The client %d at interface %d is to be  manually"
                       "allocated at server present at node %d"
                       "interface %d \n",
                       originatingNodeId,
                       incomingInterface,
                       node->nodeId,
                       incomingInterface);
                }
                list<struct dhcpLease*>::iterator leaseIterator;
                for (leaseIterator = serverPtr->serverLeaseList->begin();
                     leaseIterator != serverPtr->serverLeaseList->end();
                     leaseIterator++)
                {
                    if (AppDhcpCheckIfSameClientId(
                            (struct dhcpLease*)(*leaseIterator),
                            clientIdentifier,
                            data))
                    {
                        lease = (*leaseIterator);
                    }
                }

                if (!lease)
                {
                    // If no lease present for this client in list of leases
                    // Create a new lease with ip from manual file
                    // allocate memory for  lease

                    lease =
                        (struct dhcpLease*)MEM_malloc(sizeof(dhcpLease));
                    memset(lease, 0, sizeof(struct dhcpLease));
                    lease->clientIdentifier[0] = '\0';
                    (lease->ipAddress).networkType =
                                    manualAlloc->ipAddress.networkType;
                    (lease->ipAddress).IPV4 =
                                manualAlloc->ipAddress.IPV4;
                    memcpy(
                        &lease->serverId,
                        &serverPtr->interfaceAddress,
                        sizeof(Address));
                    lease->macAddress.hwLength = data.hlen;
                    lease->macAddress.hwType = data.htype;
                    lease->macAddress.byte =
                        (unsigned char*)MEM_malloc(data.hlen);
                    memcpy(
                        lease->macAddress.byte,
                        data.chaddr,
                        data.hlen);
                    (lease->defaultGateway).networkType =
                                    (serverPtr->defaultGateway).networkType;
                    (lease->defaultGateway).IPV4 =
                            (serverPtr->defaultGateway).IPV4;
                    (lease->subnetMask).networkType =
                                    (serverPtr->subnetMask).networkType;
                    (lease->subnetMask).IPV4 =
                                (serverPtr->subnetMask).IPV4;
                    (lease->subnetNumber).networkType =
                                (lease->ipAddress).networkType;
                    (lease->subnetNumber).IPV4 =
                                (lease->ipAddress).IPV4 &
                                (lease->subnetMask).IPV4;
                    (lease->primaryDNSServer).networkType =
                                (serverPtr->primaryDNSServer).networkType;
                    (lease->primaryDNSServer).IPV4 =
                            (serverPtr->primaryDNSServer).IPV4;
                    if (lease->listOfSecDNSServer == NULL)
                    {
                        lease->listOfSecDNSServer = new std::list<Address*>;
                    }
                    AppDhcpCopySecondaryDnsServerList(
                                        serverPtr->listSecDnsServer,
                                        lease->listOfSecDNSServer);
                    lease->status = DHCP_OFFERED;

                    // Insert the newly created lease to list
                    serverPtr->serverLeaseList->push_back(lease);
                    return(lease);
                }
                else if (lease && lease->status == DHCP_AVAILABLE)
                {
                    // Lease is already present and the status is AVAILABLE
                    // Allocate the lease.If status is not AVAILABLE then
                    // the client cannot be offered any lease as the client
                    // needs to be manually allocated and the lease to be
                    // allocated is not free

                    lease->status = DHCP_OFFERED;
                    lease->macAddress.hwLength = data.hlen;
                    lease->macAddress.hwType = data.htype;
                    if (lease->macAddress.byte)
                    {
                        MEM_free(lease->macAddress.byte);
                    }
                    lease->macAddress.byte =
                        (unsigned char*)MEM_malloc(data.hlen);
                    memcpy(lease->macAddress.byte,
                        data.chaddr,
                        data.hlen);
                    return(lease);
                }
                else if (lease && lease->status != DHCP_AVAILABLE)
                {
                    if (DHCP_DEBUG)
                    {
                        printf(
                          "The client %d at interface %d is to be  manually"
                          "allocated but the lease is currently not"
                          "AVAILABLE at server present at node %d"
                          "interface %d \n",
                          originatingNodeId,
                          incomingInterface,
                          node->nodeId,
                          incomingInterface);
                    }
                }
            }
        }
    }
    // No manual allocation present at server or the lease
    // the client is to be manually allocated but the lease is not
    // avaialable

    return(NULL);
}
//--------------------------------------------------------------------------
// NAME                 : AppDhcpServerCreateNewLease
// PURPOSE              : Creates new lease and adds it to lease list
//                        present at DHCP server
// PARAMETERS           :
// + node               : Node*                     : pointer to the node.
// + serverPtr          : struct appDataDhcpServer* : pointer to DHCP server
// + data               : struct dhcpData           : DHCP packet
// RETURN:
// struct dhcpLease*    : lease if new created else NULL.
//--------------------------------------------------------------------------
static
struct dhcpLease* AppDhcpServerCreateNewLease(
    Node* node,
    struct appDataDhcpServer* serverPtr,
    struct dhcpData data)
{
    Address ipAddressToAllocate;
    struct dhcpLease* lease = NULL;

    // Allocate the first lease to the first IP address in range

    memcpy(&ipAddressToAllocate,
           &serverPtr->addressRangeStart,
           sizeof(Address));

    // check if ip-address to allocate is in manual allocation; if it is
    // then increment untill it is not
    bool isManual = TRUE;
    while (isManual)
    {
        if (AppDhcpCheckIfIpInManualAllocationList(
                                                serverPtr,
                                                ipAddressToAllocate))
        {
            ipAddressToAllocate.IPV4++;
        }
        else
        {
            isManual = FALSE;
        }
    }

    list<struct dhcpLease*>::iterator it;
    for (it = serverPtr->serverLeaseList->begin();
         it != serverPtr->serverLeaseList->end();
         it++)
    {
        if ((*it)->ipAddress.IPV4 == ipAddressToAllocate.IPV4)
        {
            ipAddressToAllocate.IPV4 = (*it)->ipAddress.IPV4;
            ipAddressToAllocate.IPV4++;
        }
    }
    // we now have address that is highest uptill now and can be allocated
    // check if ip-address to allocate is in manual allocation; if it is
    // then increment untill it is not
    isManual = TRUE;
    while (isManual)
    {
        if (AppDhcpCheckIfIpInManualAllocationList(
                                                serverPtr,
                                                ipAddressToAllocate))
        {
            ipAddressToAllocate.IPV4++;
        }
        else
        {
            isManual = FALSE;
        }
    }
    // check if this address is in range configured
    if ((ipAddressToAllocate.IPV4 <= serverPtr->addressRangeEnd.IPV4) &&
        (ipAddressToAllocate.IPV4 >= serverPtr->addressRangeStart.IPV4))
    {
        lease = (struct dhcpLease*)MEM_malloc(sizeof(dhcpLease));
        memset(lease, 0, sizeof(struct dhcpLease));
        (lease->ipAddress).networkType =
            ipAddressToAllocate.networkType;
        (lease->ipAddress).IPV4 = (ipAddressToAllocate).IPV4;
        memcpy(
            &lease->serverId,
            &serverPtr->interfaceAddress,
            sizeof(Address));
        lease->macAddress.hwLength = data.hlen;
        lease->macAddress.hwType = data.htype;
        lease->macAddress.byte = (unsigned char*)MEM_malloc(data.hlen);
        memcpy(lease->macAddress.byte, data.chaddr, data.hlen);
        (lease->defaultGateway).networkType =
            (serverPtr->defaultGateway).networkType;
        (lease->defaultGateway).IPV4 =(serverPtr->defaultGateway).IPV4;
        (lease->subnetMask).networkType =
            (serverPtr->subnetMask).networkType;
        (lease->subnetMask).IPV4 = (serverPtr->subnetMask).IPV4;
        (lease->subnetNumber).networkType =
                                (lease->ipAddress).networkType;
        (lease->subnetNumber).IPV4 =
                                (lease->ipAddress).IPV4 &
                                (lease->subnetMask).IPV4;
        (lease->primaryDNSServer).networkType =
            (serverPtr->primaryDNSServer).networkType;
        (lease->primaryDNSServer).IPV4 = (serverPtr->primaryDNSServer).IPV4;
        if (lease->listOfSecDNSServer == NULL)
        {
             lease->listOfSecDNSServer = new std::list<Address*>;
        }
        AppDhcpCopySecondaryDnsServerList(
                                        serverPtr->listSecDnsServer,
                                        lease->listOfSecDNSServer);
        lease->status = DHCP_OFFERED;
        serverPtr->serverLeaseList->push_back(lease);
        return(lease);
    }
    else
    {
        if (DHCP_DEBUG)
        {
            printf("No lease avaialable at server for  server at"
                   " node %d \n",
                   node->nodeId);
        }
        return(NULL);
    }
}
//--------------------------------------------------------------------------
// NAME      : AppDhcpClientHandleTimeout
// PURPOSE   : Handles timeout of any packet at client
// PARAMETERS:
// + node    : Node*    : pointer to the node.
// + msg     : Message* : Timeout message
// RETURN:
// bool      : TRUE     : message to be fred
//             FALSE    : message not to be fred
//--------------------------------------------------------------------------
static
bool AppDhcpClientHandleTimeout(
    Node* node,
    Message* msg)
{
    struct appDataDhcpClient* clientPtr = NULL;

    // Get the interface index
    Int32* interfaceIndex = (Int32*)MESSAGE_ReturnInfo(msg);

    // Get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(node, *interfaceIndex);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d at interface %d Not a DHCP client \n",
                   node->nodeId,
                   *interfaceIndex);
        }
        return(TRUE);
    }
    switch (clientPtr->state)
    {
        case DHCP_CLIENT_SELECT:
        {
            if (DHCP_DEBUG)
            {
                printf("DISCOVERY timeout for client node"
                       "%d at interface %d \n",
                       node->nodeId,
                       *interfaceIndex);
                clocktype simulationTime = node->getNodeTime();
                char simulationTimeStr[MAX_STRING_LENGTH] = "";
                TIME_PrintClockInSecond(simulationTime,
                                        simulationTimeStr);
                printf("Time = %s \n", simulationTimeStr);
            }
            break;
        }
        case DHCP_CLIENT_REQUEST:
        {
            if (DHCP_DEBUG)
            {
                printf("REQUEST timeout for  client node"
                       "%d at interface %d \n",
                       node->nodeId,
                       *interfaceIndex);
                clocktype simulationTime = node->getNodeTime();
                char simulationTimeStr[MAX_STRING_LENGTH] = "";
                TIME_PrintClockInSecond(simulationTime,
                                        simulationTimeStr);
                printf("Time = %s \n", simulationTimeStr);
            }
            break;
        }
        case DHCP_CLIENT_INFORM:
        {
            if (DHCP_DEBUG)
            {
                printf("INFORM timeout for  client node"
                       "%d at interface %d \n",
                       node->nodeId,
                       *interfaceIndex);
                clocktype simulationTime = node->getNodeTime();
                char simulationTimeStr[MAX_STRING_LENGTH] = "";
                TIME_PrintClockInSecond(simulationTime,
                                        simulationTimeStr);
                printf("Time = %s \n", simulationTimeStr);
            }
            break;
        }
        case DHCP_CLIENT_RENEW:
        {
            if (DHCP_DEBUG)
            {
                printf("RENEW timeout for  node %d"
                       "at interface %d \n",
                       node->nodeId,
                       *interfaceIndex);
                clocktype simulationTime = node->getNodeTime();
                char simulationTimeStr[MAX_STRING_LENGTH] = "";
                TIME_PrintClockInSecond(simulationTime,
                                        simulationTimeStr);
                printf("Time = %s \n", simulationTimeStr);
            }
            // Make new renewal message and update the same in lease
            // Get Lease which enters into renew state

            Int32 leaseStatus = DHCP_RENEW;

            // Check the lease
            struct dhcpLease* clientLease = NULL;
            list<struct dhcpLease*>::iterator it;
            for (it = clientPtr->clientLeaseList->begin();
                 it != clientPtr->clientLeaseList->end();
                 it++)
            {
                if ((*it)->status == leaseStatus)
                {
                    clientLease = *it;
                    break;
                }
            }

            if (clientLease->renewTimeout == 0)
            {
                // change the event of message and schedule
                // renew again

                msg->eventType = MSG_APP_DHCP_CLIENT_RENEW;
                clientLease->renewTimeout++;
                clientLease->renewMsg = msg;
                clientLease->status = DHCP_ACTIVE;
                MESSAGE_Send(node, msg, 0);

                // message should not be fred
                return(FALSE);
            }
            else
            {
                // message should be fred
                // Cancel the timeout msg
                if (clientPtr->timeoutMssg != NULL)
                {
                    MESSAGE_CancelSelfMsg(
                        node,
                        clientPtr->timeoutMssg);
                    clientPtr->timeoutMssg = NULL;
                }
                return(TRUE);
            }
            break;
        }
        case DHCP_CLIENT_REBIND:
        {
            if (DHCP_DEBUG)
            {
                printf("REBIND timeout for  node %d"
                       "at interface %d \n",
                       node->nodeId,
                       *interfaceIndex);
                clocktype simulationTime = node->getNodeTime();
                char simulationTimeStr[MAX_STRING_LENGTH] = "";
                TIME_PrintClockInSecond(simulationTime,
                                        simulationTimeStr);
                printf("Time = %s \n", simulationTimeStr);
            }
            // Make new rebind message and update the same in lease
            // Get Lease which enters into rebind state

            Int32 leaseStatus = DHCP_REBIND;

            // Check the lease
            struct dhcpLease* clientLease = NULL;
            list<struct dhcpLease*>::iterator it;
            for (it = clientPtr->clientLeaseList->begin();
                 it != clientPtr->clientLeaseList->end();
                 it++)
            {
                if ((*it)->status == leaseStatus)
                {
                    clientLease = *it;
                    break;
                }
            }
            if (clientLease->rebindTimeout == 0)
            {
                // change the event of message and schedule REBIND again
                msg->eventType = MSG_APP_DHCP_CLIENT_REBIND;
                clientLease->rebindMsg = msg;
                clientLease->status = DHCP_RENEW;
                clientLease->rebindTimeout++;
                MESSAGE_Send(node, msg, 0);

                 // message should not be fred
                 return(FALSE);
            }
            else
            {
                // message should be fred
                // Cancel the timeout msg
                if (clientPtr->timeoutMssg != NULL)
                {
                    MESSAGE_CancelSelfMsg(
                        node,
                        clientPtr->timeoutMssg);
                    clientPtr->timeoutMssg = NULL;
                }
                return(TRUE);
            }
            break;
        }
        default:
        {
            return(TRUE);
            break;
        }
    }

    // Timeout other than RENEW and REBIND
    // Incerase the timeout by exponential backoff

    clientPtr->retryCounter =
        clientPtr->retryCounter * DHCP_RETRY_COUNTER_EXP_INC;
    clocktype timerDelay = (clocktype) ((clientPtr->timeout
                      * (clientPtr->retryCounter))
                      + RANDOM_erand(clientPtr->jitterSeed));

    // The maximum timeout delay can be 60 seconds
    clocktype maxDelay = DHCP_MAX_RETRANS_TIMER;
    if (timerDelay <= maxDelay)
    {
        // change the xid
        clientPtr->recentXid = RANDOM_nrand(clientPtr->jitterSeed);
        (clientPtr->dataPacket)->xid = clientPtr->recentXid;
        if (clientPtr->reacquireTime != 0)
        {
            clientPtr->reacquireTime = node->getNodeTime();
        }

        // send the data packet again
        AppDhcpSendDhcpPacket(
                        node,
                        *interfaceIndex,
                        DHCP_CLIENT_PORT,
                        ANY_ADDRESS,
                        DHCP_SERVER_PORT,
                        clientPtr->tos,
                        clientPtr->dataPacket);

        // Increment the packet sent
        switch (clientPtr->state)
        {
            case DHCP_CLIENT_SELECT:
            {
                clientPtr->numDiscoverSent++;
                break;
            }
            case DHCP_CLIENT_REQUEST:
            {
                clientPtr->numRequestSent++;
                break;
            }
            case DHCP_CLIENT_INFORM:
            {
                clientPtr->numInformSent++;
                break;
            }
            default:
            {
                break;
            }
        }
        // initiate retrasmission
        Message* message = MESSAGE_Alloc(
                                    node,
                                    APP_LAYER,
                                    APP_DHCP_CLIENT,
                                    MSG_APP_DHCP_TIMEOUT);
        MESSAGE_InfoAlloc(node,
                          message,
                          sizeof(Int32));
        Int32* info = (Int32*)MESSAGE_ReturnInfo(message);
        *(info) = *interfaceIndex;
        clientPtr->timeoutMssg = message;
        if (DHCP_DEBUG)
        {
            printf("Sending the packet again from node %d interface %d \n",
                   node->nodeId,
                   *interfaceIndex);
            char simulationTimeStr[MAX_STRING_LENGTH] = "";
            TIME_PrintClockInSecond(timerDelay, simulationTimeStr);
            printf("Timout delay = %s \n", simulationTimeStr);
        }
        MESSAGE_Send(node, message, timerDelay);

        // Message should be freed
        return(TRUE);
    }
    else
    {
        // If timeout delay is greater than max delay of 60 seconds
        if (clientPtr->state == DHCP_CLIENT_INFORM)
        {
            return(TRUE);

            // If a client receives no reply to its DHCPINFORM message
            // it will retransmit it periodically. After a retry period
            // it will give up and use default configuration values.
            // It will also typically generate an error report to
            // inform an administrator or user of the problem.
        }
        else
        {
            if (DHCP_DEBUG)
            {
                printf("Maximum retry limit reached hence moving the"
                       " client at node %d interface %d to INIT state \n",
                       node->nodeId,
                       *interfaceIndex);
            }

            // move to INIT state
            clientPtr->retryCounter = 1;
            clientPtr->timeoutMssg = NULL;
            clientPtr->recentXid = 0;
            clientPtr->state = DHCP_CLIENT_INIT;
            clientPtr->reacquireTime = 0;

            // free the data packet
            if (clientPtr->dataPacket != NULL)
            {
                MEM_free(clientPtr->dataPacket);
                clientPtr->dataPacket = NULL;
            }
            clientPtr->timeoutMssg = NULL;
            AppDhcpClientStateInit(node, *interfaceIndex);
            return(TRUE);
        }
    }
}
//--------------------------------------------------------------------------
// NAME      : AppDhcpClientReceivedAck
// PURPOSE   : Handles the behaviour of client when ACK packet received
// PARAMETERS:
// + node    : Node*    : pointer to the node.
// + msg     : Message* : Packet
// RETURN    : NONE
//--------------------------------------------------------------------------
static
void AppDhcpClientReceivedAck (
    Node* node,
    Message* msg)
{
    struct appDataDhcpClient* clientPtr = NULL;
    UdpToAppRecv* info = NULL;
    Int32 incomingInterface = 0;
    struct dhcpData data;

    // Get the incoming inetrface index
    info = (UdpToAppRecv*)MESSAGE_ReturnInfo(msg);
    incomingInterface = info->incomingInterfaceIndex;

    // Get the data packet
    memcpy(&data, MESSAGE_ReturnPacket(msg), sizeof(struct dhcpData));
    clientPtr = AppDhcpClientGetDhcpClient(node, incomingInterface);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d at interface %d "
                   "Not a DHCP client \n",
                   node->nodeId,
                   incomingInterface);
        }
        MESSAGE_Free(node, msg);
        return;
    }
    if ((clientPtr->recentXid == data.xid) &&
        ((clientPtr->state == DHCP_CLIENT_REQUEST)||
          (clientPtr->state == DHCP_CLIENT_RENEW)||
          (clientPtr->state == DHCP_CLIENT_REBIND)||
          (clientPtr->state == DHCP_CLIENT_INFORM)||
          (clientPtr->state == DHCP_CLIENT_INIT_REBOOT)))
    {
        clientPtr->numAckRecv++;

        // Cancel the timeout message schduled
        if (clientPtr->timeoutMssg)
        {
            MESSAGE_CancelSelfMsg(
                node,
                clientPtr->timeoutMssg);
            clientPtr->timeoutMssg = NULL;
        }
        if (clientPtr->state == DHCP_CLIENT_RENEW ||
            clientPtr->state == DHCP_CLIENT_REBIND)
        {
            // get the lease
            struct dhcpLease* clientLease = NULL;
            Int32 leaseStatus;
            switch (clientPtr->state)
            {
                case DHCP_CLIENT_RENEW :
                {
                    leaseStatus = DHCP_RENEW;
                    break;
                }
                case DHCP_CLIENT_REBIND :
                {
                    leaseStatus = DHCP_REBIND;
                    break;
                }
                default:
                {
                    break;
                }
            }

            // Get the lease to RENEW or REBIND
            list<struct dhcpLease*>::iterator it;
            for (it = clientPtr->clientLeaseList->begin();
                 it != clientPtr->clientLeaseList->end();
                 it++)
            {
                if ((*it)->status == leaseStatus)
                {
                    clientLease = *it;
                    break;
                }
            }
            if (clientLease && clientPtr->state == DHCP_CLIENT_RENEW)
            {
                clientLease->renewMsg = NULL;

                // Cancel REBIND message
                if (clientLease->rebindMsg)
                {
                    MESSAGE_CancelSelfMsg(
                        node,
                        clientLease->rebindMsg);
                    clientLease->rebindMsg = NULL;
                }
            }
            if (clientLease && clientPtr->state == DHCP_CLIENT_REBIND)
            {
                clientLease->rebindMsg = NULL;
            }
            // Cancel the expiry message
            if (clientLease && clientLease->expiryMsg)
            {
                MESSAGE_CancelSelfMsg(
                    node,
                    clientLease->expiryMsg);
                clientLease->expiryMsg = NULL;
            }
        }

        // If ACK received is for  inform
        // No no need to use ARP

        if (clientPtr->state == DHCP_CLIENT_INFORM ||
            clientPtr->state == DHCP_CLIENT_RENEW ||
            clientPtr->state == DHCP_CLIENT_REBIND ||
            clientPtr->lastIP.IPV4 == data.yiaddr)
        {
            AppDhcpClientStateBound(node, data, incomingInterface);
        }
        else
        {
            // store the Ack packet received
            // Free the request packet

            if (clientPtr->dataPacket)
            {
                MEM_free(clientPtr->dataPacket);
                clientPtr->dataPacket = NULL;
            }

            // Store the ACK packet
            clientPtr->dataPacket =
                (struct dhcpData*)MEM_malloc(sizeof(struct dhcpData));
            memcpy(
                clientPtr->dataPacket,
                &data,
                sizeof(struct dhcpData));
            if (DHCP_DEBUG)
            {
                printf("ACK received at node %d at"
                       "interface %d \n",
                       node->nodeId,
                       incomingInterface);
                printf("sending for  ARP check"
                       "before updating \n");
                clocktype simulationTime = node->getNodeTime();
                char simulationTimeStr[MAX_STRING_LENGTH] = "";
                TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
                printf("Time at sending for ARP \n = %s",
                       simulationTimeStr);
            }
            clientPtr->arpInterval = node->getNodeTime();
            Address newAddress;
            newAddress.networkType = NETWORK_IPV4;

            newAddress.IPV4 = data.yiaddr;
            ArpCheckAddressForDhcp(
                             node,
                             newAddress,
                             incomingInterface);
        }
    }
}
//---------------------------------------------------------------------------
// NAME                 : AppDhcpServerHandleOfferRequest
// PURPOSE              : Handles the behaviour of server when REQUEST of
//                        OFFER is received
// PARAMETERS:
// + node               : Node*           : pointer to the node.
// + data               : struct dhcpData : REQUEST packet
// + incomingInterface  : Int32           : incomingInterface
// RETURN               : NONE
//---------------------------------------------------------------------------
static
void AppDhcpServerHandleOfferRequest (
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface)
{
    struct appDataDhcpServer* serverPtr = NULL;
    struct dhcpData* ackData = NULL;
    struct dhcpLease* lease = NULL;

    // Get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(node, incomingInterface);
    if (serverPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP sever at interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }

    // Get the server identifier
    UInt32 serverIdentifier = 0;
    dhcpGetOption(
         data.options,
         DHO_DHCP_SERVER_IDENTIFIER,
         DHCP_ADDRESS_OPTION_LENGTH,
         &serverIdentifier);

    // Get the requested IP Address
    UInt32 requestedIp = 0;
    dhcpGetOption(
         data.options,
         DHO_DHCP_REQUESTED_ADDRESS,
         DHCP_ADDRESS_OPTION_LENGTH,
         &requestedIp);

    // Find the lease to be allocated from list of
    // leases at server
    list<struct dhcpLease*>::iterator it;
    for (it = serverPtr->serverLeaseList->begin();
         it != serverPtr->serverLeaseList->end();
         it++)
    {
        if ((*it)->ipAddress.IPV4 == requestedIp)
        {
            lease = *it;
            break;
        }
    }
    if (lease && data.giaddr != 0 && lease->status != DHCP_OFFERED)
    {
        // Duplicate Request packet from relay
        return;
    }
    if (lease &&
        (lease->status == DHCP_OFFERED) &&
        (memcmp((lease->macAddress).byte,
                 data.chaddr,
                 data.hlen) == 0))
    {
        // Found the lease that was offered
        // Cancel the offer timeout message

        if (serverPtr->timeoutMssg)
        {
            MESSAGE_CancelSelfMsg(node, serverPtr->timeoutMssg);
            serverPtr->timeoutMssg = NULL;
        }

        // Get the client identifier
        UInt8 val = dhcpGetOptionLength(
                        data.options,
                        DHO_DHCP_CLIENT_IDENTIFIER);
        char clientIdentifier[MAX_STRING_LENGTH] = "";
        if (val != 0)
        {
            dhcpGetOption(
                data.options,
                DHO_DHCP_CLIENT_IDENTIFIER,
                val,
                clientIdentifier);
        }
        if (strlen(clientIdentifier) > 0)
        {
            memcpy(
                lease->clientIdentifier,
                clientIdentifier,
                val);
        }
        else
        {
            // Copy mac address to client identifier
            memcpy(
                lease->clientIdentifier,
                data.chaddr,
                data.hlen);
        }
        lease->status = DHCP_ALLOCATED;
        ackData = AppDhcpServerMakeAck(
                        node,
                        data,
                        lease,
                        incomingInterface);
        if (ackData == NULL)
        {
            ERROR_ReportErrorArgs("DHCP Server: Insufficient memory "
                    "Ack packet creation falied for  node %d\n",
                    node->nodeId);
        }

        // Send the ACK data
        if (DHCP_DEBUG)
        {
            printf("Sending ACK from server node %d "
                   "at inetrface %d \n",
                   node->nodeId,
                   incomingInterface);
            clocktype simulationTime = node->getNodeTime();
            char simulationTimeStr[MAX_STRING_LENGTH] = "";
            TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
            printf("Time at allocation = %s \n", simulationTimeStr);
        }
        if (data.giaddr != 0)
        {
            AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        data.giaddr,
                        DHCP_SERVER_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
        }
        else if (data.giaddr == 0)
        {
            AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        ANY_ADDRESS,
                        DHCP_CLIENT_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
        }

        // Increment the number of ACK sent
        serverPtr->numAckSent++;

        // get the lease time and schedule
        // expiry of lease

        UInt32 leaseTime = 0;
        dhcpGetOption(
               data.options,
               DHO_DHCP_LEASE_TIME,
               DHCP_LEASE_TIME_OPTION_LENGTH,
               &leaseTime);
        if (leaseTime != (UInt32)DHCP_INFINITE_LEASE && leaseTime != 0)
        {
            Message* message = MESSAGE_Alloc(
                                node,
                                APP_LAYER,
                                APP_DHCP_SERVER,
                                MSG_APP_DHCP_LEASE_EXPIRE);
            MESSAGE_InfoAlloc(
                       node,
                       message,
                       sizeof(struct dhcpLease));
            struct dhcpLease* info =
                (dhcpLease*) MESSAGE_ReturnInfo(message);
            memcpy(info, lease, sizeof(struct dhcpLease));
            lease->expiryMsg = message;
            char buf[MAX_STRING_LENGTH] = "";
            sprintf(buf, "%d", lease->leaseTime);
            clocktype time = TIME_ConvertToClock(buf);
            MESSAGE_Send(node, message, time);
        }
        if (serverPtr->dataPacket != NULL)
        {
            MEM_free(serverPtr->dataPacket);
        }
        serverPtr->dataPacket = ackData;
    }
    else
    {
        // Lease is not found. Send the NACK
        struct dhcpLease lease;
        memset(&lease, 0, sizeof(struct dhcpLease));
        ackData = AppDhcpServerMakeAck(
                                node,
                                data,
                                NULL,
                                incomingInterface);

        if (ackData == NULL)
        {
            ERROR_ReportErrorArgs(
                    "DHCP Server: Insufficient memory "
                    "Ack packet creation falied for  node %d\n",
                    node->nodeId);
        }
        (ackData->ciaddr) = 0;
        (ackData->yiaddr) = 0;
        (ackData->siaddr) = 0;
        UInt32 leaseTime  = 0;
        dhcpSetOption(
            ackData->options,
            DHO_DHCP_LEASE_TIME,
            DHCP_DHO_LEASE_TIME_LEN,
            &leaseTime);

        UInt8 msgType = DHCPNAK;

        dhcpSetOption(
            ackData->options,
            DHO_DHCP_MESSAGE_TYPE,
            DHCP_DHO_MESSAGE_TYPE_LEN,
            &msgType);

        if (DHCP_DEBUG)
        {
            printf("Sending NAK from server node %d "
                   "at inetrface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        if (data.giaddr != 0)
        {
            AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        data.giaddr,
                        DHCP_SERVER_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
        }
        else if (data.giaddr == 0)
        {
            AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        ANY_ADDRESS,
                        DHCP_CLIENT_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
        }
        serverPtr->numNakSent++;
        if (serverPtr->dataPacket != NULL)
        {
            MEM_free(serverPtr->dataPacket);
        }
        serverPtr->dataPacket = ackData;
    }

}
//---------------------------------------------------------------------------
// NAME                 : AppDhcpServerHandleRenewRebindRequest
// PURPOSE              : Handles the behaviour of server when REQUEST of
//                        RENEW/REBIND is received
// PARAMETERS           :
// + node               : Node*            : pointer to the node.
// + data               : struct dhcpData  : REQUEST packet
// + incomingInterface  : Int32            : incoming interface
// RETURN               : NONE
// --------------------------------------------------------------------------
static
void AppDhcpServerHandleRenewRebindRequest (
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface)
{
    struct appDataDhcpServer* serverPtr = NULL;
    struct dhcpData* ackData = NULL;
    struct dhcpLease* lease = NULL;
    char buf[MAX_STRING_LENGTH] = "";

    // Get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(node, incomingInterface);
    if (serverPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP sever at interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }
    if (DHCP_DEBUG)
    {
        printf("Server at node %d interface %d"
               "got renewal/rebind request \n",
               node->nodeId,
               incomingInterface);
    }

    // Get the lease to renew or rebind
    list<struct dhcpLease*>::iterator it;
    for (it = serverPtr->serverLeaseList->begin();
         it != serverPtr->serverLeaseList->end();
         it++)
    {
        if ((*it)->ipAddress.IPV4 == data.ciaddr)
        {
            lease = *it;
        }
    }

    if (lease == NULL)
    {
        // request has been received at server other than the one
        // that assigned it
        // Check if IP Address lies in its range

        if (data.ciaddr >= serverPtr->addressRangeStart.IPV4 &&
            data.ciaddr <= serverPtr->addressRangeEnd.IPV4)
        {
            // Ip-address lies in its range
            // Check if address reserved for  manual allocation
            Address addressRebind;
            addressRebind.networkType =
                                (serverPtr->addressRangeStart).networkType;
            addressRebind.IPV4 = data.ciaddr;
            if (AppDhcpCheckIfIpInManualAllocationList(
                                                serverPtr,
                                                addressRebind))
            {
                if (DHCP_DEBUG)
                {
                    printf("Lease for  renewal reserved for manual"
                           "allocation at server at node %d "
                           "interface %d \n",
                           node->nodeId,
                           incomingInterface);
                }
                return;
            }

            // Allocate the lease
            lease = (struct dhcpLease*)MEM_malloc(sizeof(struct dhcpLease));
            memset(lease, 0, sizeof(struct dhcpLease));

            // Get the client identifier
            UInt8 val = dhcpGetOptionLength(
                            data.options,
                            DHO_DHCP_CLIENT_IDENTIFIER);
            char clientIdentifier[MAX_STRING_LENGTH] = "";
            if (val != 0)
            {
                dhcpGetOption(
                    data.options,
                    DHO_DHCP_CLIENT_IDENTIFIER,
                    val,
                    clientIdentifier);
                clientIdentifier[val] = '\0';
            }
            if (strlen(clientIdentifier) > 0)
            {
                memcpy(lease->clientIdentifier, clientIdentifier, val);
            }
            else
            {
                // Copy mac address to client identifier
                memcpy(lease->clientIdentifier, data.chaddr, data.hlen);
            }

            // If requested lease time present then assign that to lease
            UInt32 requestedLeaseTime = 0;
            dhcpGetOption(
                   data.options,
                   DHO_DHCP_LEASE_TIME,
                   DHCP_LEASE_TIME_OPTION_LENGTH,
                   &requestedLeaseTime);
            if (requestedLeaseTime == (UInt32)DHCP_INFINITE_LEASE)
            {
                lease->leaseTime = (UInt32)DHCP_INFINITE_LEASE;
            }
            else if (requestedLeaseTime != 0 &&
                requestedLeaseTime <= serverPtr->maxLeaseTime)
            {
                lease->leaseTime = requestedLeaseTime;
            }
            else
            {
                lease->leaseTime = serverPtr->defaultLeaseTime;
            }
            (lease->ipAddress).networkType =
                (serverPtr->addressRangeStart).networkType;
            (lease->ipAddress).IPV4 = data.ciaddr;
            (lease->serverId).networkType = NETWORK_IPV4;
            (lease->serverId).IPV4 =
                    NetworkIpGetInterfaceAddress(node, incomingInterface);
            lease->macAddress.hwLength = data.hlen;
            lease->macAddress.hwType = data.htype;
            lease->macAddress.byte = (unsigned char*)MEM_malloc(data.hlen);
            memcpy(lease->macAddress.byte , data.chaddr, data.hlen);

            (lease->defaultGateway).networkType =
                (serverPtr->defaultGateway).networkType;
            (lease->defaultGateway).IPV4 = (serverPtr->defaultGateway).IPV4;
            (lease->subnetMask).networkType =
                (serverPtr->subnetMask).networkType;
            (lease->subnetMask).IPV4 = (serverPtr->subnetMask).IPV4;
            (lease->subnetNumber).networkType =
                                (lease->ipAddress).networkType;
            (lease->subnetNumber).IPV4 =
                                (lease->ipAddress).IPV4 &
                                (lease->subnetMask).IPV4;
            (lease->primaryDNSServer).networkType =
                (serverPtr->primaryDNSServer).networkType;
            (lease->primaryDNSServer).IPV4 =
                            (serverPtr->primaryDNSServer).IPV4;
            if (lease->listOfSecDNSServer == NULL)
            {
                lease->listOfSecDNSServer = new std::list<Address*>;
            }
            AppDhcpCopySecondaryDnsServerList(
                                        serverPtr->listSecDnsServer,
                                        lease->listOfSecDNSServer);
            lease->status = DHCP_ALLOCATED;

            // Insert the newly created lease to list
            serverPtr->serverLeaseList->push_back(lease);
        }
    }
    if (lease == NULL ||
        (lease != NULL && lease->status != DHCP_ALLOCATED &&
         lease->status != DHCP_AVAILABLE))
    {
        if (DHCP_DEBUG)
        {
            printf("Lease for  renewal not there at server at "
                   "node %d interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }
    if (lease && lease->status == DHCP_AVAILABLE)
    {
        // Get the client identifier
        UInt8 val = dhcpGetOptionLength(
                        data.options,
                        DHO_DHCP_CLIENT_IDENTIFIER);
        char clientIdentifier[MAX_STRING_LENGTH] = "";
        if (val != 0)
        {
            dhcpGetOption(
                data.options,
                DHO_DHCP_CLIENT_IDENTIFIER,
                val,
                clientIdentifier);
            clientIdentifier[val] = '\0';
        }
        if (strlen(clientIdentifier) > 0)
        {
            memcpy(
                lease->clientIdentifier,
                clientIdentifier,
                val);
        }
        else
        {
            // Copy mac address to client identifier
            memcpy(
                lease->clientIdentifier,
                data.chaddr,
                data.hlen);
        }

        // If requested lease time present then assign that lease
        UInt32 requestedLeaseTime = 0;
        dhcpGetOption(
               data.options,
               DHO_DHCP_LEASE_TIME,
               DHCP_LEASE_TIME_OPTION_LENGTH,
               &requestedLeaseTime);
        if (requestedLeaseTime == (UInt32)DHCP_INFINITE_LEASE)
        {
            lease->leaseTime = (UInt32)DHCP_INFINITE_LEASE;
        }
        else if (requestedLeaseTime != 0 &&
             requestedLeaseTime <= serverPtr->maxLeaseTime)
        {
            lease->leaseTime = requestedLeaseTime;
        }
        else
        {
            lease->leaseTime = serverPtr->defaultLeaseTime;
        }
        (lease->ipAddress).networkType =
            (serverPtr->addressRangeStart).networkType;
        (lease->ipAddress).IPV4 = data.ciaddr;
        (lease->serverId).networkType = NETWORK_IPV4;

        (lease->serverId).IPV4 =
                    NetworkIpGetInterfaceAddress(node, incomingInterface);
        lease->macAddress.hwLength = data.hlen;
        lease->macAddress.hwType = data.htype;
        lease->macAddress.byte = (unsigned char*)MEM_malloc(data.hlen);
        memcpy(lease->macAddress.byte, data.chaddr, data.hlen);

        (lease->defaultGateway).networkType =
            (serverPtr->defaultGateway).networkType;
        (lease->defaultGateway).IPV4 = (serverPtr->defaultGateway).IPV4;
        (lease->subnetMask).networkType =
            (serverPtr->subnetMask).networkType;
        (lease->subnetMask).IPV4 = (serverPtr->subnetMask).IPV4;
        (lease->subnetNumber).networkType =
                                (lease->ipAddress).networkType;
        (lease->subnetNumber).IPV4 =
                                (lease->ipAddress).IPV4 &
                                (lease->subnetMask).IPV4;
        (lease->primaryDNSServer).networkType =
            (serverPtr->primaryDNSServer).networkType;
        (lease->primaryDNSServer).IPV4 = (serverPtr->primaryDNSServer).IPV4;
        if (lease->listOfSecDNSServer == NULL)
        {
             lease->listOfSecDNSServer = new std::list<Address*>;
        }
        AppDhcpCopySecondaryDnsServerList(
                                        serverPtr->listSecDnsServer,
                                        lease->listOfSecDNSServer);
        lease->status = DHCP_ALLOCATED;
    }
    else if (lease &&
             (lease->status == DHCP_ALLOCATED) &&
             (memcmp((lease->macAddress).byte,
                     data.chaddr,
                     data.hlen) == 0))
    {
        // cancel the lease expiry message
        if (lease->expiryMsg != NULL)
        {
            // calculate the remainting time of lease
            // If lease is going to expire in next 0.1 seconds do not
            // respond
            clocktype temptime =
                (node->getNodeTime() - lease->expiryMsg->packetCreationTime);
            sprintf(buf, "%d", lease->leaseTime);
            clocktype leaseTime = TIME_ConvertToClock(buf);
            clocktype remainTime = leaseTime - temptime;
            clocktype completeTime = leaseTime - remainTime;
            if (completeTime >
               DHCP_SERVER_RENEWREBIND_DONOT_RESPOND_LEASETIME * (leaseTime))
            {
                return;
            }
            if (lease->expiryMsg)
            {
                MESSAGE_CancelSelfMsg(node, lease->expiryMsg);
                lease->expiryMsg = NULL;
            }
        }
    }

    // Get the ack packet
    ackData = AppDhcpServerMakeAck(node,
                                   data,
                                   lease,
                                   incomingInterface);
    if (ackData == NULL)
    {
        ERROR_ReportErrorArgs(
                "DHCP Server: Insufficient memory "
                "Ack packet creation falied for  node %d\n",
                node->nodeId);
    }
    if (DHCP_DEBUG)
    {
        printf("Sending ACK from server node %d "
               "at inetrface %d \n",
               node->nodeId,
               incomingInterface);
        clocktype simulationTime = node->getNodeTime();
        char simulationTimeStr[MAX_STRING_LENGTH] = "";
        TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
        printf("Time at allocation = %s \n", simulationTimeStr);
    }
  // Send the ACK packet
    if (data.giaddr == 0)
    {
        AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        data.ciaddr,
                        DHCP_CLIENT_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
    }
    else if (data.giaddr != 0)
    {
        AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        data.giaddr,
                        DHCP_SERVER_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
    }
    // Increment the ACK packet
    serverPtr->numAckSent++;

    // Schedule new lease expiry event
    Message* message = MESSAGE_Alloc(
                        node,
                        APP_LAYER,
                        APP_DHCP_SERVER,
                        MSG_APP_DHCP_LEASE_EXPIRE);
    MESSAGE_InfoAlloc(
                   node,
                   message,
                   sizeof(struct dhcpLease));
    struct dhcpLease* info = (struct dhcpLease*)MESSAGE_ReturnInfo(message);
    memcpy(info, lease, sizeof(struct dhcpLease));
    lease->expiryMsg = message;
    sprintf(buf, "%d", lease->leaseTime);
    clocktype time = TIME_ConvertToClock(buf);
    if (serverPtr->dataPacket != NULL)
    {
        MEM_free(serverPtr->dataPacket);
    }
    serverPtr->dataPacket = ackData;
    MESSAGE_Send(node, message, (time));
}
//---------------------------------------------------------------------------
// NAME                : AppDhcpServerHandleInitRebootRequest
// PURPOSE             : Handles the behaviour of server when REQUEST of
//                        INIT-REBOOT is received
// PARAMETERS:
// + node              : Node*           : pointer to the node.
// + data              : struct dhcpData :REQUEST packet
// + incomingInterface : Int32           : inoming interface
// RETURN              : NONE
//---------------------------------------------------------------------------
static
void AppDhcpServerHandleInitRebootRequest (
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface)
{
    struct appDataDhcpServer* serverPtr = NULL;
    struct dhcpData* ackData = NULL;
    struct dhcpLease* lease = NULL;

    // Get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(node, incomingInterface);
    if (serverPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP sever at interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }

    // Get the server identifier
    UInt32 serverIdentifier = 0;
    dhcpGetOption(
        data.options,
        DHO_DHCP_SERVER_IDENTIFIER,
        DHCP_ADDRESS_OPTION_LENGTH,
        &serverIdentifier);

    // Get the requested IP Address
    UInt32 requestedIp = 0;
    dhcpGetOption(
        data.options,
        DHO_DHCP_REQUESTED_ADDRESS,
        DHCP_ADDRESS_OPTION_LENGTH,
        &requestedIp);
    if (DHCP_DEBUG)
    {
        printf("Request received from client in"
               "INIT-REBOOT state at server at node %d "
               " interface %d \n",
               node->nodeId,
               incomingInterface);
    }

    // Search the list of leases for  requested IP Address
    list<struct dhcpLease*>::iterator it;
    for (it = serverPtr->serverLeaseList->begin();
         it != serverPtr->serverLeaseList->end();
         it++)
    {
        if ((*it)->ipAddress.IPV4 == requestedIp)
        {
            lease = *it;
        }
    }
    if (lease == NULL)
    {
        // Check if the lease lies in its range
        if (requestedIp >= serverPtr->addressRangeStart.IPV4 &&
            requestedIp <= serverPtr->addressRangeEnd.IPV4)
        {
            // Server can allocate the lease
            // Send the ACK if the lease is not reserved
            // for manual allocation
            // Check the address if it is reserved for manual.
            Address dataRequestedIp;
            dataRequestedIp.networkType = NETWORK_IPV4;
            dataRequestedIp.IPV4 = requestedIp;
            if (AppDhcpCheckIfIpInManualAllocationList(
                                                serverPtr,
                                                dataRequestedIp))
            {
                    // Cannot allocat the lease hence return
                    return;
            }
            // allocate the lease
            lease =
                (struct dhcpLease*)MEM_malloc(sizeof( struct dhcpLease));
            memset(lease, 0, sizeof(struct dhcpLease));

            lease->clientIdentifier[0] = '\0';
            (lease->ipAddress).networkType =
                (dataRequestedIp).networkType;
            (lease->ipAddress).IPV4 =(dataRequestedIp).IPV4;
            (lease->serverId).networkType = NETWORK_IPV4;

            (lease->serverId).IPV4 =
                    NetworkIpGetInterfaceAddress(node, incomingInterface);
            lease->macAddress.hwLength = data.hlen;
            lease->macAddress.hwType = data.htype;
            lease->macAddress.byte =
                (unsigned char*)MEM_malloc(data.hlen);
            memcpy(lease->macAddress.byte, data.chaddr, data.hlen);

            (lease->defaultGateway).networkType =
                (serverPtr->defaultGateway).networkType;
            (lease->defaultGateway).IPV4 =(serverPtr->defaultGateway).IPV4;
            (lease->subnetMask).networkType =
                (serverPtr->subnetMask).networkType;
            (lease->subnetMask).IPV4 =(serverPtr->subnetMask).IPV4;
            (lease->subnetNumber).networkType =
                                (lease->ipAddress).networkType;
            (lease->subnetNumber).IPV4 =
                                (lease->ipAddress).IPV4 &
                                (lease->subnetMask).IPV4;
            (lease->primaryDNSServer).networkType =
                (serverPtr->primaryDNSServer).networkType;
            (lease->primaryDNSServer).IPV4 =
                        (serverPtr->primaryDNSServer).IPV4;
            if (lease->listOfSecDNSServer == NULL)
            {
                lease->listOfSecDNSServer = new std::list<Address*>;
            }
            AppDhcpCopySecondaryDnsServerList(
                                        serverPtr->listSecDnsServer,
                                        lease->listOfSecDNSServer);
            lease->status = DHCP_ALLOCATED;

            // Insert the newly created lease to list
            serverPtr->serverLeaseList->push_back(lease);
        }
        else
        {
            // Lease not there
            return;
        }
    }
    if (lease && lease->status == DHCP_ALLOCATED)
    {
        // Check if lease is ALLOCATED to requesting client
        if (memcmp(lease->macAddress.byte, data.chaddr, data.hlen) == 0)
        {
            // Lease is allocated to same client.
            // Cancel the expiry messgae and send ACK

            if (lease->expiryMsg)
            {
                MESSAGE_CancelSelfMsg(
                           node,
                           lease->expiryMsg);
                lease->expiryMsg = NULL;
            }
        }
        else
        {
            if (DHCP_DEBUG)
            {
                printf("Lease has been allocated"
                       "to some other client. Cannot alocate "
                       "same at server present at node %d interface %d \n",
                       node->nodeId,
                       incomingInterface);
            }

            // Send NAK
             ackData = AppDhcpServerMakeAck(node,
                                   data,
                                   NULL,
                                   incomingInterface);
            if (ackData == NULL)
            {
                ERROR_ReportErrorArgs(
                        "DHCP Server: Insufficient memory "
                        "NACK packet creation falied for  node %d\n",
                        node->nodeId);
            }
            (ackData->ciaddr) = 0;
            (ackData->yiaddr) = 0;
            (ackData->siaddr) = 0;

            //set leasee time
            UInt32 leaseTime = 0;
            dhcpSetOption(
                ackData->options,
                DHO_DHCP_LEASE_TIME,
                DHCP_LEASE_TIME_OPTION_LENGTH,
                &leaseTime);
            UInt8 msgType = DHCPNAK;
            dhcpSetOption(
                ackData->options,
                DHO_DHCP_MESSAGE_TYPE,
                1,
                &msgType);
            if (DHCP_DEBUG)
            {
                printf("Sending NAK from server node %d "
                       "at inetrface %d \n",
                       node->nodeId,
                       incomingInterface);
            }
            if (data.giaddr != 0)
            {
                AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        data.giaddr,
                        DHCP_SERVER_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
            }
            else if (data.giaddr == 0)
            {
                AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        ANY_ADDRESS,
                        DHCP_CLIENT_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
            }
            serverPtr->numNakSent++;
            if (serverPtr->dataPacket != NULL)
            {
                MEM_free(serverPtr->dataPacket);
            }
            serverPtr->dataPacket = ackData;
            return;
        }
    }
    else if (lease && lease->status != DHCP_AVAILABLE)
    {
        // Send NAK
        ackData = AppDhcpServerMakeAck(
                                    node,
                                    data,
                                    NULL,
                                    incomingInterface);
        if (ackData == NULL)
        {
            ERROR_ReportErrorArgs(
                    "DHCP Server: Insufficient memory "
                    "NACK packet creation falied for  node %d\n",
                    node->nodeId);
        }
        (ackData->ciaddr) = 0;
        (ackData->yiaddr) = 0;
        (ackData->siaddr) = 0;

        //set leasee time
        UInt32 leaseTime = 0;
        dhcpSetOption(
            ackData->options,
            DHO_DHCP_LEASE_TIME,
            DHCP_LEASE_TIME_OPTION_LENGTH,
            &leaseTime);
        UInt8 msgType = DHCPNAK;
        dhcpSetOption(
            ackData->options,
            DHO_DHCP_MESSAGE_TYPE,
            1,
            &msgType);
        if (DHCP_DEBUG)
         {
             printf("Sending NAK from server node %d "
                    "at inetrface %d \n",
                    node->nodeId,
                    incomingInterface);
         }
         if (data.giaddr != 0)
         {
             AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        data.giaddr,
                        DHCP_SERVER_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
        }
        else if (data.giaddr == 0)
        {
            AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        ANY_ADDRESS,
                        DHCP_CLIENT_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
        }
        if (serverPtr->dataPacket != NULL)
        {
            MEM_free(serverPtr->dataPacket);
        }
        serverPtr->dataPacket = ackData;
        return;
    }

    // Send ACK packet in case lease has not been allocated to
    // any other client
    // Allocate the lease to this client

    UInt8 val = dhcpGetOptionLength(
                        data.options,
                        DHO_DHCP_CLIENT_IDENTIFIER);
    char clientIdentifier[MAX_STRING_LENGTH] = "";
    if (val != 0)
    {
        dhcpGetOption(
            data.options,
            DHO_DHCP_CLIENT_IDENTIFIER,
            val,
            clientIdentifier);
        clientIdentifier[val] = '\0';
    }
    if (strlen(clientIdentifier) > 0)
    {
        memcpy(
            lease->clientIdentifier,
            clientIdentifier,
            val);
    }
    else
    {
        // Copy mac address to client identifier
        memcpy(
            lease->clientIdentifier,
            data.chaddr,
            data.hlen);
    }
    lease->status = DHCP_ALLOCATED;

    // Create the ACK packet
    ackData = AppDhcpServerMakeAck(
                             node,
                             data,
                             lease,
                             incomingInterface);
    if (ackData == NULL)
    {
        ERROR_ReportErrorArgs(
                "DHCP Server: Insufficient memory "
                "Ack packet creation falied for  node %d\n",
                node->nodeId);
    }
    if (DHCP_DEBUG)
    {
        printf("Sending ACK from server node %d "
               "at inetrface %d \n",
               node->nodeId,
               incomingInterface);
        clocktype simulationTime = node->getNodeTime();
        char simulationTimeStr[MAX_STRING_LENGTH] = "";
        TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
        printf("Time at allocation = %s \n", simulationTimeStr);
    }
    if (data.giaddr == 0)
    {
        AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        ANY_ADDRESS,
                        DHCP_CLIENT_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
    }
    if (data.giaddr != 0)
    {
         AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        data.giaddr,
                        DHCP_SERVER_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
    }

    // Increment the ACK packet
    serverPtr->numAckSent++;
    if (lease->leaseTime != (UInt32)DHCP_INFINITE_LEASE
        && lease->leaseTime != 0)
    {
        Message* message = MESSAGE_Alloc(
                    node,
                    APP_LAYER,
                    APP_DHCP_SERVER,
                    MSG_APP_DHCP_LEASE_EXPIRE);
        MESSAGE_InfoAlloc(
                   node,
                   message,
                   sizeof(struct dhcpLease));
        struct dhcpLease* info =
            (struct dhcpLease*)MESSAGE_ReturnInfo(message);
        memcpy(info, lease, sizeof(struct dhcpLease));
        lease->expiryMsg = message;
        char buf[MAX_STRING_LENGTH] = "";
        sprintf(buf, "%d", lease->leaseTime);
        clocktype time = TIME_ConvertToClock(buf);
        if (serverPtr->dataPacket != NULL)
        {
            MEM_free(serverPtr->dataPacket);
        }
        serverPtr->dataPacket = ackData;
        MESSAGE_Send(node, message, (time));
    }
}
//--------------------DHCP static functions implementataion ends---------

//--------------------------------------------------------------------------
// NAME             : AppDhcpClientInit.
// PURPOSE          : Initialize DHCP client data structure.
// PARAMETERS       :
// + node           : Node*       : The pointer to the node.
// + interfaceIndex : Int32       : interfaceIndex
// + nodeInput      : NodeInput*  : The pointer to configuration
// RETURN           : NONE
// -------------------------------------------------------------------------
void AppDhcpClientInit(
    Node* node,
    Int32 interfaceIndex,
    const NodeInput* nodeInput)
{
    struct appDataDhcpClient* clientPtr = NULL;
    bool retVal = FALSE;
    Int32 matchType = 0;

    // Now start initialiazing the client
    if (DHCP_DEBUG)
    {
        printf("\n Initializing client on interface %d of"
               "node %d \n",
               interfaceIndex,
               node->nodeId);
    }

    // Create a new client pointer
    clientPtr = AppDhcpClientNewDhcpClient(node, interfaceIndex, nodeInput);
    if (clientPtr == NULL)
    {
        ERROR_ReportErrorArgs(
                "DHCP Client: Insufficient memory "
                "Client initialization failed for node %d\n",
                node->nodeId);
    }
    else
    {
        if (DHCP_DEBUG)
        {
            printf("Client successfully initialized for  node %d "
                   "at interface %d \n",
                   node->nodeId,
                   interfaceIndex);
        }
        // Read whether MANET enabled for  scenario
        // If MANET is enabled then the clients will behave as relay agent
        // after coming to BOUND state
        clientPtr->manetEnabled = FALSE;
        retVal = AppDhcpCheckDhcpEntityConfigLevel(
                                        node,
                                        nodeInput,
                                        interfaceIndex,
                                        "DHCP-MANET-ENABLED-CLIENT",
                                        &matchType);


        if (retVal)
        {
            clientPtr->manetEnabled = TRUE;
            if (DHCP_DEBUG)
            {
                printf ("This is a MANET-ENABLED DHCP client \n");
            }
        }

        // Read DHCP_STATISTICS enabled or not
        // If DHCP statistics is enabled then the statistics will be printed
        // for  DHCP in .stat file
        BOOL parameterValue = FALSE;
        BOOL wasFound = FALSE;
        clientPtr->dhcpClientStatistics = FALSE;
        IO_ReadBool(node->nodeId,
                    MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                                         node,
                                                         node->nodeId,
                                                         interfaceIndex),
                    nodeInput,
                    "DHCP-STATISTICS",
                    &wasFound,
                    &parameterValue);

        // DHCP-STATISTICS enabled, by default it will not be enabled
        if (wasFound && parameterValue == TRUE)
        {
            clientPtr->dhcpClientStatistics = TRUE;
        }

        // Reterieve the current subnet mask for  the interface
        NodeAddress subnetMask = MAPPING_GetSubnetMaskForInterface(
                                                         node,
                                                         node->nodeId,
                                                         interfaceIndex);

        // Initialize the old IP address
        Address address;
        memset(&address, 0, sizeof(Address));
        address.IPV4 =
            NetworkIpGetInterfaceAddress(node, interfaceIndex);
        address.networkType = NETWORK_IPV4;

        // Inform mapping and interface about the initilization
        // of DHCP client on this interface
        // Make the interface as invalid
        // Check the state of client and schedule DISCOVERY or
        // INFORM procedure

        if (clientPtr->state == DHCP_CLIENT_INIT)
        {
            if (DHCP_DEBUG)
            {
                printf("DHCPDISCOVER for  node %d at interfce %d \n",
                       node->nodeId,
                       interfaceIndex);
            }
            Message* message = MESSAGE_Alloc(
                                        node,
                                        APP_LAYER,
                                        APP_DHCP_CLIENT,
                                        MSG_APP_DHCP_InitEvent);
            MESSAGE_InfoAlloc(
                           node,
                           message,
                           sizeof(Int32));
            Int32* info = (Int32*)MESSAGE_ReturnInfo(message);
            *(info) = interfaceIndex;
            MESSAGE_Send(
                     node,
                     message,
                     RANDOM_nrand(clientPtr->jitterSeed));

            NetworkIpProcessDHCP(
                             node,
                             interfaceIndex,
                             &address,
                             subnetMask,
                             INIT_DHCP,
                             address.networkType);
        }//end of DISCOVER
        if (clientPtr->state == DHCP_CLIENT_INFORM)
        {
            if (DHCP_DEBUG)
            {
                printf("DHCPINFORM for  node %d at interfce %d \n",
                       node->nodeId,
                       interfaceIndex);
            }
            Message* message = MESSAGE_Alloc(
                                         node,
                                         APP_LAYER,
                                         APP_DHCP_CLIENT,
                                         MSG_APP_DHCP_InformEvent);
            MESSAGE_InfoAlloc(
                            node,
                            message,
                            sizeof(Int32));
            Int32* info = (Int32*)MESSAGE_ReturnInfo(message);
            *(info) = interfaceIndex;
            MESSAGE_Send(
                    node,
                    message,
                    RANDOM_nrand(clientPtr->jitterSeed));

            NetworkIpProcessDHCP(
                             node,
                             interfaceIndex,
                             &address,
                             subnetMask,
                             INFORM_DHCP,
                             address.networkType);
        }// end of INFORM
    } // end of else
#ifdef TEST_DHCPRELEASE

    // schedule RELEASE event
    if (clientPtr->dhcpReleaseTime != 0)
    {
        Message* message = MESSAGE_Alloc(
                                    node,
                                    APP_LAYER,
                                    APP_DHCP_CLIENT,
                                    MSG_APP_DHCP_ReleaseEvent);
        MESSAGE_InfoAlloc(
                       node,
                       message,
                       sizeof(Int32));
        Int32* info = (Int32*) MESSAGE_ReturnInfo(message);
        *(info) = interfaceIndex;
        MESSAGE_Send(
                node,
                message,
                clientPtr->dhcpReleaseTime);
    }
#endif

    return;
}

//--------------------------------------------------------------------------
// NAME             : AppDhcpClientNewDhcpClient
// PURPOSE          : create a new DHCP client data structure, place it
//                    at the beginning of the application list.
// PARAMETERS       :
// + node           : Node*         : The pointer to the node.
// + interfaceIndex : Int32         : interfaceIndex
// + nodeInput      : NodeInput*    : The pointer to configuration
// RETURN           :
// struct appDataDhcpClient* : the pointer to the created DHCP client data
//                             structure NULL if no data structure allocated
//--------------------------------------------------------------------------
struct appDataDhcpClient* AppDhcpClientNewDhcpClient(
    Node* node,
    Int32 interfaceIndex,
    const NodeInput* nodeInput)
{
    struct appDataDhcpClient* dhcpClient = NULL;
    BOOL retVal = FALSE;
    BOOL isnodeId = FALSE;
    char buf[MAX_STRING_LENGTH] = "";
    NodeAddress ipAddress = 0;
    clocktype time = 0;
    Int32 matchType = 0;

    // Allocate memory for  client
    dhcpClient = (struct appDataDhcpClient*)
        MEM_malloc(sizeof(struct appDataDhcpClient));
    if (dhcpClient == NULL)
    {
        return(NULL);
    }
    memset(dhcpClient, 0, sizeof(struct appDataDhcpClient));

    dhcpClient->interfaceIndex = interfaceIndex;

    // Make recent XID as 0 during initializtion
    dhcpClient->recentXid = 0;

    // Set the DHCP client MAC address
    dhcpClient->hardwareAddress = GetMacHWAddress(node, interfaceIndex);

    // Check if DHCPINFORM enabled or not If enabled
    // set client state as INFORM else set client state as INIT
    BOOL parameterValue = FALSE;
    IO_ReadBoolInstance(
                    node->nodeId,
                    MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                                        node,
                                                        node->nodeId,
                                                        interfaceIndex),
                    nodeInput,
                    "DHCP-CLIENT-INFORM",
                    interfaceIndex,
                    TRUE,
                    &retVal,
                    &parameterValue);

    if (retVal && parameterValue == TRUE)
    {
        dhcpClient->state = DHCP_CLIENT_INFORM;
    }
    else
    {
        dhcpClient->state = DHCP_CLIENT_INIT;
    }

    // Read the client id  which is optional
    // if present. It can be interface wise only

    IO_ReadString(
                node->nodeId,
                interfaceIndex,
                NetworkIpGetInterfaceAddress(node, interfaceIndex),
                NULL,
                nodeInput,
                "DHCP-CLIENT-ID",
                buf,
                retVal,
                matchType);
    if (retVal == TRUE)
    {
        if (strlen(buf) > MAX_STRING_LENGTH)
        {
            MEM_free(dhcpClient);
            ERROR_ReportErrorArgs(
                    "Client identifier length can be max upto "
                    "%d for  node %d\n",
                    MAX_STRING_LENGTH,
                    node->nodeId);
        }
        memcpy(
            dhcpClient->dhcpClientIdentifier,
            buf,
            MAX_STRING_LENGTH);
    }
    else
    {
        // Client id not given
        dhcpClient->dhcpClientIdentifier[0] = '\0';

    }

    // Read the client configured lease time , which is optional,
    // if present it should be a number if the value is 0 it indicates
    // client has request for INFINITE LEASE

    IO_ReadString(
           node->nodeId,
           interfaceIndex,
           NetworkIpGetInterfaceAddress(node, interfaceIndex),
           NULL,
           nodeInput,
           "DHCP-CLIENT-LEASE-TIME",
           buf,
           retVal,
           matchType);
    if (retVal == TRUE)
    {
        time = TIME_ConvertToClock(buf);

        if (time == 0)
        {
            MEM_free(dhcpClient);
            ERROR_ReportErrorArgs(
                    "Invalid value for  "
                    "DHCP-CLIENT-LEASE-TIME at node %d ",
                    node->nodeId);
        }
        if (AppDhcpCheckInfiniteLeaseTime(time, nodeInput))
        {
            dhcpClient->dhcpLeaseTime = (UInt32)DHCP_INFINITE_LEASE;
        }
        else
        {
            if ((time / SECOND) < DHCP_MINIMUM_LEASE_TIME)
            {
                ERROR_ReportErrorArgs(
                "DHCP-CLIENT-LEASE-TIME must be greater than equal to 12S at"
                " interface %d of node %d", interfaceIndex, node->nodeId);
            }
            // Keep time in seconds as options allow time of only 32 bits
            time = time / SECOND;
            dhcpClient->dhcpLeaseTime = (UInt32)(time & 0x00000000ffffffff);
        }
    }

    // Read the client configured initial
    // message retransmission timer if not provided
    // default value of 10 seconds is taken

    dhcpClient->timeout = DHCP_RETRANS_TIMER;
    IO_ReadString(
            node->nodeId,
            interfaceIndex,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            NULL,
            nodeInput,
            "DHCP-CLIENT-MESSAGE-RETRANSMISSION-TIMER",
            buf,
            retVal,
            matchType);
    if (retVal == TRUE)
    {
        time = TIME_ConvertToClock(buf);
        if (time == 0)
        {
            MEM_free(dhcpClient);
            ERROR_ReportErrorArgs(
                "Invalid value for DHCP-CLIENT-MESSAGE-RETRANSMISSION-TIMER"
                "at node %d ",
                node->nodeId);
        }
        clocktype maxDelay = DHCP_MAX_RETRANS_TIMER;
        if (time > maxDelay)
        {
            MEM_free(dhcpClient);
            ERROR_ReportErrorArgs(
                "Value for DHCP-CLIENT-MESSAGE-RETRANSMISSION-TIMER "
                "exceeds maximum re-transmission value of 64 seconds "
                " at node %d interface %d \n",
                node->nodeId,
                interfaceIndex);
        }
        dhcpClient->timeout = time;
    }

    // Read the client configured reject ip if present;
    // which is optional

    IO_ReadString(
            node->nodeId,
            interfaceIndex,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            NULL,
            nodeInput,
            "DHCP-CLIENT-REJECT-IP",
            buf,
            retVal,
            matchType);
    if (retVal == TRUE)
    {
        IO_ParseNodeIdOrHostAddress(buf, &ipAddress, &isnodeId);
        if (isnodeId == FALSE)
        {
            if (ipAddress == 0)
            {
                MEM_free(dhcpClient);
                ERROR_ReportErrorArgs(
                        "Invalid value for  DHCP-CLIENT-REJECT-IP"
                        "at node %d ",
                        node->nodeId);
            }
            (dhcpClient->rejectIP).networkType =
                                MAPPING_GetNetworkType(buf);
            (dhcpClient->rejectIP).IPV4 = ipAddress;
        }
        else
        {
            MEM_free(dhcpClient);
            ERROR_ReportErrorArgs("Rejct IP  can be ip address only\n");
        }
    }
#ifdef TEST_DHCPRELEASE

    IO_ReadString(
           node->nodeId,
           interfaceIndex,
           NetworkIpGetInterfaceAddress(node, interfaceIndex),
           NULL,
           nodeInput,
           "DHCP-CLIENT-SHUTDOWN-TIME",
           buf,
           retVal,
           matchType);
    if (retVal == TRUE)
    {
        time = TIME_ConvertToClock(buf);
        dhcpClient->dhcpReleaseTime = time;
    }

#endif

    //Initialize other parameters for  DHCP client
    dhcpClient->sourcePort = DHCP_CLIENT_PORT;
    dhcpClient->tos = APP_DEFAULT_TOS;
    dhcpClient->numDiscoverSent = 0;
    dhcpClient->numOfferRecv = 0;
    dhcpClient->numRequestSent = 0;
    dhcpClient->numAckRecv = 0;
    dhcpClient->numInformSent = 0;
    memset (&dhcpClient->lastIP, 0, sizeof(Address));

    // set the seed
    RANDOM_SetSeed(dhcpClient->jitterSeed,
                   node->globalSeed,
                   node->nodeId,
                   NETWORK_PROTOCOL_IP,
                   interfaceIndex);

    // Initialize the List of leases for  each interface
    dhcpClient->clientLeaseList = new std::list<struct dhcpLease*>;
    dhcpClient->timeoutMssg = NULL;
    dhcpClient->retryCounter = 1;
    dhcpClient->dataPacket = NULL;
    dhcpClient->dhcpClientStatistics = TRUE;
    dhcpClient->manetEnabled = FALSE;
    APP_RegisterNewApp(node, APP_DHCP_CLIENT, dhcpClient);
    return(dhcpClient);
}

//---------------------------------------------------------------------------
// NAME             : AppDhcpServerInit.
// PURPOSE          : Initializes the DHCP server.
// PARAMETERS       :
// + node           : Node*         : The pointer to the node.
// + interfaceIndex : Int32         : interfaceIndex
// + nodeInput      : NodeInput*    : The pointer to configuration
// RETURN           : none.
// --------------------------------------------------------------------------
void AppDhcpServerInit(
    Node* node,
    Int32 interfaceIndex,
    const NodeInput* nodeInput)
{
    struct appDataDhcpServer* serverPtr = NULL;
    BOOL parameterValue = FALSE;
    BOOL retVal = FALSE;
    Int32 matchType = 0;


    // Initialization of DHCP server
    if (DHCP_DEBUG)
    {
        printf("\n Initializing server on interface %d of"
               "node %d \n",
               interfaceIndex,
               node->nodeId);
    }
    serverPtr = AppDhcpServerNewDhcpServer(
                                      node,
                                      interfaceIndex,
                                      nodeInput);
    if (serverPtr == NULL)
    {
        ERROR_ReportErrorArgs(
                "DHCP Server: Insufficient memory "
                "server initiation falied for  node %d  at interface %d\n",
                node->nodeId,
                interfaceIndex);
    }
    if (DHCP_DEBUG)
    {
        printf("DHCP Server initialized for  Node %d at interface %d \n",
               node->nodeId,
               interfaceIndex);
    }
    // Read DHCP_STATISTICS enabled or not
    // If DHCP statistics is enabled then the statistics will be printed
    // for  DHCP in .stat file
    serverPtr->dhcpServerStatistics = FALSE;
    IO_ReadBool(node->nodeId,
                MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                                         node,
                                                         node->nodeId,
                                                         interfaceIndex),
                nodeInput,
                "DHCP-STATISTICS",
                &retVal,
                &parameterValue);

    // DHCP-STATISTICS enabled, by default it will not be enabled
    if (retVal && parameterValue == TRUE)
    {
        serverPtr->dhcpServerStatistics = TRUE;
    }

    return;
}
//--------------------------------------------------------------------------
// NAME             : AppDhcpServerNewDhcpServer.
// PURPOSE          : create a new DHCP server data structure, place it
//                    at the beginning of the application list.
// PARAMETERS       :
// + node           : Node*         : The pointer to the node.
// + interfaceIndex : Int32         : interfaceIndex
// + nodeInput      : NodeInput*    : The pointer to configuration
// RETURN           :
// struct appDataDhcpServer* : the pointer to the created DHCP server data
//                             structure NULL if no data structure allocated
//--------------------------------------------------------------------------
struct appDataDhcpServer* AppDhcpServerNewDhcpServer(
    Node* node,
    Int32 interfaceIndex,
    const NodeInput* nodeInput)
{
    struct appDataDhcpServer* dhcpServer = NULL;
    char buf[MAX_STRING_LENGTH] = "";
    BOOL retVal = FALSE;
    BOOL isnodeId = FALSE;
    NodeAddress ipAddress = 0;
    clocktype time = 0;
    Int32 matchType = 0;
    NodeInput dhcpManualAllocData;
    Int32 i = 0;

    // Allocate memory to server pointer
    dhcpServer = (struct appDataDhcpServer*)
        MEM_malloc(sizeof(struct appDataDhcpServer));
    if (dhcpServer == NULL)
    {
        return(NULL);
    }
    memset(dhcpServer, 0, sizeof(struct appDataDhcpServer));

    // Read the configured default lease time for  server
    dhcpServer->defaultLeaseTime = DHCP_SERVER_DEFAULT_DEFAULT_LEASE_TIME;
    IO_ReadString(
        node->nodeId,
        interfaceIndex,
        NetworkIpGetInterfaceAddress(node, interfaceIndex),
        NULL,
        nodeInput,
        "DHCP-SERVER-DEFAULT-LEASE-TIME",
        buf,
        retVal,
        matchType);
    if (retVal == TRUE)
    {
        time = TIME_ConvertToClock(buf);
        if (time == 0)
        {
            MEM_free(dhcpServer);
            ERROR_ReportErrorArgs(
                "Invalid value for  DHCP-SERVER-DEFAULT-LEASE-TIME"
                "at node %d ",
                node->nodeId);
        }
        if (AppDhcpCheckInfiniteLeaseTime(time, nodeInput))
        {
            dhcpServer->defaultLeaseTime = (UInt32)DHCP_INFINITE_LEASE;
        }
        else
        {
            if ((time / SECOND) < DHCP_MINIMUM_LEASE_TIME)
            {
                ERROR_ReportErrorArgs(
                    "DHCP-SERVER-DEFAULT-LEASE-TIME must be greater than "
                    "equal to 12S at interface %d of node %d",
                    interfaceIndex, node->nodeId);
            }

            // Keep time in seconds
            time = time / SECOND;
            dhcpServer->defaultLeaseTime = (UInt32)time;
        }
    }

    // Read the server configured max lease time
    dhcpServer->maxLeaseTime = DHCP_SERVER_DEFAULT_MAX_LEASE_TIME;

    IO_ReadString(
        node->nodeId,
        interfaceIndex,
        NetworkIpGetInterfaceAddress(node, interfaceIndex),
        NULL,
        nodeInput,
        "DHCP-SERVER-MAX-LEASE-TIME",
        buf,
        retVal,
        matchType);
    if (retVal == TRUE)
    {
        time = TIME_ConvertToClock(buf);
        if (time == 0)
        {
            MEM_free(dhcpServer);
            ERROR_ReportErrorArgs(
                    "Invalid value for  "
                    "DHCP-SERVER-MAX-LEASE-TIME at node %d ",
                    node->nodeId);
        }

        if (AppDhcpCheckInfiniteLeaseTime(time, nodeInput))
        {
            dhcpServer->maxLeaseTime = (UInt32)DHCP_INFINITE_LEASE;
        }
        else
        {
            if ((time / SECOND) < DHCP_MINIMUM_LEASE_TIME)
            {
                ERROR_ReportErrorArgs(
                    "DHCP-SERVER-MAX-LEASE-TIME must be greater than equal "
                    "to 12S at interface %d of node %d",
                    interfaceIndex, node->nodeId);
            }

            // Keep time in seconds
            time = time / SECOND;
            dhcpServer->maxLeaseTime = (UInt32)time;
        }
    }

    // Check if max lease time is greater than equal to default lease time
    // check if default lease and max lease are infinite; if both are 
    // infinite then no need to check for greater
    bool infiniteMaxLeaseTime = false;
    bool infiniteDefaultLeaseTime = false;
    if (AppDhcpCheckInfiniteLeaseTime(
            dhcpServer->maxLeaseTime * SECOND, nodeInput))
    {
        infiniteMaxLeaseTime = true;
    }
    if (AppDhcpCheckInfiniteLeaseTime(
            dhcpServer->defaultLeaseTime * SECOND, nodeInput))
    {
        infiniteDefaultLeaseTime = true;
    }
    if (!(infiniteMaxLeaseTime && infiniteDefaultLeaseTime))
    {
        if (dhcpServer->maxLeaseTime < dhcpServer->defaultLeaseTime)
        {
            MEM_free(dhcpServer);
            ERROR_ReportErrorArgs(
                "DHCP-SERVER-MAX-LEASE-TIME of DHCP server is less"
                " than DHCP-SERVER-DEFAULT-LEASE-TIME "
                "at DHCP server configured at node %d at interface %d",
                node->nodeId,
                interfaceIndex);
        }
    }
    // Get starting address of range of address that
    // can be given by DHCP server.This can be provided
    // interface wise only

    IO_ReadString(
        node->nodeId,
        interfaceIndex,
        NetworkIpGetInterfaceAddress(node, interfaceIndex),
        NULL,
        nodeInput,
        "DHCP-SERVER-START-IP-RANGE",
        buf,
        retVal,
        matchType);

    if (retVal == TRUE)
    {
        IO_ParseNodeIdOrHostAddress(buf, &ipAddress, &isnodeId);
        if (isnodeId == FALSE)
        {
            if (ipAddress == 0)
            {
                MEM_free(dhcpServer);
                ERROR_ReportErrorArgs(
                        "Invalid value for DHCP-SERVER-START-IP-RANGE"
                        " at node %d ",
                        node->nodeId);
            }
            (dhcpServer->addressRangeStart).networkType =
                                            MAPPING_GetNetworkType(buf);
            (dhcpServer->addressRangeStart).IPV4 = ipAddress;
        }
        else
        {
            MEM_free(dhcpServer);
            ERROR_ReportErrorArgs(
                    "IP Start range can currently"
                    " be ip address only\n");
        }
    }
    else
    {
        MEM_free(dhcpServer);
        ERROR_ReportErrorArgs(
                "This is a mandatory parameter for DHCP server."
                " Please specify the DHCP-SERVER-START-IP-RANGE"
                " for  node %d at interface %d \n",
                node->nodeId,
                interfaceIndex);
    }

    // Get last address of range of address that
    // can be given by DHCP server.This can be provided
    // interface wise only

    IO_ReadString(
                node->nodeId,
                interfaceIndex,
                NetworkIpGetInterfaceAddress(node, interfaceIndex),
                NULL,
                nodeInput,
                "DHCP-SERVER-END-IP-RANGE",
                buf,
                retVal,
                matchType);
    if (retVal == TRUE)
    {
        IO_ParseNodeIdOrHostAddress(buf, &ipAddress, &isnodeId);
        if (isnodeId == FALSE)
        {
            if (ipAddress == 0)
            {
                MEM_free(dhcpServer);
                ERROR_ReportErrorArgs(
                        "Invalid value for DHCP-SERVER-END-IP-RANGE"
                        "at node %d ",
                        node->nodeId);
            }
            (dhcpServer->addressRangeEnd).networkType =
                                        MAPPING_GetNetworkType(buf);
            (dhcpServer->addressRangeEnd).IPV4 = ipAddress;
        }
        else
        {
            MEM_free(dhcpServer);
            ERROR_ReportErrorArgs(
                    "IP End range can currently"
                    " be ip address only\n");
        }
    }
    else
    {
        MEM_free(dhcpServer);
        ERROR_ReportErrorArgs(
                "This is a mandatory parameter for DHCP server."
                " Please specify the DHCP-SERVER-END-IP-RANGE"
                " for  node %d at interface %d \n",
                node->nodeId,
                interfaceIndex);
    }

    // Check if end IP Address is greater than equal to start IP Address
    if (dhcpServer->addressRangeEnd.IPV4 <
        dhcpServer->addressRangeStart.IPV4)
    {
        MEM_free(dhcpServer);
        ERROR_ReportErrorArgs(
                "\n DHCP-SERVER-END-IP-RANGE of DHCP server is less"
                " than DHCP-SERVER-START-IP-RANGE "
                "at DHCP server configured at node %d at interface %d",
                node->nodeId,
                interfaceIndex);
    }

    // Get default gateway associated with address range.
    // This can be provided
    // interface wise only

    IO_ReadString(
                node->nodeId,
                interfaceIndex,
                NetworkIpGetInterfaceAddress(node, interfaceIndex),
                NULL,
                nodeInput,
                "DHCP-SERVER-DEFAULT-GATEWAY",
                buf,
                retVal,
                matchType);
    if (retVal == TRUE)
    {
        IO_ParseNodeIdOrHostAddress(buf, &ipAddress, &isnodeId);
        if (isnodeId == FALSE)
        {
            if (ipAddress == 0)
            {
                MEM_free(dhcpServer);
                ERROR_ReportErrorArgs(
                    "Invalid value for  DHCP-SERVER-DEFAULT-GATEWAY"
                    "at node %d ",
                    node->nodeId);
            }
            (dhcpServer->defaultGateway).networkType =
                                    MAPPING_GetNetworkType(buf);
            (dhcpServer->defaultGateway).IPV4 = ipAddress;
        }
        else
        {
            MEM_free(dhcpServer);
            ERROR_ReportErrorArgs(
                    "Default gteway currently"
                    " be ip address only\n");
        }
    }
    else
    {
        MEM_free(dhcpServer);
        ERROR_ReportErrorArgs(
                "This is a mandatory parameter for  DHCP server."
                " Please specify the DHCP-SERVER-DEFAULT-GATEWAY"
                " for  node %d at interface %d \n",
                node->nodeId,
                interfaceIndex);
    }

    // Get subnet mask associated with address range.
    // This can be provided
    // interface wise only

    IO_ReadString(
            node->nodeId,
            interfaceIndex,
            NetworkIpGetInterfaceAddress(node,interfaceIndex),
            NULL,
            nodeInput,
            "DHCP-SERVER-SUBNET-MASK",
            buf,
            retVal,
            matchType);
    if (retVal == TRUE)
    {
        IO_ParseNodeIdOrHostAddress(buf, &ipAddress, &isnodeId);
        if (isnodeId == FALSE)
        {
            if (ipAddress == 0)
            {
                MEM_free(dhcpServer);
                ERROR_ReportErrorArgs(
                        "Invalid value for  DHCP-SERVER-SUBNET-MASK"
                        "at node %d ",
                        node->nodeId);
            }
            (dhcpServer->subnetMask).networkType =
                                        MAPPING_GetNetworkType(buf);
            (dhcpServer->subnetMask).IPV4 = ipAddress;
        }
        else
        {
            MEM_free(dhcpServer);
            ERROR_ReportErrorArgs(
                    "Subnet mask currently"
                    " be ip address only\n");
        }
    }
    else
    {
        MEM_free(dhcpServer);
        ERROR_ReportErrorArgs(
               "This is a mandatory parameter for  DHCP server."
               " Please specify the DHCP-SERVER-SUBNET-MASK"
               " for  node %d at interface %d \n",
               node->nodeId,
               interfaceIndex);
    }

    // Get primary DNS server for  address range.This can be provided
    // interface wise only

    IO_ReadString(
            node->nodeId,
            interfaceIndex,
            NetworkIpGetInterfaceAddress(node,interfaceIndex),
            NULL,
            nodeInput,
            "DHCP-SERVER-PRIMARY-DNS-SERVER",
            buf,
            retVal,
            matchType);
    if (retVal == TRUE)
    {
        IO_ParseNodeIdOrHostAddress(buf, &ipAddress, &isnodeId);
        if (isnodeId == FALSE)
        {
            if (ipAddress == 0)
            {
                MEM_free(dhcpServer);
                ERROR_ReportErrorArgs(
                    "Invalid value for  DHCP-SERVER-PRIMARY-DNS-SERVER"
                    "at node %d ",
                    node->nodeId);
            }
            (dhcpServer->primaryDNSServer).networkType =
                MAPPING_GetNetworkType(buf);
            (dhcpServer->primaryDNSServer).IPV4 = ipAddress;
        }
        else
        {
            MEM_free(dhcpServer);
            ERROR_ReportErrorArgs(
                    "DHCP-SERVER-PRIMARY-DNS-SERVER can currently"
                    " be ip address only\n");
        }
    }
    else
    {
        MEM_free(dhcpServer);
        ERROR_ReportErrorArgs(
                "This is a mandatory parameter for  DHCP server."
                " Please specify the DHCP-SERVER-PRIMARY-DNS-SERVER"
                " for  node %d at interface %d \n",
                node->nodeId,
                interfaceIndex);
    }

    // Get secondary DNS server list This can be provided
    // interface wise only. This is optional parameter


    dhcpServer->listSecDnsServer = NULL;
    IO_ReadString(
            node->nodeId,
            interfaceIndex,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            NULL,
            nodeInput,
            "DHCP-SERVER-SECONDARY-DNS-SERVERS",
            buf,
            retVal,
            matchType);
    if (retVal == TRUE)
    {
        // Initialize the list of secondary DNS servers
        dhcpServer->listSecDnsServer = new std::list<Address*>;

        // Read the list of DNS servers
        char localBuffer[MAX_STRING_LENGTH] = "";
        char* stringPtr = buf;
        while (*stringPtr != '\0')
        {
            IO_GetDelimitedToken(
                                localBuffer,
                                stringPtr,
                                "(,) ",
                                &stringPtr);

            IO_ParseNodeIdOrHostAddress(localBuffer, &ipAddress, &isnodeId);
            if (isnodeId == FALSE)
            {
                if (ipAddress == 0)
                {
                    std::list<Address*>::iterator it;
                    for (it = dhcpServer->listSecDnsServer->begin();
                         it != dhcpServer->listSecDnsServer->end();
                         it++)
                    {
                        MEM_free(*it);
                    }
                    delete(dhcpServer->listSecDnsServer);
                    MEM_free(dhcpServer);
                    ERROR_ReportErrorArgs(
                            "Invalid value for "
                            "DHCP-SERVER-SECONDARY-DNS-SERVER"
                            "at node %d ",
                            node->nodeId);
                }
                Address* dnsServerAddr;
                dnsServerAddr = (Address*)MEM_malloc(sizeof(Address));
                dnsServerAddr->networkType =
                        MAPPING_GetNetworkType(localBuffer);
                dnsServerAddr->IPV4 = ipAddress;

                // Add to linked list
                dhcpServer->listSecDnsServer->push_back(dnsServerAddr);
            }
            else
            {
                MEM_free(dhcpServer);
                ERROR_ReportErrorArgs(
                        "DHCP-SERVER-SECONDARY-DNS-SERVERS"
                        "can currently be ip address only\n");
            }
        }
    }

    // Initialize the List of leases
    dhcpServer->serverLeaseList = new std::list<struct dhcpLease*>;
    // Initialize the list
    dhcpServer->manualAllocationList =
                        new std::list<struct appDhcpServerManualAlloc*>;
    dhcpServer->numManualLeaseInRange = 0;
    // Read the manual allocation file if present
    IO_ReadCachedFileInstance(
                        node->nodeId,
                        NetworkIpGetInterfaceAddress(node, interfaceIndex),
                        nodeInput,
                        "DHCP-SERVER-MANUAL-ALLOCATION-CONFIG-FILE",
                        interfaceIndex,
                        TRUE,
                        &retVal,
                        &dhcpManualAllocData);

    if (retVal)
    {
        char localBuffer[MAX_STRING_LENGTH] = "";
        struct appDhcpServerManualAlloc* manualAlloc;

        for (i = 0 ; i < dhcpManualAllocData.numLines; i++)
        {
            manualAlloc =
                    (struct appDhcpServerManualAlloc*)
                    MEM_malloc(sizeof(struct appDhcpServerManualAlloc));
            char* stringPtr = dhcpManualAllocData.inputStrings[i];
            IO_GetDelimitedToken(
                                localBuffer,
                                stringPtr,
                                "( )",
                                &stringPtr);
            IO_ParseNodeIdOrHostAddress(localBuffer, &ipAddress, &isnodeId);
            if (isnodeId == TRUE)
            {
                manualAlloc->incomingInterface = ipAddress;
            }
            else
            {
                MEM_free(manualAlloc);
                MEM_free(dhcpServer);
                ERROR_ReportErrorArgs("Error in manual allocation file");
            }
            IO_GetDelimitedToken(
                                localBuffer,
                                stringPtr,
                                "( )",
                                &stringPtr);
            IO_ParseNodeIdOrHostAddress(localBuffer, &ipAddress, &isnodeId);
            if (isnodeId == TRUE)
            {
                manualAlloc->nodeId = ipAddress;
            }
            else
            {
                MEM_free(manualAlloc);
                MEM_free(dhcpServer);
                ERROR_ReportErrorArgs("Error in manual allocation file");
            }
            IO_GetDelimitedToken(
                                localBuffer,
                                stringPtr,
                                "( )",
                                &stringPtr);
            IO_ParseNodeIdOrHostAddress(localBuffer, &ipAddress, &isnodeId);
            if (isnodeId == FALSE)
            {
                if (ipAddress == 0)
                {
                    MEM_free(manualAlloc);
                    MEM_free(dhcpServer);
                    ERROR_ReportErrorArgs(
                            "Invalid value for  "
                            "ip address in manual allocation file"
                            "at node %d ",
                            node->nodeId);
                }
                memset(&manualAlloc->ipAddress, 0, sizeof(Address));
                manualAlloc->ipAddress.networkType =
                    MAPPING_GetNetworkType(localBuffer);
                manualAlloc->ipAddress.IPV4 = ipAddress;
            }
            else
            {
                MEM_free(manualAlloc);
                MEM_free(dhcpServer);
                ERROR_ReportErrorArgs("Error in manual allocation file");
            }

            // insert into linked list
            dhcpServer->manualAllocationList->push_back(manualAlloc);
            // check whether this manual lease lies in
            // the address range
            if ((manualAlloc->ipAddress.IPV4 <=
                dhcpServer->addressRangeEnd.IPV4) &&
                (manualAlloc->ipAddress.IPV4 >=
                dhcpServer->addressRangeStart.IPV4))
            {
                dhcpServer->numManualLeaseInRange++;
            }
        }
    }

    // calculate the total lease that can be allocated at this server
    // this should be the (num of lease in range) + (num manual lease)
    //  -(num of manual lease in range)
    // calculate num of manual lease in range
    dhcpServer->numTotalLease = ((dhcpServer->addressRangeEnd.IPV4 -
                                dhcpServer->addressRangeStart.IPV4) + 1) +
                                dhcpServer->manualAllocationList->size() -
                                dhcpServer->numManualLeaseInRange;

    // IP- address of server should not be allocated and thus is 
    // made UNAVAILABLE from list of addresses
    // Check if servers's own IP lies in the range
    // If that is the case then server's address should
    // be offered and kept as UNAVAILABLE.
    NodeAddress serverIpAddress = 
       NetworkIpGetInterfaceAddress(node, interfaceIndex);
    if (serverIpAddress <= dhcpServer->addressRangeEnd.IPV4 &&
        serverIpAddress >= dhcpServer->addressRangeStart.IPV4)
    {
        // make that lease UNAVAILABLE and insert into lease
        dhcpLease* lease = 
            (struct dhcpLease*)MEM_malloc(sizeof(struct dhcpLease));
        memset(lease, 0, sizeof(struct dhcpLease));
        lease->clientIdentifier[0] = '\0'; 
        (lease->ipAddress).networkType = NETWORK_IPV4; 
        (lease->ipAddress).IPV4 = serverIpAddress;
        (lease->serverId).networkType = NETWORK_IPV4;
        (lease->serverId).IPV4 = serverIpAddress;
   
        lease->status = DHCP_UNAVAILABLE;

        // Insert the lease to list
        dhcpServer->serverLeaseList->push_back(lease);

    }
   
    // Set other parameters for  DHCP server
    // Set the interface address for  server
    (dhcpServer->interfaceAddress).networkType = NETWORK_IPV4;

    (dhcpServer->interfaceAddress).IPV4 =
        NetworkIpGetInterfaceAddress(node, interfaceIndex);
    dhcpServer->sourcePort = DHCP_SERVER_PORT;
    dhcpServer->numDiscoverRecv = 0;
    dhcpServer->numOfferSent = 0;
    dhcpServer->numOfferReject = 0;
    dhcpServer->numRequestRecv = 0;
    dhcpServer->numAckSent = 0;
    RANDOM_SetSeed(dhcpServer->jitterSeed,
                   node->globalSeed,
                   node->nodeId,
                   NETWORK_PROTOCOL_IP,
                   interfaceIndex);
    dhcpServer->dataPacket = NULL;
    dhcpServer->dhcpServerStatistics = TRUE;
    // Register the server
    APP_RegisterNewApp(node, APP_DHCP_SERVER, dhcpServer);
    return(dhcpServer);
}


//--------------------------------------------------------------------------
// NAME                     : AppDhcpClientGetDhcpClient.
// PURPOSE                  : search for a DHCP client data structure.
// PARAMETERS               :
// + node                   : Node* : The pointer to the node.
// + interfaceIndex         : Int32 : Interface index which act as client
// RETURN                   :
// struct appDataDhcpClient : the pointer to the DHCP client data structure,
//                            NULL if nothing found.
//--------------------------------------------------------------------------
struct appDataDhcpClient* AppDhcpClientGetDhcpClient(
    Node* node,
    Int32 interfaceIndex)
{
    AppInfo* appList = node->appData.appPtr;
    struct appDataDhcpClient* dhcpClient = NULL;
    if (interfaceIndex < 0 ||
        interfaceIndex >= node->numberInterfaces)
    {
        // invalid interface index 
        // cannot continue further
        if (DHCP_DEBUG)
        {
            printf("Node %d in function AppDhcpClientGetDhcpClient: "
                   "invalid interface index", node->nodeId);
        }
        return (NULL);
    }

    // Get the client pointer from application list
    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_DHCP_CLIENT)
        {
            dhcpClient = (struct appDataDhcpClient*)appList->appDetail;
            if (dhcpClient->interfaceIndex == interfaceIndex)
            {
                return(dhcpClient);
            }
        }
    }
    return(NULL);
}

//--------------------------------------------------------------------------
// NAME                         : AppDhcpServerGetDhcpServer
// PURPOSE                      : search for a DHCP Server data structure.
// PARAMETERS                   :
// + node                       : Node*    : pointer to the node.
// + interfaceIndex             : Int32    : interface index which act
//                                          as Server
// RETURN                       :
// struct appDataDhcpServer*    : the pointer to the DHCP server data
//                                structure, NULL if nothing found.
//--------------------------------------------------------------------------
struct appDataDhcpServer* AppDhcpServerGetDhcpServer(
    Node* node,
    Int32 interfaceIndex)
{
    Address interfaceAddress;

    if (interfaceIndex < 0 ||
        interfaceIndex >= node->numberInterfaces)
    {
        // invalid interface index 
        // cannot continue further
        if (DHCP_DEBUG)
        {
            printf("Node %d in function AppDhcpServerGetDhcpServer: "
                   "invalid interface index", node->nodeId);
        }
        return (NULL);
    }
    // Get the interface address
    interfaceAddress.IPV4 =
        NetworkIpGetInterfaceAddress(node, interfaceIndex);
    interfaceAddress.networkType = NETWORK_IPV4;

    AppInfo* appList = node->appData.appPtr;
    struct appDataDhcpServer* dhcpServer = NULL;

    // Get the server pointer from application list
    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_DHCP_SERVER)
        {
            dhcpServer = (struct appDataDhcpServer*)appList->appDetail;
            if (((dhcpServer->interfaceAddress).IPV4) ==
                  interfaceAddress.IPV4)
            {
                return(dhcpServer);
            }
        }
    }
    return(NULL);
}

//---------------------------------------------------------------------------
// NAME         : AppLayerDhcpClient.
// PURPOSE      : Models the behaviour of DHCP Client on receiving the
//                message encapsulated in msg.
// PARAMETERS   :
// + node       : Node*     : The pointer to the node.
// + msg        : Message*  : message received by the layer
// RETURN       : none.
//---------------------------------------------------------------------------
void AppLayerDhcpClient(
    Node* node,
    Message* msg)
{
    struct appDataDhcpClient* clientPtr = NULL;
    UdpToAppRecv* info = NULL;

    // Get the interface which sent the message
    Int32 interfaceIndex = ANY_INTERFACE;
    if (msg->eventType == MSG_APP_FromTransport)
    {
        info = (UdpToAppRecv*)MESSAGE_ReturnInfo(msg);
        interfaceIndex = info->incomingInterfaceIndex;
    }
    else
    {
        interfaceIndex = *((Int32*)MESSAGE_ReturnInfo(msg));
    }
    // Get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(node, interfaceIndex);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d at interface %d Not a DHCP client \n",
                    node->nodeId,
                    interfaceIndex);
        }
        MESSAGE_Free(node, msg);
        return;
    }
    switch (msg->eventType)
    {
        case MSG_APP_DHCP_InitEvent:
        {
            AppDhcpClientStateInit(
                               node,
                               interfaceIndex);
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_DHCP_InformEvent:
        {
            AppDhcpClientStateInform(node, interfaceIndex);
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_DHCP_TIMEOUT :
        {
            // Any DHCP client packet has timedout
            if (AppDhcpClientHandleTimeout(node, msg))
            {
                MESSAGE_Free(node, msg);
            }
            break;
        }
        case MSG_APP_FromTransport:
        {
            // DHCP protocol packet received
            AppDhcpClientHandleDhcpPacket(node,
                                          msg);
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_DHCP_ReleaseEvent:
        {
            AppDhcpClientHandleReleaseEvent(node, msg);
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_DHCP_CLIENT_RENEW:
        {
            AppDhcpClientHandleRenewEvent(node, msg);
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_DHCP_CLIENT_REBIND:
        {
            AppDhcpClientHandleRebindEvent(node, msg);
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_DHCP_LEASE_EXPIRE:
        {
            AppDhcpClientHandleLeaseExpiry(node, msg);
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_DHCP_InvalidateClient:
        {
            // Make address state as INVALID
            NodeAddress ipv4Address =
                MAPPING_GetSubnetMaskForInterface(node,
                                                  node->nodeId,
                                                  interfaceIndex);
            Address sourceAddress;
            sourceAddress.IPV4 = NetworkIpGetInterfaceAddress(
                                                            node,
                                                            interfaceIndex);
            sourceAddress.networkType =
                ResolveNetworkTypeFromSrcAndDestNodeId(
                                                node,
                                                node->nodeId,
                                                node->nodeId);
            NetworkIpProcessDHCP(
                            node,
                            interfaceIndex,
                            &(sourceAddress) ,
                            ipv4Address,
                            LEASE_EXPIRY,
                            sourceAddress.networkType);
            if (clientPtr->dataPacket != NULL)
            {
                MEM_free(clientPtr->dataPacket);
            }
            break;
        }
        default:
        {
            ERROR_ReportErrorArgs(
                    "DHCP Client: Incorrect event %d for  node %d\n",
                        msg->eventType, node->nodeId);
            MESSAGE_Free(node, msg);
            break;
        }
    }
}

//---------------------------------------------------------------------------
// NAME             : AppDhcpClientStateInit
// PURPOSE          : Models the behaviour of client when it enters
//                    INIT state
// PARAMETERS       :
// + node           : Node*    : pointer to the node which enters INIt state
// + interfaceIndex : Int32    : interface of node which enters INIT state
// RETURN           : NONE
// --------------------------------------------------------------------------
void AppDhcpClientStateInit(
    Node* node,
    Int32 interfaceIndex)
{
    struct appDataDhcpClient* clientPtr = NULL;
    struct dhcpData* discoverData = NULL;

    if (DHCP_DEBUG)
    {
        printf("\n Client enters into INIT state. Performing DHCP client"
               " Init for  node %d at interface %d \n",
               node->nodeId,
               interfaceIndex);
    }

    clientPtr = AppDhcpClientGetDhcpClient(
                                    node,
                                    interfaceIndex);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d at interface %d not a DHCP client \n",
                   node->nodeId,
                   interfaceIndex);
        }
        return;
    }

    // Create the discover packet
    discoverData = AppDhcpClientMakeDiscover(
                                        clientPtr,
                                        node,
                                        interfaceIndex);
    if (discoverData == NULL)
    {
        ERROR_ReportErrorArgs(
                "DHCP Client: Insufficient memory "
                "DISCOVER packet creation falied for  node %d\n",
                node->nodeId);
    }

    // Record the XID for  this client before sending packet
    clientPtr->recentXid = discoverData->xid;

    if (DHCP_DEBUG)
    {
        printf("Broadcasting DHCPDISCOVER from node %d at interface %d \n",
               node->nodeId,
               interfaceIndex);
        clocktype simulationTime = node->getNodeTime();
        char simulationTimeStr[MAX_STRING_LENGTH] = "";
        TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
        printf("Time = %s \n", simulationTimeStr);
    }

    // Broadcast the DISCOVER packet
    AppDhcpSendDhcpPacket(
                        node,
                        interfaceIndex,
                        APP_DHCP_CLIENT,
                        ANY_ADDRESS,
                        APP_DHCP_SERVER,
                        clientPtr->tos,
                        discoverData);

    clientPtr->numDiscoverSent++;

    if (clientPtr->dataPacket != NULL)
    {
        MEM_free(clientPtr->dataPacket);
    }
    clientPtr->dataPacket = discoverData;

    // schedule re-retrasmission for DISCOVER packet
    clocktype timerDelay = (clocktype) ((clientPtr->timeout
                      * (clientPtr->retryCounter))
                      + RANDOM_erand(clientPtr->jitterSeed));

    Message* message = MESSAGE_Alloc(node,
                                     APP_LAYER,
                                     APP_DHCP_CLIENT,
                                     MSG_APP_DHCP_TIMEOUT);
    MESSAGE_InfoAlloc(node,
                      message,
                      sizeof(Int32));

    Int32* info = (Int32*)MESSAGE_ReturnInfo(message);
    *(info) = interfaceIndex;

    // Store the timeout message
    clientPtr->timeoutMssg = message;

    // Change state of DHCP client
    clientPtr->state = DHCP_CLIENT_SELECT;

    if (DHCP_DEBUG)
    {
        char simulationTimeStr[MAX_STRING_LENGTH] = "";
        TIME_PrintClockInSecond(timerDelay, simulationTimeStr);
        printf("Timout of DISCOVER after time  = %s \n", simulationTimeStr);
    }
    MESSAGE_Send(node, message, timerDelay);
    return;
}

//--------------------------------------------------------------------------
// NAME:           : AppDhcpClientMakeDiscover.
// PURPOSE:        : make DHCPDISCOVER packet to send
// PARAMETERS:
// + clientPtr     : struct appDataDhcpClient*: pointer to the client data.
// + node          : Node*                    : client node.
// +interfaceIndex : Int32                    : interface that will send
//                                              the DHCPDISCOVER packet
// RETURN:
// struct dhcpData*: pointer to the DHCPDISCOVER packet created.
//                   NULL if nothing found.
//---------------------------------------------------------------------------

struct dhcpData* AppDhcpClientMakeDiscover(
    struct appDataDhcpClient* clientPtr,
    Node* node,
    Int32 interfaceIndex)
{
    struct dhcpData* discoverData = NULL;
    UInt8 val = 0;

    // Allocate memory for DISCOVER packet
    discoverData = (struct dhcpData*)MEM_malloc(sizeof(struct dhcpData));
    if (discoverData == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("memory not allocated for  DHCPData at node %d"
                    " interface %d \n",
                   node->nodeId,
                   interfaceIndex);
        }
        return(NULL);
    }

    memset(discoverData, 0, sizeof(struct dhcpData));

    /* Fields as used for  DISCOVER
      ’op’ BOOTREQUEST
      ’htype’ (From "Assigned Numbers" RFC)
      ’hlen’ (Hardware address length in octets)
      ’hops’ 0
      ’xid’ selected by client
      ’secs’ 0 or seconds since DHCP process started
      ’flags’ Set ’BROADCAST’if client broadcast reply
      ’ciaddr’ 0 (DHCPDISCOVER)
      ’yiaddr’ 0
      ’siaddr’ 0
      ’giaddr’ 0
      ’chaddr’ client’s hardware address
      ’sname’ options, if indicated ’sname/file’otherwise unused
      ’file’ options, if indicated in ’sname/file’ otherwise unused
      Requested IP address MAY (DISCOVER)
      IP address lease time MAY (DISCOVER)
      Use ’file’/’sname’ fields MAY MAY MAY
      DHCP message type DHCPDISCOVER
      Client identifier MAY
      Vendor class identifier MAY
      Server identifier MUST NOT
      Parameter request list MAY
      Maximum message size MAY
      Message SHOULD NOT
      Site-specific MAY
      All others MAY */

    discoverData->op = BOOTREQUEST;
    discoverData->htype = (UInt8)clientPtr->hardwareAddress.hwType;
    discoverData->hlen = (UInt8)clientPtr->hardwareAddress.hwLength;
    discoverData->hops = 0;
    discoverData->xid = RANDOM_nrand(clientPtr->jitterSeed);
    discoverData->secs = (UInt16)(node->getNodeTime() / SECOND);

    // For QualNet this will always be broadcast
    discoverData->flags = DHCP_BROADCAST;
    discoverData->ciaddr = 0;
    discoverData->yiaddr = 0;
    discoverData->siaddr = 0;
    discoverData->giaddr = 0;
    memcpy(discoverData->chaddr,
           clientPtr->hardwareAddress.byte,
           clientPtr->hardwareAddress.hwLength);
    discoverData->sname[0] = '\0';
    discoverData->file[0] = '\0';

    // Setting options part of DISCOVER packet
    val = DHCPDISCOVER;
    dhcpSetOption(discoverData->options, DHO_DHCP_MESSAGE_TYPE, 1, &val);

    if (clientPtr->lastIP.IPV4 != 0)
    {
        UInt32 val1 = clientPtr->lastIP.IPV4;
        dhcpSetOption(
            discoverData->options,
            DHO_DHCP_REQUESTED_ADDRESS,
            DHCP_ADDRESS_OPTION_LENGTH,
            &val1);
    }
    if (clientPtr->dhcpLeaseTime)
    {
        UInt32 val1 = clientPtr->dhcpLeaseTime;
        dhcpSetOption(
            discoverData->options,
            DHO_DHCP_LEASE_TIME,
            DHCP_LEASE_TIME_OPTION_LENGTH,
            &val1);
    }

    if (clientPtr->dhcpClientIdentifier[0] != '\0')
    {
        UInt8 val1 = (UInt8)strlen(clientPtr->dhcpClientIdentifier);
        dhcpSetOption(
             discoverData->options,
             DHO_DHCP_CLIENT_IDENTIFIER,
             val1,
             &(clientPtr->dhcpClientIdentifier));
    }
    return(discoverData);
}
//--------------------------------------------------------------------------
// NAME:            : AppDhcpRelayInit.
// PURPOSE:         : Initialize DHCP relay agent data structure.
// PARAMETERS:
// + node           : Node*       : The pointer to the node.
// + interfaceIndex : Int32       : interfaceIndex
// + nodeInput      : NodeInput*  : The pointer to configuration
// RETURN:          : none.
// --------------------------------------------------------------------------
void AppDhcpRelayInit(
    Node* node,
    Int32 interfaceIndex,
    const NodeInput* nodeInput)
{
    struct appDataDhcpRelay* relayPtr = NULL;
    BOOL parameterValue = FALSE;
    BOOL retVal = FALSE;
    Int32 matchType = 0;

    if (DHCP_DEBUG)
    {
        printf("Initilizing DHCP Relay Agent on interface %d of"
                "node %d \n",
                interfaceIndex,
                node->nodeId);
    }

    // Create new relay pointer
    relayPtr = AppDhcpRelayNewDhcpRelay(
                    node,
                    interfaceIndex,
                    nodeInput);
    if (relayPtr == NULL)
    {
        ERROR_ReportErrorArgs(
                "\n DHCP Relay: Insufficient memory "
                "DHCP Relay initiation failed for  node %d at interface %d",
               node->nodeId,
               interfaceIndex);
    }
    if (DHCP_DEBUG)
    {
        printf("DHCP Relay initialized for  Node %d at interface %d \n",
               node->nodeId,
               interfaceIndex);
    }
    // Read DHCP_STATISTICS enabled or not
    // If DHCP statistics is enabled then the statistics will be printed
    // for  DHCP in .stat file
    relayPtr->dhcpRelayStatistics = FALSE;
    IO_ReadBool(node->nodeId,
                MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                                         node,
                                                         node->nodeId,
                                                         interfaceIndex),
                nodeInput,
                "DHCP-STATISTICS",
                &retVal,
                &parameterValue);

    // DHCP-STATISTICS enabled, by default it will not be enabled
    if (retVal && parameterValue == TRUE)
    {
        relayPtr->dhcpRelayStatistics = TRUE;
    }

    return;
}

//---------------------------------------------------------------------------
// NAME:            : AppDhcpRelayNewDhcpRelay.
// PURPOSE:         : create a new DHCP Relay data structure, place it
//                    at the beginning of the application list.
// PARAMETERS:
// + node           : Node*         : The pointer to the node.
// + interfaceIndex : Int32         : interfaceIndex
// + nodeInput      : NodeInput*    : The pointer to configuration
// RETURN:
// struct appDataDhcpRelay* : the pointer to the created DHCP Relay data
//                            structure, NULL if no data structure allocated.
//---------------------------------------------------------------------------
struct appDataDhcpRelay* AppDhcpRelayNewDhcpRelay(
    Node* node,
    Int32 interfaceIndex,
    const NodeInput* nodeInput)
{
    struct appDataDhcpRelay* dhcpRelay = NULL;
    char buf[MAX_STRING_LENGTH] = "";
    BOOL retVal = FALSE;
    Int32 matchType = 0;
    BOOL isnodeId = FALSE;
    NodeAddress ipAddress = 0;

    // Allocate memory to relay agent pointer
    dhcpRelay = (struct appDataDhcpRelay*)
        MEM_malloc(sizeof(struct appDataDhcpRelay));
    if (dhcpRelay == NULL)
    {
        return(NULL);
    }
    memset(dhcpRelay, 0, sizeof(struct appDataDhcpRelay));
    dhcpRelay->interfaceIndex = interfaceIndex;

    // Get Server IP Addresses list configured
    IO_ReadString(
        node->nodeId,
        interfaceIndex,
        NetworkIpGetInterfaceAddress(node, interfaceIndex),
        NULL,
        nodeInput,
        "DHCP-RELAY-SERVER-ADDRESS",
        buf,
        retVal,
        matchType);
    if (retVal)
    {
        // Initialize the list of DHCP servers
        dhcpRelay->serverAddrList = new std::list<Address*>;

        // Read the list of DHCP servers
        char localBuffer[MAX_STRING_LENGTH] = "";
        char* stringPtr = buf;
        while (*stringPtr != '\0')
        {
            IO_GetDelimitedToken(
                                localBuffer,
                                stringPtr,
                                "(,) ",
                                &stringPtr);

            IO_ParseNodeIdOrHostAddress(
                localBuffer,
                &ipAddress,
                &isnodeId);
            if (isnodeId == FALSE)
            {
                if (ipAddress == 0)

                {
                    if (!dhcpRelay->serverAddrList->empty())
                    {
                        list<Address*>::iterator it;
                        for (it = dhcpRelay->serverAddrList->begin();
                             it != dhcpRelay->serverAddrList->end();
                             it++)
                        {
                            delete(*it);
                        }
                    }
                    delete (dhcpRelay->serverAddrList);
                    MEM_free(dhcpRelay);
                    ERROR_ReportErrorArgs(
                            "Invalid value for "
                            "DHCP-RELAY-SERVER-ADDRESS"
                            " at node %d ",
                            node->nodeId);
                }
                Address* dhcpServerAddr = NULL;
                dhcpServerAddr = (Address*)MEM_malloc(sizeof(Address));
                memset(dhcpServerAddr, 0, sizeof(Address));
                dhcpServerAddr->networkType =
                    MAPPING_GetNetworkType(localBuffer);
                dhcpServerAddr->IPV4 = ipAddress;

                // Add to list
                dhcpRelay->serverAddrList->push_back(dhcpServerAddr);
            }
            else
            {
                if (!dhcpRelay->serverAddrList->empty())
                {
                    list<Address*>::iterator it;
                    for (it = dhcpRelay->serverAddrList->begin();
                         it != dhcpRelay->serverAddrList->end();
                         it++)
                    {
                        delete(*it);
                    }
                }
                delete (dhcpRelay->serverAddrList);
                MEM_free(dhcpRelay);
                ERROR_ReportErrorArgs(
                        "DHCP-SERVER-ADDRESS"
                        "can currently be ip address only\n");
            }
        }
    }
    else
    {
        MEM_free(dhcpRelay);
        ERROR_ReportErrorArgs(
            "This is a mandatory parameter for  DHCP relay."
            " Please specify the DHCP-RELAY-SERVER-ADDRESS"
            " for  node %d at interface %d \n",
            node->nodeId,
            interfaceIndex);
    }
    dhcpRelay->dataPacket = NULL;

    // Register the relay agent
    APP_RegisterNewApp(node, APP_DHCP_RELAY, dhcpRelay);
    return(dhcpRelay);
}

//---------------------------------------------------------------------------
// NAME:         : AppLayerDhcpRelay.
// PURPOSE:      : Models the behaviour of DHCP Relay on receiving the
//                 message encapsulated in msg.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppLayerDhcpRelay(
    Node* node,
    Message* msg)
{
    switch (msg->eventType)
    {
        case MSG_APP_FromTransport:
        {
            AppDhcpRelayHandleDhcpPacket(node, msg);
            break;
        }
        default:
        {
            if (DHCP_DEBUG)
            {
                printf("Incorrect packet received at node %d \n",
                       node->nodeId);
            }
            break;
        }
    }
}

//---------------------------------------------------------------------------
// NAME:        : AppDhcpServerFinalize.
// PURPOSE:     : Collect statistics of a DHCP Server session.
// PARAMETERS:
// + node       : Node*    : pointer to the node.
// RETURN       : NONE
//---------------------------------------------------------------------------
void AppDhcpServerFinalize(Node* node)
{
    Address interfaceAddress;
    Int32 i;
    struct appDhcpServerManualAlloc* manualAlloc = NULL;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (DHCP_DEBUG)
        {
            printf("DHCP Server finalizing at Node %d at interface %d \n",
                   node->nodeId,
                   i);
        }
        AddressMapType* map = node->partitionData->addressMapPtr;
        NetworkProtocolType networkProtocolType =
                MAPPING_GetNetworkProtocolTypeForInterface(
                           map,
                           node->nodeId,
                           i);
        NetworkType networkType = NETWORK_IPV4;
        if (networkProtocolType != IPV4_ONLY &&
            networkProtocolType != DUAL_IP)
        {
            //error
            ERROR_ReportErrorArgs(
                    "Node %d : DHCP only supported for  IPV4 network\n",
                    node->nodeId);
        }
        if (networkProtocolType == IPV4_ONLY)
        {
            networkType = NETWORK_IPV4;
        }
        else if (networkProtocolType == DUAL_IP)
        {
            networkType = NETWORK_DUAL;
        }
        interfaceAddress.IPV4 =
            MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                               node,
                                               node->nodeId,
                                               i);
        interfaceAddress.networkType = networkType;

        struct appDataDhcpServer* serverPtr = NULL;
        AppInfo* appList = node->appData.appPtr;
        AppInfo* tmpAppList = NULL;
        struct appDataDhcpServer* dhcpServer = NULL;
        for (; appList != NULL; appList = appList->appNext)
        {
            if (appList->appType == APP_DHCP_SERVER)
            {
                dhcpServer = (struct appDataDhcpServer*) appList->appDetail;
                if ((dhcpServer != NULL) &&
                    ((dhcpServer->interfaceAddress).IPV4) ==
                       interfaceAddress.IPV4)
                {
                    serverPtr = dhcpServer;
                    tmpAppList = appList;
                    break;
                }
            }
        }
        if (serverPtr == NULL)
        {
            continue;
        }
        struct dhcpLease* IPLease = NULL;
        list<struct dhcpLease*>::iterator it;
        // calculate AVAILABLE lease
        // lease will be AVAILABLE if they are in range and not in manual
        // list
        // num of AVAILABLE = AVAILABLE lease in range -
        //                    manual lease in range
        for (Int32 k = serverPtr->addressRangeStart.IPV4;
             k <= serverPtr->addressRangeEnd.IPV4; ++k)
        {
            // check if this ip is in manual list; if present then it is
            // not available
            bool isAvailable = TRUE;
            Address leaseAddress;
            SetIPv4AddressInfo(&leaseAddress, k);
            if (AppDhcpCheckIfIpInManualAllocationList(
                                                serverPtr,
                                                leaseAddress))
            {
                isAvailable =  FALSE;
            }
            // check if ip-address present in lease list and not AVAILABLE;
            // if present and not in AVAILABLE state then it is not
            // AVAILABLE
            else if (!serverPtr->serverLeaseList->empty())
            {
                for (it = serverPtr->serverLeaseList->begin();
                     it != serverPtr->serverLeaseList->end();
                     ++it)
                {
                    IPLease = *it;
                    // if lease present in the list and not available then
                    // lease is used and not available
                    if (IPLease->ipAddress.IPV4 == k &&
                        IPLease->status != DHCP_AVAILABLE)
                    {
                        isAvailable = FALSE;
                        break;
                    }
                }
            }
            if (isAvailable == TRUE)
            {
                serverPtr->numAvailableLease++;
            }
        }
        // calculate other leases count
        for (it = serverPtr->serverLeaseList->begin();
             it != serverPtr->serverLeaseList->end();
             it++)
        {
            IPLease = *it;
            if (IPLease->macAddress.byte != NULL)
            {
                MEM_free(IPLease->macAddress.byte);
                IPLease->macAddress.byte = NULL;
            }
            if (IPLease->listOfSecDNSServer != NULL)
            {
                if (!IPLease->listOfSecDNSServer->empty())
                {
                    list<Address*>::iterator it1;
                    for (it1 = IPLease->listOfSecDNSServer->begin();
                         it1 != IPLease->listOfSecDNSServer->end();
                         it1++)
                    {
                        MEM_free(*it1);
                    }
                    delete(IPLease->listOfSecDNSServer);
                    IPLease->listOfSecDNSServer = NULL;
                }
            }
            if (AppDhcpCheckIfIpInManualAllocationList(
                                                serverPtr,
                                                IPLease->ipAddress))
            {
                if (IPLease->status == DHCP_UNAVAILABLE)
                {
                    serverPtr->numUnavailableLease++;
                }
                else
                {
                    serverPtr->numManualLease++;
                }
            }
            else
            {
                switch (IPLease->status)
                {
                    case DHCP_OFFERED:
                    {
                        serverPtr->numOfferedLease++;
                        break;
                    }
                    case DHCP_ALLOCATED:
                    {
                        serverPtr->numAllocatedLease++;
                        break;
                    }
                    case DHCP_UNAVAILABLE:
                    {
                        serverPtr->numUnavailableLease++;
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
            }
            MEM_free(IPLease);
        }

        if (serverPtr->dhcpServerStatistics == TRUE)
        {
            AppDhcpServerPrintStats(node, serverPtr, i);
        }

        // Free the server pointer
        if (serverPtr->listSecDnsServer != NULL)
        {
            list<Address*>::iterator it1;
            for (it1 = serverPtr->listSecDnsServer->begin();
                 it1 != serverPtr->listSecDnsServer->end();
                 it1++)
            {
                MEM_free(*it1);
            }
            delete(serverPtr->listSecDnsServer);
            serverPtr->listSecDnsServer = NULL;
        }
        delete(serverPtr->serverLeaseList);
        if (!serverPtr->manualAllocationList->empty())
        {
            std::list<struct appDhcpServerManualAlloc*>::iterator it;
            for (it = serverPtr->manualAllocationList->begin();
                 it != serverPtr->manualAllocationList->end();
                 it++)
            {
                MEM_free((*it));
            }
        }
        delete (serverPtr->manualAllocationList);
        if (serverPtr->dataPacket != NULL)
        {
           MEM_free(serverPtr->dataPacket);
        }
        MEM_free(serverPtr);
        if (tmpAppList != NULL)
        {
            tmpAppList->appDetail = NULL;
        }
    }
}

//--------------------------------------------------------------------------
// NAME:        : AppDhcpClientFinalize.
// PURPOSE:     : Collect statistics of a DHCPClient session.
// PARAMETERS:
// +Node*       : node    : pointer to the node.
// RETURN:      : NONE
//--------------------------------------------------------------------------
void AppDhcpClientFinalize(
                 Node* node)
{
    Int32 i = 0;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (DHCP_DEBUG)
        {
            printf("DHCP Client finalizing at Node %d at interface %d \n",
                   node->nodeId,
                   i);
        }
        AppInfo* appList = node->appData.appPtr;
        struct appDataDhcpClient* clientPtr = NULL;
        struct appDataDhcpClient* dhcpClient;
        AppInfo* tmpAppList = NULL;

        // Get the client pointer from application list
        for (; appList != NULL; appList = appList->appNext)
        {
            if (appList->appType == APP_DHCP_CLIENT)
            {
                dhcpClient = (struct appDataDhcpClient*)appList->appDetail;
                if ((dhcpClient != NULL) &&
                    dhcpClient->interfaceIndex == i)
                {
                    clientPtr = dhcpClient;
                    tmpAppList = appList;
                    break;
                }
            }
        }
        if (clientPtr == NULL)
        {
            continue;
        }
       if (clientPtr && clientPtr->dhcpClientStatistics == TRUE)
       {
            struct dhcpLease* IPLease = NULL;
            list<struct dhcpLease*>::iterator it;
            for (it = clientPtr->clientLeaseList->begin();
                 it != clientPtr->clientLeaseList->end();
                 it++)
            {
                IPLease = *it;;
                // free mac address byte
                if (IPLease->macAddress.byte != NULL)
                {
                    MEM_free(IPLease->macAddress.byte);
                    IPLease->macAddress.byte = NULL;
                }

                // free secondary DNS servers
                if (IPLease->listOfSecDNSServer != NULL)
                {
                    if (!IPLease->listOfSecDNSServer->empty())
                    {
                        list<Address*>::iterator it1;
                        for (it1 = IPLease->listOfSecDNSServer->begin();
                             it1 != IPLease->listOfSecDNSServer->end();
                             it1++)
                        {
                            MEM_free(*it1);
                        }
                    }
                    delete(IPLease->listOfSecDNSServer);
                    IPLease->listOfSecDNSServer = NULL;
                }
                switch (IPLease->status)
                {
                    case DHCP_ACTIVE:
                    {
                        clientPtr->numActiveLease++;
                        break;
                    }
                    case DHCP_INACTIVE:
                    {
                        clientPtr->numInactiveLease++;
                        break;
                    }
                    case DHCP_RENEW:
                    {
                        clientPtr->numRenewLease++;
                        break;
                    }
                    case DHCP_REBIND:
                    {
                        clientPtr->numRebindLease++;
                        break;
                    }
                    case DHCP_MANUAL:
                    {
                        clientPtr->numManualLease++;
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                MEM_free(IPLease);
            }

            AppDhcpClientPrintStats(node, clientPtr, i);
        }

        NetworkDataIp* ip = node->networkData.networkVar;
        IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[i];
        if (interfaceInfo->listOfSecondaryDNSServer &&
            !ListIsEmpty(node, interfaceInfo->listOfSecondaryDNSServer))
        {
            ListFree(node, interfaceInfo->listOfSecondaryDNSServer, FALSE);
            interfaceInfo->listOfSecondaryDNSServer = NULL;
        }

        // Free the client pointer
        if (clientPtr)
        {
            MEM_free((clientPtr->hardwareAddress).byte);
            (clientPtr->hardwareAddress).byte = NULL;
        }
        if (clientPtr->dataPacket != NULL)
        {
            MEM_free(clientPtr->dataPacket);
            clientPtr->dataPacket = NULL;
        }
        delete (clientPtr->clientLeaseList);
        MEM_free(clientPtr);
        if (tmpAppList != NULL)
        {
            tmpAppList->appDetail = NULL;
        }
    }
}

//---------------------------------------------------------------------------
// NAME:         : AppLayerDhcpServer.
// PURPOSE:      : Models the behaviour of DHCP Server on receiving the
//                 message encapsulated in msg.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN        : none.
//---------------------------------------------------------------------------

void
AppLayerDhcpServer(
    Node* node,
    Message* msg)
{
    UdpToAppRecv* info = NULL;
    struct appDataDhcpServer* serverPtr = NULL;
    Int32 incomingInterface = 0 ;
    struct dhcpData data;
    Address interfaceAddress;

    switch (msg->eventType)
    {
        case MSG_APP_FromTransport:
        {
            AppDhcpServerHandleDhcpPacket(node, msg);
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_DHCP_LEASE_EXPIRE:
        {
            AppDhcpServerHandleLeaseExpiry(node, msg);
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_DHCP_TIMEOUT:
        {
            AppDhcpServerHandleTimeout(node, msg);
            MESSAGE_Free(node, msg);
            break;
        }
        default:
        {
            if (DHCP_DEBUG)
            {
                printf("Incorrect message event received at node %d \n",
                       node->nodeId);
            }
            MESSAGE_Free(node, msg);
            break;
        }
    }
}

//--------------------------------------------------------------------------
// NAME:               : AppDhcpServerReceivedDiscover
// PURPOSE:            : models the behaviour of server when a DISCOVER
//                       message is received.
// PARAMETERS:
// +node               : Node*           : DHCP server node.
// +data               : struct dhcpData : DISCOVER packet received.
// +incomingInterface  : Int32           : interface on which packte is
//                                         received.
// +originatingNodeId  : NodeAddress     : Node that originated the message
// RETURN              : none
//--------------------------------------------------------------------------
void AppDhcpServerReceivedDiscover(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface,
    NodeAddress originatingNodeId)
{
    struct appDataDhcpServer* serverPtr = NULL;
    struct dhcpLease* lease = NULL;
    struct dhcpData* offerData = NULL;

    // Get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(node, incomingInterface);
    if (serverPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP server at interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }

    // Increment the count of DISCOVER packet received at server
    serverPtr->numDiscoverRecv++;

    // Find any available lease to offer
    lease = AppDhcpServerFindLease(
                            node,
                            data,
                            incomingInterface,
                            originatingNodeId);
    if (lease == NULL && data.giaddr == 0)
    {
        if (DHCP_DEBUG)
        {
            printf("DHCP Server: No lease available at server present at "
                   "node %d for  interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }

    // DISCOVER from relay might have already sent an offer
    if (lease == NULL && data.giaddr != 0)
    {
        return;
    }
    offerData = AppDhcpServerMakeOffer(
                                    node,
                                    data,
                                    lease,
                                    incomingInterface);
    if (offerData == NULL)
    {
        ERROR_ReportErrorArgs(
                "DHCP Server: Insufficient memory "
                "Offer packet creation falied for  node %d\n",
                node->nodeId);
    }

    // Offer packet created to send
    // Increase the count of number of OFFER sent

    serverPtr->numOfferSent++;
    if (serverPtr->dataPacket != NULL)
    {
        MEM_free(serverPtr->dataPacket);
    }
    serverPtr->dataPacket = offerData;

    // Check the broadcast flag and send the offer
    if (DHCP_DEBUG)
    {
        printf("Sending OFFER message from node %d at interface %d \n",
               node->nodeId,
               incomingInterface);
    }
    if (data.giaddr != 0)
    {
        AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        data.giaddr,
                        DHCP_SERVER_PORT,
                        APP_DEFAULT_TOS,
                        offerData);
    }
    else if (data.giaddr == 0)
    {
        AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        ANY_ADDRESS,
                        DHCP_CLIENT_PORT,
                        APP_DEFAULT_TOS,
                        offerData);
    }

    // Schedule timeout event for  DHCP server
    Message* message = MESSAGE_Alloc(
                                node,
                                APP_LAYER,
                                APP_DHCP_SERVER,
                                MSG_APP_DHCP_TIMEOUT);
    MESSAGE_InfoAlloc(node,
                      message,
                      sizeof(Int32));
    Address* info = (Address*)MESSAGE_ReturnInfo(message);
    info->networkType = NETWORK_IPV4;
    info->IPV4 = NetworkIpGetInterfaceAddress(node, incomingInterface);
    char buf[MAX_STRING_LENGTH] = "";
    sprintf(buf, "%d", DHCP_OFFER_TIMEOUT);
    serverPtr->timeoutMssg = message;
    MESSAGE_Send(node, message, TIME_ConvertToClock(buf));
    return;
}

//---------------------------------------------------------------------------
// NAME:            : AppDhcpServerMakeOffer
// PURPOSE:         : make DHCPOFFER packet to send
// PARAMETERS:
// + node           : Node*             : pointer to the server node.
// + data           : struct dhcpData   : packet received from client.
// + lease          : struct dhcpLease* : pointer to the lease to offer
// + interfaceIndex : Int32             : interface index of server
// RETURN:
// struct dhcpData* : pointer to DHCPOFFER packet cretaed
//                    NULL if nothing found.
//---------------------------------------------------------------------------
struct dhcpData* AppDhcpServerMakeOffer(
    Node* node,
    struct dhcpData data,
    struct dhcpLease* lease,
    Int32 interfaceIndex)
{
    struct dhcpData* offerData = NULL;
    struct appDataDhcpServer* serverPtr = NULL;

    // Allocate memory for  OfferData
    offerData = (struct dhcpData*)MEM_malloc(sizeof(struct dhcpData));
    if (offerData == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("memory not allocated for  OFFER \n");
        }
        return(NULL);
    }
    memset(offerData, 0, sizeof(struct dhcpData));

    // get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(
                            node,
                            interfaceIndex);
    if (serverPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP sever at interface %d \n",
                   node->nodeId,
                   interfaceIndex);
        }
        MEM_free(offerData);
        return(NULL);
    }
    /* Fields as used for  OFFER
      ’op’ BOOTREPLY
      ’htype’ (From "Assigned Numbers" RFC)
      ’hlen’ (Hardware address length in octets)
      ’hops’ 0
      ’xid’ xid’ from client DHCPDISCOVER
      ’secs’ 0 or seconds since DHCP process started
      ’flags’ flag from client DISCOVER
      ’ciaddr’ 0 (DHCPDISCOVER)
      ’yiaddr’ IP address offered to client
      ’siaddr’ IP address of next bootstrap server
      ’giaddr’ ’giaddr’ from client DHCPDISCOVER
      ’chaddr’ chchaddr’ from client DHCPDISCOVER
      ’sname’ Server host name or options
      ’file’ Client boot file name or options
      Requested IP address MUST NOT
      IP address lease time MUST
      Use ’file’/’sname’ fields MAY
      DHCP message type DHCPOFFER
      Client identifier MUST NOT
      Vendor class identifier MAY
      Server identifier MUST
      Parameter request list MAY
      Maximum message size MUST NOT
      Site-specific MAY
      All others MAY */

    offerData->op = BOOTREPLY;
    offerData->htype = data.htype;
    offerData->hlen = data.hlen;
    offerData->hops = 0;
    offerData->xid = data.xid;
    offerData->secs = 0;
    offerData->flags = data.flags;
    offerData->ciaddr = 0;
    offerData->yiaddr = lease->ipAddress.IPV4;
    offerData->siaddr = NetworkIpGetInterfaceAddress(node, interfaceIndex);
    offerData->giaddr = data.giaddr;
    memcpy(offerData->chaddr, data.chaddr, data.hlen);

    offerData->sname[0] = '\0';
    offerData->file[0] = '\0';

    // options
    // Message type

    UInt8 val = DHCPOFFER;
    dhcpSetOption(
        offerData->options,
        DHO_DHCP_MESSAGE_TYPE,
        1,
        &val);

    // Requested IP MUST NOT be present for  OFFER
    // Lease time MUST be present for  OFFER .Check the DISCOVER packet

    UInt32 requestedLeaseTime = 0;
    UInt32 val1 = 0;
    dhcpGetOption(
         data.options,
         DHO_DHCP_LEASE_TIME,
         DHCP_LEASE_TIME_OPTION_LENGTH,
         &requestedLeaseTime);
    if (requestedLeaseTime == (UInt32)DHCP_INFINITE_LEASE)
    {
        val1 = (UInt32)DHCP_INFINITE_LEASE;
        dhcpSetOption(
             offerData->options,
             DHO_DHCP_LEASE_TIME,
             DHCP_LEASE_TIME_OPTION_LENGTH,
             &val1);
        lease->leaseTime = (UInt32)DHCP_INFINITE_LEASE;
    }
    else if (requestedLeaseTime != 0 &&
        requestedLeaseTime <= serverPtr->maxLeaseTime)
    {
        val1 = requestedLeaseTime;
        dhcpSetOption(
            offerData->options,
            DHO_DHCP_LEASE_TIME,
            DHCP_LEASE_TIME_OPTION_LENGTH,
            &val1);
        lease->leaseTime = val1;
    }
    else
    {
        val1 = serverPtr->defaultLeaseTime;
        dhcpSetOption(
             offerData->options,
             DHO_DHCP_LEASE_TIME,
             DHCP_LEASE_TIME_OPTION_LENGTH,
             &val1);
        lease->leaseTime = serverPtr->defaultLeaseTime;
    }

    // Server identifier MUST be present in OFFER
    val1 = NetworkIpGetInterfaceAddress(node, interfaceIndex);
    dhcpSetOption(
        offerData->options,
        DHO_DHCP_SERVER_IDENTIFIER,
        DHCP_ADDRESS_OPTION_LENGTH,
        &val1);
    val1 = 0;
    val1 = (serverPtr->subnetMask).IPV4;
    dhcpSetOption(
        offerData->options,
        DHO_SUBNET_MASK,
        DHCP_ADDRESS_OPTION_LENGTH,
        &val1);

    val1 = (serverPtr->defaultGateway).IPV4;
    dhcpSetOption(
        offerData->options,
        DHO_ROUTERS,
        DHCP_ADDRESS_OPTION_LENGTH,
        &val1);

    Int32 noSecondaryDNS = 0;
    if (serverPtr->listSecDnsServer != NULL)
    {
        if (!serverPtr->listSecDnsServer->empty())
        {
            noSecondaryDNS = serverPtr->listSecDnsServer->size();
        }
    }
    Int32 i = 0;
    UInt32* DNSServers;
    DNSServers = (UInt32*)MEM_malloc((noSecondaryDNS + 1) * sizeof(UInt32));
    DNSServers[0] = (serverPtr->primaryDNSServer).IPV4;
    i = 1;
    if (noSecondaryDNS != 0)
    {
        list<Address*>::iterator it;
        for (it = serverPtr->listSecDnsServer->begin();
             it != serverPtr->listSecDnsServer->end();
             it++)
        {
            DNSServers[i] = (*it)->IPV4;
            i++;
        }
    }
    dhcpSetOption(
        offerData->options,
        DHO_DOMAIN_NAME_SERVERS,
        (UInt8)(noSecondaryDNS+1) * DHCP_DOMAIN_NAME_SERVER_OPTION_LENGTH,
        DNSServers);

    if (DNSServers)
    {
        MEM_free(DNSServers);
    }
    return (offerData);
}

//---------------------------------------------------------------------------
// NAME:            : AppDHCPClientArpReply.
// PURPOSE:         : models the behaviour of client when it gets ARP reply
//                    message is received.
// PARAMETERS:
// + node           : Node*    : DHCP client node.
// + interfaceIndex : Int32    : interface which act as client.
// + reply          : bool     : TRUE if no duplicate found
//                               FALSE if duplicate found.
// RETURN:          : NONE
//---------------------------------------------------------------------------
void AppDHCPClientArpReply(
    Node* node,
    Int32 interfaceIndex,
    bool reply)
{
    struct appDataDhcpClient* clientPtr =
        AppDhcpClientGetDhcpClient(node, interfaceIndex);
    if (reply == FALSE && clientPtr->state == DHCP_CLIENT_REQUEST)
    {
        if (DHCP_DEBUG)
        {
            printf("\nSend DECLINE from client at node %d"
                   " interface %d \n",
                   node->nodeId,
                   interfaceIndex);
        }
        AppDhcpClientSendDecline(
                            node,
                            *(clientPtr->dataPacket),
                            interfaceIndex);
    }
    if (reply == TRUE &&
        (clientPtr->state == DHCP_CLIENT_REQUEST ||
          clientPtr->state == DHCP_CLIENT_INIT_REBOOT))
    {
        if (DHCP_DEBUG)
        {
            printf("Update IP address at client at node %d"
                   " interface %d \n",
                   node->nodeId,
                   interfaceIndex);
        }
        AppDhcpClientStateBound(
                            node,
                            *(clientPtr->dataPacket),
                            interfaceIndex);
    }
}


//--------------------------------------------------------------------------
// NAME:        : AppDhcpRelayFinalize.
// PURPOSE:     : Collect statistics of a dhcp relay session.
// PARAMETERS:
// +node        : Node*    : Node - pointer to the node.
// RETURN       : NONE
//--------------------------------------------------------------------------
void AppDhcpRelayFinalize(
                 Node* node)
{
    Int32 i = 0;
    if (DHCP_DEBUG)
    {
        printf("DHCP Relay finalizing at Node %d \n", node->nodeId);
    }
    for (i = 0; i < node->numberInterfaces; i++)
    {
        struct appDataDhcpRelay* relayPtr = AppDhcpRelayGetDhcpRelay(
                                                node,
                                                i);
        if (relayPtr == NULL)
        {
            continue;
        }
        if (DHCP_DEBUG)
        {
            printf("DHCP Relay finalizing at Node %d at interface %d \n",
                   node->nodeId,
                   i);
        }
        if (relayPtr->dhcpRelayStatistics == TRUE)
        {
            AppDhcpRelayPrintStats(node, relayPtr, i);
        }
        if (relayPtr->dataPacket != NULL)
        {
            MEM_free(relayPtr->dataPacket);
        }
        if (!relayPtr->serverAddrList->empty())
        {
            list<Address*>::iterator it;
            for (it = relayPtr->serverAddrList->begin();
                 it != relayPtr->serverAddrList->end();
                 it++)
            {
                delete(*it);
            }
        }
        delete (relayPtr->serverAddrList);
        MEM_free(relayPtr);
    }
}

//--------------------------------------------------------------------------
// NAME:           : AppDhcpServerPrintStats
// PURPOSE:        : Prints the stats in stat file.
// PARAMETERS:
// +node           : Node*                     : pointer to the node.
// +ServerPtr      : struct appDataDhcpServer* : pointer to the DHCP server.
// +interfaceIndex : Int32                     :interface Index
// RETURN:         : NONE
//--------------------------------------------------------------------------

void AppDhcpServerPrintStats(
    Node* node,
    struct appDataDhcpServer* ServerPtr,
    Int32 interfaceIndex)
{
    char buf[MAX_STRING_LENGTH] = "";
    sprintf(
        buf,
        "Number of DISCOVER Received = %u",
        ServerPtr->numDiscoverRecv);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of INFORM Received = %u",
        ServerPtr->numInformRecv);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of REQUEST Received = %u",
        ServerPtr->numRequestRecv);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of DECLINE Received = %u",
        ServerPtr->numDeclineRecv);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of OFFER Sent = %u",
        ServerPtr->numOfferSent);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of ACK Sent = %u",
        ServerPtr->numAckSent);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of NAK Sent = %u",
        ServerPtr->numNakSent);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of OFFER Rejected = %u",
        ServerPtr->numOfferReject);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Total number of leases = %u",
        ServerPtr->numTotalLease);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of leases with OFFERED status = %u",
        ServerPtr->numOfferedLease);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of leases with ALLOCATED status = %u",
        ServerPtr->numAllocatedLease);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of leases with AVAILABLE status = %u",
        ServerPtr->numAvailableLease);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of leases manually allocated = %u",
        ServerPtr->numManualLease);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of leases with UNAVAILABLE status = %u",
        ServerPtr->numUnavailableLease);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Server",
        ANY_DEST,
        interfaceIndex,
        buf);
}

//--------------------------------------------------------------------------
// NAME:           : AppDhcpClientPrintStats
// PURPOSE:        : Prints the stats in stat file.
// PARAMETERS:
// +node           : Node*                     : pointer to the node.
// +clientPtr      : struct appDataDhcpClient* : pointer to the DHCP client.
// +interfaceIndex : Int32                     : interface Index
// RETURN:         : none.
//--------------------------------------------------------------------------
void AppDhcpClientPrintStats(
    Node* node,
    struct appDataDhcpClient* clientPtr,
    Int32 interfaceIndex)
{
    char buf[MAX_STRING_LENGTH] = "";
    sprintf(
        buf,
        "Number of DISCOVER Sent = %u",
        clientPtr->numDiscoverSent);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of INFORM Sent = %u",
        clientPtr->numInformSent);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of REQUEST Sent = %u",
        clientPtr->numRequestSent);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of DECLINE Sent = %u",
        clientPtr->numDeclineSent);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of OFFER Received = %u",
        clientPtr->numOfferRecv);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of ACK  Received = %u",
        clientPtr->numAckRecv);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of NAK  Received = %u",
        clientPtr->numNakRecv);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of leases with ACTIVE status = %u",
        clientPtr->numActiveLease);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of leases with INACIVE status = %u",
        clientPtr->numInactiveLease);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of leases with RENEW status = %u",
        clientPtr->numRenewLease);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of leases with REBIND status = %u",
        clientPtr->numRebindLease);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of leases with MANUAL status = %u",
        clientPtr->numManualLease);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Client",
        ANY_DEST,
        interfaceIndex,
        buf);
}

//--------------------------------------------------------------------------
// NAME:            : AppDhcpRelayPrintStats
// PURPOSE:         : Prints the stats in stat file.
// PARAMETERS:
// +node            : Node*                      : pointer to the node.
// +relayPtr        : struct appDataDhcpRelay*   : pointer to the DHCP relay
// +interfaceIndex  : Int32                      : interface index
// RETURN:          : NONE
//--------------------------------------------------------------------------

void AppDhcpRelayPrintStats(
    Node* node,
    struct appDataDhcpRelay* relayPtr,
    Int32 interfaceIndex)
{
    char buf[MAX_STRING_LENGTH] = "";
    sprintf(
        buf,
        "Number of client packets relayed = %u",
        relayPtr->numClientPktsRelayed);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Relay",
        ANY_DEST,
        interfaceIndex,
        buf);
    sprintf(
        buf,
        "Number of server packets relayed = %u",
        relayPtr->numServerPktsRelayed);
    IO_PrintStat(
        node,
        "Application",
        "DHCP Relay",
        ANY_DEST,
        interfaceIndex,
        buf);

}

//--------------------------------------------------------------------------
// NAME:                    : AppDhcpRelayGetDhcpRelay.
// PURPOSE:                 : search for  a DHCP relay data structure.
// PARAMETERS:
// +node                    : Node*    : pointer to the node.
// +interfaceIndex          : Int32    : Interface index which act as client
// RETURN:
// struct appDataDhcpRelay* : the pointer to the DHCP client data structure,
//                            NULL if nothing found.
//--------------------------------------------------------------------------
struct appDataDhcpRelay* AppDhcpRelayGetDhcpRelay(
    Node* node,
    Int32 interfaceIndex)
{
    AppInfo* appList = node->appData.appPtr;
    struct appDataDhcpRelay* dhcpRelay = NULL;

    if (interfaceIndex < 0 ||
        interfaceIndex >= node->numberInterfaces)
    {
        // invalid interface index 
        // cannot continue further
        if (DHCP_DEBUG)
        {
            printf("Node %d in function AppDhcpRelayGetDhcpRelay: "
                   "invalid interface index", node->nodeId);
        }
        return (NULL);
    }

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_DHCP_RELAY)
        {
            dhcpRelay = (struct appDataDhcpRelay*)appList->appDetail;
            if (dhcpRelay->interfaceIndex == interfaceIndex)
            {
                return dhcpRelay;
            }
        }
    }
    return NULL;
}
//---------------------------------------------------------------------------
// NAME:                 : AppDhcpClientStateSelect
// PURPOSE:              : models the behaviour when client enters the
//                         SELECT state
// PARAMETERS:
// + node                : Node*            : pointer to the client node
//                                            which received the message.
// + data                : struct dhcpData  : OFFER packet received
// + incomingInterface   : Int32            : Interface on which packet
//                                            is received
// RETURN:               : none.
// --------------------------------------------------------------------------
void AppDhcpClientStateSelect(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface)
{
    struct appDataDhcpClient* clientPtr = NULL;
    struct dhcpData* requestData = NULL;

    // Get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(node, incomingInterface);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d at interface %d Not a DHCP client \n",
                   node->nodeId,
                   incomingInterface);
        }
         return;
    }

    // Check the XID if Offer is at correct client
    if (clientPtr->recentXid == data.xid)
    {
        if (DHCP_DEBUG)
        {
            printf("correct offer message received at client node %d"
                   "and interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }

        // The client chooses the first offer it receives
        // Make the DHCP Request packet

        requestData = AppDhcpClientMakeRequest(
                            node,
                            data,
                            incomingInterface);
        if (requestData == NULL)
        {
            ERROR_ReportErrorArgs(
                    "DHCP Client: Insufficient memory "
                    "REQUEST packet creation falied for  node %d\n",
                    node->nodeId);
        }

        // send the REQUEST packet
        AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_CLIENT_PORT,
                        ANY_ADDRESS,
                        DHCP_SERVER_PORT,
                        clientPtr->tos,
                        requestData);

       if (DHCP_DEBUG)
       {
           printf("Request sent from Node %d from interface %d \n",
                  node->nodeId,
                  incomingInterface);
       }

       // Change the state of client
       clientPtr->state = DHCP_CLIENT_REQUEST;

       // Increase the count of request packet sent
       clientPtr->numRequestSent++;

       // schedule retrasmission timer for  DHCPREQUEST
       clocktype timerDelay = (clocktype) ((clientPtr->timeout
                      * (clientPtr->retryCounter))
                      + RANDOM_erand(clientPtr->jitterSeed));

        // initiate retrasmission
        Message* message = MESSAGE_Alloc(
                                        node,
                                        APP_LAYER,
                                        APP_DHCP_CLIENT,
                                        MSG_APP_DHCP_TIMEOUT);
        MESSAGE_InfoAlloc(
                      node,
                      message,
                      sizeof(Int32));
        Int32* info = (Int32*)MESSAGE_ReturnInfo(message);
        *(info) = incomingInterface;
        clientPtr->timeoutMssg = message;

        // free the DISCOVER packet sent
        if (clientPtr->dataPacket)
        {
            MEM_free(clientPtr->dataPacket);
        }

        // Store the new data packet sent
        clientPtr->dataPacket = requestData;
        MESSAGE_Send(node, message, timerDelay);
    }
    else
    {
        if (DHCP_DEBUG)
        {
            printf("Offer message not for  node %d \n", node->nodeId);
        }
        return;
    }
}

//--------------------------------------------------------------------------
// NAME:             : AppDhcpClientMakeRequest
// PURPOSE:          : make DHCPREQUEST packet to send
// PARAMETERS:
// + node            : Node*           : pointer to client which received
//                                       message.
// + data            : struct dhcpData : dhcp packet to help in making
//                                       request.
// + interfaceIndex  : Int32           : interface which received the
//                                       message.
// RETURN:
// struct dhcpData*  : the DHCPREQUEST packet.NULL if nothing found.
//--------------------------------------------------------------------------

struct dhcpData* AppDhcpClientMakeRequest(
    Node* node,
    struct dhcpData data,
    Int32 interfaceIndex)
{
    struct dhcpData* requestData = NULL;
    struct appDataDhcpClient* clientPtr = NULL;
    UInt8 val2;

    // Get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(
                        node,
                        interfaceIndex);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d not a DHCP client at interface %d \n",
                   node->nodeId,
                   interfaceIndex);
        }
        return(NULL);
    }

    // Allocate memory for  request data
    requestData = (struct dhcpData*)MEM_malloc(sizeof(struct dhcpData));
    if (requestData == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("memory not allocated for  DHCPREQUEST \n");
        }
        return(NULL);
    }
    memset(requestData, 0, sizeof(struct dhcpData));

       /* Fields as used for  REQUEST
      ’op’ BOOTREQUEST
      ’htype’ (From "Assigned Numbers" RFC)
      ’hlen’ (Hardware address length in octets)
      ’hops’ 0
      ’xid’ xid from server offer message
      ’secs’ 0 or seconds since DHCP process started
      ’flags’ Set ’BROADCAST’if client broadcast reply
      ’ciaddr’ 0 or client's network address
      ’yiaddr’ 0
      ’siaddr’ 0
      ’giaddr’ 0
      ’chaddr’ client’s hardware address
      ’sname’ options, if indicated ’sname/file’otherwise unused
      ’file’ options, if indicated in ’sname/file’ otherwise unused
      Requested IP address MUST in (SELECTING or INIT-REBOOT
                           MUST NOT in BOUND or RENEWING)
      IP address lease time MAY
      Use ’file’/’sname’ fields MAY MAY MAY
      DHCP message type DHCPREQUEST
      Client identifier MAY
      Vendor class identifier MAY
      Server identifier     MUST (after SELECTING)
                            MUST NOT (after INIT-REBOOT,
                            BOUND, RENEWING
                            or REBINDING)
      Parameter request list MAY
      Maximum message size MAY
      Message SHOULD NOT
      Site-specific MAY
      All others MAY */

    requestData->op = BOOTREQUEST;
    requestData->htype = (UInt8)clientPtr->hardwareAddress.hwType;
    requestData->hlen = (UInt8)clientPtr->hardwareAddress.hwLength;
    requestData->hops = 0;
    requestData->xid = data.xid;
    requestData->secs = (UInt16)(node->getNodeTime() / SECOND);

    // For QualNet this will be set to BROADCAST
    requestData->flags = DHCP_BROADCAST;
    requestData->ciaddr = 0;
    requestData->yiaddr = 0;
    requestData->siaddr = 0;
    requestData->giaddr = 0;
    memcpy(requestData->chaddr,
           clientPtr->hardwareAddress.byte,
           requestData->hlen);
    requestData->sname[0] = '\0';
    requestData->file[0] = '\0';

    //options
    val2 = DHCPREQUEST;
    dhcpSetOption(requestData->options,
                  DHO_DHCP_MESSAGE_TYPE,
                  1,
                  &val2);
    if (data.options[0]!= '\0')
    {
        UInt32 val = data.yiaddr;

        //Requested IP MUST be present for  REQUEST for
        // selecting and INIT-REBOOT state

         if (clientPtr->state == DHCP_CLIENT_SELECT)
         {
             if (val != 0)
             {
                 dhcpSetOption(requestData->options,
                               DHO_DHCP_REQUESTED_ADDRESS,
                               DHCP_ADDRESS_OPTION_LENGTH,
                               &val);
             }
         }

        // Lease time MAY be present for  OFFER
        if (clientPtr->dhcpLeaseTime)
        {
            UInt32 val1 = clientPtr->dhcpLeaseTime;
            dhcpSetOption(requestData->options,
                          DHO_DHCP_LEASE_TIME,
                          DHCP_LEASE_TIME_OPTION_LENGTH,
                          &val1);
        }
        else
        {
            dhcpGetOption(
                   data.options,
                   DHO_DHCP_LEASE_TIME,
                   DHCP_LEASE_TIME_OPTION_LENGTH,
                   &val);
            if (val != 0)
            {
                dhcpSetOption(
                    requestData->options,
                    DHO_DHCP_LEASE_TIME,
                    DHCP_LEASE_TIME_OPTION_LENGTH,
                    &val);
            }
        }

        //Client identifier MAY be present for  OFFER. Check the clientPtr
        if (clientPtr->dhcpClientIdentifier[0] != '\0')
        {
             UInt8 val1 = (UInt8)strlen(clientPtr->dhcpClientIdentifier);
             dhcpSetOption(
                requestData->options,
                DHO_DHCP_CLIENT_IDENTIFIER,
                val1,
                &(clientPtr->dhcpClientIdentifier));
        }

        // Server identifier MUST  after selecting state
        val = 0;
        if (clientPtr->state == DHCP_CLIENT_SELECT)
        {
            dhcpGetOption(data.options,
                          DHO_DHCP_SERVER_IDENTIFIER,
                          DHCP_ADDRESS_OPTION_LENGTH,
                          &val);
            if (val != 0)
            {
                dhcpSetOption(requestData->options,
                              DHO_DHCP_SERVER_IDENTIFIER,
                              DHCP_ADDRESS_OPTION_LENGTH,
                              &val);
            }
        }
        dhcpGetOption(data.options,
                      DHO_SUBNET_MASK,
                      DHCP_ADDRESS_OPTION_LENGTH,
                      &val);
        if (val != 0)
        {
            dhcpSetOption(requestData->options,
                          DHO_SUBNET_MASK,
                          DHCP_ADDRESS_OPTION_LENGTH,
                          &val);
        }

        dhcpGetOption(data.options,
                      DHO_ROUTERS,
                      DHCP_ADDRESS_OPTION_LENGTH,
                      &val);
        if (val != 0)
        {
            dhcpSetOption(requestData->options,
                          DHO_ROUTERS,
                          DHCP_ADDRESS_OPTION_LENGTH,
                          &val);
        }

        // get the domain name sever length
        val2 = dhcpGetOptionLength(
                     data.options,
                     DHO_DOMAIN_NAME_SERVERS);
        if (val2 != 0)
        {
            //Int32 noDNSServer = val2/4;
            UInt32 *DNSServers;
            DNSServers = (UInt32*)MEM_malloc((val2));

            dhcpGetOption(data.options,
                          DHO_DOMAIN_NAME_SERVERS,
                          val2,
                          DNSServers);
            dhcpSetOption(requestData->options,
                          DHO_DOMAIN_NAME_SERVERS,
                          val2,
                          DNSServers);
            MEM_free(DNSServers);
        }
    }
    return(requestData);
}

//--------------------------------------------------------------------------
// NAME:                : AppDhcpServerReceivedRequest
// PURPOSE:             : models the behaviour of server when a REQUEST
//                      : message is received.
// PARAMETERS:
// + node               : Node*           : DHCP server node.
// + data               : struct dhcpData : REQUEST packet received.
// +incomingInterface   : Int32           : interface on which packte is
//                                          received.
// RETURN               : none
//---------------------------------------------------------------------------
void AppDhcpServerReceivedRequest(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface)
{
    struct appDataDhcpServer* serverPtr = NULL;

    // Get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(node, incomingInterface);
    if (serverPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP sever at interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }

    // Increment the REQUEST packet
    serverPtr->numRequestRecv++;
    if (DHCP_DEBUG)
    {
        printf("Received DHCPREQUEST message at node %d from "
               "interface %d \n",
               node->nodeId,
               incomingInterface);
    }

    // Check the type of REQUEST
    // Check if REQUEST is in response to OFFER
    // Get the server identifier

    UInt32 serverIdentifier = 0;
    dhcpGetOption(data.options,
                  DHO_DHCP_SERVER_IDENTIFIER,
                  DHCP_ADDRESS_OPTION_LENGTH,
                  &serverIdentifier);

    // Get the requested IP Address
    UInt32 requestedIp = 0;
    dhcpGetOption(
         data.options,
         DHO_DHCP_REQUESTED_ADDRESS,
         DHCP_ADDRESS_OPTION_LENGTH,
         &requestedIp);
    if ((serverIdentifier)!= 0 && (requestedIp) != 0)
    {
        // The request is in respone to offer
        AppDhcpServerHandleOfferRequest(
                    node,
                    data,
                    incomingInterface);
    }
    else if (data.ciaddr != 0 && requestedIp == 0)
    {
        // This is a renewal or rebind request
        AppDhcpServerHandleRenewRebindRequest(
                    node,
                    data,
                    incomingInterface);
    }
    else if (data.ciaddr == 0 && requestedIp != 0)
    {
        // This is INIT-REBOOT request
        AppDhcpServerHandleInitRebootRequest(
                    node,
                    data,
                    incomingInterface);
    }
}

//--------------------------------------------------------------------------
// NAME:              : AppDhcpServerMakeAck
// PURPOSE:           : constructs DHCPACK
// PARAMETERS:
// + node             : Node*             : DHCP server node.
// + data             : struct dhcpData   : request packet received
// + lease            : struct dhcpLease* : lease to be allocated.
// +interfaceIndex    : Int32             : InterfaceId
// RETURN:
// struct dhcpData*   : the pointer to the DHCP ACK packet,
//                      NULL if nothing found.
// --------------------------------------------------------------------------
struct dhcpData* AppDhcpServerMakeAck(
    Node* node,
    struct dhcpData data,
    struct dhcpLease* lease,
    Int32 interfaceIndex)
{
    struct dhcpData* ackData = NULL;
    struct appDataDhcpServer* serverPtr = NULL;

    // get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(node, interfaceIndex);
    if (serverPtr == NULL)
    {
        MEM_free(serverPtr);
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP severat interface %d \n",
                   node->nodeId,
                   interfaceIndex);
        }
        return(NULL);
    }

    // Allocate memory for  Ack Data
    ackData = (struct dhcpData*)MEM_malloc(sizeof(struct dhcpData));
    if (ackData == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("memory not allocated for  OFFER \n");
        }
        return(NULL);
    }
    memset(ackData, 0, sizeof(struct dhcpData));

    ackData->op = BOOTREPLY;
    ackData->htype = data.htype;
    ackData->hlen = data.hlen;
    ackData->hops = data.hops;    //Relay agent not implemented
    ackData->xid = data.xid;    // Any random number
    ackData->secs = 0;    //filled in by send_discover
    ackData->flags = data.flags;    //10: Flag bits
    ackData->ciaddr = data.ciaddr;
    if (lease)
    {
        ackData->yiaddr = lease->ipAddress.IPV4;
    }
    else
    {
         ackData->yiaddr = 0;
    }
    ackData->siaddr = NetworkIpGetInterfaceAddress(node, interfaceIndex);
    ackData->giaddr = data.giaddr;
    memcpy(ackData->chaddr, data.chaddr, data.hlen);
    ackData->sname[0] = '\0';
    ackData->file[0] = '\0';
    if (lease)
    {
        //options
        UInt8 val1 = DHCPACK;
        dhcpSetOption(ackData->options,
                      DHO_DHCP_MESSAGE_TYPE,
                      1,
                      &val1);

         // Requested IP MUST NOT be present for  OFFER
         // Lease time MUST be present for  OFFER .Check the DISCOVER packet

        UInt32 val = lease->leaseTime;
        dhcpSetOption(ackData->options,
                      DHO_DHCP_LEASE_TIME,
                      DHCP_LEASE_TIME_OPTION_LENGTH,
                      &val);
        val = (UInt32)(DHCP_T1*(lease->leaseTime));
        dhcpSetOption(ackData->options,
                      DHO_DHCP_RENEWAL_TIME,
                      DHCP_LEASE_TIME_OPTION_LENGTH,
                      &val);
        val = (UInt32)(DHCP_T2*(lease->leaseTime));
        dhcpSetOption(ackData->options,
                      DHO_DHCP_REBINDING_TIME,
                      DHCP_LEASE_TIME_OPTION_LENGTH,
                      &val);

        // Client identifier MUST NOT be present for  OFFER
        // Server identifier MUST be preent in OFFER

        val = NetworkIpGetInterfaceAddress(node, interfaceIndex);
        dhcpSetOption(ackData->options,
                      DHO_DHCP_SERVER_IDENTIFIER,
                      DHCP_ADDRESS_OPTION_LENGTH,
                      &val);
         //Parameter Request list MUST NOT be present in OFFER
        val = (serverPtr->subnetMask).IPV4;
        dhcpSetOption(ackData->options,
                      DHO_SUBNET_MASK,
                      DHCP_ADDRESS_OPTION_LENGTH,
                      &val);

         val = (serverPtr->defaultGateway).IPV4;
         dhcpSetOption(ackData->options,
                       DHO_ROUTERS,
                       DHCP_ADDRESS_OPTION_LENGTH,
                       &val);

        Int32 noSecondaryDNS = 0;
        if (serverPtr->listSecDnsServer != NULL)
        {
            if (!serverPtr->listSecDnsServer->empty())
            {
                noSecondaryDNS = serverPtr->listSecDnsServer->size();
            }
        }
        Int32 i = 0;
        UInt32* DNSServers;
        DNSServers = (UInt32*)
            MEM_malloc((noSecondaryDNS + 1) * sizeof(UInt32));
        DNSServers[0] = (serverPtr->primaryDNSServer).IPV4;
        i = 1;
        if (noSecondaryDNS != 0)
        {
            list<Address*>::iterator it;
            for (it = serverPtr->listSecDnsServer->begin();
                 it != serverPtr->listSecDnsServer->end();
                 it++)
            {
                DNSServers[i] = (*it)->IPV4;
                i++;
            }
        }

        dhcpSetOption(ackData->options,
                      DHO_DOMAIN_NAME_SERVERS,
                      (UInt8)(noSecondaryDNS + 1) *
                      DHCP_DOMAIN_NAME_SERVER_OPTION_LENGTH,
                      DNSServers);
        MEM_free(DNSServers);
    }
    return(ackData);
}

//---------------------------------------------------------------------------
// NAME:                  : AppDhcpClientStateBound
// PURPOSE:               : models the behaviour when client enters the
//                          BOUND state
// PARAMETERS:
// + node                 : Node*             : pointer to the client node
//                                              which received the message.
// + data                 : struct dhcpData   : ACK packet received
// + incomingInterface    : Int32             : Interface on which packet
//                                              is received
// RETURN:                : none
//---------------------------------------------------------------------------
void AppDhcpClientStateBound(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface)
{

    struct appDataDhcpClient* clientPtr = NULL;
    struct dhcpLease* lease = NULL;

    // Get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(
                        node,
                        incomingInterface);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d not a DHCP client at interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }
    NetworkType networkType = NETWORK_IPV4;

    // Get the lease time
    UInt32 leaseTime;
    dhcpGetOption(
        data.options,
        DHO_DHCP_LEASE_TIME,
        DHCP_LEASE_TIME_OPTION_LENGTH,
        &leaseTime);

    // A new lease in case of following states
    if (clientPtr->state == DHCP_CLIENT_REQUEST ||
        clientPtr->state == DHCP_CLIENT_INFORM ||
        clientPtr->state == DHCP_CLIENT_INIT_REBOOT)
    {
        if (!clientPtr->clientLeaseList->empty())
        {
            // Check if the same lease present in database
            // in state other than ACTIVE
            list<struct dhcpLease*>::iterator it;
            for (it = clientPtr->clientLeaseList->begin();
                 it != clientPtr->clientLeaseList->end();
                 it++)
            {
                if ((*it)->ipAddress.IPV4 == data.yiaddr)
                {
                    lease = *it;
                    break;
                }
            }
        }
        if (lease == NULL)
        {
            // Lease not present
            // Costruct the lease to be inserted into linked list
            // Allocate memory for  the lease

            lease =
                (struct dhcpLease*)MEM_malloc(sizeof(struct dhcpLease));
            memset(lease, 0, sizeof(struct dhcpLease));
        }

        // If client identifier is present then insert the same
        // in lease

        if (clientPtr->dhcpClientIdentifier[0] != '\0')
        {
            memcpy(lease->clientIdentifier,
                   clientPtr->dhcpClientIdentifier,
                   strlen(clientPtr->dhcpClientIdentifier));
        }

        if (clientPtr->lastIP.IPV4 == data.yiaddr)
        {
            clientPtr->arpInterval = 0;
        }
        else
        {
            clientPtr->arpInterval = node->getNodeTime() -
                                         clientPtr->arpInterval;
        }

        // Insert the IP Address in lease
        if (clientPtr->state == DHCP_CLIENT_INFORM)
        {
            lease->ipAddress.networkType = networkType;
            lease->ipAddress.IPV4 = data.ciaddr;
            clientPtr->lastIP.networkType = networkType;
            clientPtr->lastIP.IPV4 = data.ciaddr;
        }
        else
        {
            lease->ipAddress.networkType = networkType;
            lease->ipAddress.IPV4 = data.yiaddr;
            clientPtr->lastIP.networkType = networkType;
            clientPtr->lastIP.IPV4 = data.yiaddr;
        }

        // Get the server Id to insert in lease
        UInt32 serverIdentifier;
        dhcpGetOption(data.options,
                      DHO_DHCP_SERVER_IDENTIFIER,
                      DHCP_ADDRESS_OPTION_LENGTH,
                      &serverIdentifier);
        (lease->serverId).networkType = networkType;
        (lease->serverId).IPV4 = serverIdentifier;

        // Insert mac - address
        lease->macAddress.hwLength = data.hlen;
        lease->macAddress.hwType = data.htype;
        lease->macAddress.byte = (unsigned char*)MEM_malloc(data.hlen);
        memcpy(lease->macAddress.byte, data.chaddr, data.hlen);

        // Get the default gateway to insert into lease
        UInt32 defaultGateway;
        dhcpGetOption(
                   data.options,
                   DHO_ROUTERS,
                   DHCP_ADDRESS_OPTION_LENGTH,
                   &defaultGateway);
        (lease->defaultGateway).networkType = networkType;
        (lease->defaultGateway).IPV4 = defaultGateway;

        // Get the subnet mask to insert into lease
        UInt32 subnetMask;
        dhcpGetOption(
                   data.options,
                   DHO_SUBNET_MASK,
                   DHCP_ADDRESS_OPTION_LENGTH,
                   &subnetMask);
        (lease->subnetMask).networkType = networkType;
        (lease->subnetMask).IPV4 = subnetMask;
         (lease->subnetNumber).networkType =
                                (lease->ipAddress).networkType;
        (lease->subnetNumber).IPV4 =
                                (lease->ipAddress).IPV4 &
                                (lease->subnetMask).IPV4;
        // get the domain name sever length to insert DNS servers
        // into the lease
        UInt8 val = dhcpGetOptionLength(
                  data.options,
                  DHO_DOMAIN_NAME_SERVERS);
        Int32 noDNSServer = val / DHCP_DOMAIN_NAME_SERVER_OPTION_LENGTH;
        UInt32* DNSServers;
        DNSServers = (UInt32*)MEM_malloc((val));
        dhcpGetOption(
                  data.options,
                  DHO_DOMAIN_NAME_SERVERS,
                  val,
                  DNSServers);
        UInt32 primaryDNS;
        primaryDNS = DNSServers[0];
        (lease->primaryDNSServer).networkType = networkType;
        (lease->primaryDNSServer).IPV4 = primaryDNS;

        // Insert secondary DNS if present
        if (noDNSServer > 1)
        {
            if (lease->listOfSecDNSServer == NULL)
            {
                lease->listOfSecDNSServer = new std::list<Address*>;
            }
            else
            {
                list<Address*>::iterator it;
                for (it = lease->listOfSecDNSServer->begin();
                     it != lease->listOfSecDNSServer->end();
                     it++)
                {
                    MEM_free(*it);
                }
                lease->listOfSecDNSServer->clear();
            }
            for (val = 1; val < noDNSServer; val++)
            {
                Address* secondaryDNS;
                secondaryDNS = (Address*)MEM_malloc(sizeof(Address));
                secondaryDNS->networkType = networkType;
                secondaryDNS->IPV4 = DNSServers[val];
                lease->listOfSecDNSServer->push_back(secondaryDNS);
            }
        }

        // Check if lease present in list of leases at client
        struct dhcpLease* lease1 = NULL;
        if (clientPtr->state == DHCP_CLIENT_INFORM)
        {
            lease->status = DHCP_MANUAL;
            lease->leaseTime = (UInt32)DHCP_INFINITE_LEASE;
            list<struct dhcpLease*>::iterator it;
            for (it = clientPtr->clientLeaseList->begin();
                 it != clientPtr->clientLeaseList->end();
                 it++)
            {
                if ((*it)->ipAddress.IPV4 == data.ciaddr)
                {
                    lease1 = *it;
                    break;
                }
            }
        }
        else
        {
            lease->leaseTime = leaseTime;

            lease->status = DHCP_ACTIVE;
            list<struct dhcpLease*>::iterator it;
            for (it = clientPtr->clientLeaseList->begin();
                 it != clientPtr->clientLeaseList->end();
                 it++)
            {
                if ((*it)->ipAddress.IPV4 == data.yiaddr)
                {
                    lease1 = *it;
                    break;
                }
            }
        }

        // Insert the newly created lease to list
        if (lease1 == NULL)
        {
            clientPtr->clientLeaseList->push_back(lease);
        }

        // Update the interface info with new configuration parameters
        NetworkDataIp* ip = node->networkData.networkVar;
        IpInterfaceInfoType* interfaceInfo =
                ip->interfaceInfo[incomingInterface];
        (interfaceInfo->subnetMask).networkType = networkType;
        (interfaceInfo->subnetMask).IPV4 = subnetMask;
        (interfaceInfo->primaryDnsServer).networkType = networkType;
        (interfaceInfo->primaryDnsServer).IPV4 = primaryDNS;
        if (noDNSServer > 1)
        {
            if (interfaceInfo->listOfSecondaryDNSServer == NULL)
            {
                ListInit(node, &interfaceInfo->listOfSecondaryDNSServer);
            }
            else
            {
                ListFree(
                    node,
                    interfaceInfo->listOfSecondaryDNSServer,
                    FALSE);
                ListInit(node, &interfaceInfo->listOfSecondaryDNSServer);
            }
            for (val = 1; val < noDNSServer; val++)
            {
                Address* secondaryDNS;
                secondaryDNS = (Address*)MEM_malloc(sizeof(Address));
                secondaryDNS->networkType = networkType;
                secondaryDNS->IPV4 = DNSServers[val];
                ListInsert(node,
                           interfaceInfo->listOfSecondaryDNSServer,
                           node->getNodeTime(),
                           secondaryDNS);
            }
        }
        ip->gatewayConfigured = TRUE;
        ip->defaultGatewayId = defaultGateway;

        // Call the process DHCP function of network_ip to
        // propagate the new ip information

        if (lease->leaseTime != (UInt32)DHCP_INFINITE_LEASE &&
            lease->leaseTime != 0)
        {
            char buf[MAX_STRING_LENGTH] = "";
            sprintf(buf, "%d", lease->leaseTime);
            clocktype time = TIME_ConvertToClock(buf);
            if (clientPtr->arpInterval != 0)
            {
                time = time - (clientPtr->arpInterval);
            }

            NetworkIpProcessDHCP(node,
                                 incomingInterface,
                                 &lease->ipAddress,
                                 (lease->subnetMask).IPV4,
                                 RECEIVE_ADDRESS,
                                 networkType);
        }
        else
        {
            NetworkIpProcessDHCP(node,
                                 incomingInterface,
                                 &lease->ipAddress,
                                (lease->subnetMask).IPV4,
                                 RECEIVE_ADDRESS,
                                 networkType);
        }
        if (DHCP_DEBUG)
        {
            // Print the new IP address allocated
            NodeAddress addr = MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                    node,
                                    node->nodeId,
                                    incomingInterface);
            char str[MAX_STRING_LENGTH] = "";
            Address TempAddr;
            TempAddr.networkType = networkType;
            TempAddr.IPV4 = addr;
            IO_ConvertIpAddressToString(&(TempAddr), str);
            printf("New IP address allocated for  node %d for "
                   "interface %d = %s \n",
                   node->nodeId,
                   incomingInterface,str);
            IO_ConvertIpAddressToString(&(lease->defaultGateway), str);
            printf("Default gateway : %s \n", str);
            IO_ConvertIpAddressToString(&(lease->subnetMask), str);
            printf("Subnet Mask: %s \n", str);
            IO_ConvertIpAddressToString(&(lease->primaryDNSServer), str);
            printf("Primary DNS : %s \n", str);
            printf("Secondary DNS servers \n");
            Address* addrSecDns;
            if (lease->listOfSecDNSServer != NULL)
            {
                list<Address*>::iterator it1;
                for (it1 = lease->listOfSecDNSServer->begin();
                     it1 != lease->listOfSecDNSServer->end();
                     it1++)
                {
                    addrSecDns = *it1;
                    IO_ConvertIpAddressToString(addrSecDns, str);
                    printf("%s \n", str);
                }
            }
            clocktype simulationTime = node->getNodeTime();
            char simulationTimeStr[MAX_STRING_LENGTH] = "";
            TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
            printf("Time at allocation = %s \n", simulationTimeStr);
        }

        if (DNSServers)
        {
            MEM_free(DNSServers);
        }
    }
    if (clientPtr->state == DHCP_CLIENT_RENEW ||
        clientPtr->state == DHCP_CLIENT_REBIND)
    {
        // Get the lease out of list of leases
        if (DHCP_DEBUG)
        {
            printf("Renewal ACK received at node %d"
                   "for  interface %d \n",
                   node->nodeId,
                   incomingInterface);
            clocktype simulationTime = node->getNodeTime();
            char simulationTimeStr[MAX_STRING_LENGTH] = "";
            TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
            printf("Time at renewal ack = %s \n", simulationTimeStr);
        }
        list<struct dhcpLease*>::iterator it;
        for (it = clientPtr->clientLeaseList->begin();
             it != clientPtr->clientLeaseList->end();
             it++)
        {
            if ((*it)->ipAddress.IPV4 == data.yiaddr)
            {
                lease = *it;
                break;
            }
        }
        if (lease == NULL)
        {
            return;
        }

        lease->status = DHCP_ACTIVE;
        lease->leaseTime = leaseTime;

        // Get the server Id to insert in lease
        UInt32 serverIdentifier;
        dhcpGetOption(data.options,
                      DHO_DHCP_SERVER_IDENTIFIER,
                      DHCP_ADDRESS_OPTION_LENGTH,
                      &serverIdentifier);
        (lease->serverId).networkType = networkType;
        (lease->serverId).IPV4 = serverIdentifier;

        // Insert the mac-address into lease
        lease->macAddress.hwLength = data.hlen;
        lease->macAddress.hwType = data.htype;
        if (!lease->macAddress.byte)
        {
            lease->macAddress.byte =
                (unsigned char*)MEM_malloc(data.hlen);
        }
        memset(lease->macAddress.byte,
                0,
                data.hlen);
        memcpy(lease->macAddress.byte, data.chaddr, data.hlen);

        // Get default gateway to insert into lease
        UInt32 defaultGateway;
        dhcpGetOption(data.options,
                      DHO_ROUTERS,
                      DHCP_ADDRESS_OPTION_LENGTH,
                      &defaultGateway);
        (lease->defaultGateway).networkType = networkType;
        (lease->defaultGateway).IPV4 = defaultGateway;

        // Get the subnet mask to insert into lease
        UInt32 subnetMask;
        dhcpGetOption(data.options,
                      DHO_SUBNET_MASK,
                      DHCP_ADDRESS_OPTION_LENGTH,
                      &subnetMask);
        (lease->subnetMask).networkType = networkType;
        (lease->subnetMask).IPV4 = subnetMask;

        (lease->subnetNumber).networkType =
                                (lease->ipAddress).networkType;
        (lease->subnetNumber).IPV4 =
                                (lease->ipAddress).IPV4 &
                                (lease->subnetMask).IPV4;
        // get the domain name severs to insert into lease
        UInt8 val = dhcpGetOptionLength(data.options,
                                        DHO_DOMAIN_NAME_SERVERS);
        Int32 noDNSServer = val / DHCP_DOMAIN_NAME_SERVER_OPTION_LENGTH;
        UInt32* DNSServers;
        DNSServers = (UInt32*)MEM_malloc((val));

        dhcpGetOption(data.options,
                      DHO_DOMAIN_NAME_SERVERS,
                      val,
                      DNSServers);
        UInt32 primaryDNS;
        primaryDNS = DNSServers[0];

        (lease->primaryDNSServer).networkType = networkType;
        (lease->primaryDNSServer).IPV4 = primaryDNS;

        if (noDNSServer > 1)
        {
            if (lease->listOfSecDNSServer == NULL)
            {
                lease->listOfSecDNSServer = new std::list<Address*>;
            }
            else
            {
                list<Address*>::iterator it1;
                for (it1 = lease->listOfSecDNSServer->begin();
                     it1 != lease->listOfSecDNSServer->end();
                     it1++)
                {
                    MEM_free(*it1);
                }
                lease->listOfSecDNSServer->clear();
            }
            for (val = 1; val < noDNSServer; val++)
            {
                Address* secondaryDNS;
                secondaryDNS = (Address*)MEM_malloc(sizeof(Address));
                secondaryDNS->networkType = networkType;
                secondaryDNS->IPV4 = DNSServers[val];
                lease->listOfSecDNSServer->push_back(secondaryDNS);
            }
        }
        // update the interface info
        NetworkDataIp* ip = node->networkData.networkVar;
        IpInterfaceInfoType* interfaceInfo =
                ip->interfaceInfo[incomingInterface];
        (interfaceInfo->subnetMask).networkType = networkType;
        (interfaceInfo->subnetMask).IPV4 = subnetMask;
        (interfaceInfo->primaryDnsServer).networkType = networkType;
        (interfaceInfo->primaryDnsServer).IPV4 = primaryDNS;
        if (noDNSServer > 1)
        {
            if (interfaceInfo->listOfSecondaryDNSServer == NULL)
            {
                ListInit(node, &interfaceInfo->listOfSecondaryDNSServer);
            }
            else
            {
                ListFree(
                    node,
                    interfaceInfo->listOfSecondaryDNSServer,
                    FALSE);
                ListInit(node, &interfaceInfo->listOfSecondaryDNSServer);
            }
            for (val = 1; val < noDNSServer; val++)
            {
                Address* secondaryDNS;
                secondaryDNS = (Address*)MEM_malloc(sizeof(Address));
                secondaryDNS->networkType = networkType;
                secondaryDNS->IPV4 = DNSServers[val];
                ListInsert(node,
                           interfaceInfo->listOfSecondaryDNSServer,
                           node->getNodeTime(),
                           secondaryDNS);
            }
        }
        ip->gatewayConfigured = TRUE;
        ip->defaultGatewayId = defaultGateway;

        if (DHCP_DEBUG)
        {
            //Print the renewed IP address allocated
            NodeAddress addr = MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                    node,
                                    node->nodeId,
                                    incomingInterface);
            char str[MAX_STRING_LENGTH] = "";
            Address TempAddr;
            TempAddr.networkType = networkType;
            TempAddr.IPV4 = addr;
            IO_ConvertIpAddressToString(&(TempAddr), str);
            printf("New IP address allocated for  node %d for "
                   "interface %d = %s \n",
                   node->nodeId,
                   incomingInterface,
                   str);
            IO_ConvertIpAddressToString(&(lease->defaultGateway), str);
            printf("Default gateway : %s \n", str);
            IO_ConvertIpAddressToString(&(lease->subnetMask), str);
            printf("Subnet Mask: %s \n", str);
            IO_ConvertIpAddressToString(&(lease->primaryDNSServer), str);
            printf("Primary DNS : %s \n", str);
            printf("Secondary DNS servers \n");
            Address* addrSecDns;
            if (lease->listOfSecDNSServer != NULL)
            {
                list<Address*>::iterator it1;
                for (it1 = lease->listOfSecDNSServer->begin();
                     it1 != lease->listOfSecDNSServer->end();
                     it1++)
                {
                    addrSecDns = *it1;
                    IO_ConvertIpAddressToString(addrSecDns, str);
                    printf("%s \n", str);
                }
            }
            clocktype simulationTime = node->getNodeTime();
            char simulationTimeStr[MAX_STRING_LENGTH] = "";
            TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
            printf("Time at allocation = %s \n", simulationTimeStr);
        }

        if (DNSServers)
        {
            MEM_free(DNSServers);
        }
    }
    if (clientPtr->state != DHCP_CLIENT_INFORM &&
        leaseTime != (UInt32)DHCP_INFINITE_LEASE &&
        leaseTime != 0)
    {
        // Get the renewal and rebind time
        UInt32 rebindTime;
        UInt32 renewTime;
        char buf[MAX_STRING_LENGTH] = "";
        clocktype time;

        dhcpGetOption(
                   data.options,
                   DHO_DHCP_RENEWAL_TIME,
                   DHCP_LEASE_TIME_OPTION_LENGTH,
                   &renewTime);
        dhcpGetOption(
                   data.options,
                   DHO_DHCP_REBINDING_TIME,
                   DHCP_LEASE_TIME_OPTION_LENGTH,
                   &rebindTime);
        Message* message = MESSAGE_Alloc(
                             node,
                             APP_LAYER,
                             APP_DHCP_CLIENT,
                             MSG_APP_DHCP_CLIENT_RENEW);
        MESSAGE_InfoAlloc(
                          node,
                          message,
                          sizeof(Int32));
        Int32* info = (Int32*)MESSAGE_ReturnInfo(message);
        *(info) = incomingInterface;
        lease->renewMsg = message;
        lease->renewTimeout = 0;
        sprintf(buf, "%d", renewTime);
        time = TIME_ConvertToClock(buf);
        if (clientPtr->arpInterval != 0 && clientPtr->arpInterval <= time)
        {
            MESSAGE_Send(node,
                         message,
                         (time - clientPtr->arpInterval));
        }
        else
        {
            MESSAGE_Send(node, message, time);
        }

        // schedule an event at T2 when client enters REBINDING state
        // and broadcast renewal request
        // T2 defaults to 0.875*dutaion of lease

        message = MESSAGE_Alloc(
                             node,
                             APP_LAYER,
                             APP_DHCP_CLIENT,
                             MSG_APP_DHCP_CLIENT_REBIND);
        MESSAGE_InfoAlloc(
                        node,
                        message,
                        sizeof(Int32));
        info = (Int32*)MESSAGE_ReturnInfo(message);
        *(info) = incomingInterface;
        lease->rebindMsg = message;
        lease->rebindTimeout = 0;
        sprintf(buf, "%d", rebindTime);
        time = TIME_ConvertToClock(buf);
        if (clientPtr->arpInterval != 0 && clientPtr->arpInterval <= time)
        {
            MESSAGE_Send(node,
                         message,
                         (time) - clientPtr->arpInterval);
        }
        else
        {
            MESSAGE_Send(node, message, time);
        }

        // schedule an event for  expiry of lease
        message = MESSAGE_Alloc(
                             node,
                             APP_LAYER,
                             APP_DHCP_CLIENT,
                             MSG_APP_DHCP_LEASE_EXPIRE);

        MESSAGE_InfoAlloc(
                      node,
                      message,
                      sizeof(Int32));
        info = (Int32*)MESSAGE_ReturnInfo(message);
        *(info) = incomingInterface;
        lease->expiryMsg = message;
        sprintf(buf, "%d", lease->leaseTime);
        time = TIME_ConvertToClock(buf);
        if (clientPtr->reacquireTime != 0 &&
            clientPtr->state != DHCP_CLIENT_REQUEST)
        {
            time = time - (node->getNodeTime() - clientPtr->reacquireTime);
            clientPtr->reacquireTime = 0;
        }
        if (clientPtr->arpInterval != 0 && clientPtr->arpInterval <= time)
        {
            MESSAGE_Send(node,
                         message,
                        (time) - clientPtr->arpInterval);
            clientPtr->arpInterval = 0;
        }
        else
        {
            MESSAGE_Send(node, message,time);
        }
    }
    clientPtr->reacquireTime = 0;

    // free the request or Ack packet
    if (clientPtr->dataPacket)
    {
        MEM_free(clientPtr->dataPacket);
        clientPtr->dataPacket = NULL;
    }

    // if MANET is enabled then make this client relay agent
    if (clientPtr->manetEnabled == TRUE &&
        (clientPtr->state == DHCP_CLIENT_INFORM ||
          clientPtr->state == DHCP_CLIENT_REQUEST))
    {
        // Allocate memory to relay agent pointer
        struct appDataDhcpRelay* dhcpRelay = (struct appDataDhcpRelay*)
            MEM_malloc(sizeof(struct appDataDhcpRelay));
        if (dhcpRelay == NULL)
        {
            ERROR_ReportErrorArgs("Not enough memory to allocate relay agent\n");
        }
        memset(dhcpRelay, 0, sizeof(struct appDataDhcpRelay));
        dhcpRelay->interfaceIndex = incomingInterface;

        // Get Server IP Addresses list configured
        // Initialize the list of DHCP servers
        dhcpRelay->serverAddrList = new std::list<Address*>;

        Address* dhcpServerAddr;
        dhcpServerAddr = (Address*)MEM_malloc(sizeof(Address));
        dhcpServerAddr->networkType = networkType;

        UInt32 serverIdentifier;
        dhcpGetOption(data.options,
                      DHO_DHCP_SERVER_IDENTIFIER,
                      DHCP_ADDRESS_OPTION_LENGTH,
                      &serverIdentifier);

        dhcpServerAddr->IPV4 = serverIdentifier;

        // Add to linked list
        dhcpRelay->serverAddrList->push_back(dhcpServerAddr);

        // enable relay statistics if statistics is enabled
        dhcpRelay->dhcpRelayStatistics = clientPtr->dhcpClientStatistics;
         // Register the relay agent
        APP_RegisterNewApp(node, APP_DHCP_RELAY, dhcpRelay);
    }

    // Move the client to BOUND state
    clientPtr->state = DHCP_CLIENT_BOUND;
    return;
}

//--------------------------------------------------------------------------
// NAME:           : AppDhcpClientStateRenewRebind
// PURPOSE:        : models the behaviour when client enters the RENEWstate
// PARAMETERS:
// +node           : Node*             : pointer to the client node which
//                                       received the message.
// +interfaceIndex : Int32             : Interface on which client is enabled
// +serverAddress  : Address           : server address for  unicast
// +clientLease    : struct dhcpLease* : Lease which enters into
//                                       RENEW/REBIND state.
// RETURN:         : none.
//--------------------------------------------------------------------------
void AppDhcpClientStateRenewRebind(
    Node* node,
    Int32 incomingInterface,
    Address serverAddress,
    struct dhcpLease* clientLease)
{
    struct appDataDhcpClient* clientPtr = NULL;
    struct dhcpData* requestData = NULL;
    struct dhcpData data;
    clocktype delay = 0;
    char buf[MAX_STRING_LENGTH] = "";
    clocktype time;

    if (DHCP_DEBUG)
    {
        printf("Performing DHCP client renew/rebind for  node %d "
               "at interface %d \n",
               node->nodeId,
               incomingInterface);
    }
    clientPtr = AppDhcpClientGetDhcpClient(
                        node,
                        incomingInterface);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d at interface %d not a DHCP client \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }

    memset(&data, 0, sizeof(struct dhcpData));
    data.options[0] = '\0';

    // Get the REQUEST data
    requestData = AppDhcpClientMakeRequest(
                        node,
                        data,
                        incomingInterface);
    if (requestData == NULL)
    {
        ERROR_ReportErrorArgs(
                "DHCP Client: Insufficient memory "
                "REQUEST packet creation falied for  node %d\n",
                node->nodeId);
    }

    // Make it RENEWAL/REBIND REQUEST
    // Create new XID

    requestData->xid = RANDOM_nrand(clientPtr->jitterSeed);
    (requestData->ciaddr) = NetworkIpGetInterfaceAddress(
                                node,
                                incomingInterface);

    // Record the XID for  this client before sending packet
    clientPtr->recentXid = requestData->xid;

    //Lease time MAY be present for  OFFER
    if (clientPtr->dhcpLeaseTime)
    {
        UInt32 val1 = clientPtr->dhcpLeaseTime;
        dhcpSetOption(requestData->options,
                      DHO_DHCP_LEASE_TIME,
                      DHCP_LEASE_TIME_OPTION_LENGTH,
                      &val1);
    }

    //Send the REQUEST packet
    if (clientPtr->state == DHCP_CLIENT_RENEW)
    {
        if (DHCP_DEBUG)
        {
            printf("Unicasting Request from node %d interface %d"
                   "in renew state \n",
                   node->nodeId,
                   incomingInterface);
            clocktype simulationTime = node->getNodeTime();
            char simulationTimeStr[MAX_STRING_LENGTH] = "";
            TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
            printf("Time  = %s \n", simulationTimeStr);
        }
        // send the REQUEST packet
        AppDhcpSendDhcpPacket(
                        node,
                        (Int32)incomingInterface,
                        (short)DHCP_CLIENT_PORT,
                        serverAddress.IPV4,
                        (short)DHCP_SERVER_PORT,
                        clientPtr->tos,
                        requestData);

         // schedule retransmission timer
        sprintf(buf, "%d", clientLease->leaseTime);
        time = TIME_ConvertToClock(buf);
        delay = (clocktype)(DHCP_T1_RETRANSMIT*(time));
    }
    if (clientPtr->state == DHCP_CLIENT_REBIND)
    {
        if (DHCP_DEBUG)
        {
            printf("Broadcasting Request from node %d interface %d"
                    "in rebind state \n",
                    node->nodeId,
                    incomingInterface);
            clocktype simulationTime = node->getNodeTime();
            char simulationTimeStr[MAX_STRING_LENGTH] = "";
            TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
            printf("Time  = %s \n", simulationTimeStr);
        }

        AppDhcpSendDhcpPacket(
                        node,
                        (Int32)incomingInterface,
                        (short)DHCP_CLIENT_PORT,
                        ANY_ADDRESS,
                        (short)DHCP_SERVER_PORT,
                        clientPtr->tos,
                        requestData);

        // schedule retransmission timer
        sprintf(buf, "%d", clientLease->leaseTime);
        time = TIME_ConvertToClock(buf);
        delay = (clocktype)(DHCP_T2_RETRANSMIT * (time));
    }

    clientPtr->reacquireTime = node->getNodeTime();
    char simulationTimeStr[MAX_STRING_LENGTH] = "";
    TIME_PrintClockInSecond(delay, simulationTimeStr);
    if (DHCP_DEBUG)
    {
        printf("delay = %s \n", simulationTimeStr);
    }
    Message* message = MESSAGE_Alloc(
                                node,
                                APP_LAYER,
                                APP_DHCP_CLIENT,
                                MSG_APP_DHCP_TIMEOUT);
    MESSAGE_InfoAlloc(
                    node,
                    message,
                    sizeof(Int32));
    Int32* info = (Int32*)MESSAGE_ReturnInfo(message);
    *(info) = incomingInterface;
    clientPtr->timeoutMssg = message;
    if (clientPtr->dataPacket != NULL)
    {
        MEM_free(clientPtr->dataPacket);
    }
    clientPtr->dataPacket = requestData;

    // Increment the request packet
    clientPtr->numRequestSent++;
    MESSAGE_Send(node, message, delay);
}

//---------------------------------------------------------------------------
// NAME:            : AppDhcpClientStateInform
// PURPOSE:         : Models the behaviour of client when it enters
//                    INFORM state
// PARAMETERS:
// + node           : Node* : pointer to the node which enters INFORM state.
// + interfaceIndex : Int32 : interface of node which enters INFORMstate
// RETURN           : NONE
// --------------------------------------------------------------------------
void AppDhcpClientStateInform(
    Node* node,
    Int32 interfaceIndex)
{
    struct appDataDhcpClient* clientPtr = NULL;
    struct dhcpData* informData = NULL;
    if (DHCP_DEBUG)
    {
        printf("DHCPINFORM from node %d at interface %d \n",
               node->nodeId,
               interfaceIndex);
    }

    // Get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(node,
                                           interfaceIndex);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d not a DHCP client at interface %d \n",
                   node->nodeId,
                   interfaceIndex);
        }
        return;
    }
    informData = (struct dhcpData*)MEM_malloc(sizeof(struct dhcpData));
    if (informData == NULL)
    {
        if (DHCP_DEBUG)
        {
            ERROR_ReportErrorArgs(
                    "DHCP Client: Insufficient memory "
                    "INFORM packet creation falied for  node %d\n",
                    node->nodeId);
        }
    }
    memset(informData, 0, sizeof(struct dhcpData));
        /* Fields as used for  INFORM
      ’op’ BOOTREQUEST
      ’htype’ (From "Assigned Numbers" RFC)
      ’hlen’ (Hardware address length in octets)
      ’hops’ 0
      ’xid’ selected by client
      ’secs’ 0 or seconds since DHCP process started
      ’flags’ Set ’BROADCAST’if client broadcast reply
      ’ciaddr’ client's network address
      ’yiaddr’ 0
      ’siaddr’ 0
      ’giaddr’ 0
      ’chaddr’ client’s hardware address
      ’sname’ options, if indicated ’sname/file’otherwise unused
      ’file’ options, if indicated in ’sname/file’ otherwise unused
      Requested IP address MUST NOT
      IP address lease time MUST NOT
      Use ’file’/’sname’ fields MAY MAY MAY
      DHCP message type DHCPDISCOVER
      Client identifier MAY
      Vendor class identifier MAY
      Server identifier MUST NOT
      Parameter request list MAY
      Maximum message size MAY
      Message SHOULD NOT
      Site-specific MAY
      All others MAY */

    informData->op = BOOTREQUEST;
    informData->htype = (UInt8)clientPtr->hardwareAddress.hwType;
    informData->hlen = (UInt8)clientPtr->hardwareAddress.hwLength;
    informData->hops = 0;
    informData->xid = RANDOM_nrand(clientPtr->jitterSeed);;
    informData->secs = (UInt16)(node->getNodeTime() / SECOND);
    informData->flags = DHCP_BROADCAST;
    informData->ciaddr = NetworkIpGetInterfaceAddress(node, interfaceIndex);
    informData->yiaddr = 0;
    informData->siaddr = 0;
    informData->giaddr = 0;
    memcpy(informData->chaddr,
           clientPtr->hardwareAddress.byte,
           informData->hlen);
    informData->sname[0] = '\0';
    informData->file[0] = '\0';

    UInt8 val = DHCPINFORM;
    dhcpSetOption(informData->options,
                  DHO_DHCP_MESSAGE_TYPE,
                  1,
                  &val);

    // Record the XID for  this client before sending packet
     clientPtr->recentXid = informData->xid;

     // Change the state for  client
    clientPtr->state = DHCP_CLIENT_INFORM;

    if (DHCP_DEBUG)
    {
        printf("Broadcasting INFORM from node %d interface %d \n",
               node->nodeId,
               interfaceIndex);
        clocktype simulationTime = node->getNodeTime();
        char simulationTimeStr[MAX_STRING_LENGTH] = "";
        TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
        printf("Time  = %s \n", simulationTimeStr);
    }

    // Send the INFORM packet
    AppDhcpSendDhcpPacket(
                        node,
                        interfaceIndex,
                        DHCP_CLIENT_PORT,
                        ANY_ADDRESS,
                        DHCP_SERVER_PORT,
                        clientPtr->tos,
                        informData);

    clientPtr->numInformSent++;
    if (clientPtr->dataPacket != NULL)
    {
        MEM_free(clientPtr->dataPacket);
    }
    clientPtr->dataPacket = informData;
    clocktype timerDelay = (clocktype) ((clientPtr->timeout
                      * (clientPtr->retryCounter))
                      + RANDOM_erand(clientPtr->jitterSeed));
    // initiate retrasmission
    Message* message = MESSAGE_Alloc(
                                    node,
                                    APP_LAYER,
                                    APP_DHCP_CLIENT,
                                    MSG_APP_DHCP_TIMEOUT);
    MESSAGE_InfoAlloc(node,
                      message,
                      sizeof(Int32));
    Int32* info = (Int32*)MESSAGE_ReturnInfo(message);
    *(info) = interfaceIndex;
    clientPtr->timeoutMssg = message;
    MESSAGE_Send(node, message, timerDelay);
}

//---------------------------------------------------------------------------
// NAME:                : AppDhcpServerReceivedInform.
// PURPOSE:             : models the behaviour of server when a INFORM
//                      : message is received.
// PARAMETERS:
// + node               : Node*           : DHCP server node.
// + data               : struct dhcpData : INFORM packet received.
// + incomingInterface  : Int32           : interface on which packte is
//                                          received.
// RETURN:              : NONE
//---------------------------------------------------------------------------
void AppDhcpServerReceivedInform(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface)
{
    struct appDataDhcpServer* serverPtr = NULL;
    struct dhcpData* ackData = NULL;

    // Get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(node, incomingInterface);
    if (serverPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP server \n", node->nodeId);
        }
        return;
    }

    // Increment the count of INFORM packet received
    serverPtr->numInformRecv++;
    if (DHCP_DEBUG)
    {
        printf("Received INFORM message at node %d from "
               "interface %d \n",
               node->nodeId,
               incomingInterface);
    }

    // Create ACK data
    ackData = (struct dhcpData*)MEM_malloc(sizeof(struct dhcpData));
    if (ackData == NULL)
    {
        if (DHCP_DEBUG)
        {
            ERROR_ReportErrorArgs(
                    "DHCP Server: Insufficient memory "
                    "ACK packet creation falied for  node %d\n",
                    node->nodeId);
        }
        return;
    }

    memset(ackData, 0, sizeof(struct dhcpData));
    ackData->op = BOOTREPLY;
    ackData->htype = data.htype;
    ackData->hlen = data.hlen;
    ackData->hops = 0;
    ackData->xid = data.xid;
    ackData->secs = 0;
    ackData->flags = data.flags;
    (ackData->ciaddr) = data.ciaddr;
    (ackData->yiaddr) = 0;
    ackData->siaddr = NetworkIpGetInterfaceAddress(node, incomingInterface);
    ackData->giaddr = data.giaddr;
    memcpy(ackData->chaddr, data.chaddr, data.hlen);
    ackData->sname[0] = '\0';
    ackData->file[0] = '\0';

    //options
    UInt8 val1 = DHCPACK;
    dhcpSetOption(ackData->options,
                  DHO_DHCP_MESSAGE_TYPE,
                  1,
                  &val1);
     UInt32 val = NetworkIpGetInterfaceAddress(node, incomingInterface);
     dhcpSetOption(ackData->options,
                   DHO_DHCP_SERVER_IDENTIFIER,
                   DHCP_ADDRESS_OPTION_LENGTH,
                   &val);
     val = (serverPtr->subnetMask).IPV4;
    dhcpSetOption(ackData->options,
                  DHO_SUBNET_MASK,
                  DHCP_ADDRESS_OPTION_LENGTH,
                  &val);
    val = (serverPtr->defaultGateway).IPV4;
    dhcpSetOption(ackData->options,
                  DHO_ROUTERS,
                  DHCP_ADDRESS_OPTION_LENGTH,
                  &val);
    Int32 noSecondaryDNS  = 0;
    if (serverPtr->listSecDnsServer != NULL)
    {
        if (!serverPtr->listSecDnsServer->empty())
        {
            noSecondaryDNS = serverPtr->listSecDnsServer->size();
        }
    }
    Int32 i = 0;
    UInt32* DNSServers;
    DNSServers = (UInt32*)MEM_malloc((noSecondaryDNS + 1) * sizeof(UInt32));
    DNSServers[0] = (serverPtr->primaryDNSServer).IPV4;
    i = 1;
    if (noSecondaryDNS != 0)
    {
        list<Address*>::iterator it1;
        for (it1 = serverPtr->listSecDnsServer->begin();
             it1 != serverPtr->listSecDnsServer->end();
             it1++)
        {
            DNSServers[i] = (*it1)->IPV4;
            i++;
        }
    }
    dhcpSetOption(ackData->options,
                  DHO_DOMAIN_NAME_SERVERS,
                  (UInt8)(noSecondaryDNS + 1) *
                  DHCP_DOMAIN_NAME_SERVER_OPTION_LENGTH,
                  DNSServers);
    MEM_free(DNSServers);
    if (DHCP_DEBUG)
    {
        printf("Sending ACK from server node %d "
               "at inetrface %d \n",
               node->nodeId,
               incomingInterface);
    }
    if (data.giaddr != 0)
    {
        AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        data.giaddr,
                        DHCP_SERVER_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
    }
    else if (data.giaddr == 0)
    {
        AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_SERVER_PORT,
                        data.ciaddr,
                        DHCP_CLIENT_PORT,
                        APP_DEFAULT_TOS,
                        ackData);
    }
    serverPtr->numAckSent++;
    if (serverPtr->dataPacket != NULL)
    {
        MEM_free(serverPtr->dataPacket);
    }
    serverPtr->dataPacket = ackData;
}

//--------------------------------------------------------------------------
// NAME:               : AppDhcpClientSendRelease
// PURPOSE:            : models the behaviour when client needs to send
//                       RELEASE message
// PARAMETERS:
// +node               : Node*   : pointer to the client node which received
//                                 the message.
// +serverId           : Address : serverId
// +incomingInterface  : Int32   : Interface on which packet is received
// RETURN:             : none.
//--------------------------------------------------------------------------
void AppDhcpClientSendRelease(
    Node* node,
    Address serverId,
    Int32 incomingInterface)
{
    struct appDataDhcpClient* clientPtr = NULL;
    struct dhcpData* releaseData = NULL;
    clientPtr = AppDhcpClientGetDhcpClient(node, incomingInterface);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d not a DHCP client at interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }

    //Allocate memory for  releaseData
    releaseData = (struct dhcpData*)MEM_malloc(sizeof(struct dhcpData));
    if (releaseData == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("memory not allocated for  DHCPData \n");
        }
        return;
    }
    memset(releaseData, 0, sizeof(struct dhcpData));

    AddressMapType* map = node->partitionData->addressMapPtr;
    NetworkProtocolType networkProtocolType =
                MAPPING_GetNetworkProtocolTypeForInterface(
                           map,
                           node->nodeId,
                           incomingInterface);
    NetworkType networkType = NETWORK_IPV4;
    if (networkProtocolType != IPV4_ONLY &&
        networkProtocolType != DUAL_IP)
    {
        //error
        MEM_free(releaseData);
        ERROR_ReportErrorArgs(
                "Node %d : DHCP only supported for  IPV4 network\n",
                node->nodeId);
    }
    if (networkProtocolType == IPV4_ONLY)
    {
        networkType = NETWORK_IPV4;
    }
    else if (networkProtocolType == DUAL_IP)
    {
        networkType = NETWORK_DUAL;
    }

    releaseData->op = BOOTREQUEST;
    releaseData->htype = (UInt8) clientPtr->hardwareAddress.hwType;
    releaseData->hlen = (UInt8) clientPtr->hardwareAddress.hwLength;
    releaseData->hops = 0;
    releaseData->xid = RANDOM_nrand(clientPtr->jitterSeed);
    releaseData->secs = 0;
    releaseData->flags = DHCP_BROADCAST;
    releaseData->ciaddr = NetworkIpGetInterfaceAddress(
                                node,
                                incomingInterface),
    releaseData->yiaddr = 0;
    releaseData->siaddr = 0;
    releaseData->giaddr = 0;

     // Client hardware address
    memcpy(releaseData->chaddr,
           clientPtr->hardwareAddress.byte,
           releaseData->hlen);

     // for  sname and file : options, if indicated in
     //’sname/file’ ’sname/file’ option; otherwise unused
    releaseData->sname[0] = '\0';
    releaseData->file[0] = '\0';

     //options
     //Requested IP MAY be present for  DISCOVER
    UInt8 val2 = DHCPRELEASE;
    dhcpSetOption(releaseData->options,
                  DHO_DHCP_MESSAGE_TYPE,
                  1,
                  &val2);

     // Client identifier MAY be present for  DISCOVER. Check the clientPtr
     if (strlen(clientPtr->dhcpClientIdentifier) > 0)
     {
         UInt8 val1 = (UInt8)strlen(clientPtr->dhcpClientIdentifier);
         dhcpSetOption(releaseData->options,
                       DHO_DHCP_CLIENT_IDENTIFIER,
                       val1,
                       &(clientPtr->dhcpClientIdentifier));
     }

     // Server identifier MUST be present in decline
     UInt32 val = serverId.IPV4;
     dhcpSetOption(releaseData->options,
                   DHO_DHCP_SERVER_IDENTIFIER,
                   DHCP_ADDRESS_OPTION_LENGTH,
                   &val);
    if (DHCP_DEBUG)
    {
        printf("Sending Release from client at node %d interface %d \n",
               node->nodeId,
               incomingInterface);
    }
    // Unicast the RELEASE
    AppDhcpSendDhcpPacket(
                        node,
                        (Int32)incomingInterface,
                        (short)DHCP_CLIENT_PORT,
                        serverId.interfaceAddr.ipv4,
                        (short)DHCP_SERVER_PORT,
                        clientPtr->tos,
                        releaseData);

    // Invalidate client after 10MS
    clocktype delayTime =
        TIME_ConvertToClock(DHCP_CLIENT_RELEASE_INVALIDATION_INTERVAL);
    Message* message = MESSAGE_Alloc(
                                node,
                                APP_LAYER,
                                APP_DHCP_CLIENT,
                                MSG_APP_DHCP_InvalidateClient);
    MESSAGE_InfoAlloc(
                   node,
                   message,
                   sizeof(Int32));
    Int32* info = (Int32*)MESSAGE_ReturnInfo(message);
    *(info) = incomingInterface;
    MESSAGE_Send(
             node,
             message,
             delayTime);
    if (clientPtr->dataPacket != NULL)
    {
        MEM_free(clientPtr->dataPacket);
    }
    clientPtr->dataPacket = releaseData;
    return;
}

//---------------------------------------------------------------------------
// NAME:                : AppDhcpClientSendDecline
// PURPOSE:             : models the behaviour when client needs to send
//                        DECLINE message
// PARAMETERS:
// + node               : Node*           : pointer to the client node which
//                                          received the message.
// + data               : struct dhcpData : ACK packet received
// + incomingInterface  : Int32           : Interface on which packet is
//                                          received
// RETURN:              : none.
//---------------------------------------------------------------------------
void AppDhcpClientSendDecline(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface)
{
    struct appDataDhcpClient* clientPtr = NULL;
    struct dhcpData* declineData = NULL;
    clientPtr = AppDhcpClientGetDhcpClient(node, incomingInterface);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d not a DHCP client at interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }
    if (clientPtr->state == DHCP_CLIENT_REQUEST)
    {
        // Construct decline message
        declineData = AppDhcpClientMakeDecline(
                                               node,
                                               data,
                                               clientPtr,
                                               incomingInterface);

    }
    clientPtr->numDeclineSent++;

    // Broadcast the DHCPDECLINE
    AppDhcpSendDhcpPacket(
                        node,
                        incomingInterface,
                        DHCP_CLIENT_PORT,
                        ANY_ADDRESS,
                        DHCP_SERVER_PORT,
                        clientPtr->tos,
                        declineData);
    // change the state of client
    clientPtr->state = DHCP_CLIENT_INIT;

    // send the client to init state with a min delay of 10 sec
    Message* message = MESSAGE_Alloc(node,
                                     APP_LAYER,
                                     APP_DHCP_CLIENT,
                                     MSG_APP_DHCP_InitEvent);
    MESSAGE_InfoAlloc(node,
                      message,
                      sizeof(Int32));
    Int32* info = (Int32*)MESSAGE_ReturnInfo(message);
    *(info) = incomingInterface;
    clocktype delay =
        TIME_ConvertToClock(DHCP_CLIENT_DECLINE_INVALIDATION_INTERVAL);
    if (clientPtr->dataPacket != NULL)
    {
        MEM_free(clientPtr->dataPacket);
    }
    clientPtr->dataPacket = declineData;
    MESSAGE_Send(node, message, delay);
}

//---------------------------------------------------------------------------
// NAME:            : AppDhcpClientMakeDecline
// PURPOSE:         : make DHCPDECLINE packet to send
// PARAMETERS:
// + node           : Node                      : pointer to node
// + data           : struct dhcpData           : data packet
// + clientPtr      : struct appDataDhcpClient* : pointer to the client data
// + interfaceIndex : Int32                     : interface that will send
// RETURN:
// struct dhcpData* : pointer to the DHCPDECLINE packet created.
//                    NULL if nothing found.
//---------------------------------------------------------------------------

struct dhcpData* AppDhcpClientMakeDecline(
    Node* node,
    struct dhcpData data,
    struct appDataDhcpClient* clientPtr,
    Int32 interfaceIndex)
{
    struct dhcpData* declineData = NULL;

    // Allocate memory for  DECLINE Data
    declineData = (struct dhcpData*)MEM_malloc(sizeof(struct dhcpData));
    if (declineData == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("memory not allocated for  DHCPData \n");
        }
        return(NULL);
    }
    memset(declineData, 0, sizeof(struct dhcpData));

    NetworkType networkType = NETWORK_IPV4;

    declineData->op = BOOTREQUEST;
    declineData->htype = (UInt8)clientPtr->hardwareAddress.hwType;
    declineData->hlen = (UInt8)clientPtr->hardwareAddress.hwLength;
    declineData->hops = 0;
    declineData->xid = RANDOM_nrand(clientPtr->jitterSeed);
    declineData->secs = 0;
    declineData->flags = DHCP_BROADCAST;
    declineData->ciaddr = 0;
    declineData->yiaddr = 0;
    declineData->siaddr = 0;
    declineData->giaddr = 0;

     // Client hardware address
    memcpy(declineData->chaddr,
           clientPtr->hardwareAddress.byte,
           declineData->hlen);

    // for  sname and file : options, if indicated in
    //’sname/file’ ’sname/file’ option; otherwise unused

    declineData->sname[0] = '\0';
    declineData->file[0] = '\0';

     // options
    UInt8 val2 = DHCPDECLINE;
    dhcpSetOption(declineData->options,
                  DHO_DHCP_MESSAGE_TYPE,
                  1,
                  &val2);
    UInt32 val = data.yiaddr;
    if (val != 0)
        dhcpSetOption(declineData->options,
                      DHO_DHCP_REQUESTED_ADDRESS,
                      DHCP_ADDRESS_OPTION_LENGTH,
                      &val);

    if (strlen(clientPtr->dhcpClientIdentifier) > 0)
    {
        UInt8 val1 = (UInt8)strlen(clientPtr->dhcpClientIdentifier);
        dhcpSetOption(declineData->options,
                      DHO_DHCP_CLIENT_IDENTIFIER,
                      val1,
                      &(clientPtr->dhcpClientIdentifier));
    }

     // Server identifier MUST be present in decline
     val = data.siaddr;
     dhcpSetOption(declineData->options,
                   DHO_DHCP_SERVER_IDENTIFIER,
                   DHCP_ADDRESS_OPTION_LENGTH,
                   &val);

    return(declineData);
}

//--------------------------------------------------------------------------
// NAME:            : AppDHCPClientFaultEnd.
// PURPOSE:         : models the behaviour of client when the fault on
//                    DHCP client ends.
// PARAMETERS:
// + node           : Node*    : DHCP client node.
// + interfaceIndex : Int32    : interface which act as client.
// RETURN           : NONE
// --------------------------------------------------------------------------
void AppDHCPClientFaultEnd(
    Node* node,
    Int32 interfaceIndex)
{
    struct appDataDhcpClient* clientPtr = NULL;

    // Get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(
                                node,
                                interfaceIndex);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d not a DHCP client at interface %d \n",
                   node->nodeId,
                   interfaceIndex);
        }
        return;
    }
    if (DHCP_DEBUG)
    {
        printf("Node %d up due to fault end at inteface index %d \n",
               node->nodeId,
               interfaceIndex);
    }
    if (clientPtr->dataPacket != NULL)
    {
        MEM_free(clientPtr->dataPacket);
    }
    clientPtr->dataPacket = NULL;

    if (clientPtr->timeoutMssg != NULL)
    {
        MESSAGE_CancelSelfMsg(
              node,
              clientPtr->timeoutMssg);
        clientPtr->timeoutMssg = NULL;
    }
    if (!clientPtr->clientLeaseList->empty())
    {
        list<struct dhcpLease*>::iterator it;
        struct dhcpLease* lastLease = NULL;
        for (it = clientPtr->clientLeaseList->begin();
             it != clientPtr->clientLeaseList->end();
             it++)
        {
            lastLease = *it;
            if (lastLease->status == DHCP_ACTIVE ||
                lastLease->status == DHCP_MANUAL)
            {
                if (lastLease->renewMsg != NULL)
                {
                     MESSAGE_CancelSelfMsg(
                        node,
                        lastLease->renewMsg);
                     lastLease->renewMsg = NULL;
                }
                if (lastLease->rebindMsg != NULL)
                {
                    MESSAGE_CancelSelfMsg(
                        node,
                        lastLease->rebindMsg);
                    lastLease->rebindMsg = NULL;
                }
                lastLease->status = DHCP_INACTIVE;
                break;
            }
        }
    }
    NodeAddress subnetMask = MAPPING_GetSubnetMaskForInterface(
                                                        node,
                                                        node->nodeId,
                                                        interfaceIndex);

     // Initialize the old IP address
    Address address;
    memset(&address, 0, sizeof(Address));
    address.IPV4 = NetworkIpGetInterfaceAddress(node, interfaceIndex);
    AddressMapType* map = node->partitionData->addressMapPtr;
    NetworkProtocolType networkType =
            MAPPING_GetNetworkProtocolTypeForInterface(
                               map,
                               node->nodeId,
                               interfaceIndex);
    if (networkType != IPV4_ONLY && networkType != DUAL_IP)
    {
         // error
         MEM_free(clientPtr);
         ERROR_ReportErrorArgs(
                 "Node %d : DHCP only supported for  IPV4 network\n",
                 node->nodeId);
    }
    if (networkType == IPV4_ONLY)
    {
        address.networkType = NETWORK_IPV4;
    }
    else if (networkType == DUAL_IP)
    {
        address.networkType = NETWORK_DUAL;
    }
    if (clientPtr->state == DHCP_CLIENT_INIT ||
        clientPtr->state == DHCP_CLIENT_SELECT)
    {
        NetworkIpProcessDHCP(
                      node,
                      interfaceIndex,
                      &address,
                      subnetMask,
                      INIT_DHCP,
                      address.networkType);

        clientPtr->retryCounter = 1;
        /*if (clientPtr->state == DHCP_CLIENT_SELECT)
        {*/
        AppDhcpClientStateInit(node, interfaceIndex);
        //}
        /*else
        {
            clientPtr->state = DHCP_CLIENT_INIT_REBOOT;
            AppDhcpClientStateRebootInit(node, interfaceIndex);
        }*/
    }
    else if (clientPtr->state == DHCP_CLIENT_INIT_REBOOT)
    {
        NetworkIpProcessDHCP(
                      node,
                      interfaceIndex,
                      &address,
                      subnetMask,
                      INIT_DHCP,
                      address.networkType);
        clientPtr->retryCounter = 1;
        /*if (clientPtr->state == DHCP_CLIENT_SELECT)
        {
            AppDhcpClientStateInit(node, interfaceIndex);
        }*/
        /*else
        {
            clientPtr->state = DHCP_CLIENT_INIT_REBOOT;*/
            AppDhcpClientStateRebootInit(node, interfaceIndex);
        //}
    }
    else if (clientPtr->state == DHCP_CLIENT_INFORM)
    {
        NetworkIpProcessDHCP(
                         node,
                         interfaceIndex,
                         &address,
                         subnetMask,
                         INFORM_DHCP,
                         address.networkType);
        clientPtr->retryCounter = 1;
        AppDhcpClientStateInform(node, interfaceIndex);
    }
}

//--------------------------------------------------------------------------
// NAME:            : AppDHCPClientFaultStart.
// PURPOSE:         : models the behaviour of client when the fault on
//                    DHCP client starts.
// PARAMETERS:
// + node           : Node*    : DHCP client node.
// + interfaceIndex : Int32    : interface which act as client.
// RETURN           : NONE
//---------------------------------------------------------------------------
void AppDHCPClientFaultStart(
    Node* node,
    Int32 interfaceIndex)
{
    struct appDataDhcpClient* clientPtr = NULL;
    clientPtr = AppDhcpClientGetDhcpClient(node, interfaceIndex);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d not a DHCP client at interface %d \n",
                   node->nodeId,
                   interfaceIndex);
        }
        return;
    }
    if (DHCP_DEBUG)
    {
        printf("Node %d going down due to fault at inteface index %d \n",
               node->nodeId,
               interfaceIndex);
    }
    if (clientPtr->dataPacket != NULL)
    {
        MEM_free(clientPtr->dataPacket);
    }
    clientPtr->dataPacket = NULL;
    if (clientPtr->timeoutMssg != NULL)
    {
        MESSAGE_CancelSelfMsg(node,
                              clientPtr->timeoutMssg);
        clientPtr->timeoutMssg = NULL;
    }
    if (!clientPtr->clientLeaseList->empty())
    {
        struct dhcpLease* lastLease = NULL;
        list<struct dhcpLease*>::iterator it;
        for (it = clientPtr->clientLeaseList->begin();
             it != clientPtr->clientLeaseList->end();
             it++)
        {
            lastLease = *it;
            if (lastLease->renewMsg != NULL)
            {
                MESSAGE_CancelSelfMsg(node,
                                      lastLease->renewMsg);
                lastLease->renewMsg = NULL;
            }
            if (lastLease->rebindMsg != NULL)
            {
                 MESSAGE_CancelSelfMsg(node,
                                       lastLease->rebindMsg);
                lastLease->rebindMsg = NULL;
            }
            if (lastLease->expiryMsg != NULL)
            {
                MESSAGE_CancelSelfMsg(node,
                                      lastLease->expiryMsg);
                lastLease->expiryMsg = NULL;
            }
            if (lastLease->status == DHCP_ACTIVE ||
                lastLease->status == DHCP_INACTIVE)
            {
                lastLease->status = DHCP_INACTIVE;
                clientPtr->state = DHCP_CLIENT_INIT_REBOOT;
            }
            else if (lastLease->status == DHCP_MANUAL)
            {
                clientPtr->state = DHCP_CLIENT_INFORM;
            }
        }
    }
    else
    {
        clientPtr->state = DHCP_CLIENT_INIT;
    }
}

//---------------------------------------------------------------------------
// NAME:               : AppDhcpServerFindLease.
// PURPOSE:            : search for  a DHCP lease to offer.
// PARAMETERS:
// +node               : Node*           : DHCP server.
// +data               : struct dhcpData : DISCOVER packet received.
// +incomingInterface  : Int32           : interface on which packet is
//                                         received.
// +originatingNodeId  : NodeAddress     : source which sent the message
//RETURN:
// struct dhcpLease*   : the pointer to the lease found,NULL if nothing
//                       found.
//---------------------------------------------------------------------------
struct dhcpLease* AppDhcpServerFindLease(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface,
    NodeAddress originatingNodeId)
{
    struct appDataDhcpServer* serverPtr = NULL;
    struct dhcpLease* lease = NULL;
    Address interfaceAddress;
    struct appDhcpServerManualAlloc* manualAlloc = NULL;
    UInt32 requestedIp = 0;
    char clientIdentifier[MAX_STRING_LENGTH] = "";
    UInt8 clientIdLength = 0;

    // Get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(node, incomingInterface);
    if (serverPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP sever at interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return(NULL);
    }

    // Parse the option of DISCOVER packet
    // to Requested IP and client identifier

    dhcpGetOption(
                data.options,
                DHO_DHCP_REQUESTED_ADDRESS,
                DHCP_ADDRESS_OPTION_LENGTH,
                &requestedIp);

    // Get the client identifier
    clientIdLength = dhcpGetOptionLength(data.options,
                                         DHO_DHCP_CLIENT_IDENTIFIER);

    if (clientIdLength != 0)
    {
        dhcpGetOption(
                   data.options,
                   DHO_DHCP_CLIENT_IDENTIFIER,
                   clientIdLength,
                   clientIdentifier);
        clientIdentifier[clientIdLength] = '\0';
    }

    lease = AppDhcpServerCheckClientForManualLease(
                                node,
                                serverPtr,
                                originatingNodeId,
                                incomingInterface,
                                data);
    if (lease != NULL)
    {
        // server has lease to offer through manual allocation
        return(lease);
    }

    // Lease not there in manual allocation Check if the lease list is empty
    lease = NULL;
    if (serverPtr->serverLeaseList->empty())
    {
        // First lease to be inserted hence construct a lease
        // with the starting address
        // Check the address if it is reserved for  manual.
        // If reserved allocate the next address

        Address firstAddress;
        memcpy(&firstAddress,
               &serverPtr->addressRangeStart,
               sizeof(Address));
        BOOL validFirstAddress = FALSE;
        while (!validFirstAddress &&
               firstAddress.IPV4 <= serverPtr->addressRangeEnd.IPV4)
        {
            if (AppDhcpCheckIfIpInManualAllocationList(
                                                serverPtr,
                                                firstAddress))
            {
                firstAddress.IPV4++;
            }
            else
            {
                validFirstAddress = TRUE;
            }
        }
        if (validFirstAddress != TRUE)
        {
            if (DHCP_DEBUG)
            {
                printf("No lease to offer at server node %d "
                       "interface %d \n",
                       node->nodeId,
                       incomingInterface);
            }
            return(NULL);
        }

        lease = (struct dhcpLease*)MEM_malloc(sizeof(struct dhcpLease));
        memset(lease, 0, sizeof(struct dhcpLease));

        lease->clientIdentifier[0] = '\0';
        (lease->ipAddress).networkType = (firstAddress).networkType;
        (lease->ipAddress).IPV4 = (firstAddress).IPV4;
        (lease->serverId).networkType = NETWORK_IPV4;
        (lease->serverId).IPV4 =
            NetworkIpGetInterfaceAddress(node, incomingInterface);
        lease->macAddress.hwLength = data.hlen;
        lease->macAddress.hwType = data.htype;
        lease->macAddress.byte = (unsigned char*)MEM_malloc(data.hlen);
        memcpy(lease->macAddress.byte , data.chaddr, data.hlen);

        (lease->defaultGateway).networkType =
            (serverPtr->defaultGateway).networkType;
        (lease->defaultGateway).IPV4 = (serverPtr->defaultGateway).IPV4;
        (lease->subnetMask).networkType =
            (serverPtr->subnetMask).networkType;
        (lease->subnetMask).IPV4 = (serverPtr->subnetMask).IPV4;
        (lease->subnetNumber).networkType =
                                (lease->ipAddress).networkType;
        (lease->subnetNumber).IPV4 =
                                (lease->ipAddress).IPV4 &
                                (lease->subnetMask).IPV4;
        (lease->primaryDNSServer).networkType =
            (serverPtr->primaryDNSServer).networkType;
        (lease->primaryDNSServer).IPV4 = (serverPtr->primaryDNSServer).IPV4;
        if (lease->listOfSecDNSServer == NULL)
        {
             lease->listOfSecDNSServer = new std::list<Address*>;
        }
        AppDhcpCopySecondaryDnsServerList(
                                        serverPtr->listSecDnsServer,
                                        lease->listOfSecDNSServer);
        lease->status = DHCP_OFFERED;

        // Insert the newly created lease to list
        serverPtr->serverLeaseList->push_back(lease);
        return(lease);
    }

    // Lease not there in manual allocation
    // Check for  lease in normal list of leases as it is not empty
    else
    {
        // check if any lease already offered/allocated for this IP
        // if offered send no lease
        lease = NULL;
        list<struct dhcpLease*>::iterator it;
        for (it = serverPtr->serverLeaseList->begin();
             it != serverPtr->serverLeaseList->end();
             it++)
        {
            if (AppDhcpCheckIfSameClientId(
                    (struct dhcpLease*)(*it),
                    clientIdentifier,
                    data) &&
                (((*it)->status == DHCP_ALLOCATED ||
                  (*it)->status == DHCP_OFFERED) &&
                 (*it)->status != DHCP_UNAVAILABLE))
            {
                // lease already allocated
                return(NULL);
            }
        }

        // No lease allocated/offered to this client
        // Check if client has requested any IPAddress
        // If client has requested any IP Address check
        // if that ip is AVAILABLE to offer

        if (requestedIp != 0)
        {
            Address ipAddress;
            memset(&ipAddress, 0, sizeof(Address));
            ipAddress.networkType = NETWORK_IPV4;
            ipAddress.IPV4 = requestedIp;

            list<struct dhcpLease*>::iterator it;
            for (it = serverPtr->serverLeaseList->begin();
                 it != serverPtr->serverLeaseList->end();
                 it++)
            {
                if (MAPPING_CompareAddress((*it)->ipAddress, ipAddress) == 0
                    && (*it)->status == DHCP_AVAILABLE)
                {
                    if (!AppDhcpCheckIfIpInManualAllocationList(
                            serverPtr, ipAddress))
                    {
                        lease = *it;
                        lease->status = DHCP_OFFERED;
                        lease->macAddress.hwLength = data.hlen;
                        lease->macAddress.hwType = data.htype;
                        if (lease->macAddress.byte)
                        {
                            MEM_free(lease->macAddress.byte);
                        }
                        lease->macAddress.byte =
                            (unsigned char*)MEM_malloc(data.hlen);
                        memcpy(lease->macAddress.byte,
                               data.chaddr,
                               data.hlen);
                        return(lease);
                    }
                }
            }
        }

        // Requested IP not present or not free
        // Find any old lease that was allocated to this client
        lease = NULL;
        for (it = serverPtr->serverLeaseList->begin();
             it != serverPtr->serverLeaseList->end();
             it++)
        {
            if (AppDhcpCheckIfSameClientId(*it, clientIdentifier, data))
            {
                lease = *it;
            }
        }
        if (lease && lease->status == DHCP_AVAILABLE)
        {
            lease->status = DHCP_OFFERED;
            lease->macAddress.hwLength = data.hlen;
            lease->macAddress.hwType = data.htype;
            if (lease->macAddress.byte)
            {
                MEM_free(lease->macAddress.byte);
            }
            lease->macAddress.byte = (unsigned char*)MEM_malloc(data.hlen);
            memcpy(lease->macAddress.byte, data.chaddr, data.hlen);
            return(lease);
        }

        // Either reuqested IP not found or requested Ip
        // not present in DISCOVER
        // Find a lease available that is AVAILABLE
        lease = NULL;
        for (it = serverPtr->serverLeaseList->begin();
             it != serverPtr->serverLeaseList->end();
             it++)
        {
            if ((*it)->status == DHCP_AVAILABLE &&
                !AppDhcpCheckIfIpInManualAllocationList(
                            serverPtr, (*it)->ipAddress))
            {
                lease = *it;
            }
        }
        if (lease)
        {
            lease->status = DHCP_OFFERED;
            lease->macAddress.hwLength = data.hlen;
            lease->macAddress.hwType = data.htype;
            if (lease->macAddress.byte)
            {
                MEM_free(lease->macAddress.byte);
            }
            lease->macAddress.byte = (unsigned char*)MEM_malloc(data.hlen);
            memcpy(lease->macAddress.byte, data.chaddr, data.hlen);
            return(lease);
        }

        // No available lease need to insert new lease
        // in the linked list
        // Get the new lease

        lease = AppDhcpServerCreateNewLease(
                                node,
                                serverPtr,
                                data);
        if (lease != NULL)
        {
            return(lease);
        }
        else if (lease == NULL)
        {
            return(NULL);
        }
    }
    return(NULL);
}
//---------------------------------------------------------------------------
// NAME:            : AppDhcpClientStateRebootInit
// PURPOSE:         : models the behaviour when client enters the INIT
//                    REBOOT state
// PARAMETERS:
// + node           : Node*    : pointer to the client node which received
//                               the message.
// + interfaceIndex : Int32    : Interface on which client is enabled
// RETURN:          : NONE
// --------------------------------------------------------------------------
void AppDhcpClientStateRebootInit(
    Node* node,
    Int32 interfaceIndex)
{
    struct appDataDhcpClient* clientPtr = NULL;
    struct dhcpData* requestData = NULL;
    dhcpData data;

    if (DHCP_DEBUG)
    {
        printf("Performing DHCP client INIT REBOOT for  node %d "
               "at interface %d \n",
               node->nodeId,
               interfaceIndex);
    }
    clientPtr = AppDhcpClientGetDhcpClient(node, interfaceIndex);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d at interface %d not a DHCP client \n",
                   node->nodeId,
                   interfaceIndex);
        }
        return;
    }

    Address oldAddress ;
    NodeAddress addr = MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                    node,
                                    node->nodeId,
                                    interfaceIndex);
    oldAddress.IPV4 = addr;
    oldAddress.networkType = NETWORK_IPV4;
    //MAPPING_InvalidateIpv4AddressForInterface(
    //                                node,
    //                                interfaceIndex,
    //                                &oldAddress,
    //                                FALSE);
    memset(&data, 0, sizeof(struct dhcpData));
    data.options[0] = '\0';

    // Make the request packet
    requestData = AppDhcpClientMakeRequest(
                            node,
                            data,
                            interfaceIndex);

    // Change request packet data for  INIT-REBOOT state
    requestData->xid = RANDOM_nrand(clientPtr->jitterSeed);

    // Requested IP must be present in INIT-REBOOT state
    UInt32 val = clientPtr->lastIP.IPV4;
    if (val != 0)
    {
        dhcpSetOption(
            requestData->options,
            DHO_DHCP_REQUESTED_ADDRESS,
            DHCP_ADDRESS_OPTION_LENGTH,
            &val);
    }
    if (clientPtr->dhcpLeaseTime != 0)
    {
        val = clientPtr->dhcpLeaseTime;
        dhcpSetOption(
            requestData->options,
            DHO_DHCP_LEASE_TIME,
            DHCP_LEASE_TIME_OPTION_LENGTH,
            &val);
    }
    val = 0;
    dhcpSetOption(
        requestData->options,
        DHO_DHCP_SERVER_IDENTIFIER,
        DHCP_ADDRESS_OPTION_LENGTH,
        &val);

    // Record the XID for  this client before sending packet
    clientPtr->recentXid = requestData->xid;

    // Send the REQUEST packet
    if (DHCP_DEBUG)
    {
        printf("Broadcasting Request from node %d interface %d"
               "in INIT REBOOT state \n",
               node->nodeId,
               interfaceIndex);
         clocktype simulationTime = node->getNodeTime();
         char simulationTimeStr[MAX_STRING_LENGTH] = "";
         TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
         printf("Time  = %s \n", simulationTimeStr);
     }

     AppDhcpSendDhcpPacket(
                node,
                (Int32)interfaceIndex,
                (short)DHCP_CLIENT_PORT,
                ANY_ADDRESS,
                (short)DHCP_SERVER_PORT,
                clientPtr->tos,
                requestData);
    // Increment the REQUEST packet
    clientPtr->numRequestSent++;
    if (clientPtr->dataPacket != NULL)
    {
        MEM_free(clientPtr->dataPacket);
    }
    clientPtr->dataPacket = requestData;

    // schedule retrasmission for  REQUEST packet
    clocktype timerDelay = (clocktype) ((clientPtr->timeout
                      * (clientPtr->retryCounter))
                      + RANDOM_erand(clientPtr->jitterSeed));
    Message* message = MESSAGE_Alloc(
                            node,
                            APP_LAYER,
                            APP_DHCP_CLIENT,
                            MSG_APP_DHCP_TIMEOUT);
    MESSAGE_InfoAlloc(
                      node,
                      message,
                      sizeof(Int32));

    Int32* info = (Int32*)MESSAGE_ReturnInfo(message);
    *(info) = interfaceIndex;
    clientPtr->timeoutMssg = message;

    if (DHCP_DEBUG)
    {
        char simulationTimeStr[MAX_STRING_LENGTH] = "";
        TIME_PrintClockInSecond(timerDelay, simulationTimeStr);
        printf("Timout delay = %s \n", simulationTimeStr);
    }
    MESSAGE_Send(node, message, timerDelay);
    return;
}

//---------------------------------------------------------------------------
// NAME:         : AppDhcpInitialization
// PURPOSE:      : initializes the DHCP model
// PARAMETERS:
// + node        : Node*         : The pointer to the node.
// + nodeInput   : NodeInout*    : The pointer to configuration
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpInitialization(Node* node,
                           const NodeInput* nodeInput)
{
    BOOL parameterValue = FALSE;
    BOOL retVal;
    Int32 matchType = 0;
    bool isPresent = FALSE;
    BOOL isServerPresent = FALSE;
    BOOL isRelayAgent = FALSE;
    BOOL serverConfiguredAtNode = FALSE;
    BOOL relayAgentConfiguredAtNode = FALSE;
    // DHCP Initialization
    for (Int32 i = 0; i < node->numberInterfaces; i++)
    {
        IO_ReadBoolInstance(
                        node->nodeId,
                        MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                                         node,
                                                         node->nodeId,
                                                         i),
                        nodeInput,
                        "DHCP-ENABLED",
                        i,
                        TRUE,
                        &retVal,
                        &parameterValue);

        // if DHCP is not enabled on this interface
        if (retVal == FALSE || parameterValue == FALSE)
        {
            continue;
        }
        // if DHCP enabled
        if (retVal && parameterValue == TRUE)
        {
            // check if this is Ipv4 interface; report error if not
            if (NetworkIpGetInterfaceType(node, i) != NETWORK_IPV4 &&
                NetworkIpGetInterfaceType(node, i) != NETWORK_DUAL)
            {

                ERROR_ReportErrorArgs(
                    "Node %d : DHCP only supported for  IPV4 network\n",
                    node->nodeId);
            }
            // check for server and relay agent at this inetrface,
            // if not server or relay agent make it client if dhcp enabled
            // globally or at node level

            // check for server
            isPresent = AppDhcpCheckDhcpEntityConfigLevel(node,
                                                          nodeInput,
                                                          i,
                                                          "DHCP-DEVICE-TYPE",
                                                          &matchType,
                                                          "SERVER");
            if (isPresent && !serverConfiguredAtNode)
            {
                switch(matchType)
                {
                    case MATCH_GLOBAL:
                    {
                        // error
                        ERROR_ReportErrorArgs("DHCP-SERVER cannot be "
                                "configured at global level\n");
                        break;
                    }
                    case MATCH_NODE_ID:
                    {
                        if (DHCP_DEBUG)
                        {
                            printf("\n DHCP server enabled for node %d "
                                   "at all interfaces",
                                   node->nodeId);
                        }
                        serverConfiguredAtNode = TRUE;
                        for (Int32 k = 0; k < node->numberInterfaces; k++)
                        {
                            Int32 clientMatchType = 0;
                            Int32 dhcpEnabledMatchType = 0;
                            // check if dhcp is enabled at this interface and
                            // check if client is not configured at this
                            // interface
                            if (AppDhcpCheckDhcpEntityConfigLevel(
                                                   node,
                                                   nodeInput,
                                                   k,
                                                   "DHCP-ENABLED",
                                                   &dhcpEnabledMatchType) &&
                                !AppDhcpCheckDhcpEntityConfigLevel(
                                                     node,
                                                     nodeInput,
                                                     k,
                                                     "DHCP-DEVICE-TYPE",
                                                     &clientMatchType,
                                                     "CLIENT"))
                            {
                                // check if relay-agent is also configured
                                // at this interface at same level; report
                                // error as relay cannot be configured along
                                // with server at same level; if present at
                                // higher level then that will take priority
                                // and server should not be initialized
                                Int32 relayMatchType = 0;
                                bool initServer = TRUE;
                                if (AppDhcpCheckDhcpEntityConfigLevel(
                                                 node,
                                                 nodeInput,
                                                 k,
                                                 "DHCP-DEVICE-TYPE",
                                                 &relayMatchType,
                                                 "RELAY"))
                                {
                                    if (relayMatchType == matchType)
                                    {
                                        ERROR_ReportErrorArgs(
                                           "Node %u : dhcp "
                                           "relay agent cannot be "
                                           "configured as a DHCP Server \n",
                                            node->nodeId);
                                    }
                                    // if server is configured at higher
                                    // level then initialize server at this
                                    // interface
                                    if (relayMatchType >= matchType)
                                    {
                                        initServer = FALSE;
                                    }
                                }
                                // if server is configured at higher level
                                // then initialize
                                if (initServer)
                                {
                                    AppDhcpServerInit(node,
                                                      k,
                                                      nodeInput);
                                    isServerPresent = TRUE;
                                }
                            }
                        }
                        break;
                    }
                    case MATCH_INTERFACE:
                    {
                        if (DHCP_DEBUG)
                        {
                            printf("DHCP server enabled for node %d at"
                                   " interfaces %d\n",
                                   node->nodeId,
                                   i);
                        }
                        // dhcp enbaling is already checked for this
                        // interface
                        AppDhcpServerInit(node, i, nodeInput);
                        isServerPresent = TRUE;
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                //continue;
            }
            // check for relay agent
            isPresent = AppDhcpCheckDhcpEntityConfigLevel(
                                                     node,
                                                     nodeInput,
                                                     i,
                                                     "DHCP-DEVICE-TYPE",
                                                     &matchType,
                                                     "RELAY");
            if (isPresent && !relayAgentConfiguredAtNode)
            {
                // check if server not configured on any interface of
                // this node
                if (isServerPresent)
                {
                    ERROR_ReportErrorArgs(
                            "Node %u : dhcp relay agent can't be"
                            " configured as a DHCP Server \n",
                            node->nodeId);
                }
                switch(matchType)
                {
                    case MATCH_GLOBAL:
                    {
                        ERROR_ReportErrorArgs("DHCP-RELAY-AGENT cannot be "
                                "configured at global level\n");
                        break;
                    }
                    case MATCH_NODE_ID:
                    {
                        if (DHCP_DEBUG)
                        {
                            printf("\n DHCP relay agent enabled for "
                                    "node %d at all interface ",
                                   node->nodeId,
                                   i);
                        }
                        relayAgentConfiguredAtNode = TRUE;
                        for (Int32 k = 0; k < node->numberInterfaces; k++)
                        {
                            Int32 dhcpEnabledMatchType = 0;
                            // check if dhcp is enabled at this interface
                            if (AppDhcpCheckDhcpEntityConfigLevel(
                                                     node,
                                                     nodeInput,
                                                     k,
                                                     "DHCP-ENABLED",
                                                     &dhcpEnabledMatchType))
                            {
                                // check if client is also configured at this
                                // interface at same level; report error as
                                // client cannot be configured along with
                                // relay-agent at same level; if present at
                                // higher level then that will take priority
                                // and relay agent should not be initialized
                                Int32 clientMatchType = 0;
                                bool initRelay = TRUE;
                                if (AppDhcpCheckDhcpEntityConfigLevel(
                                                 node,
                                                 nodeInput,
                                                 k,
                                                 "DHCP-DEVICE-TYPE",
                                                 &clientMatchType,
                                                 "CLIENT"))
                                {
                                    if (clientMatchType == matchType)
                                    {
                                        ERROR_ReportErrorArgs(
                                                "Node %u : dhcp"
                                            "relay agent can't be "
                                            "configured as a DHCP Client",
                                            node->nodeId);
                                    }
                                    // if relay is configured at higher level
                                    // than client then initialize relay
                                    if (clientMatchType >= matchType)
                                    {
                                        initRelay = FALSE;
                                    }
                                }
                                if (initRelay)
                                {
                                    AppDhcpRelayInit(node, k, nodeInput);
                                    isRelayAgent = TRUE;
                                }
                            }
                        }
                        break;
                    }
                    case MATCH_INTERFACE:
                    {
                        // if it is specified at interface then all interface
                        // should be relay agent
                        Int32 relayMatchType = 0;
                        bool notEnabled = FALSE;
                        for (Int32 k = 0; k < node->numberInterfaces; k++)
                        {
                            if (!AppDhcpCheckDhcpEntityConfigLevel(
                                                     node,
                                                     nodeInput,
                                                     k,
                                                     "DHCP-DEVICE-TYPE",
                                                     &relayMatchType,
                                                     "RELAY"))
                            {
                                notEnabled = TRUE;
                                break;
                            }
                        }
                        if (notEnabled)
                        {
                            ERROR_ReportErrorArgs(
                                "Node %u : DHCP-RELAY-AGENT is "
                                    "not enabled at all interfaces",
                                    node->nodeId);
                        }
                        else
                        {
                            AppDhcpRelayInit(node, i, nodeInput);
                            isRelayAgent = TRUE;
                        }
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                //continue;
            }
            // this interface is client if DHCP-CLIENT configured
            matchType = 0;
            isPresent = AppDhcpCheckDhcpEntityConfigLevel(
                                                     node,
                                                     nodeInput,
                                                     i,
                                                     "DHCP-DEVICE-TYPE",
                                                     &matchType,
                                                     "CLIENT");
            // if DHCP enabled at this interface and it is not relay or
            // client or server then an error condition
            if (!isPresent && !isRelayAgent)
            {
                // if this is not server then error condition
                // check if server not configured on this interface
                if (AppDhcpServerGetDhcpServer(
                        node,
                        i) == NULL)
                {
                    ERROR_ReportErrorArgs("Node %d interface %d is DHCP "
                            "enabled but no DHCP Server or DHCP Relay or "
                            "DHCP Client configured\n",
                            node->nodeId, i);
                }
            }
            if (isPresent)
            {
                // check if relay agent is not configured on any
                // interface of this node
                if (isRelayAgent)
                {
                    ERROR_ReportErrorArgs(
                            "Node %u : dhcp relay agent can't be"
                            " configured as a DHCP Client",
                            node->nodeId);
                }
                if (DHCP_DEBUG)
                {
                    printf("\n Enabling client on node %d at interface %d",
                           node->nodeId,
                           i);
                }
                // check if server not configured on this interface
                if (AppDhcpServerGetDhcpServer(
                        node,
                        i) == NULL)
                {
                    AppDhcpClientInit(node, i, nodeInput);
                }
            }
        }
    }
}



//---------------------------------------------------------------------------
// NAME:            : AppDhcpCheckDhcpEntityConfigLevel
// PURPOSE:         : checks the configuration of DHCP entity(server/client
//                    /relay-agent) at an inteface of node
// PARAMETERS:
// + node           : Node*       : The pointer to the node.
// + nodeInput      : NodeInput*  : The pointer to configuration
// + interfaceIndex : Int32       : interfaceIndex
// + entityName     : const char* : DHCP enity name
// + matchType      : Int32*      : match level of configuration
// + findString     : const char* : Pointer to parameterValue to be matched
// RETURN:          : bool
//                    TRUE : if enity configuration present
//                    FALSE: if entity configuration not present
//---------------------------------------------------------------------------

bool AppDhcpCheckDhcpEntityConfigLevel(Node* node,
                                       const NodeInput* nodeInput,
                                       Int32 interfaceIndex,
                                       const char* entityName,
                                       Int32* matchType,
                                       const char* findString)
{
    char parameterValue[MAX_STRING_LENGTH] = "";
    BOOL retVal;
    IO_ReadString(node->nodeId,
                  interfaceIndex,
                  MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                                     node,
                                                     node->nodeId,
                                                     interfaceIndex),
                  NULL,
                  nodeInput,
                  entityName,
                  parameterValue,
                  retVal,
                  *matchType);

    if (retVal &&
        !(strcmp(entityName,"DHCP-DEVICE-TYPE")))
    {
        if ((strcmp(parameterValue,"SERVER")) &&
            (strcmp(parameterValue,"CLIENT")) &&
            (strcmp(parameterValue,"RELAY")))
        {
            // error
            ERROR_ReportErrorArgs("The values for parameter DHCP-DEVICE-TYPE can"
                "be SERVER, CLIENT or RELAY only");
        }
    }
    else if ((retVal && strcmp(parameterValue,"YES")) &&
        (strcmp(parameterValue,"NO")))
    {
        // error
        ERROR_ReportErrorArgs(
                "%s present at node %d with invalid parameter\n",
                entityName,
                node->nodeId);
    }

    if (retVal && !strcmp(parameterValue, findString))
    {
        return TRUE;
    }
    return FALSE;
}

//---------------------------------------------------------------------------
// NAME:         : AppDhcpClientHandleDhcpPacket.
// PURPOSE:      : Models the behaviour of DHCP Client on receiving a DHCP
//                 packet encapsulated in msg.
// PARAMETERS:
// + node        : Node*     : The pointer to the node.
// + msg         : Message*  : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpClientHandleDhcpPacket(
    Node* node,
    Message* msg)
{
    struct appDataDhcpClient* clientPtr = NULL;
    UdpToAppRecv* info = NULL;
    Int32 incomingInterface = 0;
    struct dhcpData data;

    info = (UdpToAppRecv*)MESSAGE_ReturnInfo(msg);
    incomingInterface = info->incomingInterfaceIndex;

    // Get the data packet
    memcpy(&data, MESSAGE_ReturnPacket(msg), sizeof(struct dhcpData));

    // Get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(node,
                                           incomingInterface);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d at interface %d not a DHCP client \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }

    // Get the message type
    UInt8 messageType = 0;
    dhcpGetOption(
                data.options,
                DHO_DHCP_MESSAGE_TYPE,
                1,
                &messageType);
    switch((int)messageType)
    {
        case DHCPOFFER:
        {
            if (DHCP_DEBUG)
            {
                printf("offer message received at node %d "
                       "at interface %d \n",
                       node->nodeId,
                       incomingInterface);
                clocktype simulationTime = node->getNodeTime();
                char simulationTimeStr[MAX_STRING_LENGTH] = "";
                TIME_PrintClockInSecond(simulationTime,
                                        simulationTimeStr);
                printf("Time = %s \n", simulationTimeStr);
            }

            // Check if the offer is at correct client through xid

            if ((clientPtr->recentXid == data.xid) &&
                (clientPtr->state == DHCP_CLIENT_SELECT))
            {
                clientPtr->numOfferRecv++;
                clientPtr->retryCounter = 1;

                // Cancel the timeout message scheduled
                if (clientPtr->timeoutMssg)
                {
                    MESSAGE_CancelSelfMsg(
                        node,
                        clientPtr->timeoutMssg);
                    clientPtr->timeoutMssg = NULL;
                }
                AppDhcpClientStateSelect(
                                     node,
                                     data,
                                     incomingInterface);
            }
            else if (clientPtr->recentXid == data.xid)
            {
                // offer recived but client not in state to accept
                clientPtr->numOfferRecv++;
            }
            break;
        }
        case DHCPACK:
        {
            AppDhcpClientReceivedAck(node, msg);
            break;
        }
        case DHCPNAK:
        {
            if (clientPtr->recentXid == data.xid)
            {
                if (DHCP_DEBUG)
                {
                    printf("DHCPNAK received at node %d"
                           "at interface %d \n",
                           node->nodeId,
                           incomingInterface);
                }

                // Move the client to INIT state
                clientPtr->arpInterval = 0;
                clientPtr->reacquireTime = 0;
                clientPtr->numNakRecv++;
                // Cancel the timeout message
                if (clientPtr->timeoutMssg != NULL)
                {
                    MESSAGE_CancelSelfMsg(
                        node,
                        clientPtr->timeoutMssg);
                    clientPtr->timeoutMssg = NULL;
                }
                clientPtr->state = DHCP_CLIENT_INIT;
                if (clientPtr->dataPacket != NULL)
                {
                    MEM_free(clientPtr->dataPacket);
                    clientPtr->dataPacket = NULL;
                }
                AppDhcpClientStateInit(
                            node,
                            incomingInterface);
            }
            break;
        }
        default:
        {
            break;
        }
    }
}

//---------------------------------------------------------------------------
// NAME:         : AppDhcpClientHandleReleaseEvent.
// PURPOSE:      : Models the behaviour of DHCP Client on receiving
//                 DHCPRelease event.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpClientHandleReleaseEvent(
    Node* node,
    Message* msg)
{
    struct appDataDhcpClient* clientPtr = NULL;

    // Get the interface which sent the message
    Int32* interfaceIndex = (Int32*)MESSAGE_ReturnInfo(msg);
    // Get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(node, *interfaceIndex);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d at interface %d Not a DHCP client \n",
                    node->nodeId,
                    *interfaceIndex);
        }
        return;
    }

    // Cancel the timeout message scheduled
    if (clientPtr->timeoutMssg != NULL)
    {
        MESSAGE_CancelSelfMsg(node, clientPtr->timeoutMssg);
        clientPtr->timeoutMssg = NULL;
    }

    // Find the lease that has to be released
    Int32 leaseStatus = DHCP_ACTIVE;

    // Check the lease

    struct dhcpLease* clientLease = NULL;
    list<struct dhcpLease*>::iterator it;
    for (it = clientPtr->clientLeaseList->begin();
         it != clientPtr->clientLeaseList->end();
         it++)
    {
        if ((*it)->status == leaseStatus)
        {
            clientLease = *it;
            break;
        }
    }
    if (clientLease)
    {
        clientLease->status = DHCP_INACTIVE;
        clientPtr->state = DHCP_CLIENT_START;
        // Cancel the renew rebind and expiry message
        if (clientLease->expiryMsg)
        {
            MESSAGE_CancelSelfMsg(
                node,
                clientLease->expiryMsg);
            clientLease->expiryMsg = NULL;
        }
        if (clientLease->rebindMsg)
        {
            MESSAGE_CancelSelfMsg(
                    node,
                    clientLease->rebindMsg);
            clientLease->rebindMsg = NULL;
        }
        if (clientLease->renewMsg)
        {
            MESSAGE_CancelSelfMsg(
                    node,
                    clientLease->renewMsg);
            clientLease->renewMsg = NULL;
        }
        AppDhcpClientSendRelease(
                    node,
                    clientLease->serverId,
                    *interfaceIndex);
    }
    else
    {
        // error
        ERROR_ReportErrorArgs(
                    "NO ACTIVE lease present at DHCP"
                    "client at node %d on interface %d to release",
                    node->nodeId,
                    *interfaceIndex);
    }
}

//---------------------------------------------------------------------------
// NAME:         : AppDhcpClientHandleRenewEvent.
// PURPOSE:      : Models the behaviour of DHCP Client on receiving DHCP
//                 lease renew event.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpClientHandleRenewEvent(
    Node* node,
    Message* msg)
{
    struct appDataDhcpClient* clientPtr = NULL;
    if (DHCP_DEBUG)
    {
        char simulationTimeStr[MAX_STRING_LENGTH] = "";
        TIME_PrintClockInSecond(node->getNodeTime(), simulationTimeStr);
        printf("Time at entry of renew state = %s \n",
               simulationTimeStr);
    }
    Int32* interfaceIndex = (Int32*)MESSAGE_ReturnInfo(msg);

    // get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(node, *interfaceIndex);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d not a DHCP client at interface %d \n",
                   node->nodeId,
                   *interfaceIndex);
        }
        return;
    }

    // Get Lease which enters into renew state
    Int32 leaseStatus = DHCP_ACTIVE;

    // Check the lease
    struct dhcpLease* clientLease = NULL;
    list<struct dhcpLease*>::iterator it;
    for (it = clientPtr->clientLeaseList->begin();
         it != clientPtr->clientLeaseList->end();
         it++)
    {
        if ((*it)->status == leaseStatus)
        {
            clientLease = *it;
            break;
        }
    }
    if (clientLease)
    {
        clientLease->status = DHCP_RENEW;
        clientPtr->state = DHCP_CLIENT_RENEW;
        if (DHCP_DEBUG)
        {
            printf("Node %d at interface %d enters into"
                           "renew state \n",
                           node->nodeId,
                           *interfaceIndex);
        }

        // Unicast a request packet to server
        AppDhcpClientStateRenewRebind(
                                    node,
                                    *interfaceIndex,
                                    clientLease->serverId,
                                    clientLease);
    }
}

//---------------------------------------------------------------------------
// NAME:         : AppDhcpClientHandleRebindEvent.
// PURPOSE:      : Models the behaviour of DHCP Client on receiving DHCP
//                 lease rebind event.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpClientHandleRebindEvent(
    Node* node,
    Message* msg)
{

    struct appDataDhcpClient* clientPtr = NULL;
    Int32* interfaceIndex = (Int32*)MESSAGE_ReturnInfo(msg);

    // Get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(node, *interfaceIndex);
    if (clientPtr == NULL)
    {
        printf("Node %d not a DHCP client at interface %d \n",
               node->nodeId,
               *interfaceIndex);
        return;
    }
    if (clientPtr->timeoutMssg != NULL)
    {
        MESSAGE_CancelSelfMsg(node, clientPtr->timeoutMssg);
        clientPtr->timeoutMssg = NULL;
    }

    // Get Lease which enters into rebind state
    Int32 leaseStatus = DHCP_RENEW;

    // Check the lease

    struct dhcpLease* clientLease = NULL;
    list<struct dhcpLease*>::iterator it;
    for (it = clientPtr->clientLeaseList->begin();
         it != clientPtr->clientLeaseList->end();
         it++)
    {
        if ((*it)->status == leaseStatus)
        {
            clientLease = *it;
            break;
        }
    }
    if (clientLease)
    {
        clientLease->status = DHCP_REBIND;
        clientPtr->state = DHCP_CLIENT_REBIND;
        if (DHCP_DEBUG)
        {
            printf("Node %d at interface %d enters into"
                   "rebind state \n",
                   node->nodeId,
                   *interfaceIndex);
        }

        // Broadcast a request packet to server
        AppDhcpClientStateRenewRebind(
                                node,
                                *interfaceIndex,
                                clientLease->serverId,
                                clientLease);
    }
}

//---------------------------------------------------------------------------
// NAME:         : AppDhcpClientHandleLeaseExpiry.
// PURPOSE:      : Models the behaviour of DHCP Client on lease expiry
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpClientHandleLeaseExpiry(
    Node* node,
    Message* msg)
{
    struct appDataDhcpClient* clientPtr = NULL;
    Int32* interfaceIndex = (Int32*)MESSAGE_ReturnInfo(msg);

    // get the client pointer
    clientPtr = AppDhcpClientGetDhcpClient(
                    node,
                    *interfaceIndex);
    if (clientPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d not a DHCP client at interface %d \n",
                   node->nodeId,
                   *interfaceIndex);
        }
        return;
    }

    // Cancel the timeout message scheduled
    if (clientPtr->timeoutMssg != NULL)
    {
        MESSAGE_CancelSelfMsg(node, clientPtr->timeoutMssg);
        clientPtr->timeoutMssg = NULL;
    }

    // Change the status of lease in client linked list
    Int32 leaseStatus = DHCP_REBIND;

    // Get the lease from linked list
    struct dhcpLease* clientLease = NULL;
    list<struct dhcpLease*>::iterator it;
    for (it = clientPtr->clientLeaseList->begin();
         it != clientPtr->clientLeaseList->end();
         it++)
    {
        if ((*it)->status == leaseStatus)
        {
            clientLease = *it;
            break;
        }
    }
    if (clientLease)
    {
        clientLease->status = DHCP_INACTIVE;

        if (DHCP_DEBUG)
        {
            printf("Lease expired for  node %d at interface %d \n",
                   node->nodeId,
                   *interfaceIndex);
            clocktype simulationTime = node->getNodeTime();
            char simulationTimeStr[MAX_STRING_LENGTH] = "";
            TIME_PrintClockInSecond(
                simulationTime,
                simulationTimeStr);
            printf("Time at expiry = %s \n", simulationTimeStr);
        }
        NodeAddress ipv4Address = MAPPING_GetSubnetMaskForInterface(
                                                     node,
                                                     node->nodeId,
                                                     *interfaceIndex);
        NetworkIpProcessDHCP(
                     node,
                     *interfaceIndex,
                     &clientLease->ipAddress,
                     ipv4Address,
                     LEASE_EXPIRY,
                     NETWORK_IPV4);
        clientPtr->state = DHCP_CLIENT_INIT;
        if (clientPtr->dataPacket != NULL)
        {
            MEM_free(clientPtr->dataPacket);
            clientPtr->dataPacket = NULL;
        }
        AppDhcpClientStateInit(node, *interfaceIndex);
    }
    else
    {
        // error
        ERROR_ReportErrorArgs(
                "NO lease present at DHCP"
                "client at node %d on interface %d to expire",
                node->nodeId,
                *interfaceIndex);
    }
}

//---------------------------------------------------------------------------
// NAME:         : AppDhcpServerHandleDhcpPacket.
// PURPOSE:      : Models the behaviour of DHCP server on receiving a DHCP
//                 packet encapsulated in msg.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpServerHandleDhcpPacket(
    Node* node,
    Message* msg)
{
    struct appDataDhcpServer* serverPtr = NULL;
    UdpToAppRecv* info = NULL;
    Int32 incomingInterface = 0;
    struct dhcpData data;
    //Address interfaceAddress;

    // Get the incoming inetrface index
    info = (UdpToAppRecv*)MESSAGE_ReturnInfo(msg);
    incomingInterface = info->incomingInterfaceIndex;

    // Get the data pointer
    memcpy(&data, MESSAGE_ReturnPacket(msg), sizeof(struct dhcpData));

    // Get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(
                                node,
                                incomingInterface);
    if (serverPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP sever at interface %d \n",
                   node->nodeId,
                   incomingInterface);
        }
        return;
    }
    if (data.op != BOOTREQUEST && data.op != BOOTREPLY)
    {
        MESSAGE_Free(node, msg);
        return;
    }
    UInt8 messageType = 0;
    dhcpGetOption(
        data.options,
        DHO_DHCP_MESSAGE_TYPE,
        1,
        &messageType);
    switch ((int)messageType)
    {
        case DHCPDISCOVER:
        {
            if (DHCP_DEBUG)
            {
                printf("Received DISCOVER message at node %d"
                       "from interface %d \n",
                       node->nodeId,
                       incomingInterface);
                clocktype simulationTime = node->getNodeTime();
                char simulationTimeStr[MAX_STRING_LENGTH] = "";
                TIME_PrintClockInSecond(
                    simulationTime,
                    simulationTimeStr);
                printf("Time = %s \n", simulationTimeStr);
            }
            // Get the originator of packet via info if this packet is from
            // relay agent
            Int32 originator = 0;
            if (data.giaddr != 0)
            {
                Int32* originatorNodeId = (Int32*)
                    MESSAGE_ReturnInfo(msg, INFO_TYPE_DhcpPacketOriginator);
                originator = *originatorNodeId;
            }
            else
            {
                originator = msg->originatingNodeId;
            }
            AppDhcpServerReceivedDiscover(
                        node,
                        data,
                        incomingInterface,
                        originator);

            break;
        }
        case DHCPREQUEST:
        {
            if (DHCP_DEBUG)
            {
                printf("Request message received at node %d at "
                       "interface %d \n",
                       node->nodeId,
                       incomingInterface);
            }

            // Check if request is for  this server
            // get the server identifier

            UInt32 serverIdentifier = 0;
            dhcpGetOption(data.options,
                          DHO_DHCP_SERVER_IDENTIFIER,
                          DHCP_ADDRESS_OPTION_LENGTH,
                          &serverIdentifier);
            if ((serverIdentifier == NetworkIpGetInterfaceAddress(
                                                        node,
                                                        incomingInterface))
                 || (serverIdentifier == 0))
            {
                AppDhcpServerReceivedRequest(
                        node,
                        data,
                        incomingInterface);
            }
            else
            {
                // A Request is received at server.
                // Check if this server had offered any lease
                // to this client
                // make the lease offered as available
                // change the status of lease

                // Get the lease that is OFFERED
                list<struct dhcpLease*>::iterator it;
                for (it = serverPtr->serverLeaseList->begin();
                     it != serverPtr->serverLeaseList->end();
                     it++)
                {
                    // Check the lease and Check if lease is offered to
                    // same client
                    if ((*it)->status == DHCP_OFFERED &&
                        memcmp(data.chaddr,
                               (*it)->macAddress.byte,
                               data.hlen) == 0)
                    {
                        (*it)->status = DHCP_AVAILABLE;

                        // Cancel the offer timeout message
                        if (serverPtr->timeoutMssg)
                        {
                            MESSAGE_CancelSelfMsg(
                                                    node,
                                                    serverPtr->timeoutMssg);
                            serverPtr->timeoutMssg = NULL;
                        }
                        serverPtr->numOfferReject++;
                    }
                }
            }
            break;
        }
        case DHCPINFORM:
        {
            if (DHCP_DEBUG)
            {
                printf("INFORM received at server node %d \n",
                       node->nodeId);
            }

            // send the ACK corresponding to it
            AppDhcpServerReceivedInform(
                        node,
                        data,
                        incomingInterface);
            break;
        }
        case DHCPDECLINE:
        {
            struct dhcpLease* lease = NULL;
            if (DHCP_DEBUG)
            {
                printf("Received DECLINE message at node %d"
                       "from interface %d \n",
                       node->nodeId,
                       incomingInterface);
            }

            // Check if Decline mssg is at assigning server
            // get the server identifier

            UInt32 serverIdentifier = 0;
            dhcpGetOption(
                        data.options,
                        DHO_DHCP_SERVER_IDENTIFIER,
                        DHCP_ADDRESS_OPTION_LENGTH,
                        &serverIdentifier);
            if (NetworkIpGetInterfaceAddress(node, incomingInterface)
                                                    == serverIdentifier)
            {
                if (DHCP_DEBUG)
                {
                    printf("DECLINE came to server at node %d interface "
                           "%d \n", node->nodeId, incomingInterface);
                }
                serverPtr->numDeclineRecv++;

                UInt32 ipAddress = 0;
                dhcpGetOption(
                            data.options,
                            DHO_DHCP_REQUESTED_ADDRESS,
                            DHCP_ADDRESS_OPTION_LENGTH,
                            &ipAddress);
                if (ipAddress == 0)
                {
                    ERROR_ReportErrorArgs(
                            "DHCP Server at %d: DHCPDECLINE "
                            "not having requested IP address parameter \n",
                            node->nodeId);
                }
                else
                {
                    list<struct dhcpLease*>::iterator it;
                    for (it = serverPtr->serverLeaseList->begin();
                         it != serverPtr->serverLeaseList->end();
                         it++)
                    {
                        if ((*it)->ipAddress.IPV4 == ipAddress)
                        {
                            lease = *it;
                            break;
                        }
                    }
                }

                // change the status of lease and make it unavaialable
                if (lease)
                {
                   lease->status = DHCP_UNAVAILABLE;
                }
                else
                {
                   ERROR_ReportErrorArgs(
                          "DHCP Server at %d: DHCPDECLINE "
                          "requested IP address lease not present at "
                          "server \n",
                          node->nodeId);
                }

                // cancel lease timeout mssg
                if (lease->expiryMsg)
                {
                   MESSAGE_CancelSelfMsg(node, lease->expiryMsg);
                   lease->expiryMsg = NULL;
                }
            }
            break;
        }
        case DHCPRELEASE:
        {
            struct dhcpLease* lease = NULL;
            if (DHCP_DEBUG)
            {
                printf("Received RELEASE message at node %d"
                       "from interface %d \n",
                       node->nodeId,
                       incomingInterface);
            }

            // Check if Release mssg is at assigning server
            // get the server identifier

            UInt32 serverIdentifier = 0;
            dhcpGetOption(data.options,
                          DHO_DHCP_SERVER_IDENTIFIER,
                          DHCP_ADDRESS_OPTION_LENGTH,
                          &serverIdentifier);
            if (NetworkIpGetInterfaceAddress(node, incomingInterface) ==
                                                           serverIdentifier)
            {
                if (DHCP_DEBUG)
                {
                    printf("Relase came to server \n");
                }

                // get the lease allocated and make it unavaialable
                // get the client identifier

                UInt8 val = dhcpGetOptionLength(
                                            data.options,
                                            DHO_DHCP_CLIENT_IDENTIFIER);
                char clientIdentifier[MAX_STRING_LENGTH] = "";
                dhcpGetOption(
                            data.options,
                            DHO_DHCP_CLIENT_IDENTIFIER,
                            val,
                            clientIdentifier);
                clientIdentifier[val] = '\0';
                if (strlen(clientIdentifier) > 0)
                {
                    list<struct dhcpLease*>::iterator it;
                    for (it = serverPtr->serverLeaseList->begin();
                         it != serverPtr->serverLeaseList->end();
                         it++)
                    {
                        if (memcmp((*it)->clientIdentifier,
                                    clientIdentifier,
                                    val) == 0)
                        {
                            lease = *it;
                            break;
                        }
                    }
                }
                else
                {
                    list<struct dhcpLease*>::iterator it;
                    for (it = serverPtr->serverLeaseList->begin();
                         it != serverPtr->serverLeaseList->end();
                         it++)
                    {
                        if (memcmp((*it)->clientIdentifier,
                                    data.chaddr,
                                    data.hlen) == 0)
                        {
                            lease = *it;
                            break;
                        }
                    }
                }

                // change the status of lease and make it avaialble
                if (lease)
                {
                    lease->status = DHCP_AVAILABLE;
                }

                // cancel lease expiry mssg
                if (lease->expiryMsg)
                {
                    MESSAGE_CancelSelfMsg(node, lease->expiryMsg);
                    lease->expiryMsg = NULL;
                }
            }
            break;
        }
    }
}

//---------------------------------------------------------------------------
// NAME:         : AppDhcpServerHandleLeaseExpiry.
// PURPOSE:      : Models the behaviour of DHCP Server on lease expiry
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpServerHandleLeaseExpiry(
    Node* node,
    Message* msg)

{
    struct appDataDhcpServer* serverPtr = NULL;
    // Get the info of lease to expire
    struct dhcpLease* leaseInfo = (dhcpLease*)MESSAGE_ReturnInfo(msg);

    // Get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(
                        node,
                        NetworkIpGetInterfaceIndexFromAddress(
                                   node,
                                   leaseInfo->serverId.IPV4));
    if (serverPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP sever at \n",
                   node->nodeId);
        }
        return;
    }
    if (DHCP_DEBUG)
    {
        char str[MAX_STRING_LENGTH] = "";
        IO_ConvertIpAddressToString(&(leaseInfo->ipAddress), str);
        printf("Lease expired for  Ip %s at server node %d \n",
               str,
               node->nodeId);
        clocktype simulationTime = node->getNodeTime();
        char simulationTimeStr[MAX_STRING_LENGTH] = "";
        TIME_PrintClockInSecond(simulationTime, simulationTimeStr);
        printf("Time at expiry = %s \n", simulationTimeStr);
    }

    // Change the status of lease in linked list
    list<struct dhcpLease*>::iterator it;
    struct dhcpLease* leaseItem = NULL;
    for (it = serverPtr->serverLeaseList->begin();
         it != serverPtr->serverLeaseList->end();
         it++)
    {
        if ((*it)->ipAddress.IPV4 == leaseInfo->ipAddress.IPV4)
        {
            leaseItem = *it;
            break;
        }
    }
    if (leaseItem)
    {
        leaseItem->status = DHCP_AVAILABLE;
    }
}

//---------------------------------------------------------------------------
// NAME:         : AppDhcpServerHandleTimeout.
// PURPOSE:      : Models the behaviour of DHCP Server on timeout of offer
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpServerHandleTimeout(
    Node* node,
    Message* msg)
{

    struct appDataDhcpServer* serverPtr = NULL;
    // get the server adress
    Address* serverAddress = (Address*)MESSAGE_ReturnInfo(msg);

    // get the server pointer
    serverPtr = AppDhcpServerGetDhcpServer(
                    node,
                    NetworkIpGetInterfaceIndexFromAddress(
                                      node,
                                      (*serverAddress).IPV4));
    if (serverPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP sever at \n",
                   node->nodeId);
        }
        return;
    }
    // find the lease that is offered and change its status
    // change the status of lease

    Int32 leaseStatus = DHCP_OFFERED;

    // Get the lease
    struct dhcpLease* serverLease = NULL;
    list<struct dhcpLease*>::iterator it;
    for (it = serverPtr->serverLeaseList->begin();
         it != serverPtr->serverLeaseList->end();
         it++)
    {
        if ((*it)->status == leaseStatus)
        {
            serverLease = *it;
            break;
        }
    }
    if (serverLease)
    {
        serverLease->status = DHCP_AVAILABLE;
    }
    if (serverPtr->dataPacket != NULL)
    {
        MEM_free(serverPtr->dataPacket);
    }
    serverPtr->dataPacket = NULL;
}

//---------------------------------------------------------------------------
// NAME:         : AppDhcpRelayHandleDhcpPacket.
// PURPOSE:      : Models the behaviour of DHCP relay on receiving a DHCP
//                 packet encapsulated in msg.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpRelayHandleDhcpPacket(
    Node* node,
    Message* msg)
{
    UdpToAppRecv* info = NULL;
    struct appDataDhcpRelay* relayPtr = NULL;
    Int32 i = 0;
    struct dhcpData* data = NULL;
    NodeAddress relayIP = 0;

    info = (UdpToAppRecv*)MESSAGE_ReturnInfo(msg);
    data = (struct dhcpData*)MEM_malloc(sizeof(struct dhcpData));
    memcpy(data, MESSAGE_ReturnPacket(msg), sizeof(struct dhcpData));

    // get the relay pointer
    relayPtr = AppDhcpRelayGetDhcpRelay(
                                node,
                                (Int32)info->incomingInterfaceIndex);
    if (relayPtr == NULL)
    {
        if (DHCP_DEBUG)
        {
            printf("Node %d Not a DHCP relay at interface %d \n",
                   node->nodeId,
                   (Int32)info->incomingInterfaceIndex);
        }
        if (data)
        {
            MEM_free(data);
        }
        return;
    }
    else
    {
        switch(data->op)
        {
            case BOOTREPLY:
            {
                // check if giaaadr matches any of its interface
                NodeAddress interfaceAddress;
                bool correctRelayAgent = FALSE;
                for (i = 0; i < node->numberInterfaces; i++)
                {
                    interfaceAddress = NetworkIpGetInterfaceAddress(
                                                                    node,
                                                                    i);
                    if (interfaceAddress == data->giaddr)
                    {
                        correctRelayAgent = TRUE;
                        break;
                    }
                }
                if (correctRelayAgent == TRUE && data->giaddr != 0)
                {
                    // get the interface to broadcast packet
                    NodeAddress sourceAddress = data->giaddr;
                    data->giaddr = 0;
                    relayPtr->numServerPktsRelayed++;
                    if (relayPtr->dataPacket != NULL)
                    {
                        MEM_free(relayPtr->dataPacket);
                    }
                    relayPtr->dataPacket = data;
                    AppDhcpSendDhcpPacket(
                                        node,
                                        i,
                                        (short)APP_DHCP_SERVER,
                                        ANY_ADDRESS,
                                        (short)DHCP_CLIENT_PORT,
                                        APP_DEFAULT_TOS,
                                        data);
                }
                if (correctRelayAgent == FALSE)
                {
                    // discard the packet
                    if (relayPtr->dataPacket != NULL)
                    {
                        MEM_free(relayPtr->dataPacket);
                    }
                    MEM_free(data);
                }
                break;
            }
            case BOOTREQUEST:
            {
                if (data->hops > DHCP_RELAY_MAX_HOP)
                {
                    // discrad the packet
                    if (relayPtr->dataPacket != NULL)
                    {
                        MEM_free(relayPtr->dataPacket);
                    }
                    MEM_free(data);
                }
                else
                {
                    if (data->giaddr == 0)
                    {
                        relayIP = NetworkIpGetInterfaceAddress(
                                              node,
                                              (Int32)info->
                                              incomingInterfaceIndex);

                        // in case of MANET if relay agent
                        // not configured yet
                        if (relayIP == 0)
                        {
                            MEM_free(data);
                            break;
                        }
                        else
                        {
                            data->giaddr = relayIP;
                        }
                    }
                    data->hops++;
                    relayPtr->numClientPktsRelayed++;
                    Address dhcpServerAddr;
                    if (relayPtr->dataPacket != NULL)
                    {
                        MEM_free(relayPtr->dataPacket);
                    }
                    relayPtr->dataPacket = data;
                    list<Address*>::iterator it;
                    for (it = relayPtr->serverAddrList->begin();
                         it != relayPtr->serverAddrList->end();
                         it++)
                    {
                         memcpy(
                             &dhcpServerAddr,
                             *it,
                             sizeof(Address));
                         AppDhcpSendDhcpPacket(
                                        node,
                                        (Int32)info->incomingInterfaceIndex,
                                        (short)APP_DHCP_SERVER,
                                        dhcpServerAddr.IPV4,
                                        (short)DHCP_SERVER_PORT,
                                        APP_DEFAULT_TOS,
                                        data,
                                        msg->originatingNodeId);
                    }
                }
                break;
            }
            default:
            {
                if (DHCP_DEBUG)
                {
                    printf(
                        "Incorrect packet received at node %d \n",
                           node->nodeId);
                }
                break;
            }
        }
    }
    return;
}

//---------------------------------------------------------------------------
// NAME:               : AppDhcpSendDhcpPacket.
// PURPOSE:            : Creates and sends a DHCP packet via UDP
// PARAMETERS:
// + node              : Node*             : The pointer to the node.
// + interfaceIndex    : Int32             : interfaceIndex
// + sourcePort.....  .: short             : sourcePort
// + destAddress       : NodeAddress       : destination address
// + destPort          : short             : destination port
// + priority......  ..: TosType           : priority of packet
// + data              : struct dhcpData*  : dhcp data packet
// + originator        : Int32             : originator node id used when
//                                           client packets are relayed from
//                                           relay agent

// RETURN:             : none.
//---------------------------------------------------------------------------
void AppDhcpSendDhcpPacket(Node* node,
                           Int32 interfaceIndex,
                           short sourcePort,
                           NodeAddress destAddress,
                           short destPort,
                           TosType priority,
                           struct dhcpData* data,
                           Int32 originator)
{
    Message* msg = APP_UdpCreateMessage(
                        node,
                        NetworkIpGetInterfaceAddress(node, interfaceIndex),
                        sourcePort,
                        destAddress,
                        destPort,
                        TRACE_DHCP,
                        priority);

    APP_AddHeader(node,
                  msg,
                  (char*)data,
                  sizeof(struct dhcpData));

    // add originator info if packets relayed from relay agent; as originator
    // nodeid will be required for manual allocation
    if (originator != 0)
    {
        // Add the originator node id as info field
        MESSAGE_AddInfo(
                    node,
                    msg,
                    sizeof(Int32),
                    INFO_TYPE_DhcpPacketOriginator);
        Int32* originatorNodeId = 
                        (Int32*)MESSAGE_ReturnInfo(
                                            msg,
                                            INFO_TYPE_DhcpPacketOriginator);
        *originatorNodeId = originator;
    }
    APP_UdpSend(node, msg);
}

//---------------------------------------------------------------------------
// NAME:                  : AppDhcpCopySecondaryDnsServerList.
// PURPOSE:               : Copy a list of secondary DNS server into
 //                         another list
// PARAMETERS:
// + fromDnsServerList    : std::list<Address*>* : from DNS server list
// + toDnsServerList      : std::list<Address*>* : to DNS server list
// RETURN:                : none.
//---------------------------------------------------------------------------

void AppDhcpCopySecondaryDnsServerList(
    std::list<Address*>* fromDnsServerList,
    std::list<Address*>* toDnsServerList)
{
    if (fromDnsServerList != NULL)
    {
        std::list<Address*>::iterator it;
        for (it = fromDnsServerList->begin();
             it != fromDnsServerList->end();
             it++)
        {
            Address* addrSecDns = (Address*)MEM_malloc(sizeof(Address));
            memcpy(addrSecDns, (*it), sizeof(Address));
            toDnsServerList->push_back(addrSecDns);
        }
    }
}

//---------------------------------------------------------------------------
// NAME:                  : AppDhcpCheckInfiniteLeaseTime.
// PURPOSE:               : checks if a lease time is infinite
// PARAMETERS:
// + clocktype            : time              : time to check
// + nodeInput            : const NodeInput*  : pointer to node input
// RETURN:                ::
// bool                   :TRUE if inifinite lease FALSE otherwise
//---------------------------------------------------------------------------

bool AppDhcpCheckInfiniteLeaseTime(
                                clocktype time,
                                const NodeInput* nodeInput)
{
    clocktype configMaxSimClock = 0;
    clocktype startSimClock = 0;
    char startSimClockStr[MAX_STRING_LENGTH] = "";
    char maxSimClockStr[MAX_STRING_LENGTH] = "";
    char simulationTimeStr[MAX_STRING_LENGTH] = "";
    Int32 nToken = 0;
    BOOL wasFound = FALSE;

    IO_ReadString(
                ANY_NODEID,
                ANY_ADDRESS,
                nodeInput,
                "SIMULATION-TIME",
                &wasFound,
                simulationTimeStr);

    if (wasFound == FALSE)
    {
        ERROR_ReportError("\"SIMULATION-TIME\" must be specified in the "
            "configuration file");
    }

    nToken = sscanf(
                simulationTimeStr,
                "%s %s",
                startSimClockStr,
                maxSimClockStr);

    if (nToken == 1)
    {
        startSimClock = 0;
        configMaxSimClock = TIME_ConvertToClock(startSimClockStr);
    }
    else
    {
        startSimClock = TIME_ConvertToClock(startSimClockStr);
        configMaxSimClock = TIME_ConvertToClock(maxSimClockStr);
        configMaxSimClock = configMaxSimClock - startSimClock;
    }
    if (time >= configMaxSimClock)
    {
        return TRUE;
    }
    return FALSE;
}
