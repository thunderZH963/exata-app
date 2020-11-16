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


// /**
// PROTOCOL     :: Queue-Scheduler
// LAYER        ::
// REFERENCES   ::
// + "Link-sharing and Resource Management Models for Packet Networks"
//   by Sally Floyd and Van Jacobson This paper appeared in IEEE/ACM
//   Transactions on Networking, Vol. 3 No. 4, August 1995
//   http://www-nrg.ee.lbl.gov/papers/link.pdf
// + "Quality of Service on Packet Switched Networks"
//   http://www.polito.it/~Risso/pubs/thesis.pdf
// COMMENTS     :: None
// **/


#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "api.h"
#include "if_scheduler.h"
#include "sch_strictprio.h"
#include "sch_wrr.h"
#include "resource_manager_cbq.h"

//--------------------------------------------------------------------------
// Start: Utility Functions
//--------------------------------------------------------------------------

//**
// FUNCTION   :: CBQResourceManager::GetCurrentAgency
// LAYER      ::
// PURPOSE    :: Finds the agency that exits in Agency array
// PARAMETERS ::
// + agencyArray : DataBuffer* : All agency name
// + identity[] : char : Identity of an agency
// RETURN     :: ResourceSharingNode* : Reference of ResourceSharingNode
//                                  structure
// **/

ResourceSharingNode* CBQResourceManager::GetCurrentAgency(
    DataBuffer* agencyArray,
    char identity[])
{
    int i = 0;
    int numAgency = 0;
    ResourceSharingNode** cbqAgency;

    numAgency = BUFFER_GetCurrentSize(agencyArray)
                / sizeof(ResourceSharingNode*);

    cbqAgency = (ResourceSharingNode**) BUFFER_GetData(agencyArray);

    for (i = 0; i < numAgency; i++)
    {
        if (strcmp(cbqAgency[i]->agency, identity) == 0)
        {
            return cbqAgency[i];
        }
    }
    return NULL;
}


//**
// FUNCTION   :: CBQResourceManager::DeleteResourceSharingGraph
// LAYER      ::
// PURPOSE    :: Delete Link sharing graph
// PARAMETERS :: None
// RETURN     :: void : Null
// **/

void CBQResourceManager::DeleteResourceSharingGraph()
{
    int i;
    ResourceSharingNode** cbqAgency = (ResourceSharingNode**)
        BUFFER_GetData(&this->listAgency);

    int numAgency = BUFFER_GetCurrentSize(&this->listAgency)
        / sizeof(ResourceSharingNode*);

    ResourceSharingNode** cbqApplication = (ResourceSharingNode**)
        BUFFER_GetData(&this->listApplication);

    int numApplication = BUFFER_GetCurrentSize(&this->listApplication)
        / sizeof(ResourceSharingNode*);

    // Free the leaf nodes
    for (i = 0; i < numApplication; i++)
    {
        MEM_free(cbqApplication[i]);
    }

    // Free non leaf nodes
    for (i = 0; i < numAgency; i++)
    {
        BUFFER_DestroyDataBuffer(&cbqAgency[i]->descendent);
        MEM_free(cbqAgency[i]);
    }

    BUFFER_ClearDataFromDataBuffer(&this->listAgency,
        BUFFER_GetData(&(this->listAgency)),
        BUFFER_GetCurrentSize(&this->listAgency),
        FALSE);

    BUFFER_ClearDataFromDataBuffer(&this->listApplication,
        BUFFER_GetData(&this->listApplication),
        BUFFER_GetCurrentSize(&this->listApplication),
        FALSE);
}


//**
// FUNCTION   :: CBQResourceManager::ReadResourceSharingStr
// LAYER      ::
// PURPOSE    :: Reads the link-sharing structure from input file
// PARAMETERS ::
// + lsrmInput : const NodeInput : Resource sharing input
// RETURN     :: void : Null
// **/

void CBQResourceManager::ReadResourceSharingStr(
    const NodeInput lsrmInput)
{
    int tmpCounter = 0;
    BOOL nodeSpecificMatchFound = FALSE;
    BOOL interfaceSpecificMatchFound = FALSE;
    BOOL generalNodeParameterFound = FALSE;
    BOOL generalInterfaceParameterFound = FALSE;

    BUFFER_InitializeDataBuffer(&listAgency,
        sizeof(ResourceSharingNode*) * 5);

    BUFFER_InitializeDataBuffer(&listApplication,
        sizeof(ResourceSharingNode*) * 5);

    if (CBQ_DEBUG_LINK)
    {
        printf("\nCBQ : Link Sharing Structure:\n(Node: %u Interface: %u)",
                nodeInfo->nodeId, interfaceIndexInfo);
        printf("<Node> <Intf> <agency> <Decendent1><Decendent2>...\n");
    }

    for (tmpCounter = 0; tmpCounter < lsrmInput.numLines; tmpCounter++)
    {
        int items = 0;
        char nodeString[20] = {0};
        char interfaceString[20] = {0};
        BOOL isNodeId = FALSE;
        unsigned int nodeId = 0;
        int interfaceIndex = 0;

        char identity[MAX_STRING_LENGTH];
        float weight;
        int priority = -1;
        unsigned int efficient = 0;
        unsigned int borrow = 0;
        ResourceSharingNode* ancestorPtr = NULL;

        // For IO_GetDelimitedToken
        char* next;
        char seps[]   = ",\n";
        char space[]  = " ";
        char* token;
        char iotoken[MAX_STRING_LENGTH] = {0};
        char inputString[MAX_STRING_LENGTH] = {0};

        memset(inputString, '\0', MAX_STRING_LENGTH);
        memcpy(inputString, lsrmInput.inputStrings[tmpCounter],
            strlen(lsrmInput.inputStrings[tmpCounter]));

        sscanf(inputString, "%s %s", nodeString, interfaceString);

        if (strcmp(nodeString, "ANY"))
        {
            IO_ParseNodeIdOrHostAddress(nodeString, &nodeId, &isNodeId);
            if (!isNodeId)
            {
                ERROR_ReportError("First argument should be node id or "
                    "ANY\n");
            }
            if (nodeId != nodeInfo->nodeId)
            {
                continue;
            }
            else
            {
                nodeSpecificMatchFound = TRUE;
            }
        }
        else if (nodeSpecificMatchFound)
        {
            continue;
        }
        else
        {
            generalNodeParameterFound = TRUE;
        }

        if (strcmp(interfaceString, "ANY"))
        {
            interfaceIndex = (unsigned int) atoi(interfaceString);
            if ((interfaceIndex < 0) ||
                (interfaceIndex >= nodeInfo->numberInterfaces))
            {
                ERROR_ReportError("Second argument should be valid "
                    "interface index or ANY\n");
            }

            if (interfaceIndex != interfaceIndexInfo)
            {
                continue;
            }
            else
            {
                interfaceSpecificMatchFound = TRUE;
            }
        }
        else if (interfaceSpecificMatchFound)
        {
            continue;
        }
        else
        {
            generalInterfaceParameterFound = TRUE;
        }

        if (CBQ_DEBUG_LINK)
        {
            printf("\n%s %s ", nodeString, interfaceString);
        }

        if ((nodeSpecificMatchFound && generalNodeParameterFound) ||
            (interfaceSpecificMatchFound && generalInterfaceParameterFound))
        {
             ERROR_Assert(this->root, "Graph can't be null in this case\n");

             DeleteResourceSharingGraph();
             this->root = NULL;

             if (generalNodeParameterFound)
             {
                 generalNodeParameterFound = FALSE;
             }

             if (generalInterfaceParameterFound)
             {
                generalInterfaceParameterFound = FALSE;
             }
        }

        token = IO_GetDelimitedToken(iotoken, inputString, space, &next);
        token = IO_GetDelimitedToken(iotoken, next, space, &next);

        // Control here means a match for current node and interface
        token = IO_GetDelimitedToken(iotoken, next, seps, &next);

        while (token != NULL)
        {
            ResourceSharingNode* cbqAgency = NULL;
            BOOL                 isAgency = FALSE;

            // While there are tokens in "string"
            items = sscanf(token, "%s %f %u %u", identity, &weight,
                 &borrow, &efficient);

            if (items != 1 && items != 4)
            {
                char errStr[MAX_STRING_LENGTH];
                sprintf(errStr, "The format for specifying agency is:\n"
                    "\t<agency name> <weight> <borrow> <efficient>");
                ERROR_ReportError(errStr);
            }

            if (!isdigit(identity[0]))
            {
                // This is an Agency
                isAgency = TRUE;
            }
            else
            {
                // This is an application
                priority = (int) atoi(identity);
            }

            if (isAgency && items == 1)
            {
                if (!this->root)
                {
                    // This is the root node
                    cbqAgency = (ResourceSharingNode*)
                        MEM_malloc(sizeof(ResourceSharingNode));
                    this->root = cbqAgency;
                    cbqAgency->agency
                        = (char *) MEM_malloc(strlen(identity) + 1);
                    strcpy(cbqAgency->agency, identity);
                    cbqAgency->isAgency = TRUE;
                    cbqAgency->weight = 1.0;
                    cbqAgency->priority = -1;
                    cbqAgency->borrow = FALSE;
                    cbqAgency->efficient = FALSE;
                    cbqAgency->estimator = (ResourceEstimator*)
                                MEM_malloc(sizeof(ResourceEstimator));
                    memset(cbqAgency->estimator, 0,
                                sizeof(ResourceEstimator));
                    cbqAgency->ancestor = NULL;
                    BUFFER_AddDataToDataBuffer(&this->listAgency,
                        (char*) &cbqAgency, sizeof(ResourceSharingNode*));
                }
                else
                {
                    // CbqGetCurrentAgency this function should return
                    // NULL if the current agency doesn't exist

                    cbqAgency = GetCurrentAgency(&this->listAgency, identity);
                    if (!cbqAgency)
                    {
                        ERROR_ReportError("CBQ  :LINK-SHARING-STRUCTURE"
                            "-FILE Wrong Configuration");
                    }
                }

                ancestorPtr = cbqAgency;

                BUFFER_InitializeDataBuffer(&cbqAgency->descendent,
                    (sizeof(char*) * 5));

                if (CBQ_DEBUG_LINK)
                {
                    printf("%s, ", cbqAgency->agency);
                }
            }
            else if (items == 4)
            {
                // Memory allocation and
                // variable initialization for CBQ agency

                ResourceSharingNode* cbqAgency = NULL;
                cbqAgency = (ResourceSharingNode*) MEM_malloc(
                    sizeof(ResourceSharingNode));

                if (isAgency)
                {
                    BUFFER_AddDataToDataBuffer(&this->listAgency,
                        (char*)&cbqAgency, sizeof(ResourceSharingNode*));
                    cbqAgency->agency
                        = (char *) MEM_malloc(strlen(identity) + 1);
                    strcpy(cbqAgency->agency, identity);
                    cbqAgency->priority = -1;
                    cbqAgency->isAgency = TRUE;

                    if (CBQ_DEBUG_LINK)
                    {
                        printf("%s %f %u %u, ", identity, weight, borrow,
                            efficient);
                    }
                }
                else
                {
                    BUFFER_AddDataToDataBuffer(&this->listApplication,
                        (char*) &cbqAgency, sizeof(ResourceSharingNode*));
                    cbqAgency->agency = NULL;
                    cbqAgency->priority = priority;
                    cbqAgency->isAgency = FALSE;

                    if (CBQ_DEBUG_LINK)
                    {
                        printf("%u %f %u %u, ", priority, weight, borrow,
                            efficient);
                    }
                }

                if ((borrow < 0 ) || (borrow > 1 ) ||
                    (efficient < 0) || (efficient > 1))
                {
                    ERROR_ReportError("CBQ: <borrow>, <efficient> are"
                        " Boolean inputs 0 | 1 \n");
                }

                if ((weight <= 0.0) || (weight > 1.0))
                {
                    ERROR_ReportError("CBQ: Crossing range for"
                        " WEIGHT <0.0 - 1.0>\n");
                }
                cbqAgency->weight = weight;
                cbqAgency->borrow = (BOOL) borrow;
                cbqAgency->efficient = (BOOL) efficient;

                cbqAgency->estimator = (ResourceEstimator*)
                    MEM_malloc(sizeof(ResourceEstimator));
                memset(cbqAgency->estimator, 0, sizeof(ResourceEstimator));

                cbqAgency->ancestor = ancestorPtr;

                BUFFER_AddDataToDataBuffer(&ancestorPtr->descendent,
                    (char*) &cbqAgency, sizeof(ResourceSharingNode*));
            }

            // Get next token:
            token = IO_GetDelimitedToken(iotoken, next, seps, &next);
        }
    }
}


//**
// FUNCTION   :: CBQResourceManager::ActivateAgency
// LAYER      ::
// PURPOSE    :: Set the Agency status active
// PARAMETERS ::
// + agency : ResourceSharingNode* : ResourceSharingNode structure
// RETURN     :: void : Null
// **/

void CBQResourceManager::ActivateAgency(ResourceSharingNode* agency)
{
    ResourceSharingNode* tempNode = NULL;
    tempNode = agency;

    while (tempNode)
    {
        tempNode->estimator->isActive = TRUE;
        tempNode = tempNode->ancestor;
    }
}


//**
// FUNCTION   :: CBQResourceManager::DeactivateAgency
// LAYER      ::
// PURPOSE    :: Set the Agency status False
// PARAMETERS ::
// + agency : ResourceSharingNode* : ResourceSharingNode structure
// RETURN     :: void : Null
// **/

void CBQResourceManager::DeactivateAgency(ResourceSharingNode* agency)
{
    ResourceSharingNode* tempAgency = NULL;
    tempAgency = agency;

    while (tempAgency)
    {
        tempAgency->estimator->isActive = FALSE;

        if (tempAgency->ancestor)
        {
            int i;
            int numDescendent = 0;
            ResourceSharingNode** descendent;

            numDescendent = BUFFER_GetCurrentSize(&(tempAgency->ancestor)
                            ->descendent) / sizeof(ResourceSharingNode*);

            descendent = (ResourceSharingNode**)
                BUFFER_GetData(&(tempAgency->ancestor)->descendent);

            for (i = 0; i < numDescendent; i++)
            {
                if (descendent[i]->estimator->isActive)
                {
                    tempAgency = NULL;
                    break;
                }
            }
        }
        if (tempAgency)
        {
            tempAgency = tempAgency->ancestor;
        }
    }
}


//**
// FUNCTION   :: CBQResourceManager::GetApplicationByPriority
// LAYER      ::
// PURPOSE    :: Maps queue with application
// PARAMETERS ::
// + priority : int : Priority of application
// RETURN     :: ResourceSharingNode* : ResourceSharingNode structure
// **/

ResourceSharingNode* CBQResourceManager::GetApplicationByPriority(
    int priority)
{
    ResourceSharingNode** cbqApplication;
    int numApplication = 0;
    int i = 0;

    cbqApplication = (ResourceSharingNode**)
                        BUFFER_GetData(&this->listApplication);

    // Find the application mapping this Queue
    numApplication = BUFFER_GetCurrentSize(&this->listApplication)
                         / sizeof(ResourceSharingNode*);

    for (i = 0; i < numApplication; i++)
    {
        if (priority == cbqApplication[i]->priority)
        {
            return cbqApplication[i];
        }
    }
    return NULL;
}


//**
// FUNCTION   :: CBQResourceManager::FindFractionalBandWidth
// LAYER      ::
// PURPOSE    :: Find fractional BW for the queue
// PARAMETERS ::
// + agency : ResourceSharingNode* : ResourceSharingNode structure
// RETURN     :: double : Fraction of bandwidth value
// **/

double CBQResourceManager::FindFractionalBandWidth(
     ResourceSharingNode* agency)
{
    int i;
    int numDescendent = 0;
    ResourceSharingNode** descendent;
    double sumWeight = 0.0;
    double sumActiveWeight = 0.0;
    double sumActiveAncestorWeight = 0.0;
    double fractionBW = 0.0;

    // CBQ Agency is set in work conserving mode
    // Allow the agency to borrow bw depending on link sharing structure
    // While calculating checking would be done on Agency status(active or
    // not).
    // H-GPS fractional BW calculation formula:
    // fractionBW = ((weight[this application] * Sum of weight of all
    // agencies under my parent) / Sum of weight of all active agencies
    // under my parent) / Sum of weight of all active agencies under my
    // parent's ancestor [2]

    // Find all sons(descendents) under my parent
    numDescendent = BUFFER_GetCurrentSize(&(agency->ancestor)->descendent)
        / sizeof(ResourceSharingNode*);
    descendent = (ResourceSharingNode**)
        BUFFER_GetData(&(agency->ancestor)->descendent);

    for (i = 0; i < numDescendent; i++)
    {
        sumWeight += descendent[i]->weight;

        if (descendent[i]->estimator->isActive)
        {
            sumActiveWeight += descendent[i]->weight;
        }
    }

    if (CBQ_DEBUG)
    {
        if (!agency->isAgency)
        {
            printf("CBQ : Node: = %u    Interface = %d \n",
                nodeInfo->nodeId, interfaceIndexInfo);
            printf("      The weight of the Application[%u] Running"
                " = %lf\n", agency->priority, agency->weight);
        }
        else
        {
            printf("      The weight of the Agency"
                " = %lf\n",agency->weight);
        }
        printf("      The weight of the Parent[%s] of this"
            "application = %lf\n", agency->ancestor->agency,
            agency->ancestor->weight);
        printf("      The numDecendent of my Parent"
            " = %d\n", numDescendent);
        printf("      sumWeight = %lf, sumActiveWeight = %lf\n",
            sumWeight, sumActiveWeight);
    }

    if (agency->ancestor->ancestor != NULL)
    {
        // Find the brothers of my parent
        numDescendent =
            BUFFER_GetCurrentSize(&(agency->ancestor->ancestor)->descendent)
            / sizeof(ResourceSharingNode*);

        descendent = (ResourceSharingNode**)
            BUFFER_GetData(&(agency->ancestor->ancestor)->descendent);

        for (i = 0; i < numDescendent; i++)
        {
            if (descendent[i]->estimator->isActive)
            {
                sumActiveAncestorWeight += descendent[i]->weight;
            }
        }

        fractionBW = ((agency->weight * sumWeight)
            / sumActiveWeight) / sumActiveAncestorWeight;

        if (CBQ_DEBUG)
        {
            // Find the ancestor of  my parent
            printf("      The weight of the ancestor[%s] of  my "
                "parent = %lf\n", agency->ancestor->ancestor->agency,
                agency->ancestor->ancestor->weight);
            printf("      The numDecendent of my Parent's ancestor"
                " = %d\n", numDescendent);
            printf("      sumActiveancestorWeight = %lf\n",
                sumActiveAncestorWeight);
        }
    }
    else
    {
        fractionBW = (agency->weight * sumWeight) / sumActiveWeight;
    }
    return fractionBW;
}


//**
// FUNCTION   :: CBQResourceManager::ResourceSharingEstimator
// LAYER      ::
// PURPOSE    :: An estimator measures the inter-packet departure time for
//               each class, and estimates the class status.
//               under limit:
//               The class is under limit if it is transmitting at lower rate
//               than its allocated share or reserved rate.
//               in limit:
//               If the class is transmitting with a rate equal to its
//               allocated share.
//               over limit:
//               If the class is transmitting at larger rate than its
//               allocated share.  [2]
// PARAMETERS ::
// + pktSize : unsigned int : Packet size
// + cbqApplication : ResourceSharingNode* : CBR application
// + currentTime : const clocktype : Current simulation time.
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL CBQResourceManager::ResourceSharingEstimator(
    unsigned int pktSize,
    ResourceSharingNode* cbqApplication,
    const clocktype currentTime)
{
    ResourceSharingNode* agency = cbqApplication;

    // Set the status of the agency & all of its ancestor agency
    while (agency->ancestor)
    {
        double idle = 0.0;
        double prevPrevAvgIdle = 0.0;
        double fractionBW =0.0;
        double realInterPktDepartureTime = 0.0;
        double idealInterPacketDepartureTime = 0.0;

        // Get realInterPacketDepartureTime = (currentTime - lastServiceTime)
        realInterPktDepartureTime = (double) (currentTime
                        - agency->estimator->lastServiceTime) / SECOND;

        // If the BORROW is set TRUE, CBQ agency is operating in the
        // work-conseving mode and vicevarsa.

        if (agency->borrow)
        {
            fractionBW = FindFractionalBandWidth(agency);
        }
        else
        {
            fractionBW = agency->weight;
        }

        // Get idealInterPacketDepartureTime
        // = (packet size * 8 ) / (fraction of BW  * link rate)
        // Calculate fractionBW (the fraction of link bandwidth allowed)
        //  [1]

        idealInterPacketDepartureTime = ((double) pktSize * 8.0)
            / (fractionBW * this->interfaceBW);

        // Calculate the variable "idle"
        idle = realInterPktDepartureTime - idealInterPacketDepartureTime;

        if (CBQ_DEBUG)
        {
            printf("realInterPktDepartureTime = %f\n",
                realInterPktDepartureTime);
            printf("idealInterPacketDepartureTime = ((%u * 8.0) / (%f * %f))= %f\n",
                pktSize, fractionBW, interfaceBW, idealInterPacketDepartureTime);
        }

        // This is the first packet to be dequeued from the agency
        // So idle canot be negative, assign it to zero
        if (agency->estimator->lastServiceTime == 0.0)
        {
            idle = 0.0;
        }

        // The exponential weighted moving avg of the diff(i.e., idle)
        // variable using the equation avg<- (1-w)avg + w*idle.
        // A class is considered to be overlimit if avg is negative
        // and underlimit if avg is positive.
        // Store the idle and avgIdle value for each queue.  [1]

        prevPrevAvgIdle = agency->estimator->prevAvgIdle;

        agency->estimator->prevAvgIdle = agency->estimator->avgIdle;

        agency->estimator->avgIdle = ((1 - this->weightFactor)
            * agency->estimator->avgIdle) + (this->weightFactor * idle);

        if (agency->estimator->avgIdle > agency->estimator->maxAvgIdle)
        {
            agency->estimator->maxAvgIdle = agency->estimator->avgIdle;
        }

        // If the value of avgIdle is zero or positive
        if (agency->estimator->avgIdle >= 0.0)
        {
            // This is an under limit class or Agency.
            agency->estimator->timeToSend = 0.0;
        }
        else // If the value of avgIdle is negative
        {
            if ((agency->estimator->prevAvgIdle >= 0.0) &&
                (prevPrevAvgIdle <= 0.0))
            {
                // When the avg variable might change from negative to
                // positive, indicating that the previously-overlimit
                // class is no longer overlimit, and if this happens
                // frequently,the class will no longer need to be regulated
                // by the link-sharing scheduler. At that point, the
                // time-to-send field for that class (or agency) will be
                // reset to zero.  [1]

                agency->estimator->timeToSend = 0.0;
            }
            else
            {
                if (agency->estimator->maxAvgIdle > MAX_IDLE)
                {
                    double aValue = 0.0;
                    double aWeightFactor = 0.0;

                    // Calculate "numPktToTransmit" value
                    aValue = (MAX_IDLE / ((pktSize * 8.0)
                        / (this->interfaceBW
                        * (1 / agency->weight - 1)))) + 1.0;

                    aWeightFactor = 1.0 - this->weightFactor;

                    agency->estimator->numPktToTransmit
                        = (unsigned int)(log10(aValue)
                        / (-log10(aWeightFactor)));

                    if (CBQ_DEBUG)
                    {
                        printf("CBQ:  This agency was idle for a"
                            " long time\n");
                    }

                    // Reset agency->maxAvgIdle
                    agency->estimator->maxAvgIdle = 0.0;
                }

                if ((agency->estimator->numPktToTransmit == 0) ||
                    (agency->estimator->avgIdle < MIN_IDLE))
                {
                    // This is an over limit Agency.
                    // For OVER_LIMIT class the time-to-send field is set
                    // to a time x seconds ahead of the current time.Where
                    // for leaf class x = (packet size * 8 )
                    //  / (fraction of BW  * link rate) ;
                    // for non leaf class x = - avgIdle * ((1
                    //      - weightFactor) / weightFactor)
                    //      + ((packet size * 8 ) / (fraction of BW
                    //      * link rate))  [1]

                    if (!agency->isAgency)
                    {
                        // Application
                        agency->estimator->timeToSend
                            = ((double)currentTime / SECOND)
                            + idealInterPacketDepartureTime;
                    }
                    else
                    {
                        // Agency
                        agency->estimator->timeToSend
                            = ((double)currentTime / SECOND)
                            + (idealInterPacketDepartureTime
                            - (agency->estimator->avgIdle
                            * ((1 - this->weightFactor)
                            / this->weightFactor)));
                    }
                }
                else // (agency->numPktToTransmit > 0)
                {
                    agency->estimator->timeToSend = 0.0;
                }
            }
        }

        if (CBQ_DEBUG)
        {
            printf("\t\tidle = %f\n",idle);
            printf("\t\tAllocated FractionalBW = %lf\n",fractionBW);
            printf("\t\tprevPrevAvgIdle = %lf : PrevAvgIdle = %lf :"
                "AvgIdle = %lf\n", prevPrevAvgIdle,
                agency->estimator->prevAvgIdle, agency->estimator->avgIdle);
            printf("\t\tTime to send = %lf\n",
                agency->estimator->timeToSend);
        }

        agency = agency->ancestor;

    } //while()

    if ((cbqApplication->estimator->timeToSend == 0.0) ||
        (cbqApplication->estimator->timeToSend < ((double)currentTime
                                                            / SECOND)))
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}


//**
// FUNCTION   :: CBQResourceManager::AncestorOnlyGuideline
// LAYER      ::
// PURPOSE    :: Decides a class is to be regulated or not, depending on the
//              Ancestor Only link sharing guidelines.
//              In ancestors-only link-sharing:
//              class may continue unregulated if either:
//              1> class is under/at limit
//              2> class has an UNDER-limit ancestor [at-limit not ok]  [1]
// PARAMETERS ::
// + agencyInfo : ResourceSharingNode* : ResourceSharingNode structure
// + currentTime : const clocktype : Current simulation time
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL CBQResourceManager::AncestorOnlyGuideline(
    ResourceSharingNode* agencyInfo,
    const clocktype currentTime)
{
    ResourceSharingNode* agency = agencyInfo;

    // ancestors-only link-sharing:
    //      class may continue unregulated if either:
    //      1> class is under/at limit
    //      2> class has an UNDER-limit ancestor [at-limit not ok]

    if (!(agency->estimator->timeToSend > ((double)currentTime / SECOND)) ||
         !(agency->ancestor->estimator->timeToSend
                    > ((double)currentTime / SECOND)))
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}


//**
// FUNCTION   :: CBQResourceManager::TopLevelGuideline
// LAYER      ::
// PURPOSE    :: Decides a class is to be regulated or not, depending on the
//               top-level link sharing guidelines.
//               In top-level link-sharing:
//               class may continue unregulated if either:
//               1> class is under/at limit
//               2> class has an UNDER-limit ancestor with level
//                  <= the value of "top-level"  [1]
// PARAMETERS ::
// + agencyInfo : ResourceSharingNode* : ResourceSharingNode structure
// + currentTime : const clocktype : Current simulation time
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL CBQResourceManager::TopLevelGuideline(
    ResourceSharingNode* agencyInfo,
    const clocktype currentTime)
{

    int level = 1;// Level of the leaf Agency
    int numOverLimitAgency = 0;
    BOOL isRootAgency = FALSE;
    ResourceSharingNode* agency = agencyInfo;

    // top-level link-sharing:
    //      class may continue unregulated if either:
    //      1> class is under/at limit
    //      2> class has an UNDER-limit ancestor with level
    //          <= the value of "top-level"

    if (!(agency->estimator->timeToSend > ((double)currentTime / SECOND)))
    {
        return FALSE;
    }
    else
    {
        while (!isRootAgency)
        {
            if (level > this->guideLineLevel)
            {
                break;
            }
            if (agency->ancestor != NULL)
            {
                agency = agency->ancestor;
                level++;
                if (agency->ancestor == NULL)
                {
                   isRootAgency = TRUE;
                }
            }
            if (agency->estimator->timeToSend
                    > ((double)currentTime / SECOND))
            {
                numOverLimitAgency++;
            }
        }

        if (!numOverLimitAgency)
        {
            return FALSE;
        }
        else
        {
            return TRUE;
        }
    }
}


//---------------------------------------------------------------------------
// End: Utility Functions
//---------------------------------------------------------------------------

//**
// FUNCTION   :: CBQResourceManager::insert
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that need
//               to be passed to a scheduler data structure in order to
//               insert a message into it. The scheduler is responsible for
//               routing this packet to an appropriate queue that it
//               controls, and returning whether or not the procedure was
//               successful. The changes here are the replacement of the dscp
//               parameter with the infoField pointer.  The size of this
//               infoField is stored in infoFieldSize.
// PARAMETERS ::
// + msg : Message* : Pointer to Message structure
// + QueueIsFull : BOOL* : Status of queue full
// + queueIndex : const int : Queue index
// + infoField : const void* : Info field
// + currentTime : const clocktype : Current simulation time.
// RETURN     :: void : Null
// **/

void CBQResourceManager::insert(
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime)
{
    insert(msg,QueueIsFull,priority,infoField,currentTime,NULL);
}

void CBQResourceManager::insert(
    Node* node,
    int interfaceIndex,
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime) 
{
    insert(msg,QueueIsFull,priority,infoField,currentTime,NULL);
}

void CBQResourceManager::insert(
    Node* node,
    int interfaceIndex,
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime,
    TosType* tos) 
{
    insert(msg,QueueIsFull,priority,infoField,currentTime,NULL);
}



void CBQResourceManager::insert(
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void* infoField,
    const clocktype currentTime,
    TosType* tos
    )
{
    BOOL queueWasEmpty = FALSE;
    QueueData* qData = NULL;
    int queueIndex;
    int i;

    queueIndex = numQueues;
    for (i = 0; i < numQueues; i ++)
    {
        if (queueData[i].priority == priority)
        {
            queueIndex = i;
            break;
        }
    }

    ERROR_Assert((queueIndex >= 0) && (queueIndex < numQueues),
        "Queue does not exist!!!\n");

    // The priority queue in which incoming packet will be inserted
    qData = &queueData[queueIndex];

    if (CBQ_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(currentTime, time);
        printf("Cbq : Simtime %s got packet to enqueue\n", time);
    }

    if (qData->queue->isEmpty())
    {
        queueWasEmpty = TRUE;
    }

    if(tos == NULL)
    {
        pktScheduler->insert(msg, QueueIsFull, queueIndex, infoField,
                                currentTime);
    }
    else
    {
        pktScheduler->insert(msg, QueueIsFull, queueIndex, infoField,
                                currentTime, tos);
    }


    if (!*QueueIsFull)
    {
        if (queueWasEmpty)
        {
            // Activate the Application and ancestor agencies
            ActivateAgency(GetApplicationByPriority(qData->priority));
        }
        // Update enqueue statistic
        stats[queueIndex].totalPkt++;
    }
}



//**
// FUNCTION   :: CBQResourceManager::retrieve
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that need
//               to be passed to a scheduler data structure in order to
//               dequeue or peek at a message in its array of stored
//               messages. I've reordered the arguments slightly, and
//               incorporated the "DropFunction" functionality as well.
// PARAMETERS ::
// + priority : const int : Priority of queue
// + index : const int : Index
// + msg : Message** : Pointer of pointer to Message structure
// + msgPriority : int* : Message priority
// + operation : const QueueOperation : The retrieval mode
// + currentTime : const clocktype : Current simulation time.
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL CBQResourceManager::retrieve(
    const int priority,
    const int index,
    Message** msg,
    int* msgPriority,
    const QueueOperation operation,
    const clocktype currentTime
    )
{
    int i = 0;
    int numApplication = 0;
    unsigned int pktSize = 0;
    int queueIndex = ALL_PRIORITIES;
    int packetIndex = 0;
    BOOL isSelected = FALSE; // Is the queue selected for dequeue
    ResourceSharingNode* application = NULL;

    QueueData* qData = NULL;
    BOOL isMsgRetrieved = FALSE;
    *msg = NULL;

    BOOL isQueueSuspended = FALSE;

    if (CBQ_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(currentTime, time);
        printf("CBQ:  Simtime %s got request to dequeue\n",time);
    }

    if (!(index < numberInQueue(priority)) || (index < 0))
    {
        if (CBQ_DEBUG)
        {
            printf("CBQ: Attempting to retrieve a packet that"
                " does not exist\n");
        }
        return isMsgRetrieved;
    }

    numApplication = BUFFER_GetCurrentSize(&this->listApplication)
                    / sizeof(ResourceSharingNode*);

    if (numQueues != numApplication)
    {
        ERROR_ReportError("CBQ : Number of Application must equal"
            " num of queue at the interface \n");
    }

    if (priority != ALL_PRIORITIES) //specificPriorityOnly
    {
        // Dequeue a packet from the specified priority queue
        qData = SelectSpecificPriorityQueue(priority);
        packetIndex = index;

        for (i = 0; i < numQueues; i++)
        {
            if (queueData[i].priority == qData->priority)
            {
                queueIndex = i;
                break;
            }
        }
    }
    else
    {
        // Select the queue from which packet will be dequeued
        while ((!isSelected) && (!isEmpty(ALL_PRIORITIES)))
        {
            Message* msgToDequeue = NULL;
            int qdataPriority = ALL_PRIORITIES;

            // Generel Packet scheduler (PRR or WRR) selecting a queue
                pktScheduler->retrieve(priority,
                                        index,
                                        &msgToDequeue,
                                        &qdataPriority,
                                        PEEK_AT_NEXT_PACKET,
                                        currentTime);
            // the queue is selected for dequeue
            for (i = 0; i < numQueues; i++)
            {
                if (queueData[i].priority == qdataPriority)
                {
                    queueIndex = i;
                    break;
                }
            }

            // Update the statistical variables for dequeueing
            stats[queueIndex].numDequeueReq++;

            // Get the packetSize
            pktSize = MESSAGE_ReturnPacketSize(msgToDequeue);

            application = GetApplicationByPriority(
                                queueData[queueIndex].priority);

            // Check queueStatus of the selected queue
            if (ResourceSharingEstimator(pktSize, application, currentTime))
            {
                qData = &queueData[queueIndex];
                isSelected = TRUE;

                if (CBQ_DEBUG)
                {
                    printf("\t  Dequeue selection by GPS:\n");
                }

                if (operation == DEQUEUE_PACKET)
                {
                    stats[queueIndex].numGPSDequeue++;
                }
            }
            else
            {
                // Link sharing scheduler interacts with general scheduler
                // forcing some class not to be served (even if general
                // scheduler allows it) to meet link sharing requirement.
                // There are some Link sharing guidelines (ancestorS-ONLY or
                // FORMAL) that controls this behavior. These guide lines
                // decides whether a class is to be regulated or not.
                // When a class is to be regulated, the general
                // scheduler behavior is influenced by the link-sharing one
                // that forces a suspension for that class.  [1]

                if (!application->efficient  &&
                    (this->*resourceSharingGuidelineType)(
                                        application, currentTime))
                {
                    double extraDelay = 0.0;
                    Message* newMsg = NULL;
                    CBQResourceManagerInfo* infoPtr;

                    newMsg = MESSAGE_Alloc(this->nodeInfo, this->layerInfo,
                        LINK_MANAGEMENT_PROTOCOL_CBQ, MSG_DEFAULT);

                    MESSAGE_InfoAlloc(nodeInfo,
                                      newMsg,
                                      sizeof(CBQResourceManagerInfo));

                    infoPtr = (CBQResourceManagerInfo*)MESSAGE_ReturnInfo(newMsg);
                    infoPtr->index = queueIndex;
                    infoPtr->schPtr = (CBQResourceManager*)this;

                    // Calculate the extra delay
                    extraDelay = application->estimator->timeToSend
                        - ((double) currentTime / SECOND);

                    MESSAGE_Send(nodeInfo, newMsg,
                        (clocktype) (extraDelay * SECOND));

                    // Suspend the application corresponding this queue
                    application->estimator->suspend = true;
                    queueData[queueIndex].queue->setQueueBehavior(true);


                    if (CBQ_DEBUG)
                    {
                        printf("      The application[%u] is punished at"
                            " %0.9lf\n", application->priority,
                            ((double) currentTime / SECOND));
                    }

                    // Update stat
                    if (operation == DEQUEUE_PACKET)
                    {
                        stats[queueIndex].numSuspended++;

                        if (extraDelay > stats[queueIndex].maxExtradelay)
                        {
                            stats[queueIndex].maxExtradelay = extraDelay;
                        }
                        stats[queueIndex].totalExtradelay += extraDelay;
                    }
                }
                else
                {
                    // The queue is selected for dequeue by the Link Sharing
                    // Scheduler.Transmit a packet from this queue
                    qData = &queueData[queueIndex];
                    isSelected = TRUE;

                    if (CBQ_DEBUG)
                    {
                        printf("\t\tDequeue selection by LSS:\n");
                    }

                    if (operation == DEQUEUE_PACKET)
                    {
                        stats[queueIndex].numLSSDequeue++;
                    }
                }
            }
        }

        if (!isSelected)
        {
            // All the active Queues at the interface were punished
            // So dequeueing packet from recently punished Queue
            qData = &queueData[queueIndex];

            if (qData->queue->getQueueBehavior() == SUSPEND)
            {
                qData->queue->setQueueBehavior(RESUME);
                isQueueSuspended = TRUE;
            }

            if (CBQ_DEBUG)
            {
                printf("      Dequeue selection by Force: All the Queues "
                    "at the interface were punished & Dequeueing packet"
                    " from recently punished Queue \n");
            }
        }
    }

    // Dequeueing a pkt; calling Queue retrive function
        isMsgRetrieved = pktScheduler->retrieve(qData->priority,
                                            packetIndex,
                                            msg,
                                            msgPriority,
                                            operation,
                                            currentTime);
    // Assigning msg priority
    *msgPriority = qData->priority;

    if (isQueueSuspended)
    {
        qData->queue->setQueueBehavior(SUSPEND);
    }
    if (isMsgRetrieved)
    {
        // Update stat
        if (operation == DEQUEUE_PACKET)
        {
            stats[queueIndex].numDequeue++;
            if (priority == ALL_PRIORITIES)
            {
                ResourceSharingNode* agency = application;
                // If packet is dequeued from the selected queue
                // store the "lastServiceTime" of the agency
                while (agency)
                {
                    agency->estimator->lastServiceTime = currentTime;

                    if (agency->estimator->numPktToTransmit)
                    {
                        agency->estimator->numPktToTransmit--;
                    }
                    agency = agency->ancestor;
                }

                if (qData->queue->isEmpty())
                {
                    DeactivateAgency(application);
                }
            }
        }
    }

    if (CBQ_DEBUG)
    {
        printf("\t\tRetrieved Packet from queue %u\n", qData->priority);
    }

    ERROR_Assert((*msg) != NULL, "The msg field is NULL");

    return isMsgRetrieved;
}


//**
// FUNCTION   :: CBQResourceManager::isEmpty
// LAYER      ::
// PURPOSE    :: Returns a Boolean value of TRUE if the array of stored
//               messages in each queue that the scheduler controls are
//               empty, and FALSE otherwise
// PARAMETERS ::
// + priority :: const int : Priority of queue
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL CBQResourceManager::isEmpty(const int priority)
{
    int i = 0;
    ResourceSharingNode* application = NULL;

    if (priority == ALL_PRIORITIES)
    {
        for (i = 0; i < numQueues; i++)
        {
            application = GetApplicationByPriority(queueData[i].priority);

            if ((!queueData[i].queue->isEmpty()) &&
                (!application->estimator->suspend))
            {
                return FALSE;
            }
        }
    }
    else
    {
        for (i = 0; i < numQueues; i++)
        {
            application = GetApplicationByPriority(queueData[i].priority);

            if (queueData[i].priority == priority)
            {
                if (queueData[i].queue->isEmpty() ||
                    application->estimator->suspend)
                {
                    return TRUE;
                }
            }
        }
        return FALSE;
    }
    return TRUE;
}


//**
// FUNCTION   :: CBQResourceManager::bytesInQueue
// LAYER      ::
// PURPOSE    :: This function prototype returns the total number of bytes
//               stored in the array of either a specific queue, or all
//               queues that the scheduler controls.
// PARAMETERS ::
// + priority : const int : Queue priority
// RETURN     :: int : Total bytes use in queue
// **/

int CBQResourceManager::bytesInQueue(const int priority)
{
    int i = 0;

    if (priority == ALL_PRIORITIES)
    {
        int totalBytesInQueues = 0;

        // Return total number of packets at the interface
        for (i = 0; i < numQueues; i++)
        {
            totalBytesInQueues += queueData[i].queue->bytesInQueue();
        }
        return totalBytesInQueues;
    }
    else
    {
        for (i = 0; i < numQueues; i++)
        {
            if (priority == queueData[i].priority)
            {
                return queueData[i].queue->bytesInQueue();
            }
        }
    }

    // Error: No Queue exits with such priority value
    char errStr[MAX_STRING_LENGTH] = {0};
    sprintf(errStr, "Scheduler Error:"
        " No Queue exits with priority value %d", priority);
    ERROR_Assert(FALSE, errStr);

    return ALL_PRIORITIES;
}


//**
// FUNCTION   :: CBQResourceManager::numberInQueue
// LAYER      ::
// PURPOSE    :: This function prototype returns the number of messages
//               stored in the array of either a specific queue, or all
//               queues that the scheduler controls.
// PARAMETERS ::
// + priority : const int : Queue priority
// RETURN     :: int : Total number of packets
// **/

int CBQResourceManager::numberInQueue(const int priority)
{
    int i = 0;

    if (priority == ALL_PRIORITIES)
    {
        int numInQueue = 0;

        // Return total number of packets at the interface
        for (i = 0; i < numQueues; i++)
        {
            numInQueue += queueData[i].queue->packetsInQueue();
        }
        return numInQueue;
    }
    else
    {
        for (i = 0; i < numQueues; i++)
        {
            if (priority == queueData[i].priority)
            {
                return queueData[i].queue->packetsInQueue();
            }
        }
    }

    // Error: No Queue exits with such priority value
    char errStr[MAX_STRING_LENGTH] = {0};
    sprintf(errStr, "Scheduler Error:"
        " No Queue exits with priority value %d", priority);
    ERROR_Assert(FALSE, errStr);

    return ALL_PRIORITIES;
}


//**
// FUNCTION   :: CBQResourceManager::addQueue
// LAYER      ::
// PURPOSE    :: This function adds a queue to a scheduler.
//               This can be called either at the beginning of the
//               simulation (most likely), or during the simulation (in
//               response to QoS situations).  In either case, the
//               scheduling algorithm must accommodate the new queue, and
//               behave appropriately (recalculate turns, order, priorities)
//               immediately. This queue must have been previously setup
//               using QUEUE_Setup. Notice that the default value for
//               priority is the ALL_PRIORITIES constant, which implies that
//               the scheduler should assign the next appropriate value to
//               the queue.  This could be an error condition, if it is not
//               immediately apparent what the next appropriate value would
//               be, given the scheduling algorithm running.
// PARAMETERS ::
// + queue : Queue* : Pointer of Queue class
// + priority : const int : Priority of the queue
// + weight : const double : Weight of the queue
// RETURN         :: int : Integer
// **/

int CBQResourceManager::addQueue(
    Queue *queue,
    const int priority,
    const double weight)
{
    int addedQueuePriority = ALL_PRIORITIES;

    if ((weight <= 0.0) || (weight > 1.0))
    {
        // Considering  1.0 as this is the default value
        ERROR_ReportError(
            "CBQ: QUEUE-WEIGHT value must stay between <0.0 - 1.0>\n");
    }

    addedQueuePriority = pktScheduler->addQueue(queue, priority, weight);

    if ((numQueues == 0) || (numQueues == maxQueues))
    {
        QueueData* newQueueData
            = new QueueData[maxQueues + DEFAULT_QUEUE_COUNT];

        ResourceManagerStat* newStats
            = new ResourceManagerStat[maxQueues + DEFAULT_QUEUE_COUNT];

        if (queueData != NULL)
        {
            memcpy(newQueueData, queueData, sizeof(QueueData) * maxQueues);
            delete[] queueData;

            memcpy(newStats, stats, sizeof(ResourceManagerStat) * maxQueues);
            delete[] stats;
        }

        queueData = newQueueData;
        stats = newStats;

        maxQueues += DEFAULT_QUEUE_COUNT;
    }

    ERROR_Assert(maxQueues > 0, "Scheduler addQueue function maxQueues <= 0");

    if (addedQueuePriority == ALL_PRIORITIES)
    {
        ERROR_ReportError("CBQ Packet Scheduler addQueue function fail");
        return addedQueuePriority; // unreachable code
    }
    else //manualPrioritySelection
    {
        int i;
        for (i = 0; i < numQueues; i++)
        {
            ERROR_Assert(queueData[i].priority != addedQueuePriority,
                "Priority queue already exists");

        }

        for (i = 0; i < numQueues; i++)
        {
            if (queueData[i].priority > addedQueuePriority)
            {
                int afterEntries = numQueues - i;
                QueueData* newQueueData = new QueueData[afterEntries];

                memcpy(newQueueData, &queueData[i],
                       sizeof(QueueData) * afterEntries);

                memcpy(&queueData[i+1], newQueueData,
                       sizeof(QueueData) * afterEntries);

                queueData[i].priority = addedQueuePriority;
                queueData[i].weight = (float)weight;
                queueData[i].queue = queue;

                memset(&stats[i], 0, sizeof(ResourceManagerStat));

                numQueues++;
                delete[] newQueueData;
                return addedQueuePriority;
            }
        }

        i = numQueues;

        queueData[i].priority = addedQueuePriority;
        queueData[i].weight = (float) weight;
        queueData[i].queue = queue;

        memset(&stats[i], 0, sizeof(ResourceManagerStat));
        numQueues++;
        return addedQueuePriority;
    }
}


//**
// FUNCTION   :: CBQResourceManager::removeQueue
// LAYER      ::
// PURPOSE    :: This function removes a queue from the scheduler.
//               This function does not automatically finalize the queue,
//               so if the protocol modeler would like the queue to print
//               statistics before exiting, it must be explicitly finalized.
// PARAMETERS ::
// + priority : const int : Priority of the queue
// RETURN     :: void : Null
// **/

void CBQResourceManager::removeQueue(const int priority)
{
    int i;
    pktScheduler->removeQueue(priority);

    for (i = 0; i < numQueues; i++)
    {
        if (queueData[i].priority == priority)
        {
            int afterEntries = numQueues - (i + 1);

            if (afterEntries > 0)
            {
                memmove(&queueData[i], &queueData[i+1],
                    sizeof(QueueData) * afterEntries);

                memmove(&stats[i], &stats[i+1],
                    sizeof(ResourceManagerStat) * afterEntries);
            }
            numQueues--;
            return;
        }
    }
}


//**
// FUNCTION   :: CBQResourceManager::swapQueue
// LAYER      ::
// PURPOSE    :: This function substitutes the newly initialized queue
//               passed into this function, for the existing queue in
//               the scheduler, of type priority.  If there are packets
//               in the existing queue, they are transferred one-by-one
//               into the new queue.  This is done to attempt to replicate
//               the state of the queue, as if it had been the operative
//               queue all along.  This can result in additional drops of
//               packets that had previously been stored, and for
//               which there may be physical space in the queue.
//               If there is no such queue, it is added.
// PARAMETERS ::
// + queue : Queue* : Pointer of the Queue class
// + priority : const int : Priority of the queue
// RETURN     :: void : Null
// **/

void CBQResourceManager::swapQueue(
    Queue* queue,
    const int priority)
{
    int i = 0;

    for (i = 0; i < numQueues; i++)
    {
        if (queueData[i].priority == priority)
        {
            // If there are packets in the existing queue,
            // they are transferred one-by-one
            // into the new queue.
            pktScheduler->swapQueue(queue, priority);
            return;
        }
    }

    // If there is no such queue, it is added.
    addQueue(queue, priority);
}


//**
// FUNCTION   :: CBQResourceManager::HandleProtocolEvent
// LAYER      ::
// PURPOSE    :: This function Handles layer specific events for CBQ
// PARAMETERS ::
// + queueIndex : int : Queue index
// RETURN     :: void : Null
// **/
void CBQResourceManager::HandleProtocolEvent(
        int queueIndex)
{
    ResourceSharingNode* application = NULL;

    // Remove the suspension of queue
    application = GetApplicationByPriority(
                    queueData[queueIndex].priority);
    application->estimator->suspend = FALSE;

    queueData[queueIndex].queue->setQueueBehavior(FALSE);

    if (!isEmpty(queueData[queueIndex].priority))
    {
        if (layerInfo == NETWORK_LAYER)
        {
            MAC_NetworkLayerHasPacketToSend(nodeInfo, interfaceIndexInfo);
        }
        else
        {
            char errorStr[MAX_STRING_LENGTH] = {0};
            // Not yet supported supported
            sprintf(errorStr, "Handling layer %d is not yet"
                " supported supported\n", layerInfo);
            ERROR_ReportError(errorStr);
        }
    }
}


//**
// FUNCTION   :: CBQResourceManager::finalize
// LAYER      ::
// PURPOSE    :: This function prototype outputs the final statistics for
//               this scheduler. The layer, protocol, interfaceAddress, and
//               instanceId parameters are given to IO_PrintStat with each
//               of the queue's statistics.
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + layer : const char* : The layer string
// + interfaceIndex : const int : Interface index
// + invokingProtocol : const char* : The protocol string
// + splStatStr : const char* Special string for stat print
// RETURN     :: void : Null
// **/
void CBQResourceManager::finalize(
    Node* node,
    const char* layer,
    const int interfaceIndex,
    const char* invokingProtocol,
    const char* splStatStr)
{
    int i;
    char buf[MAX_STRING_LENGTH];
    char intfIndexStr[MAX_STRING_LENGTH] = {0};

    if (schedulerStatEnabled == FALSE)
    {
        return;
    }

    if (strcmp(invokingProtocol, "IP") == 0)
    {
        // IP scheduling finalization
        NetworkIpGetInterfaceAddressString(node,
                                           interfaceIndex,
                                           intfIndexStr);
    }
    else
    {
        sprintf(intfIndexStr, "%d", interfaceIndex);
    }

    for (i = 0; i < numQueues; i++)
    {
        sprintf(buf, "Packets Queued = %u",stats[i].totalPkt);
        IO_PrintStat(
            node,
            layer,
            "CBQ",
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Packets Dequeued = %u", stats[i].numDequeue);
        IO_PrintStat(
            node,
            layer,
            "CBQ",
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Number of Dequeue Requests = %u", stats[i].numDequeueReq);
        IO_PrintStat(
            node,
            layer,
            "CBQ",
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Selection: GPS = %u LSS = %u Forced = %u",
            stats[i].numGPSDequeue, stats[i].numLSSDequeue,
            (stats[i].numDequeue - (stats[i].numGPSDequeue
            + stats[i].numLSSDequeue)));
        IO_PrintStat(
            node,
            layer,
            "CBQ",
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Number of times Punished = %u", stats[i].numSuspended);
        IO_PrintStat(
            node,
            layer,
            "CBQ",
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Max Extradelay = %lf ", stats[i].maxExtradelay);
        IO_PrintStat(
            node,
            layer,
            "CBQ",
            intfIndexStr,
            queueData[i].priority,
            buf);

        if (stats[i].numSuspended)
        {
            sprintf(buf, "Avg Extradelay = %lf",
                (stats[i].totalExtradelay / stats[i].numSuspended));
        }
        else
        {
            sprintf(buf, "Avg Extradelay = %lf", stats[i].totalExtradelay);
        }

        IO_PrintStat(
            node,
            layer,
            "CBQ",
            intfIndexStr,
            queueData[i].priority,
            buf);
    }

    pktScheduler->finalize(node, layer, interfaceIndex, "CBQ");
}


//**
// FUNCTION   :: CBQResourceManager::Setup_ResourceManager
// LAYER      ::
// PURPOSE    :: This function runs Resource Manager initialization routine
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + rsInput : NodeInput : Resource sharing structure input
// + interfaceIndex : const int : Interface index
// + layer : const int : The string layer
// + interfaceBandwidth : const int : Interface bandwidth
// + resrcMngrGuideLine[] : const char : String for resource manager
//                                       guideline
// + resrcMngrGuideLineLevel : const int : Top-level limit
// + pktSchedulerTypeString[] : const char : Scheduler type string
// + enablePktSchedulerStat : BOOL : Packet scheduler statistics
// + enableStat : BOOL : scheduler statistics
// + graphDataStr[] : const char : Graph data string
// RETURN     :: void : Null
void CBQResourceManager::Setup_ResourceManager(
    Node* node,
    NodeInput rsInput,
    const int interfaceIndex,
    const int layer,
    const int interfaceBandwidth,
    const char resrcMngrGuideLine[],
    const int resrcMngrGuideLineLevel,
    const char pktSchedulerTypeString[],
    BOOL enablePktSchedulerStat,
    BOOL enableStat,
    const char graphDataStr[])
{
    queueData = NULL;
    numQueues = 0;
    maxQueues = 0;
    infoFieldSize = 0;
    packetsLostToOverflow = 0;
    schedulerStatEnabled = enableStat;

    schedGraphStatPtr = NULL;

    nodeInfo = node;
    interfaceIndexInfo = interfaceIndex;
    layerInfo = layer;
    interfaceBW = (double) interfaceBandwidth;
    guideLineLevel = resrcMngrGuideLineLevel;

    // weightFactor (= 1 - 2^(-RM_FILTER_GAIN))
    weightFactor = 1.0 - pow(2.0,-RM_FILTER_GAIN);

    root = NULL;
    ReadResourceSharingStr(rsInput);

    if (!strcmp(pktSchedulerTypeString, "PRR"))
    {
        pktScheduler = new StrictPriorityScheduler(enablePktSchedulerStat,
                                                   graphDataStr);
    }
    else if (!strcmp(pktSchedulerTypeString, "WRR"))
    {
        pktScheduler = new WrrScheduler(enablePktSchedulerStat,
                                        graphDataStr);
    }
    else
    {
        char errStr[MAX_STRING_LENGTH] = {0};
        sprintf(errStr, "CBQ: Unknown CBQ-GENERAL-SCHEDULER Specified\n"
            "\t\t Supported CBQ-GENERAL-SCHEDULER are PRR | WRR\n");
        ERROR_Assert(FALSE, errStr);
    }

    if (pktScheduler == NULL)
    {
        char errStr[MAX_STRING_LENGTH] = {0};
        sprintf(errStr, "Scheduler Error: Failed to assign memory for"
            " scheduler %s", pktSchedulerTypeString);
        ERROR_Assert(FALSE, errStr);
    }

    if (!strcmp(resrcMngrGuideLine, "ANCESTOR-ONLY"))
    {
        resourceSharingGuidelineType
            = &CBQResourceManager::AncestorOnlyGuideline;
    }
    else if (!strcmp(resrcMngrGuideLine, "TOP-LEVEL"))
    {
        resourceSharingGuidelineType
            = &CBQResourceManager::TopLevelGuideline;
    }
    else
    {
        char errStr[MAX_STRING_LENGTH] = {0};
        sprintf(errStr, "CBQ: Unknown CBQ-LINK-SHARING-GUIDELINE Specified\n"
            "\t\t Supported are ANCESTOR-ONLY | TOP-LEVEL\n");
        ERROR_Assert(FALSE, errStr);
    }
}


//**
// FUNCTION   :: CBQResourceManagerHandleProtocolEvent
// LAYER      ::
// PURPOSE    :: Removes the suspension of queue and trigger dequeue request
//               Currently this function is called from ip.cpp
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + msg : Message* : Pointer to Message structure
// RETURN     :: void : Null
// **/
void CBQResourceManagerHandleProtocolEvent(
    Node* node,
    Message* msg)
{
    CBQResourceManagerInfo* infoPtr =
        (CBQResourceManagerInfo*) MESSAGE_ReturnInfo(msg);

    CBQResourceManager* scheduler = infoPtr->schPtr;
    unsigned int qDataIndex = infoPtr->index;

    ERROR_Assert(msg->eventType == MSG_DEFAULT,"Wrong event type in CBQ");

    if (CBQ_DEBUG)
    {
        printf("\t\tTriggering Dequeue request for queue[%d] at%lf\n",
            qDataIndex, ((double)node->getNodeTime() / SECOND));
    }
    scheduler->HandleProtocolEvent(qDataIndex);

    MESSAGE_Free(node, msg);
}


//**
// FUNCTION   :: RESOURCE_MANAGER_Setup
// LAYER      ::
// PURPOSE    :: This function runs Resource Manager initialization routine
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + rsInput : NodeInput : Resource sharing structure input
// + interfaceIndex : const int : Interface index
// + layer : const int : The layer string
// + interfaceBandwidth : const int : Interface bandwidth
// + resrcMngr : CBQResourceManager** : Pointer of pointer to
//                                      CBQResourceManager structure
// + resrcMngrGuideLine[] : const char : String for resource manager
//                                       guideline
// + resrcMngrGuideLineLevel : const int : Resource manager guideline label
// + pktSchedulerTypeString[] : const char : Scheduler type string
// + enablePktSchedulerStat : BOOL : Packet scheduler statistics
// + enableStat : BOOL : Scheduler statistics
// + graphDataStr : const char* : Graph data string
// RETURN     :: void : Null
// **/

void RESOURCE_MANAGER_Setup(
    Node* node,
    NodeInput rsInput,
    const int interfaceIndex,
    const int layer,
    const int interfaceBandwidth,
    CBQResourceManager** resrcMngr,
    const char resrcMngrGuideLine[],
    const int resrcMngrGuideLineLevel,
    const char pktSchedulerTypeString[],
    BOOL enablePktSchedulerStat,
    BOOL enableStat,
    const char* graphDataStr)
{
    *resrcMngr = new CBQResourceManager;

    (*resrcMngr)->Setup_ResourceManager(node,
                                    rsInput,
                                    interfaceIndex,
                                    layer,
                                    interfaceBandwidth,
                                    resrcMngrGuideLine,
                                    resrcMngrGuideLineLevel,
                                    pktSchedulerTypeString,
                                    enablePktSchedulerStat,
                                    enableStat,
                                    graphDataStr);
}


//**
// FUNCTION   :: ReadCBQResourceManagerConfiguration
// LAYER      ::
// PURPOSE    :: Reads CBQ configuration parameters from .config file
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceIndex : int : Interface Index
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + lsrmInput : NodeInput* : Resource sharing input
// + resrcMngrGuideLine : char* : Resource sharing guideline
// + resrcMngrGuideLineLevel : int* : Top-level limit
// + pktSchedulerString : char* : Packet scheduler Module
// RETURN     :: void : Null
// **/


void ReadCBQResourceManagerConfiguration(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    NodeInput* lsrmInput,
    char* resrcMngrGuideLine,
    int* resrcMngrGuideLineLevel,
    char* pktSchedulerString)
{
    BOOL wasFound;
    char errorStr[MAX_STRING_LENGTH] = {0};

    // Read the "LINK-SHARING-STRUCTURE" from input file
    IO_ReadCachedFile(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "LINK-SHARING-STRUCTURE-FILE",
        &wasFound,
        lsrmInput);

    if (!wasFound)
    {
        sprintf(errorStr, "Node: %d Missing LINK-SHARING-STRUCTURE-FILE"
            " specification..", node->nodeId);
        ERROR_ReportError(errorStr);
    }

    // Read the Link Sharing GuideLine specified for CBQ
    IO_ReadString(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "CBQ-LINK-SHARING-GUIDELINE",
            &wasFound,
            resrcMngrGuideLine);

    if (!wasFound || (strcmp(resrcMngrGuideLine, "ANCESTOR-ONLY") &&
        strcmp(resrcMngrGuideLine, "TOP-LEVEL")))
    {
        sprintf(errorStr, "Node: %d Missing CBQ-LINK-SHARING-GUIDELINE"
            " specification..", node->nodeId);
        ERROR_ReportError(errorStr);
    }

    if (!strcmp(resrcMngrGuideLine, "TOP-LEVEL"))
    {
        // Top-Level Link Sharing Guideline
        IO_ReadInt(
                node,
                node->nodeId,
                interfaceIndex,
                nodeInput,
                "CBQ-TOP-LEVEL",
                &wasFound,
                resrcMngrGuideLineLevel);

        if (!wasFound)
        {
            sprintf(errorStr, "Node: %d Missing CBQ-TOP-LEVEL"
                " specification..", node->nodeId);
            ERROR_ReportError(errorStr);
        }

        if (*resrcMngrGuideLineLevel < 1)
        {
            ERROR_ReportError("Top level can't be less than 1\n");
        }
    }

    // Read the general Packet scheduler specified for CBQ
    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "CBQ-GENERAL-SCHEDULER",
        &wasFound,
        pktSchedulerString);

    if (!wasFound || (strcmp(pktSchedulerString, "PRR") &&
        strcmp(pktSchedulerString, "WRR")))
    {
        sprintf(errorStr, "Node: %d Missing CBQ-GENERAL-SCHEDULER"
            " specification..", node->nodeId);
        ERROR_ReportError(errorStr);
    }
}


// /**
// FUNCTION   :: CBQResourceManager::~CBQResourceManager
// LAYER      ::
// PURPOSE    :: This function will free the memory in the
//               CBQResourceManager
// PARAMETERS ::
// RETURN     :: void : Null
// **/
CBQResourceManager::~CBQResourceManager()
{
    delete []queueData;
    delete []stats;
}
