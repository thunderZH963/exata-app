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
#include "mdpProtoTimer.h"
#include "node.h"
#include "partition.h"

MdpProtoTimer::MdpProtoTimer():
            msg(NULL),interval(0),repeat(0),repeat_count(0),
            timeout(0),mgr(NULL)
{

}

MdpProtoTimer::~MdpProtoTimer()
{
}

bool MdpProtoTimer::IsActive(clocktype currentTime) const
{
    if (msg == NULL)
    {
        return false;
    }
    else if (currentTime == CLOCKTYPE_MAX)
    {
        return true;
    }

    if (currentTime > -1)
    {
        clocktype diff = this->timeout - currentTime;
        if (diff > 0)
        {
            return true;
        }
        else if (diff == 0)
        {
            if (!msg->cancelled)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }
    return false;
}


clocktype MdpProtoTimer::GetTimeRemaining(clocktype currentTime) const
{
    clocktype diff = this->timeout - currentTime;

    if (diff > 0)
    {
        return diff;
    }
    else
    {
        return 0;
    }
}


bool MdpProtoTimer::Reschedule(timeoutEventType eventType, Node* node, void* classPtr)
{
    if (NULL != mgr)
    {
        MdpProtoTimerMgr* theMgr = mgr;
        theMgr->DeactivateTimer(*this, node);
        theMgr->ActivateTimer(*this, eventType, node, classPtr);
        return true;
    }
    else
    {
        if (MDP_DEBUG)
        {
            printf("MdpProtoTimer::Reschedule() error: timer not active\n");
        }
        return false;
    }
}  // end MdpProtoTimer::Reschedule()

void MdpProtoTimer::Deactivate(Node* node)
{
    mgr->DeactivateTimer(*this, node);
}

MdpProtoTimerMgr::MdpProtoTimerMgr()
{
}

MdpProtoTimerMgr::~MdpProtoTimerMgr()
{
    // (TBD) Uninstall or halt, deactivate all timers...
}


void MdpProtoTimerMgr::ActivateTimer(MdpProtoTimer& theTimer,
                                  timeoutEventType eventType,
                                  Node* node,
                                  void* classPtr)
{

    InsertTimer(&theTimer, eventType, node, classPtr);

}  // end MdpProtoTimerMgr::ActivateTimer()



void MdpProtoTimerMgr::DeactivateTimer(MdpProtoTimer& theTimer, Node* node)
{
    if (theTimer.mgr == this)
    {
        RemoveTimer(&theTimer, node);
    }
}  // end MdpProtoTimerMgr::DeactivateTimer()



void MdpProtoTimerMgr::InsertTimer(MdpProtoTimer* theTimer,
                                timeoutEventType eventType,
                                Node* node,
                                void* classPtr)
{
    struct_mdpTimerInfo* mdpInfo = NULL;
    theTimer->mgr = this;

    if (!theTimer->msg)
    {
        theTimer->msg = MESSAGE_Alloc(node,
                                  APP_LAYER,
                                  APP_MDP,
                                  MSG_APP_TimerExpired);

        if (classPtr)
        {
            MESSAGE_InfoAlloc(node, theTimer->msg, sizeof(mdpInfo));
        }

        //if (eventType == ACTIVITY_TIMEOUT)
        //{
        //    theTimer->ResetRepeatCount();
        //}
        //else if (eventType == REPAIR_TIMEOUT)
        //{
        //    theTimer->ResetRepeatCount();
        //}
    }
    else
    {
        theTimer->msg->packetCreationTime = node->getNodeTime();
        theTimer->msg->cancelled = FALSE;
    }

    if (classPtr)
    {
        mdpInfo = (struct_mdpTimerInfo*)MESSAGE_ReturnInfo(theTimer->msg);
        mdpInfo->mdpEventType = eventType;
        mdpInfo->mdpclassPtr = classPtr;
    }

    // setting timer end time sim time
    theTimer->timeout = theTimer->msg->packetCreationTime +
                                                       theTimer->interval;

    MESSAGE_Send(node, theTimer->msg, (clocktype)theTimer->interval);

}  // end MdpProtoTimerMgr::InsertTimer()


void MdpProtoTimerMgr::RemoveTimer(MdpProtoTimer* theTimer,
                                Node* node)
{
    if (theTimer->msg)
    {
        MESSAGE_CancelSelfMsg(node,theTimer->msg);
    }
    theTimer->msg = NULL;
    theTimer->interval = 0;
    theTimer->timeout = 0;
    //theTimer->repeat = 0;
    //theTimer->repeat_count = 0;
}  // end MdpProtoTimerMgr::RemoveTimer()

