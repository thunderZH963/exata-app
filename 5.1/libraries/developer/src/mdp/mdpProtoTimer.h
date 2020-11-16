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


#ifndef _MDP_PROTO_TIMER
#define _MDP_PROTO_TIMER

#include "node.h"
#include "mdpProtoDefs.h"
#include "message.h"
#include "mdpMessage.h"
#include "api.h"


class MdpProtoTimer
{
    friend class MdpProtoTimerMgr;

    public:
        // Construction/destruction
        MdpProtoTimer();
        ~MdpProtoTimer();

        // methods
        void SetInterval(double theInterval)
        {
            interval = (clocktype)(theInterval * SECOND);
        }
        void SetIntervalInClocktype(clocktype theInterval)
        {
            interval = theInterval;
        }
        clocktype GetInterval() const {return interval;}
        void SetRepeat(int numRepeat) {repeat = numRepeat;}
        int GetRepeat() const {return repeat;}
        void ResetRepeatCount() {repeat_count = repeat;}
        void DecrementRepeatCount()
            {
                repeat_count = (repeat_count > 0) ? --repeat_count : repeat_count;
            }
        int GetRepeatCount() {return repeat_count;}

        clocktype GetTimeout() {return timeout;}

        // Activity status/control
        bool IsActive(clocktype currentTime = CLOCKTYPE_MAX) const;

        clocktype GetTimeRemaining(clocktype currentTime) const;

        bool Reschedule(enum timeoutEventType, Node* node, void* classPtr);
        void Deactivate(Node* node);

    // data members
        Message*                    msg;
        clocktype                   interval;
        int                         repeat;
        int                         repeat_count;
        clocktype                   timeout;
        class MdpProtoTimerMgr*        mgr;
};  // end class MdpProtoTimer


class MdpProtoTimerMgr
{
    friend class MdpProtoTimer;

    public:
        MdpProtoTimerMgr();
        virtual ~MdpProtoTimerMgr();

        // MdpProtoTimer activation/deactivation
        virtual void ActivateTimer(MdpProtoTimer& theTimer,
                                   timeoutEventType eventType,
                                   Node* node,
                                   void* classPtr);
        virtual void DeactivateTimer(MdpProtoTimer& theTimer, Node* node);

    private:
        // Methods used internally
        void InsertTimer(MdpProtoTimer* theTimer,
                             timeoutEventType eventType,
                             Node* node,
                             void* classPtr);

        void RemoveTimer(MdpProtoTimer* theTimer,
                             Node* node);
};  // end class MdpProtoTimerMgr


#endif // _MDP_PROTO_TIMER
