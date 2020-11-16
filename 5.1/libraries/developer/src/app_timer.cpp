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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "app_timer.h"
#include "timer_manager.h"

static 
Message *AppTimerAddNewTimer(
    Node *node,
    AppDataTimerTest *timer,
    clocktype delay)
{
    Message *msg;

    msg = MESSAGE_Alloc(node, APP_LAYER, APP_TIMER, 890);
    timer->t->schedule(msg, delay);

    printf("TIMER %d: Adding timer for %lf at %lf\n",
        node->nodeId,
        (double)(node->getNodeTime()+delay)/SECOND,
        (double)node->getNodeTime()/SECOND);

    return msg;
}


void
AppLayerTimerTest(Node *node, Message *msg)
{
    AppDataTimerTest *timer = AppTimerTestGetTimerTest(node);
    if(msg->eventType == 890)
    {
        printf("TIMER %d: Got message at %lf scheduled for %lf\n",
            node->nodeId,
            (double)node->getNodeTime()/SECOND,
            (double)msg->timerExpiresAt/SECOND);

        if(node->getNodeTime() == 2*SECOND)
        {
            AppTimerAddNewTimer(node, timer, 2*SECOND);
            AppTimerAddNewTimer(node, timer, 3*SECOND);
            AppTimerAddNewTimer(node, timer, 4*SECOND);
            AppTimerAddNewTimer(node, timer, 7*SECOND);

        }
    }
    else
    {
        assert(FALSE);
    }
    //AppTimerAddNewTimer(node, timer, 1500*MILLI_SECOND);
}



void
AppTimerTestInit(
    Node *node)
{
    AppDataTimerTest *timer;
    timer = AppTimerTestNewTimerTest(node);

    timer->t = new TimerManager(node);
    
    AppTimerAddNewTimer(node, timer, 8*SECOND);
    AppTimerAddNewTimer(node, timer, 2*SECOND);

    //timer->t->cancel(timer->msgTimer[0]);

}


AppDataTimerTest *
AppTimerTestGetTimerTest(Node *node)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataTimerTest *timer;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_TIMER)
        {
            timer = (AppDataTimerTest *) appList->appDetail;

            return timer;
        }
    }

    return NULL;
}

AppDataTimerTest *
AppTimerTestNewTimerTest(Node *node)
{
    AppDataTimerTest *timer;

    timer = (AppDataTimerTest *)
                MEM_malloc(sizeof(AppDataTimerTest));
    memset(timer, 0, sizeof(AppDataTimerTest));


    APP_RegisterNewApp(node, APP_TIMER, timer);

    return timer;
}



