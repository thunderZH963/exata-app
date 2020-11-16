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

#ifndef _TIMER_APP_H_
#define _TIMER_APP_H_

class TimerManager;
/*
 * Data item structure used by timer.
 */
typedef
struct struct_app_timer_data
{
    TimerManager *t;
    Message *msgTimer[5];
}
AppDataTimerTest;



/*
 * NAME:        AppLayerTimerTest.
 * PURPOSE:     Models the behaviour of TimerTest  on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerTimerTest(Node *nodePtr, Message *msg);

/*
 * NAME:        AppTimerTestInit.
 * PURPOSE:     Initialize a TimerTest session.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverAddr - address of the server,
 *              itemsToSend - number of items to send,
 *              itemSize - size of each packet,
 *              interval - interval of packet transmission rate.
 *              startTime - time until the session starts.
 *              endTime - time until the session end.
 *              tos - the contents for the type of service field.
 *              isRsvpTeEnabled - whether RSVP-TE is enabled
 * RETURN:      none.
 */
void
AppTimerTestInit(
    Node *node);


/*
 * NAME:        AppTimerTestGetTimerTest.
 * PURPOSE:     search for a timer client data structure.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              sourcePort - source port of the timer client.
 * RETURN:      the pointer to the timer client data structure,
 *              NULL if nothing found.
 */
AppDataTimerTest *
AppTimerTestGetTimerTest(Node *nodePtr);

/*
 * NAME:        AppTimerTestNewTimerTest.
 * PURPOSE:     create a new timer client data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              remoteAddr - remote address.
 *              itemsToSend - number of items to send,
 *              itemSize - size of data packets.
 *              interval - interdeparture time of packets.
 *              startTime - time when session is started.
 *              endTime - time when session is ended.
 * RETURN:      the pointer to the created timer client data structure,
 *              NULL if no data structure allocated.
 */
AppDataTimerTest *
AppTimerTestNewTimerTest(
    Node *nodePtr);
#endif /* _TIMER_APP_H_ */

