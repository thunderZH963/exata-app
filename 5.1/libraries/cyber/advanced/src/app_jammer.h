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

#ifndef _JAMMER_APP_H_
#define _JAMMER_APP_H_

typedef struct struct_app_jammer_jam_info
{
    int channelIndex;
    clocktype duration;
} AppJammerJamInfo;

//jammer structure
struct AppJammer
{
    int interfaceIndex;
    clocktype duration;
    int scannerIndex;
    int scannerHandle;
    int minDataRate;
    bool silentMode;
    Message** signalsForChannel;
    bool* activeChannels;
    D_BOOL* origChannelListenable;
};

//jammer events that are possible
enum {
    APP_JAMMER_START_JAMMING,
    APP_JAMMER_STOP_JAMMING,
    APP_JAMMER_TERMINATE_ALL,
    APP_JAMMER_SEND_JAM_SIGNAL
};

//jammer types: silent and full jammer
enum JamType {
    JAM_TYPE_APP = 0,
    JAM_TYPE_MAC
};

// /**
// API :: AppJammerProcessReceivedSignal
// PURPOSE ::
//   Called from propagation_private for the silent jammer. All the signals 
//   intercepted by the jammer at the physical layer have to be jammed
// PARAMETERS ::
// + node              : Node*        : the jammer node
// + jammer            : AppJammer*   : the jammer data structure
// + interfaceIndex    : int          : interface index on which the jammer is running
// + channelIndex      : int          : channel to jam on
// + propRxInfo        : PropRxInfo * : receiver info
// RETURN :: void : NULL
// **/

void AppJammerProcessReceivedSignal(
    Node* node,
    AppJammer* jammer,
    int interfaceIndex,
    int channelIndex,
    PropRxInfo *propRxInfo);

// /**
// API :: AppJammerStartJamming
// PURPOSE ::
//   Used to start the jammer on a node and initialize the jammer
// PARAMETERS ::
// + node              : Node*        : the jammer node
// + delay             : clocktype    : the jammer data structure
// + duration          : clocktype    : the duration for which jamming should occur
// + interfaceIndex    : int          : interface index on which the jammer should be running
// + scannerIndex      : int          : type of jammer to choose from
// + silentMode        : bool         : check if this jammer should run as a 
//                                      silent jammer or full jammer
// + minDataRate       : int          : valid only for silent jammer, the min data 
//                                      rate above which jamming should occur
// RETURN :: void : NULL
// **/

void AppJammerStartJamming(
        Node* node,
        int interfaceIndex,
        clocktype delay,
        clocktype duration,
        int scannerIndex,
        bool silentMode,
        int minDataRate );

// /**
// API :: AppJammerStopAllJamming
// PURPOSE ::
//   Used to stop all the jammer instances running on a node
// PARAMETERS ::
// + node              : Node*        : the jammer node
// RETURN :: void : NULL
// **/
void AppJammerStopAllJamming(
        Node* node);

//**
// API :: AppJammerProcessEvent
// PURPOSE ::
//   Handle any jammer specific events
// PARAMETERS ::
// + node              : Node*        : the jammer node
// + msg               : Message*     : the message to be handled
// RETURN :: void : NULL
// **/
void AppJammerProcessEvent(
        Node* node,
        Message* msg);

//**
// API :: AppJammerFinalize
// PURPOSE ::
//   Finalize the jammer instances running on this node
// PARAMETERS ::
// + node              : Node*        : the jammer node
// RETURN :: void : NULL
// **/
void AppJammerFinalize(
        Node* node);

#endif /* _JAMMER_APP_H_ */

