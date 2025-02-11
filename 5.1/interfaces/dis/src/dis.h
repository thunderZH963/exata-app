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

#ifndef DIS_H
#define DIS_H

void
DisReadDisParameter(const NodeInput* nodeInput);

bool
DisIsActive();

void
DisInit(EXTERNAL_Interface* iface, NodeInput* nodeInput);

void
DisInitNodes(EXTERNAL_Interface* iface, NodeInput* nodeInput);

void
DisReceive(EXTERNAL_Interface* iface);

void
DisProcessEvent(Node* node, Message* msg);

void
DisFinalize(EXTERNAL_Interface* iface);

#ifdef MILITARY_RADIOS_LIB
void
DisSendRtssNotificationIfNodeIsDisEnabled(Node* node);
#endif /* MILITARY_RADIOS_LIB */

#endif /* DIS_H */
