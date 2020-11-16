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

//
// This file contains macros & constants for operating
// Abstract TCP sequence numbers.
//

#ifndef ABSTRACT_TCP_SEQ_H
#define ABSTRACT_TCP_SEQ_H

#include "transport_tcp_seq.h"

#define abstract_tcp_sendseqinit(tp) \
    (tp)->snd_una = (tp)->snd_nxt = (tp)->snd_up = \
        (tp)->iss; (tp)->snd_max = (tp)->iss +(tp)->t_maxseg

#endif // ABSTRACT_TCP_SEQ_H
