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


#ifndef _MDP_ERROR
#define _MDP_ERROR

/* Mdp Error Codes */
enum MdpError
{
    MDP_ERROR_NONE = 0,
    MDP_ERROR,
    MDP_ERROR_INSTANCE_INVALID,
    MDP_ERROR_SESSION_INVALID,
    MDP_ERROR_OBJECT_INVALID,
    MDP_ERROR_NODE_INVALID,
    MDP_ERROR_PARAMETER_INVALID,
    MDP_ERROR_TX_QUEUE_FULL,
    MDP_ERROR_FILE_OPEN,
    MDP_ERROR_FILE_EMPTY,
    MDP_ERROR_FILE_LOCKED,
    MDP_ERROR_MEMORY,
    MDP_ERROR_SOCKET_OPEN,
    MDP_ERROR_DNS_FAIL,
    MDP_ERROR_SOCKET_MCAST,
    MDP_ERROR_SOCKET_TOS
};

#endif // _MDP_ERROR
