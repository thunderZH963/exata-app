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
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

#include <stdio.h>


#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#ifndef _WIN32 // unix/linux
#include <netinet/if_ether.h>
#else // windows
#include "iphlpapi.h"
#endif

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "external.h"
#include "external_socket.h"
#include "auto-ipnetworkemulator.h"
#include "olsr_interface.h"

#define DEBUG 1

void OLSRPacketHandler::ReformatIncomingPacket(unsigned char *packet)
{
    OLSRSwapBytes(packet, TRUE);
}

void OLSRPacketHandler::ReformatOutgoingPacket(unsigned char *packet)
{
    OLSRSwapBytes(packet, FALSE);
}

void OLSRPacketHandler::OLSRSwapBytes(unsigned char *olsrPacket, BOOL in)
{
    int msgsize;
    int count;
    int minsize = (sizeof(unsigned char)*4);
    olsrpacket *olsr = (olsrpacket *) olsrPacket;

    if (in)
    {
        //Packet in network byte order,  so first have to convert in host
        //byte and read in sizes, counters etc.
        OLSRSwapPacketHeader(olsr, in);

        //Read in counters required for parsing the message
        count = olsr->olsr_packlen - minsize;

        //set m pointer to first msg
        olsrmsg *m = olsr->olsr_msg;

        while (count > 0)
        {
            if( count < minsize)
            {
                break;
            }

            OLSRSwapMsgHeader(m,in);

            switch (m->olsr_msgtype)
            {
                case HELLO_PACKET:
                    {
                        OLSRSwapHello(m, in);
                        break;
                    }
                case TC_PACKET:
                    {
                        OLSRSwapTC(m,in);
                        break;
                    }
                case MID_PACKET:
                    {
                        OLSRSwapMid(m,in);
                        break;
                    }
                case HNA_PACKET:
                    {
                        OLSRSwapHna(m,in);
                        break;
                    }
                default:
                    {
                        break;
                    }
            }

            //Get message size which is swapped
            msgsize= m->olsr_msg_size;
            count = count- msgsize;

            m = (olsrmsg * )((char *) m + msgsize);
        }
    }


    // This is output to network, so put it in
    // network order last.
    // hton conversion here
    if (!in)
    {
        //Packet in host byte order,  so first
        //read sizes and counters etc  and then
        //swap bytes
        count = olsr->olsr_packlen - minsize;

        OLSRSwapPacketHeader(olsr, in);


        //set m pointer to first msg

        olsrmsg *m = olsr->olsr_msg;

        while (count > 0)
        {
            if( count < minsize)
            {
                break;
            }

            switch (m->olsr_msgtype)
            {
                case HELLO_PACKET:
                    {
                        OLSRSwapHello(m, in);
                        break;
                    }
                case TC_PACKET:
                    {
                        OLSRSwapTC(m,in);
                        break;
                    }
                case MID_PACKET:
                    {
                        OLSRSwapMid(m,in);
                        break;
                    }
                case HNA_PACKET:
                    {
                        OLSRSwapHna(m,in);
                        break;
                    }
                default:
                    {
                        break;
                    }
            }

            //Get message size which is swapped
            //
            msgsize= m->olsr_msg_size;

            count = count- msgsize;

            //Now swap the header bytes, since we are done with this message


            OLSRSwapMsgHeader(m,in);

            //Move on to next message

            m= (olsrmsg * )((char *) m + msgsize);
        }

    }
}


 /**
// API       :: OLSRSwapHello
// PURPOSE   :: Swap header bytes for the hello message
// PARAMETERS::
// + m : olsrmsg * : The start of the  hello message
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: void
// **/
void OLSRPacketHandler::OLSRSwapHello(olsrmsg * m, BOOL in)
{
    hellomsg * h;
    hellinfo *hinfo;
    hellinfo *hinf;
    NodeAddress * haddr;
    NodeAddress * hadr;

    h = m->olsr_ipv4_hello;
    hinfo = h->hell_info;

    if(in)
    {
        //Swap the hello header bytes
        //This amounts to swapping
        // the Reserved field
        EXTERNAL_ntoh(
                &h->reserved,
                sizeof(h->reserved));


        for (hinf = hinfo; (char *)hinf < (char *)m + m->olsr_msg_size;
                                      hinf = (hellinfo *)((char *)hinf
                                                  + hinf->link_msg_size))
        {
            //Swap the link message size field
            EXTERNAL_ntoh(
                    &hinf->link_msg_size,
                    sizeof(hinf->link_msg_size));

            //Now swap all the address fields for the neighbor addresses
            haddr = (NodeAddress *)hinf->neigh_addr;

            for( hadr = haddr; (char *)hadr < (char *)hinf
                + hinf->link_msg_size; hadr++)
            {
                EXTERNAL_ntoh(
                    hadr,
                    sizeof(NodeAddress));
            }

        }

    }

    if(!in)
    {
        unsigned short link_msg_size;

        //Swap the hello header bytes
        //This amounts to swapping
        // the Reserved field
        EXTERNAL_ntoh(
                &h->reserved,
                sizeof(h->reserved));


        for (hinf = hinfo; (char *)hinf < (char *)m + m->olsr_msg_size;
                        hinf = (hellinfo *)((char *)hinf + link_msg_size))
        {

            //First save the link msg size
            link_msg_size=hinf->link_msg_size;


            //Swap the link message size field
            EXTERNAL_ntoh(
                    &hinf->link_msg_size,
                    sizeof(hinf->link_msg_size));

            //Now swap all the address fields for the neighbor addresses
            haddr = (NodeAddress *)hinf->neigh_addr;

            for( hadr = haddr; (char *)hadr < (char *)hinf
                + link_msg_size; hadr++)
            {
                EXTERNAL_ntoh(
                    hadr,
                    sizeof(NodeAddress));
            }

        }

    }

}

 /**
// API       :: OLSRSwapTC
// PURPOSE   :: Swap header bytes for the TC message
// PARAMETERS::
// + m : olsrmsg * : The start of the  TC message
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: void
// **/
void OLSRPacketHandler::OLSRSwapTC(olsrmsg * m, BOOL in)
{

    tcmsg *tc;
    NodeAddress *mprsaddr;
    NodeAddress *maddr;

    tc = m->olsr_ipv4_tc;
    mprsaddr=(NodeAddress *)tc->adv_neighbor_main_address;

    if(in)
    {
        //Swap  bytes of ANSN, Reserved and all addresses
        EXTERNAL_ntoh(
                &tc->ansn,
                sizeof(tc->ansn));

        EXTERNAL_ntoh(
                &tc->reserved,
                sizeof(tc->reserved));

        for(maddr=mprsaddr; (char *)maddr < (char *)m + m->olsr_msg_size;
                maddr++)
        {
            //Swap Address bytes
            EXTERNAL_ntoh(
                    maddr,
                    sizeof(NodeAddress));
        }
    }

    if(!in)
    {
        //Swap  bytes of ANSN, Reserved and all addresses
        EXTERNAL_ntoh(
                &tc->ansn,
                sizeof(tc->ansn));

        EXTERNAL_ntoh(
                &tc->reserved,
                sizeof(tc->reserved));

        for(maddr=mprsaddr; (char *)maddr < (char *)m + m->olsr_msg_size;
                maddr++)
        {
            //Swap Address bytes
            EXTERNAL_ntoh(
                    maddr,
                    sizeof(NodeAddress));
        }
    }

}

 /**
// API       :: OLSRSwapMid
// PURPOSE   :: Swap header bytes for the MID message
// PARAMETERS::
// + m : olsrmsg * : The start of the  MID message
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: void
// **/

void OLSRPacketHandler::OLSRSwapMid(olsrmsg *m, BOOL in)
{
    midmsg * mid;
    mid = m->olsr_ipv4_mid;
    NodeAddress* alias_addr;

    if(in)
    {

        for (alias_addr = (NodeAddress *)mid->olsr_iface_addr;
                   (char *)alias_addr < (char *)m + m->olsr_msg_size;
                                                        alias_addr++)
        {
            EXTERNAL_ntoh(
                    alias_addr,
                    sizeof(NodeAddress));
        }

    }

    if(!in)
    {

        for (alias_addr = (NodeAddress *)mid->olsr_iface_addr;
                (char *)alias_addr < (char *)m + m->olsr_msg_size;
                                                     alias_addr++)
        {
            EXTERNAL_ntoh(
                    alias_addr,
                    sizeof(NodeAddress));
        }

    }


}

 /**
// API       :: OLSRSwapHna
// PURPOSE   :: Swap header bytes for the HNA message
// PARAMETERS::
// + m : olsrmsg * : The start of the  HNA message
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: void
// **/

void OLSRPacketHandler::OLSRSwapHna(olsrmsg *m, BOOL in)
{
    hnamsg * hna;
    hna = m->olsr_ipv4_hna;
    NodeAddress* hna_addr;

    if(in)
    {
        for (hna_addr = (NodeAddress *)hna;
                   (char *)hna_addr < (char *)m + m->olsr_msg_size;
                                                        hna_addr++)
        {
            EXTERNAL_ntoh(
                    hna_addr,
                    sizeof(NodeAddress));
        }

    }
    
    if(!in)
    {

        for (hna_addr = (NodeAddress *)hna;
                   (char *)hna_addr < (char *)m + m->olsr_msg_size;
                                                        hna_addr++)
        {
            EXTERNAL_ntoh(
                    hna_addr,
                    sizeof(NodeAddress));
        }

    }
}


 /**
// API       :: OLSRSwapMsgHeader
// PURPOSE   :: Swap header bytes for the message header
// PARAMETERS::
// + m : olsrmsg * : The start of the  message header
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: void
// **/

void OLSRPacketHandler::OLSRSwapMsgHeader(olsrmsg *m, BOOL in)
{
    // three fields to swap:
    // 1. message size
    // 2. Originator Address
    // 3. Message sequence number

    //This is from Real world->QualNet, i.e. network to host
    if(in)
    {
        EXTERNAL_ntoh(
                &m->olsr_msg_size,
                sizeof(m->olsr_msg_size));

        EXTERNAL_ntoh(
                &m->originator_ipv4_address,
                sizeof(NodeAddress));

        EXTERNAL_ntoh(
                &m->olsr_msg_tail.olsr_ipv4_msg.msg_seq_no,
                sizeof(unsigned short));
    }


    //This is from QualNet->Real world, i.e. host to network
    if(!in)
    {

        EXTERNAL_ntoh(
                &m->olsr_msg_size,
                sizeof(m->olsr_msg_size));

        EXTERNAL_ntoh(
                &m->originator_ipv4_address,
                sizeof(NodeAddress));

        EXTERNAL_ntoh(
                &m->olsr_msg_tail.olsr_ipv4_msg.msg_seq_no,
                sizeof(unsigned short));

    }


}

 /**
// API       :: OLSRSwapPacketHeader
// PURPOSE   :: Swap header bytes for the packet header
// PARAMETERS::
// + olsr : olsrpacket * : The start of the  packet header
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: void
// **/
void OLSRPacketHandler::OLSRSwapPacketHeader(olsrpacket *olsr, BOOL in)
{
    if (in)
    {
        EXTERNAL_ntoh(
            &olsr->olsr_packlen,
            sizeof(olsr->olsr_packlen));

        EXTERNAL_ntoh(
            &olsr->olsr_pack_seq_no,
            sizeof(olsr->olsr_pack_seq_no));
    }

    if(!in)
    {

        EXTERNAL_ntoh(
            &olsr->olsr_packlen,
            sizeof(olsr->olsr_packlen));


        EXTERNAL_ntoh(
            &olsr->olsr_pack_seq_no,
            sizeof(olsr->olsr_pack_seq_no));
    }
}


