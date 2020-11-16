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
#include <errno.h>

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <winsock2.h>
#else
#include <netinet/ip.h>
#endif

//#include "mac_dot11.h"

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "external.h"
#include "external_util.h"
#include "external_socket.h"
#include "ipnetworkemulator.h"
#include "network_ip.h"
#include "app_forward.h"

#include "product_info.h"

#include "udp_interface.h"
#include "voip_interface.h"
#include "transport_rtp.h"
#include "arp_interface.h"
#include "ospf_interface.h"
#include "pim_interface.h"
#include "tcp_interface.h"
//Start OLSR interface
#include "olsr_interface.h"
//End OLSR interface
#include "packet_analyzer.h"
#include "pas_filter.h"

#include "ipne_qualnet_interface.h"
#include "ip6_icmp.h"

#ifdef ADDON_BOEINGFCS
#include "byte_ordering.h"
#endif

static libnet_t *libnetPAS[32];
static libnet_t *libnetPAS_DOT11;

#define CKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))
#define IP6_HDR_SIZE    40
#define IP6_FRAGHDR_SIZE    8
#define ETHER_HDR_SIZE    14

#undef PAS_DEBUG


struct DOT11_FrameHdr{
                                    //  Should Be  Actually
    UInt8             frameType;    //      -         -
    UInt8             frameFlags;   //      2         2
    UInt16            duration;     //      2         2
    Mac802Address     destAddr;     //      6         6
    Mac802Address     sourceAddr;   //      6         6
    Mac802Address     address3;     //      6         6
    UInt16            fragId: 4,    //      -         -
    seqNo: 12 ;   //      2         2
    char              FCS[4];       //      4         4
                                    //---------------------
                                    //     28        28
};

typedef struct {
                                    //  Should Be  Actually
    UInt8             frameType;    //      -         -
    UInt8             frameFlags;   //      2         2
    UInt16            duration;     //      2         2
    Mac802Address     destAddr;     //      6         6
    char              FCS[4];       //      4         4
} DOT11_ShortControlFrame;          // ---------------------
                                    //     14        14


#define    isprint(ch) ((ch) > 0x20 && (ch) < 0x7f)
#define    ISPRINT(ch) (isprint(ch)? ch:('.'))

static char temp[] = "0123456789abcdef";
#define    UNIB_HEX(a) temp[((a) & 0xf0) >> 4]
#define    LNIB_HEX(a) temp[(a) & 0x0f]
#define    SP        0x20
#define    QM        0x22

#define    PRT_BUF_SZ    81
void hexprint( unsigned char nm, register unsigned char *inp, int len )
{
    register int i;
    char    prt_buf[PRT_BUF_SZ];
    register char *ocharp;

    if (len > 0) printf("\n");
    while (len > 0) {
        ocharp = prt_buf;
        for (i = 0; i < 21; i++) {
            if (i < len) {
                *ocharp++ = UNIB_HEX(*(inp+i));
                *ocharp++ = LNIB_HEX(*(inp+i));
            }
            else {
                *ocharp++ = SP;
                *ocharp++ = SP;
            }
            *ocharp++ = SP;
        }
        *ocharp = 0;    /*  Terminate  */
        printf("%c %s", nm, prt_buf);
        len -= 21;
        inp += 21;
        if (len>0) printf("\n\r");
    }
}


void SwapUdpHeader(unsigned char* pHeader)
{
    TransportUdpHeader* header = (TransportUdpHeader*)pHeader;
    EXTERNAL_hton(
            &header->sourcePort,
            sizeof(header->sourcePort));
    EXTERNAL_hton(
            &header->destPort,
            sizeof(header->destPort));
    EXTERNAL_hton(
            &header->length,
            sizeof(header->length));
    EXTERNAL_hton(
            &header->checksum,
            sizeof(header->checksum));
}

void SwapRtpHeader(unsigned char* rtpHeader)
{
    RtpPacket* header = (RtpPacket*)rtpHeader;
    EXTERNAL_hton(
            &header->rtpPkt,
            sizeof(header->rtpPkt));
    EXTERNAL_hton(
            &header->seqNum,
            sizeof(header->seqNum));
    EXTERNAL_hton(
            &header->timeStamp,
            sizeof(header->timeStamp));
    EXTERNAL_hton(
            &header->ssrc,
            sizeof(header->ssrc));

    int cc = RtpPacketGetCc(header->rtpPkt);
    for (int i = 1; i <= cc; i++)
    {
        UInt32 csrc = header->ssrc + sizeof(UInt32) * i;
        EXTERNAL_hton(
            &csrc,
            sizeof(UInt32));
    }
}

void SwapRtcpHeader(unsigned char* rtcpHeader, UInt16 packetSize)
{
    RtcpPacket* header = (RtcpPacket*)rtcpHeader;
    UInt8 rtcpPktType = RtcpCommonHeaderGetPt(header->common.rtcpCh);
    Int32 reportCount = RtcpCommonHeaderGetCount(header->common.rtcpCh);
    UInt16 headerSize = 0;

    EXTERNAL_hton(
            &header->common.rtcpCh,
            sizeof(header->common.rtcpCh));
    EXTERNAL_hton(
            &header->common.length,
            sizeof(header->common.length));

    if (rtcpPktType == RTCP_SR)
    {
        headerSize = sizeof(RtcpCommonHeader)
                        + sizeof(RtcpSrPacket)
                        + reportCount * sizeof(RtcpRrPacket);
        EXTERNAL_hton(
                &header->rtcpPacket.sr.sr.ssrc,
                sizeof(header->rtcpPacket.sr.sr.ssrc));
        EXTERNAL_hton(
                &header->rtcpPacket.sr.sr.ntpSec,
                sizeof(header->rtcpPacket.sr.sr.ntpSec));
        EXTERNAL_hton(
                &header->rtcpPacket.sr.sr.ntpFrac,
                sizeof(header->rtcpPacket.sr.sr.ntpFrac));
        EXTERNAL_hton(
                &header->rtcpPacket.sr.sr.rtptimeStamp,
                sizeof(header->rtcpPacket.sr.sr.rtptimeStamp));
        EXTERNAL_hton(
                &header->rtcpPacket.sr.sr.senderPktCount,
                sizeof(header->rtcpPacket.sr.sr.senderPktCount));
        EXTERNAL_hton(
                &header->rtcpPacket.sr.sr.senderByteCount,
                sizeof(header->rtcpPacket.sr.sr.senderByteCount));

        for (int i = 0; i < reportCount; i++)
        {
            EXTERNAL_hton(
                    &header->rtcpPacket.sr.rr[i].ssrc,
                    sizeof(header->rtcpPacket.sr.rr[i].ssrc));
            EXTERNAL_hton(
                    &header->rtcpPacket.sr.rr[i].RrPktLost,
                    sizeof(header->rtcpPacket.sr.rr[i].RrPktLost));
            EXTERNAL_hton(
                    &header->rtcpPacket.sr.rr[i].lastSeqNum,
                    sizeof(header->rtcpPacket.sr.rr[i].lastSeqNum));
            EXTERNAL_hton(
                    &header->rtcpPacket.sr.rr[i].jitter,
                    sizeof(header->rtcpPacket.sr.rr[i].jitter));
            EXTERNAL_hton(
                    &header->rtcpPacket.sr.rr[i].lsr,
                    sizeof(header->rtcpPacket.sr.rr[i].lsr));
            EXTERNAL_hton(
                    &header->rtcpPacket.sr.rr[i].dlsr,
                    sizeof(header->rtcpPacket.sr.rr[i].dlsr));
        }
    }
    else if (rtcpPktType == RTCP_RR)
    {
        headerSize = sizeof(RtcpCommonHeader)
                        + sizeof(header->rtcpPacket.rr.ssrc)
                        + reportCount * sizeof(RtcpRrPacket);
        EXTERNAL_hton(
                &header->rtcpPacket.rr.ssrc,
                sizeof(header->rtcpPacket.rr.ssrc));
        
        for (int i = 0; i < reportCount; i++)
        {
            EXTERNAL_hton(
                    &header->rtcpPacket.rr.rr[i].ssrc,
                    sizeof(header->rtcpPacket.rr.rr[i].ssrc));
            EXTERNAL_hton(
                    &header->rtcpPacket.rr.rr[i].RrPktLost,
                    sizeof(header->rtcpPacket.rr.rr[i].RrPktLost));
            EXTERNAL_hton(
                    &header->rtcpPacket.rr.rr[i].lastSeqNum,
                    sizeof(header->rtcpPacket.rr.rr[i].lastSeqNum));
            EXTERNAL_hton(
                    &header->rtcpPacket.rr.rr[i].jitter,
                    sizeof(header->rtcpPacket.rr.rr[i].jitter));
            EXTERNAL_hton(
                    &header->rtcpPacket.rr.rr[i].lsr,
                    sizeof(header->rtcpPacket.rr.rr[i].lsr));
            EXTERNAL_hton(
                    &header->rtcpPacket.rr.rr[i].dlsr,
                    sizeof(header->rtcpPacket.rr.rr[i].dlsr));
        }
    }
    else if (rtcpPktType == RTCP_BYE)
    {
        for (int i = 0; i < reportCount; i++)
        {
            EXTERNAL_hton(
                    &header->rtcpPacket.bye.ssrc[i],
                    sizeof(header->rtcpPacket.bye.ssrc[i]));
        }
    }

    if ((rtcpPktType == RTCP_SR ||rtcpPktType == RTCP_RR)
            && (packetSize - headerSize) > 0)
    {
        unsigned char* rtcpsecondHeader = rtcpHeader + headerSize;
        RtcpPacket* secondHeader = (RtcpPacket*)rtcpsecondHeader;
        UInt8 pktType = RtcpCommonHeaderGetPt(secondHeader->common.rtcpCh);
        Int32 count = RtcpCommonHeaderGetCount(secondHeader->common.rtcpCh);

        EXTERNAL_hton(
            &secondHeader->common.rtcpCh,
            sizeof(secondHeader->common.rtcpCh));
        EXTERNAL_hton(
            &secondHeader->common.length,
            sizeof(secondHeader->common.length));

        if (pktType == RTCP_SDES)
        {
            EXTERNAL_hton(
                    &secondHeader->rtcpPacket.sdes.ssrc,
                    sizeof(secondHeader->rtcpPacket.sdes.ssrc));
            for (int i = 0; i < count; i++)
            {
                EXTERNAL_hton(
                        &secondHeader->rtcpPacket.sdes.item[i].type,
                        sizeof(secondHeader->rtcpPacket.sdes.item[i].type));
                EXTERNAL_hton(
                        &secondHeader->rtcpPacket.sdes.item[i].length,
                        sizeof(secondHeader->rtcpPacket.sdes.item[i].length));
                EXTERNAL_hton(
                        &secondHeader->rtcpPacket.sdes.item[i].data,
                        sizeof(secondHeader->rtcpPacket.sdes.item[i].data));
            }
        }
    }
}

void SwapTcpHeader(
    UInt8* tcpHeader)
{
    struct libnet_tcp_hdr* header = (struct libnet_tcp_hdr*) tcpHeader;

    EXTERNAL_hton(
        &header->th_sport,
        sizeof(header->th_sport));
    EXTERNAL_hton(
        &header->th_dport,
        sizeof(header->th_dport));
    EXTERNAL_hton(
        &header->th_seq,
        sizeof(header->th_seq));
    EXTERNAL_hton(
        &header->th_ack,
        sizeof(header->th_ack));
    EXTERNAL_hton(
        &header->th_sum,
        sizeof(header->th_sum));
    EXTERNAL_hton(
        &header->th_urp,
        sizeof(header->th_urp));

    unsigned int t;
    t=header->th_x2;
    header->th_x2 =  header->th_off;
    header->th_off = t;
}


/* interface initialization routine */

void PAS_CreateFrames(
    Node * node,
    Message *msg)
{

    libnet_ptag_t t;
    int err;
    char errString[MAX_STRING_LENGTH];

    EXTERNAL_Interface *pas = NULL;
    PASData *pasData = NULL;

    pas = EXTERNAL_GetInterfaceByName(
        &node->partitionData->interfaceList,
        "PAS");
    ERROR_Assert(pas != NULL, "PAS not loaded");

    pasData = (PASData*) pas->data;

    unsigned char frameToSendTemp[4096];
    unsigned char frameToSend[4096];

    void* macMsg = (void*) MESSAGE_ReturnPacket(msg);
    int frameSize = MESSAGE_ReturnPacketSize(msg);
    memcpy(frameToSendTemp, macMsg, frameSize);

#ifdef PRISM
    // PRISM monitoring header
    struct prism_hdr * prismHeader;
    prismHeader = (struct prism_hdr *)malloc(sizeof(struct prism_hdr));
    bzero(prismHeader, sizeof(struct prism_hdr));
    prismHeader->msgcode = 0;
    prismHeader->msglen = 0;
    sprintf(prismHeader->devname, "exata");
#endif

    DOT11_ShortControlFrame *hdr=
        (DOT11_ShortControlFrame*)frameToSendTemp;

    // for frame type swap
    // frame type field is hard-coded as host byte order
    // so this should be swapped
    UInt8 temp = hdr->frameType;
    UInt8 half= temp & 0x30;
    half >>=2;
    temp <<=4;
    temp = temp|half;
    hdr->frameType = temp;

    // for data type, LLC
    // in real world implementation, LLC is following 802.11 header
    // So, LLC(8 bytes) is stuffed for DATA frame
    if (hdr->frameType == 0x08)
    {
        char llc[8];
        llc[0]= 0xAA;
        llc[1]= 0xAA;
        llc[2]= 0x03;
        llc[3]= 0x00;
        llc[4]= 0x00;
        llc[5]= 0x00;
        llc[6]= 0x08;
        llc[7]= 0x00;


#ifdef PRISM //{
                //frameToSend = (char *)malloc(frameSize+4);
                frameToSend = (char *)malloc((frameSize+4)+ sizeof(struct prism_hdr));
                memcpy(frameToSend, prismHeader, sizeof(struct prism_hdr)); //prism monitoring header copy
                memcpy(frameToSend+sizeof(struct prism_hdr), macFrame, 24); //header copy
                memcpy(frameToSend+24+sizeof(struct prism_hdr), &llc, 8); //LLC copy
                //for DATA, headers (IP, UDP, TCP, ICMP, etc)
                //should be network byte order
                HeaderSwap(macFrame+28);
                memcpy(frameToSend+32+sizeof(struct prism_hdr), macFrame+28, frameSize-28); //body copy

            } else
            {
                frameToSend = (char *)malloc(frameSize+sizeof(struct prism_hdr));
                memcpy(frameToSend, prismHeader, sizeof(struct prism_hdr));
                memcpy(frameToSend+sizeof(struct prism_hdr), macFrame, frameSize);

                //write( sockfd, frameToSend, frameSize+sizeof(struct prism_hdr) );
                if (!PAS_SendRawPacket(pasRawSock, frameToSend, frameSize+sizeof(struct prism_hdr)))
                {
                    printf("Unable to transmit\n");
                }
            }

            free(frameToSend);
            free(prismHeader);
#else
        //frameToSend = (unsigned char *)malloc((frameSize+4));
           memcpy(frameToSend, frameToSendTemp, 24); //header copy
        memcpy(frameToSend+24, &llc, 8); //LLC copy

        // filtering
        if (!(pasData->pasFilterBit & PACKET_SNIFFER_ENABLE_MAC))
            return;

       if (!PAS_FilterCheck((IpHeaderType *)(frameToSendTemp+28), pasData->pasFilterBit))
            return;


        //for DATA, headers (IP, UDP, TCP, ICMP, etc)
        //should be network byte order
        HeaderSwap(frameToSendTemp+28);

        memcpy(frameToSend+32, frameToSendTemp+28, frameSize-28); //body copy

        t = libnet_build_802_11(frameToSend, frameSize+4, libnetPAS_DOT11, 0);
        if (t == -1)
        {
            sprintf(
                errString,
                "libnet error: %s",
                libnet_geterror(libnetPAS_DOT11));
                ERROR_ReportWarning(errString);
        }
        // Send the packet to the physical network
        err = libnet_write(libnetPAS_DOT11);
        if (err == -1)
        {
            sprintf(
                errString,
                "libnet error: %s",
                libnet_geterror(libnetPAS_DOT11));
            ERROR_ReportWarning(errString);
        }
        libnet_clear_packet(libnetPAS_DOT11);
        pasData->pasCnt++;
    }
    else
       {
        if (!(pasData->pasFilterBit & PACKET_SNIFFER_ENABLE_MAC))
          {
            return;
          }

           t = libnet_build_802_11(frameToSendTemp, frameSize-4, libnetPAS_DOT11, 0);
        if (t == -1)
        {
            sprintf(
                errString,
                "libnet error: %s",
                libnet_geterror(libnetPAS_DOT11));
                ERROR_ReportWarning(errString);
        }
        // Send the packet to the physical network
        err = libnet_write(libnetPAS_DOT11);
        if (err == -1)
        {
            sprintf(
                errString,
                "libnet error: %s",
                libnet_geterror(libnetPAS_DOT11));
            ERROR_ReportWarning(errString);
        }
        libnet_clear_packet(libnetPAS_DOT11);

        pasData->pasCnt++;

    }
#endif
}

void PAS_ProcessIpPacketOspf(
    UInt8* packet)
{
    OspfSwapBytes(
        packet,
        FALSE);
}


void PAS_ProcessIpPacketPim(
    UInt8* packet,
    int dataLength)
{
    PIMPacketHandler::ReformatOutgoingPacket(packet, dataLength);
}


void PAS_ProcessIpPacketUdp(
    UInt8* udpHeader,

    IpHeaderType *ipHeader,
    BOOL isChecksumCalculation

    //struct libnet_ipv4_hdr* ip,
    )
{
    unsigned short destPortNumber;
    UInt16 packetSize = 0;
    TransportUdpHeader *udp;
    udp= (TransportUdpHeader *)udpHeader;
    destPortNumber=udp->destPort;
    packetSize = udp->length - sizeof(TransportUdpHeader);
    int ipHeaderLength = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;

    // Swap UDP bytes
    //UDPSwapBytes(udpHeader, FALSE);
    SwapUdpHeader((unsigned char *)udp);

    if (destPortNumber == APP_ROUTING_OLSR_INRIA)
    {
        unsigned char *olsr= (unsigned char *) (
                    (unsigned char *) udp
                    + sizeof(TransportUdpHeader));
       OLSRSwapBytes(olsr,FALSE);
    }

    // Swap RTP header bytes
    if (destPortNumber == APP_RTP)
    {
        unsigned char* rtp = (unsigned char*) udp + sizeof(TransportUdpHeader);
        SwapRtpHeader(rtp);
    }

    // Swap RTCP header bytes
    if (destPortNumber == APP_RTCP)
    {
        unsigned char* rtcp= (unsigned char*) udp + sizeof(TransportUdpHeader);
        SwapRtcpHeader(rtcp, packetSize);
    }
    if (isChecksumCalculation)
    {

        udp->checksum = PAS_ComputeTcpStyleChecksum(
            //htonl(ipHeader->ip_src),
            ipHeader->ip_src,
            //htonl(ipHeader->ip_dst),
            ipHeader->ip_dst,
            ipHeader->ip_p,
            htons((UInt16)IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) - ipHeaderLength), udpHeader);
    }
}

// header swapping -> IP and following headers
void HeaderSwap(unsigned char * frameToSend)
{
    IpHeaderType *ip;
       ip = (IpHeaderType*)frameToSend;

    ip->ip_src = htonl(ip->ip_src);
    ip->ip_dst = htonl(ip->ip_dst);

    int ipHeaderLength = IpHeaderGetHLen(ip->ip_v_hl_tos_len) * 4;

    // UDP swap
    if ((ip->ip_p == IPPROTO_UDP) &&
        (IpHeaderGetIpFragOffset(ip->ipFragment)==0))
    {
        TransportUdpHeader *udpHeader =
            (TransportUdpHeader *)((char *)frameToSend+ipHeaderLength);

           PAS_ProcessIpPacketUdp(
            (UInt8*)udpHeader,
            ip,
            TRUE);  //calculate the checksum

        //SwapUdpHeader(udpHeader);
    }
    else if (ip->ip_p == IPPROTO_TCP)  // TCP swap
    {
        UInt8 *tcpHeader =
            (UInt8 *)((char *)frameToSend+ipHeaderLength);

        SwapTcpHeader(tcpHeader);

    }

#ifdef ADDON_BOEINGFCS
    else if (ip->ip_p == IPPROTO_ROUTING_CES_MALSR) {
        UInt8* nextHeader =
            (UInt8 *)((char *)frameToSend+ipHeaderLength);
        PAS_SwapBytesMALSR(
            nextHeader);
    }
#endif
    else if (ip->ip_p == IPPROTO_OSPF) {
        UInt8* nextHeader =
            (UInt8 *)((char *)frameToSend+ipHeaderLength);
        PAS_ProcessIpPacketOspf(
            nextHeader);
    }
    else if (ip->ip_p == IPPROTO_IGMP) {
        UInt8* nextHeader =
            (UInt8 *)((char *)frameToSend+ipHeaderLength);
        struct libnet_igmp_hdr* igmp;
        igmp = (struct libnet_igmp_hdr*) nextHeader;
        igmp->igmp_group.s_addr =
                    ntohl(igmp->igmp_group.s_addr);
    }

    else if (ip->ip_p == IPPROTO_PIM) {
        UInt8* nextHeader =
            (UInt8 *)((char *)frameToSend+ipHeaderLength);
        PAS_ProcessIpPacketPim(
            nextHeader,
            IpHeaderGetIpLength(ip->ip_v_hl_tos_len)-ipHeaderLength);
    }
    else if (ip->ip_p == IPPROTO_ICMP && (IpHeaderGetIpFragOffset(ip->ipFragment)==0))
    {
    struct libnet_icmpv4_hdr* icmp;
        // ICMP: Get checksum, where the data packet begins.  Call
        // PreProcesIpPacketIcmp.
        icmp = (struct libnet_icmpv4_hdr*) ((char *)frameToSend+ipHeaderLength);

        // First zero out checksum
        icmp->icmp_sum = 0;

        // Compute for ICMP style
        icmp->icmp_sum = PAS_ICMPv4Checksum(
            (UInt8*)icmp,
            htons((UInt16)(IpHeaderGetIpLength(ip->ip_v_hl_tos_len)- ipHeaderLength)));
    }
    ip->ip_v_hl_tos_len = htonl(ip->ip_v_hl_tos_len);
    //fix for ip_id
    ip->ip_id = htons(ip->ip_id);
    ip->ipFragment=htons(ip->ipFragment);
// IP header checksum calculation
    CalculateChecksum(IPPROTO_IP, (UInt8 *)ip, ipHeaderLength);
}

void PIM_HeaderSwap(unsigned char * frameToSend, BOOL incoming,BOOL isNullReg)
{
    IpHeaderType *ip;
       ip = (IpHeaderType*)frameToSend;

    int ipHeaderLength = 0;

    struct libnet_ipv4_hdr* ipHeader;
    ipHeader = (struct libnet_ipv4_hdr*) frameToSend;

    if (!incoming)
    {
        ipHeaderLength = IpHeaderGetHLen(ip->ip_v_hl_tos_len) * 4;
    }

        EXTERNAL_hton(
            &ip->ip_v_hl_tos_len,
            sizeof(ip->ip_v_hl_tos_len));
        EXTERNAL_hton(
            &ip->ip_id,
            sizeof(ip->ip_id));
        EXTERNAL_hton(
            &ip->ipFragment,
            sizeof(ip->ipFragment));
        EXTERNAL_hton(
            &ip->ip_sum,
            sizeof(ip->ip_sum));

        ip->ip_src = htonl(ip->ip_src);
        ip->ip_dst = htonl(ip->ip_dst);
    if (incoming)
    {
        ipHeaderLength = IpHeaderGetHLen(ip->ip_v_hl_tos_len) * 4;
    }

/*
    printf("%hu : %hu : %hu : %hu \n",
        IpHeaderGetVersion(ip->ip_v_hl_tos_len),
        IpHeaderGetHLen(ip->ip_v_hl_tos_len),
        IpHeaderGetIpLength(ip->ip_v_hl_tos_len),
        IpHeaderGetTOS(ip->ip_v_hl_tos_len));
*/


    // UDP swap
    if ((ip->ip_p == IPPROTO_UDP) &&
        //(IpHeaderGetIpMoreFrag(ip->ipFragment)==0) &&
        (IpHeaderGetIpFragOffset(ip->ipFragment)==0))
    {
        TransportUdpHeader *udpHeader =
            (TransportUdpHeader *)((char *)frameToSend+ipHeaderLength);

           PAS_ProcessIpPacketUdp(
            (UInt8*)udpHeader,
            ip,
            FALSE);  //no checksum calculation

        //SwapUdpHeader((unsigned char*) udpHeader);
    }
    else if (ip->ip_p == IPPROTO_TCP)  // TCP swap
    {
        UInt8 *tcpHeader =
            (UInt8 *)((char *)frameToSend+ipHeaderLength);

        SwapTcpHeader(tcpHeader);
    }
#ifdef ADDON_BOEINGFCS
    else if (ip->ip_p == IPPROTO_ROUTING_CES_MALSR) {
        UInt8* nextHeader =
            (UInt8 *)((char *)frameToSend+ipHeaderLength);
        PAS_SwapBytesMALSR(
            nextHeader);
    }
#endif
    else if (ip->ip_p == IPPROTO_OSPF) {

        UInt8* nextHeader =
            (UInt8 *)((char *)frameToSend+ipHeaderLength);
        PAS_ProcessIpPacketOspf( nextHeader);

    }
    else if (ip->ip_p == IPPROTO_PIM && !isNullReg) {
        UInt8* nextHeader =
            (UInt8 *)((char *)frameToSend+ipHeaderLength);
        PAS_ProcessIpPacketPim(
            nextHeader,
            IpHeaderGetIpLength(ip->ip_v_hl_tos_len)-ipHeaderLength);
    }
    else if (ip->ip_p == IPPROTO_ICMP && (IpHeaderGetIpFragOffset(ip->ipFragment)==0))
    {
    struct libnet_icmpv4_hdr* icmp;
        // ICMP: Get checksum, where the data packet begins.  Call
        // PreProcesIpPacketIcmp.
        icmp = (struct libnet_icmpv4_hdr*) ((char *)frameToSend+ipHeaderLength);

        // First zero out checksum
        icmp->icmp_sum = 0;

        // Compute for ICMP style
        icmp->icmp_sum = PAS_ICMPv4Checksum(
            (UInt8*)icmp,
            htons((UInt16)(IpHeaderGetIpLength(ip->ip_v_hl_tos_len)- ipHeaderLength)));
    }

//
// IP header checksum calculation
    CalculateChecksum(IPPROTO_IP, (UInt8 *)ip, ipHeaderLength);
}

// /**
// API       :: ComputeIcmpStyleChecksum
// PURPOSE   :: Computes a checksum for the packet usable for ICMP
// PARAMETERS::
// + packet : UInt8* : Pointer to the beginning of the packet
// + length : UInt16 : Length of the packet in bytes
// RETURN    :: void
// **/
UInt16 PAS_ICMPv4Checksum(
    UInt8* packet,
    UInt16 length)
{
    bool odd;
    UInt16* paddedPacket;
    int sum;
    int i;
    int packetLength;

    packetLength = ntohs(length);
    odd = packetLength & 0x1;

    // If the packet is an odd length, pad it with a zero
    if (odd)
    {
        packetLength++;
        paddedPacket = (UInt16*) MEM_malloc(packetLength);
        paddedPacket[packetLength/2 - 1] = 0;
        memcpy(paddedPacket, packet, packetLength - 1);
    }
    else
    {
        paddedPacket = (UInt16*) packet;
    }
    // Compute the checksum
    // Assumes parameters are in network byte order

    sum = 0;
    for (i = 0; i < packetLength / 2; i++)
    {
        sum += paddedPacket[i];
    }

    while ((0xffff & (sum >> 16)) > 0)
    {
        sum = (sum & 0xFFFF) + ((sum >> 16) & 0xffff);
    }

    if (odd)
    {
        MEM_free(paddedPacket);
    }

    // Return the checksum
    return ~((UInt16) sum);
}


// /**
// API       :: ComputeIcmpv6ChecksumForDiagnosis
// PURPOSE   :: Computes a checksum for the packet usable for ICMPv6
// PARAMETERS::
// + src : in6_addr * : Source IPv6 address
// + dst : in6_addr * : Destination IPv6 address
// + icmp : struct libnet_icmpv6_hdr * : Pointer to the icmpv6 header
// + icmpLen : Int32 : Length of the icmp packet to calculate
// RETURN    :: void
// **/
void ComputeIcmpv6ChecksumForDiagnosis(
    in6_addr* src,
    in6_addr* dst,
    struct libnet_icmpv6_hdr* icmp,
    Int32 icmpLen)
{
    UInt16* shortHeader = NULL;
    UInt32 length = ntohl(icmpLen);
    Int32 i = 0;
    Int32 totalLen = LIBNET_IPV6_H+icmpLen;

    Int8* header = new Int8[totalLen];

    // create psuedo-header
    shortHeader = (UInt16 *) header;

    memcpy(&header[0], src, 16);
    memcpy(&header[16], dst, 16);
    memcpy(&header[32], &length, 4);
    memset(&header[36], 0, 3);
    header[39] = 0x3a;

    // copy icmp header
    memcpy(&header[40], icmp, icmpLen);

    int sum = 0;

    for (i = 0; i < totalLen / 2; i++)
    {
        sum += shortHeader[i];
    }

    while ((0xffff & (sum >> 16)) > 0)
    {
        sum = (sum & 0xFFFF) + ((sum >> 16) & 0xffff);
    }

    // Return the checksum
    icmp->icmp_sum = ~((u_short) sum);

    delete [] header;
}

// /**
// API       :: PAS_SwapICMPv6Header
// PURPOSE   :: Swaps ICMPv6 header
// PARAMETERS::
// + ip6 : libnet_ipv6_hdr * : Pointer to Ipv6 header
// + nextHeader : UInt8 * : Pointer to ICMPv6 header
// RETURN    :: void
// **/
static void PAS_SwapICMPv6Header(
    struct libnet_ipv6_hdr* ip6,
    UInt8* nextHeader)
{
        icmp6_hdr* icp = (icmp6_hdr *)nextHeader;
        switch (icp->icmp6_type)
        {
            case ND_ROUTER_ADVERT:
            {
                icp->icmp6_dataun.icmp6_un_data16[1]
                    = htons(icp->icmp6_dataun.icmp6_un_data16[1]);
                nd_router_advert* rap = (nd_router_advert *)(nextHeader);
                rap->nd_ra_reachable = htonl(rap->nd_ra_reachable);
                rap->nd_ra_retransmit = htonl(rap->nd_ra_retransmit);
                nd_opt_mtu* ndopt_mtu = (nd_opt_mtu *) (nextHeader
                    + sizeof(nd_router_advert) + sizeof(nd_opt_hdr)
                    + ETHER_ADDR_LEN);
                ndopt_mtu->nd_opt_mtu_reserved
                    = htons(ndopt_mtu->nd_opt_mtu_reserved);
                ndopt_mtu->nd_opt_mtu_mtu
                    = htonl(ndopt_mtu->nd_opt_mtu_mtu);
                nd_opt_prefix_info* ndopt_pi
                    = (nd_opt_prefix_info *) (ndopt_mtu + 1);
                ndopt_pi->nd_opt_pi_valid_time
                    = htonl(ndopt_pi->nd_opt_pi_valid_time);
                ndopt_pi->nd_opt_pi_preferred_time
                    = htonl(ndopt_pi->nd_opt_pi_preferred_time);
                ndopt_pi->nd_opt_pi_reserved_site_plen
                    = htonl(ndopt_pi->nd_opt_pi_reserved_site_plen);
                break;
            }
            case ICMP6_PACKET_TOO_BIG:
            case ICMP6_TIME_EXCEEDED:
            case ND_NEIGHBOR_ADVERT:
            case ICMP6_PARAM_PROB:
            {
                icp->icmp6_dataun.icmp6_un_data32[0]
                    = htonl(icp->icmp6_dataun.icmp6_un_data32[0]);
                break;
            }
            case ICMP6_ECHO_REQUEST:
            case ICMP6_ECHO_REPLY:
            {
                icp->icmp6_id = htons(icp->icmp6_id);
                icp->icmp6_seq = htons(icp->icmp6_seq);
                icp->icmp6_cksum = 0;
                break;
            }
        }

        ComputeIcmpv6ChecksumForDiagnosis((in6_addr *)&ip6->ip_src,
                    (in6_addr *)&ip6->ip_dst,
                    (struct libnet_icmpv6_hdr *)nextHeader,
                    (int)ip6->ip_len);
}

// /**
// API       :: ProcessIpv6PacketForPAS
// PURPOSE   :: Swaps Ipv6 packet
// PARAMETERS::
// + packet : UInt8 * : Pointer to Ipv6 packet
// RETURN    :: void
// **/
static void ProcessIpv6PacketForPAS(
    UInt8* packet)
{
    struct libnet_ipv6_hdr* ip6 = (struct libnet_ipv6_hdr *)packet;
    UInt8* nextHeader = packet + LIBNET_IPV6_H;

    if (ip6->ip_nh == LIBNET_IPV6_NH_FRAGMENT)
    {
        // fragmentation header
        struct libnet_ipv6_frag_hdr* fragHeader
            = (struct libnet_ipv6_frag_hdr*)(packet + LIBNET_IPV6_H);
        UInt16 offSet = fragHeader->ip_frag & 0xfff8;
        EXTERNAL_hton(&fragHeader->ip_frag, sizeof(fragHeader->ip_frag));
        EXTERNAL_hton(&fragHeader->ip_id, sizeof(fragHeader->ip_id));
        if (offSet == 0)
        {
            UInt8 proto = fragHeader->ip_nh;
            UInt8* nextHdr = (UInt8*)fragHeader + sizeof(libnet_ipv6_frag_hdr);
            if (proto == IPPROTO_TCP)
            {
                struct libnet_tcp_hdr* tcp
                    = (struct libnet_tcp_hdr*)(nextHdr);

                ProcessTcpForDiagnosis(
                    ip6,
                    nextHdr,
                    &tcp->th_sum);
            }
            else if (proto == IPPROTO_UDP)
            {
                struct libnet_udp_hdr* udp
                    = (struct libnet_udp_hdr*)(nextHdr);

                ProcessUdpForDiagnosis(
                    nextHdr,
                    ip6);
            }
        }
    }
    else if (ip6->ip_nh == IPPROTO_ICMP6)
    {
        // ICMPV6 packet
        PAS_SwapICMPv6Header(ip6, nextHeader);
    }
    else if (ip6->ip_nh == IPPROTO_TCP)
    {
        struct libnet_tcp_hdr* tcp =
                (struct libnet_tcp_hdr*)(packet + LIBNET_IPV6_H);

        ProcessTcpForDiagnosis(
            ip6,
            nextHeader,
            &tcp->th_sum);
    }
    else if (ip6->ip_nh == IPPROTO_UDP)
    {
        struct libnet_udp_hdr* udp =
                (struct libnet_udp_hdr*)(packet + LIBNET_IPV6_H);

        ProcessUdpForDiagnosis(
            nextHeader,
            ip6);
    }
    else
    {
        // other Ipv6 extention/protocol headers are currently not supported
        // ip6->ip_nh = 59;
    }
    EXTERNAL_hton(&ip6->ip_len, sizeof(ip6->ip_len));
}

// /**
// API       :: PAS_IPv6
// PURPOSE   :: Create IPv6 packet and write to exata interface
// PARAMETERS::
// + node     : Node * : Node pointer
// + ip     : UInt8 * : Pointer to IPv6 packet
// + lastHopAddr : MacHWAddress * :Last hop MAC address
// + interfaceIndex : Int32 : Incoming/outgoing interface index
// RETURN    :: void
// **/
void PAS_IPv6(
    Node* node,
    UInt8* ip,
    MacHWAddress* lastHopAddr,
    Int32 interfaceIndex)
{
    UInt8 dstMacAddress[6];
    UInt8 srcMacAddress[6];
    UInt8* tempHeader = NULL;
    Int32 ipLength = 0;

    for (Int8 i = 0; i < 6; i++)
    {
        dstMacAddress[i] = 0;
        srcMacAddress[i] = 0;
    }

    EXTERNAL_Interface* pas = NULL;
    PASData* pasData = NULL;

    pas = EXTERNAL_GetInterfaceByName(
            &node->partitionData->interfaceList,
            "PAS");
    ERROR_Assert(pas != NULL, "PAS not loaded");

    pasData = (PASData*) pas->data;

    struct libnet_ipv6_hdr* ip6 = (struct libnet_ipv6_hdr*)ip;
     if (!PAS_FilterCheckIpv6(ip6, pasData->pasFilterBit)
         && !pasData->deviceNotFound)
     {
        return;
     }

    // for displaying MAC addresses, currently default MAC addresses are used
    if (lastHopAddr)
    {
        // IPv6 packet received
        memcpy(&srcMacAddress, lastHopAddr->byte, lastHopAddr->hwLength);
        dstMacAddress[0] = ((UInt8)(node->nodeId));
        dstMacAddress[1] = ((UInt8)(node->nodeId >> 8));
        dstMacAddress[2] = ((UInt8)(node->nodeId >> 16));
        dstMacAddress[3] = ((UInt8)(node->nodeId >> 24));
        dstMacAddress[5] = ((UInt8)(interfaceIndex));
    }
    else
    {
        // IPv6 packet is about to be sent
        // destination MAC address will be dispayed as 00.00.00.00.00.00
        srcMacAddress[0] = ((UInt8)(node->nodeId));
        srcMacAddress[1] = ((UInt8)(node->nodeId >> 8));
        srcMacAddress[2] = ((UInt8)(node->nodeId >> 16));
        srcMacAddress[3] = ((UInt8)(node->nodeId >> 24));
        srcMacAddress[5] = ((UInt8)(interfaceIndex));
    }

    tempHeader = (UInt8 *)MEM_malloc(ip6->ip_len + LIBNET_IPV6_H);
    memset(tempHeader, 0, ip6->ip_len + LIBNET_IPV6_H);
    memcpy(tempHeader, ip, ip6->ip_len + LIBNET_IPV6_H);

    libnet_ipv6_hdr* ipHeaderCopy = (libnet_ipv6_hdr *)tempHeader;
    ipHeaderCopy->ip_len = ip6->ip_len;

    ipLength = ipHeaderCopy->ip_len;
    ProcessIpv6PacketForPAS((UInt8*)ipHeaderCopy);

    PAS_InjectLinkPacket(
        (UInt8*) dstMacAddress,
        (UInt8*) srcMacAddress,
        ETYPE_IPV6,
        (UInt8*) ipHeaderCopy,
        ipLength + LIBNET_IPV6_H,
        libnetPAS[node->partitionId]);

    pasData->pasCnt++;
    MEM_free(tempHeader);
    tempHeader = NULL;
}

// /**
// API       :: PAS_InjectLinkPacket
// PURPOSE   :: Injects packet at link layer
// PARAMETERS::
// + dest     : UInt8 * : Destination MAC address
// + source     : UInt8 * : Source MAC address
// + type : UInt16 : Packet type (v4/v6)
// + packet : UInt8 * : Pointer to the  packet
// + packetSize : Int32 : Size of packet
// + libnetPAS : libnet_context * : libnet context
// RETURN    :: void
// **/
void PAS_InjectLinkPacket(
    UInt8* dest,
    UInt8* source,
    UInt16 type,
    UInt8* packet,
    Int32 packetSize,
    struct libnet_context* libnetPAS)
{
    libnet_ptag_t t;
    Int32 err = 0;

    // Write packet to the device at this deviceIndex
    t = libnet_build_ethernet(
            dest,
            source,
            type,
            packet,
            packetSize,
            libnetPAS,
            0);
    if (t == -1)
    {
#if 0
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(libnetPAS));
        ERROR_ReportWarning(errString);
#endif
        return;
    }
    // Send the packet to the physical network
    err = libnet_write(libnetPAS);
    if (err == -1)
    {
#if 0
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(libnetPAS));
        ERROR_ReportWarning(errString);
#endif
    }

    libnet_clear_packet(libnetPAS);
}

// /**
// API       :: PAS_IPv4
// PURPOSE   :: create IPv4 packet and write to exata interface
// PARAMETERS::
// + node     : node pointer
// + ip     : pointer to IP packet
// + previousHopAddress:  used for MAC address
// RETURN    :: void
// **/
void PAS_IPv4(Node* node, IpHeaderType * ipHeader, NodeAddress previousHopAddress, int packetSize)
{
    UInt8 dstMacAddress[6];
    UInt8 srcMacAddress[6];
    UInt8* tempHeader;
    int ipLength;

    EXTERNAL_Interface *pas = NULL;
    PASData *pasData = NULL;

    pas = EXTERNAL_GetInterfaceByName(
        &node->partitionData->interfaceList,
        "PAS");
    ERROR_Assert(pas != NULL, "PAS not loaded");

    pasData = (PASData*) pas->data;


    dstMacAddress[0] =0x00;
    dstMacAddress[1] =0x00;
    srcMacAddress[0] =0x00;
    srcMacAddress[1] =0x00;

    if (!PAS_FilterCheck(ipHeader, pasData->pasFilterBit) && !pasData->deviceNotFound)
        return;

    // if fragmented
    // This is because of the bug in the fragmentation algorithm in QualNet
    // Packet size of fragmented packet should be it's size, but
    // it keeps the original size in QualNet implementation.
    if (packetSize)
    {
        tempHeader = (UInt8 *)MEM_malloc(packetSize);
        memset(tempHeader, 0, packetSize);
        memcpy(tempHeader, ipHeader, packetSize);
    }
    else
    {
        tempHeader = (UInt8 *)MEM_malloc(IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len));
        memset(tempHeader, 0, IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len));
        memcpy(tempHeader, ipHeader, IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len));
    }

    IpHeaderType *ipHeaderCopy = (IpHeaderType *)tempHeader;
    if (packetSize)
       IpHeaderSetIpLength(&(ipHeaderCopy->ip_v_hl_tos_len), packetSize);

    if (previousHopAddress == 0) //outgoing packet
    {
        memcpy(&srcMacAddress[2], &(node->nodeId), 4);
        memcpy(&dstMacAddress[2], &previousHopAddress, 4);

    }
    else //incoming packet
    {
        memcpy(&dstMacAddress[2], &(node->nodeId), 4);
        memcpy(&srcMacAddress[2], &previousHopAddress, 4);
    }

    ipLength = IpHeaderGetIpLength(ipHeaderCopy->ip_v_hl_tos_len);
    HeaderSwap((unsigned char *)ipHeaderCopy);

    PAS_InjectLinkPacket(
        (UInt8*) dstMacAddress,
        (UInt8*) srcMacAddress,
        ETHERTYPE_IP,
        (UInt8*) ipHeaderCopy,
        ipLength,
        libnetPAS[node->partitionId]);

    pasData->pasCnt++;
    MEM_free(tempHeader);
}


// UDP packet byte-swapping and checksum calculation
//
void ProcessUdpForDiagnosis(
    UInt8* udpHeader,
    struct libnet_ipv6_hdr* ip6)
{
    unsigned short destPortNumber;
    TransportUdpHeader *udp;
    udp= (TransportUdpHeader *)udpHeader;
    destPortNumber=udp->destPort;

    // Swap UDP bytes
    SwapUdpHeader((unsigned char *)udpHeader);

     udp->checksum = 0;
     udp->checksum = AutoIPNEComputeTcpStyleChecksum(
                    (UInt8*)&ip6->ip_src,
                    (UInt8*)&ip6->ip_dst,
                    ip6->ip_nh,
                    (UInt32)ntohs(ip6->ip_len),
                    (UInt8 *)udp);
}

void ProcessTcpForDiagnosis(
    struct libnet_ipv6_hdr* ip6,
    UInt8* tcpHeader,
    UInt16* checksum)
{
    int ipHeaderLength;
    UInt16 sum2;

    SwapTcpHeader(tcpHeader);
    sum2 = *checksum;
    *checksum = 0;

    *checksum = AutoIPNEComputeTcpStyleChecksum(
                (UInt8*)&ip6->ip_src,
                (UInt8*)&ip6->ip_dst,
                ip6->ip_nh,
                (UInt32)ntohs(ip6->ip_len),
                (UInt8 *)tcpHeader);
}


UInt16 PAS_ComputeTcpStyleChecksum(
    UInt32 srcAddress,
    UInt32 dstAddress,
    UInt8 protocol,
    UInt16 tcpLength,
    UInt8 *packet)
{
    UInt8 virtualHeader[12];
    UInt16* virtualHeaders = (UInt16*) virtualHeader;
    int sum;
    int i;

    // Compute the checksum
    // Assumes parameters are in network byte order
    memcpy(&virtualHeader[0], &srcAddress, sizeof(UInt32));
    memcpy(&virtualHeader[4], &dstAddress, sizeof(UInt32));
    virtualHeader[8] = 0;
    virtualHeader[9] = protocol;
    memcpy(&virtualHeader[10], &tcpLength, sizeof(UInt16));

    // The first part of the checksum is an ICMP style checksum over the
    // packet
    sum = (UInt16) ~ComputeIcmpStyleChecksum(packet, tcpLength);

    // The second part of the checksum is the virtual header
    for (i = 0; i < 12 / 2; i++)
    {
        sum += virtualHeaders[i];
    }

    while ((0xffff & (sum >> 16)) > 0)
    {
        sum = (sum & 0xFFFF) + ((sum >> 16) & 0xffff);
    }

    // Return the checksum
    return ~((UInt16) sum);
}

/**
 * FUNCTION        :: PAS_IsDeviceInstalled
 * PURPOSE        :: ckeck if exata interface is available
 * PARAMETERS     ::
**/
BOOL PAS_IsDeviceInstalled(
    char macType, 
    char * deviceName)
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get a list of all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        ERROR_ReportWarning("PAS Interface could not initialize correctly. Reinstall pcap or WinPcap and try again");
        return FALSE;
    }
    if (alldevs == NULL)
    {
        ERROR_ReportWarning("PAS Interface failed to locate the EXata virtual device driver.");
        return FALSE;
    }

    for (d = alldevs; d != NULL; d = d->next)
    {
#ifdef _WIN32
        if (!strncmp(d->description, "SNT", 3))
#else
            if (((macType & PACKET_SNIFFER_ETHERNET) && (!strcmp(d->name, "exata" ))) ||
                    ((macType & PACKET_SNIFFER_DOT11) && (!strcmp(d->name, "exata_dot11"))))
#endif

            {
                pcap_t *pcd;
                char errbuf[PCAP_ERRBUF_SIZE];
#ifdef _WIN32
                pcd = pcap_open_live(d->name, BUFSIZ,  0, -1, errbuf);
#else
                if (macType & PACKET_SNIFFER_ETHERNET)
                    pcd = pcap_open_live("exata", BUFSIZ,  0, -1, errbuf);
                else if (macType & PACKET_SNIFFER_DOT11)
                    pcd = pcap_open_live("exata_dot11", BUFSIZ,  0, -1, errbuf);
#endif

                if (pcd == NULL)
                {
                    pcap_freealldevs(alldevs);
                    return FALSE;
                }
#ifdef _WIN32
                strcpy(deviceName, d->name);
#endif
                pcap_close(pcd);
                pcap_freealldevs(alldevs);
                return TRUE;
            }
    }
    pcap_freealldevs(alldevs);
    return FALSE;
}

int
InChecksum(u_int16_t *addr, int len)
{
    int sum;

    sum = 0;

    while (len > 1)
    {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1)
    {
        sum += *(u_int16_t *)addr;
    }

    return (sum);
}

/**
 * FUNCTION        :: CalculateChecksum
 * PURPOSE        :: calculate IP checksum
 * PARAMETERS     ::
 * + protocol:  protocol
 * + buf : pointer to the memory of IP data
 * + len : length of IP data
**/
void
CalculateChecksum(int protocol, UInt8 *buf, int len)
{
    int sum=0;
    IpHeaderType *ipHeader;
    ipHeader = (IpHeaderType*)buf;

    switch (protocol)
    {
        case IPPROTO_IP:
        {
            ipHeader->ip_sum = 0;
            sum = InChecksum((u_int16_t *)ipHeader, len);
            ipHeader->ip_sum = CKSUM_CARRY(sum);
            break;
        }
    }
}

BOOL PAS_LibnetInit(
    int partitionId,
    char pasLayer, 
    char * deviceName)
{
    char libnetError[LIBNET_ERRBUF_SIZE];
    char errString[MAX_STRING_LENGTH];

    if (pasLayer == PACKET_SNIFFER_DOT11) // dot11
    {
        libnetPAS_DOT11 = libnet_init(
            LIBNET_LINK,
            deviceName, //name of interface
            libnetError);
        if (libnetPAS_DOT11 == NULL)
        {
            if (partitionId == 0)
            {
                sprintf(errString, "libnet_init: %s", libnetError);
                ERROR_ReportWarning(errString);
            }
            return FALSE;
        }
    }
    else //network layer
    {
        libnetPAS[partitionId] = libnet_init(
            LIBNET_LINK,
            deviceName, //name of interface
            libnetError);
        if (libnetPAS[partitionId] == NULL)
        {
            sprintf(errString, "libnet_init: %s", libnetError);
            if (partitionId == 0)
            {
                ERROR_ReportWarning (errString);
            }
            return FALSE;
        }

    }
    return TRUE;
}

/**
 * FUNCTION        :: PAS_InitializeNodes
 * PURPOSE        :: Function used to initialize PAS nodes
 * PARAMETERS     ::
**/
void PAS_InitializeNodes(
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput)
{
    std::string home;
    std::string enetvSpawning;
    char deviceName[MAX_STRING_LENGTH];
    Node * nextNode;

    PASData* pasData;

    if (iface->partition->partitionId != 0)
        return;

#ifdef _WIN32
    home = std::string("WINDOWS"); // Pretend we do something with it in Windows
#else
    if (!Product::GetProductHome(home)) {
        ERROR_ReportWarning("Could not establish HOME directory for application");
        home = std::string("UNDEFINED");  // Just so we have something displayed
    }
#endif

    assert(iface != NULL);
    pasData = (PASData*) iface->data;
    assert(pasData != NULL);

    pasData->isRealtime = FALSE;

    nextNode = iface->partition->firstNode;

    // if "PACKET-SNIFFER-NODE <id>"
    // load ethernet virtual interface by default
    // load 802.11 virtual interface if it's configure.

    // first, check if ethernet interface is installed. Otherwise, bring it up.
    //if (!PAS_IsDeviceInstalled(PACKET_SNIFFER_ETHERNET, deviceName) && pasData->isPAS)
    if (!PAS_IsDeviceInstalled(PACKET_SNIFFER_ETHERNET, deviceName) )
    {
#ifdef _WIN32
        ERROR_ReportWarning("EXata interface not found. Packet Sniffer disabled\n");
        pasData->deviceNotFound = TRUE;
        pasData->isPAS = FALSE;
        return;
#else
        Int32 temp;
        enetvSpawning = home + 
            "/interfaces/pas/virtual_linux/spawnENETV ETHER";
        printf("enetvSpawing=%s\n", enetvSpawning.c_str());
        temp = system(enetvSpawning.c_str());
#endif
    }
#ifdef _WIN32
    //printf("deviceName=%s\n", deviceName);
#else
    strcpy(deviceName, "exata");
#endif
       if (!PAS_LibnetInit(iface->partition->partitionId, PACKET_SNIFFER_ETHERNET, deviceName)) //ethernet layer
    {
        // no device for PSI
        pasData->deviceNotFound=TRUE;
        //if failed, disable PSI
        pasData->isPAS = FALSE;
        ERROR_ReportWarning("EXata interface not found. Packet Sniffer disabled\n");
    }

    // PARALLEL: Inform the other partitions that they should initialize their libnets too
    if (iface->partition->getNumPartitions() > 1)
    {
        Message *dupMsg, *msg = MESSAGE_Alloc(iface->partition->firstNode, 
                EXTERNAL_LAYER, 
                EXTERNAL_PAS, 
                EXTERNAL_MESSAGE_PAS_InitLibnet);

        MESSAGE_PacketAlloc(iface->partition->firstNode, msg, strlen(deviceName) + 1, TRACE_IP);
        memset(MESSAGE_ReturnPacket(msg), 0, strlen(deviceName) + 1);
        strcpy(MESSAGE_ReturnPacket(msg), deviceName);
        MESSAGE_SetInstanceId(msg, PACKET_SNIFFER_ETHERNET);

        for (int i = 1; i < iface->partition->getNumPartitions(); i++)
        {
            dupMsg = MESSAGE_Duplicate(iface->partition->firstNode, msg);
            EXTERNAL_MESSAGE_RemoteSend(iface, i, dupMsg, 0, EXTERNAL_SCHEDULE_SAFE);
        }
        MESSAGE_Free(iface->partition->firstNode, msg);
    }

    // if MAC layer is defined
    // check if MAC protocol of nodes (interfaces) are all 802.11 (disabled)
    //
    // EXata 2 supports DOT11 (IEEE 802.11) only

    if (pasData->isPAS && pasData->isDot11)
    {
#ifdef _WIN32
        ERROR_ReportError("MAC layer not supported\n");
        return;
#else

        // first, check if ethernet interface is installed. Otherwise, bring it up.
        if (pasData->isPAS & !PAS_IsDeviceInstalled(PACKET_SNIFFER_DOT11, deviceName))
        {
            Int32 temp;
            enetvSpawning = home + 
                "/interfaces/pas/virtual_linux/spawnENETV DOT11";
            printf("enetvSpawing=%s\n", enetvSpawning.c_str());
            temp = system(enetvSpawning.c_str());
        }

#ifdef DERIUS // checking MAC protocol
        bool     non80211Mac = FALSE;

           while (nextNode != NULL)
        {
            for (i=0; i<nextNode->numberInterfaces; i++)
            {
                if (nextNode->macData[i]->macProtocol !=
                        MAC_PROTOCOL_DOT11)
                {
                    //non 802.11 MAC
                    //give warning
                    non80211Mac=TRUE;
                    sprintf(
                        errString,
                        "non 802.11 MAC at %d",
                        nextNode->nodeId);
                    ERROR_ReportWarning(errString);
                }
            }
            nextNode = nextNode->nextNodeData;
        }
#endif // DERIUS
        strcpy(deviceName, "exata_dot11");
        PAS_LibnetInit(iface->partition->partitionId, PACKET_SNIFFER_DOT11, deviceName); //dot11

        // PARALLEL: Inform the other partitions that they should initialize their libnets too
        if (iface->partition->getNumPartitions() > 1)
        {
            Message *dupMsg, *msg = MESSAGE_Alloc(iface->partition->firstNode, 
                    EXTERNAL_LAYER, 
                    EXTERNAL_PAS, 
                    EXTERNAL_MESSAGE_PAS_InitLibnet);

            MESSAGE_PacketAlloc(iface->partition->firstNode, msg, strlen(deviceName) + 1, TRACE_IP);
            memset(MESSAGE_ReturnPacket(msg), 0, strlen(deviceName) + 1);
            strcpy(MESSAGE_ReturnPacket(msg), deviceName);
            MESSAGE_SetInstanceId(msg, PACKET_SNIFFER_DOT11);

            for (int i = 1; i < iface->partition->getNumPartitions(); i++)
            {
                dupMsg = MESSAGE_Duplicate(iface->partition->firstNode, msg);
                EXTERNAL_MESSAGE_RemoteSend(iface, i, dupMsg, 0, EXTERNAL_SCHEDULE_SAFE);
            }
            MESSAGE_Free(iface->partition->firstNode, msg);
        }
#endif // _WIN32
    }

#if 0
//spawn rpcapd process if it's not running
#ifdef _WIN32
    string pName ("rpcapd.exe");
    if (!PAS_IsProcessRunning(pName))
        WinExec("\"c:\\Program Files\\WinPcap\\rpcapd.exe\" -n", SW_SHOWNORMAL);
#endif
#endif

}

/*
 * FUNCTION     PAS_Finalize
 * PURPOSE      Function used to finalize PAS
 *
 */
void PAS_Finalize(PartitionData* partitionData)
{

// Since a packet analyzer (e.g. wireshark) should be able to see the interface,
// we do not unload it.
/*
    std::string home;
    if (!Product::GetProductHome(home)) {
        home = std::string("UNDEFINED");  // Just so we have something displayed
    }

    char enetvSpawning[1024];

    if (partitionData->pasLayer & PAS_ETHER)  //unload the ethernet virtual device
    {
        sprintf(enetvSpawning, "%s/interfaces/pas/virtual_linux/spawnENETV unload ETHER", home.c_str());
        printf("enetvSpawing=%s\n", enetvSpawning);
        system(enetvSpawning);
    }

    if (partitionData->pasLayer & PAS_DOT11)  //unload the dot11 virtual device
    {
        sprintf(enetvSpawning, "%s/interfaces/pas/virtual_linux/spawnENETV unload DOT11", home.c_str());
        printf("enetvSpawing=%s\n", enetvSpawning);
        system(enetvSpawning);
    }
*/
}

BOOL PAS_LayerCheck(Node * node, int interfaceIndex, char fromWhichLayer)
{
    EXTERNAL_Interface *pas = NULL;
    PASData *pasData = NULL;

    if (!node->partitionData->isEmulationMode)
        return FALSE;

    pas = EXTERNAL_GetInterfaceByName(
        &node->partitionData->interfaceList,
        "PAS");
    ERROR_Assert(pas != NULL, "PAS not loaded");

    pasData = (PASData*) pas->data;

    if ((pasData->isPAS) &&  //PAS enabled?
       ((pasData->pasId == (int)node->nodeId) ||
        (pasData->pasId == 0)))
    {
        if ((fromWhichLayer & PACKET_SNIFFER_ETHERNET))
        {
            if (!pasData->isDot11)
                return TRUE;

            if ((pasData->isDot11)  &&
                   (node->macData[interfaceIndex]->macProtocol != MAC_PROTOCOL_DOT11) )
                return TRUE;
            if (!(pasData->pasFilterBit & PACKET_SNIFFER_ENABLE_MAC))
                return TRUE;

            return FALSE;
        }
        else if (fromWhichLayer & PACKET_SNIFFER_DOT11)
        {
            if ((pasData->isDot11) &&
                (node->macData[interfaceIndex]->macProtocol == MAC_PROTOCOL_DOT11) &&
                (pasData->pasFilterBit & PACKET_SNIFFER_ENABLE_MAC))
            {
                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }
    }
    return FALSE;
}


#if 0
#ifdef _WIN32
/*
 * FUNCTION     PAS_IsProcessRunnging
 * PURPOSE      Function used to check if a process is
 *              running on windows
 * PARAMETERS:  pName: process name
 */
bool PAS_IsProcessRunning(std::string pName)
{
    unsigned long aProcesses[1024], cbNeeded, cProcesses;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded) )
        return FALSE;

    cProcesses = cbNeeded / sizeof(unsigned long);
    for (unsigned int i = 0; i<cProcesses; i++)
    {
        if (aProcesses[i] == 0)
            continue;
        HANDLE hProcess =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,    0, aProcesses[i]);
        char buffer[50];
        GetModuleBaseName(hProcess, 0, buffer, 50);
        CloseHandle(hProcess);
        if (pName == string(buffer))
        {
            return TRUE;
        }
    }

    return FALSE;

}
#endif
#endif

void PAS_Receive(EXTERNAL_Interface *iface)
{

    PASData * pasData;
    pasData = (PASData*) iface->data;

/* Hybrid mode testing */
// Set the time management to real-time, with 0 lookahead
    clocktype now = EXTERNAL_QueryExternalTime(iface);

    if (!pasData->isRealtime)
    {
        clocktype simnow = iface->partition->firstNode->getNodeTime();
        //printf("simnow=%f\n", simnow);
        fflush(stdout);
        if (simnow >0)
        //if (simnow > pasData->realTimeStartAt)
        {
            iface->initializeTime = now - simnow;
            //printf("diff=%d\n", iface->initializeTime);
            pasData->isRealtime = TRUE;
        }

    }
}

void PAS_Forward(
    EXTERNAL_Interface *iface,
    Node *node,
    void *forwardData,
    int forwardSize)
{

}

void PAS_Initialize(
    EXTERNAL_Interface *iface,
    NodeInput *nodeInput)
{

    PASData* pasData;

    // Create new IPNEData
    pasData = (PASData*) MEM_malloc(sizeof(PASData));
    memset(pasData, 0, sizeof(PASData));
    iface->data = pasData;

    pasData->isPAS = FALSE;
    pasData->pasId = 0;
    pasData->isDot11 = FALSE;
    pasData->deviceNotFound = FALSE;
    pasData->pasCnt = 0;
    // initialize to enable all filters
    pasData->pasFilterBit = 0xF8;

    if (iface->partition->clusterId != 0)
        return;

    if (EXTERNAL_ConfigStringPresent(nodeInput, "PACKET-SNIFFER-NODE"))
    {
        char pasInput[MAX_STRING_LENGTH];
        BOOL wasFound;

        IO_ReadString(
                ANY_NODEID,
                ANY_ADDRESS,
                nodeInput,
                "PACKET-SNIFFER-NODE",
                &wasFound,
                pasInput);

        if (wasFound)
        {
            pasData->isPAS = TRUE;
            pasData->pasId = atoi(pasInput);
        }
    }

    if (EXTERNAL_ConfigStringPresent(nodeInput, "REALTIME-START-AT"))
    {
        char pasInput[MAX_STRING_LENGTH];
        BOOL wasFound;

        IO_ReadString(
                ANY_NODEID,
                ANY_ADDRESS,
                nodeInput,
                "REALTIME-START-AT",
                &wasFound,
                pasInput);

        if (wasFound)
        {
        clocktype realtimeStartAt;
        realtimeStartAt = TIME_ConvertToClock(pasInput);
        iface->horizon = realtimeStartAt;
        //data->inRealTimeMode = FALSE;
        pasData->realTimeStartAt = realtimeStartAt;
        }
    }


    if (EXTERNAL_ConfigStringPresent(nodeInput, "PACKET-SNIFFER-DOT11"))
    {
        char pasInput[MAX_STRING_LENGTH];
        BOOL wasFound;

        IO_ReadString(
                ANY_NODEID,
                ANY_ADDRESS,
                nodeInput,
                "PACKET-SNIFFER-DOT11",
                &wasFound,
                pasInput);

        if (wasFound)
        {
            if (!strcmp(pasInput, "YES"))
            {
#ifdef _WIN32
                char errorStr[MAX_STRING_LENGTH] = "";
                sprintf(errorStr,
                    "PACKET-SNIFFER: Does not support IEEE 802.11 MAC layer on Windows");
                ERROR_ReportError(errorStr);
#else
                pasData->isDot11 = TRUE; //DOT11 MAC enabled
#endif
            }
            else if (!strcmp(pasInput, "NO"))
                pasData->isDot11 = FALSE; //DOT11 MAC disabled
        }
    }

    // PACKET-SNIFFER filter configuration
    // PAS supports the following filter configuration

    // PACKET-SNIFFER-ENABLE-APP YES/NO
    // PACKET-SNIFFER-ENABLE-UDP YES/NO
    // PACKET-SNIFFER-ENABLE-TCP YES/NO
    // PACKET-SNIFFER-ENABLE-ROUTING YES/NO
    // PACKET-SNIFFER-ENABLE-MAC    YES/NO

    if (EXTERNAL_ConfigStringPresent(nodeInput, "PACKET-SNIFFER-ENABLE-APP"))
    {
        char pasFilterInput[MAX_STRING_LENGTH];
        BOOL wasFound;

        IO_ReadString(
                ANY_NODEID,
                ANY_ADDRESS,
                nodeInput,
                "PACKET-SNIFFER-ENABLE-APP",
                &wasFound,
                pasFilterInput);

        if (wasFound)
        {
            if (!strcmp(pasFilterInput, "YES"))
            {
                pasData->pasFilterBit |=  PACKET_SNIFFER_ENABLE_APP;
            }
            else if (!strcmp(pasFilterInput, "NO"))
                pasData->pasFilterBit &=  ~PACKET_SNIFFER_ENABLE_APP;

        }
    }

    if (EXTERNAL_ConfigStringPresent(nodeInput, "PACKET-SNIFFER-ENABLE-UDP"))
    {
        char pasFilterInput[MAX_STRING_LENGTH];
        BOOL wasFound;

        IO_ReadString(
                ANY_NODEID,
                ANY_ADDRESS,
                nodeInput,
                "PACKET-SNIFFER-ENABLE-UDP",
                &wasFound,
                pasFilterInput);

        if (wasFound)
        {
            if (!strcmp(pasFilterInput, "YES"))
                   pasData->pasFilterBit |=  PACKET_SNIFFER_ENABLE_UDP;
            else if (!strcmp(pasFilterInput, "NO"))
                   pasData->pasFilterBit &=  ~PACKET_SNIFFER_ENABLE_UDP;
        }
    }

    if (EXTERNAL_ConfigStringPresent(nodeInput, "PACKET-SNIFFER-ENABLE-TCP"))
    {
        char pasFilterInput[MAX_STRING_LENGTH];
        BOOL wasFound;

        IO_ReadString(
                ANY_NODEID,
                ANY_ADDRESS,
                nodeInput,
                "PACKET-SNIFFER-ENABLE-TCP",
                &wasFound,
                pasFilterInput);

        if (wasFound)
        {
            if (!strcmp(pasFilterInput, "YES"))
                   pasData->pasFilterBit |=  PACKET_SNIFFER_ENABLE_TCP;
            else if (!strcmp(pasFilterInput, "NO"))
                   pasData->pasFilterBit &=  ~PACKET_SNIFFER_ENABLE_TCP;
        }
    }

    if (EXTERNAL_ConfigStringPresent(nodeInput, "PACKET-SNIFFER-ENABLE-ROUTING"))
    {
        char pasFilterInput[MAX_STRING_LENGTH];
        BOOL wasFound;

        IO_ReadString(
                ANY_NODEID,
                ANY_ADDRESS,
                nodeInput,
                "PACKET-SNIFFER-ENABLE-ROUTING",
                &wasFound,
                pasFilterInput);

        if (wasFound)
        {
            if (!strcmp(pasFilterInput, "YES"))
                   pasData->pasFilterBit |=  PACKET_SNIFFER_ENABLE_ROUTING;
            else if (!strcmp(pasFilterInput, "NO"))
                   pasData->pasFilterBit &=  ~PACKET_SNIFFER_ENABLE_ROUTING;
        }
    }
    if (EXTERNAL_ConfigStringPresent(nodeInput, "PACKET-SNIFFER-ENABLE-MAC"))
    {
        char pasFilterInput[MAX_STRING_LENGTH];
        BOOL wasFound;

        IO_ReadString(
                ANY_NODEID,
                ANY_ADDRESS,
                nodeInput,
                "PACKET-SNIFFER-ENABLE-MAC",
                &wasFound,
                pasFilterInput);

        if (wasFound)
        {
            if (!strcmp(pasFilterInput, "YES"))
                   pasData->pasFilterBit |=  PACKET_SNIFFER_ENABLE_MAC;
            else if (!strcmp(pasFilterInput, "NO"))
                   pasData->pasFilterBit &=  ~PACKET_SNIFFER_ENABLE_MAC;
        }
    }
}

void PAS_HandleExternalMessage(
    Node *node,
    Message *msg)
{
    PASData* pasData;
    EXTERNAL_Interface *iface;

    iface = node->partitionData->interfaceTable[EXTERNAL_PAS];
    if (iface == NULL)
        return;

    pasData = (PASData*) iface->data;

    switch(msg->eventType)
    {
        case EXTERNAL_MESSAGE_PAS_InitLibnet:
        {
            int macType = MESSAGE_GetInstanceId(msg);
            char deviceName[MAX_STRING_LENGTH];

            strcpy(deviceName, MESSAGE_ReturnPacket(msg));
            if (macType == PACKET_SNIFFER_ETHERNET)
            {
                if (!PAS_LibnetInit(node->partitionId, PACKET_SNIFFER_ETHERNET, deviceName)) //ethernet layer
                {
                    // no device for PSI
                    pasData->deviceNotFound=TRUE;
                    //if failed, disable PSI
                    pasData->isPAS = FALSE;
                }
            }
            else if (macType == PACKET_SNIFFER_DOT11)
            {
                PAS_LibnetInit(node->partitionId, PACKET_SNIFFER_DOT11, deviceName);
            }

            break;
        }
        case EXTERNAL_MESSAGE_PAS_EnablePSI:
        {
            char nodeId[MAX_STRING_LENGTH];
            sprintf(nodeId, "%d", *(int *)MESSAGE_ReturnPacket(msg));
            MESSAGE_RemoveHeader(node, msg, sizeof(int), TRACE_IP);
            PSI_EnablePSI(node->partitionData, nodeId);
            break;
        }
        case EXTERNAL_MESSAGE_PAS_EnableDot11:
        {
            BOOL flag = *(BOOL *)MESSAGE_ReturnPacket(msg);
            MESSAGE_RemoveHeader(node, msg, sizeof(int), TRACE_IP);
            PSI_EnableDot11(node->partitionData, flag);
            break;
        }
        case EXTERNAL_MESSAGE_PAS_EnableApp:
        {
            BOOL flag = *(BOOL *)MESSAGE_ReturnPacket(msg);
            MESSAGE_RemoveHeader(node, msg, sizeof(int), TRACE_IP);
            PSI_EnableApp(node->partitionData, flag);
            break;
        }
        case EXTERNAL_MESSAGE_PAS_EnableUdp:
        {
            BOOL flag = *(BOOL *)MESSAGE_ReturnPacket(msg);
            MESSAGE_RemoveHeader(node, msg, sizeof(int), TRACE_IP);
            PSI_EnableUdp(node->partitionData, flag);
            break;
        }
        case EXTERNAL_MESSAGE_PAS_EnableTcp:
        {
            BOOL flag = *(BOOL *)MESSAGE_ReturnPacket(msg);
            MESSAGE_RemoveHeader(node, msg, sizeof(int), TRACE_IP);
            PSI_EnableTcp(node->partitionData, flag);
            break;
        }
        case EXTERNAL_MESSAGE_PAS_EnableRouting:
        {
            BOOL flag = *(BOOL *)MESSAGE_ReturnPacket(msg);
            MESSAGE_RemoveHeader(node, msg, sizeof(int), TRACE_IP);
            PSI_EnableRouting(node->partitionData, flag);
            break;
        }
        case EXTERNAL_MESSAGE_PAS_EnableMac:
        {
            BOOL flag = *(BOOL *)MESSAGE_ReturnPacket(msg);
            MESSAGE_RemoveHeader(node, msg, sizeof(int), TRACE_IP);
            PSI_EnableMac(node->partitionData, flag);
            break;
        }
        default:
            ;
    }

    MESSAGE_Free(node, msg);
}
