/*
 * pcap-septel.c: Packet capture interface for Intel Septel card
 *
 * The functionality of this code attempts to mimic that of pcap-linux as much
 * as possible.  This code is only needed when compiling in the Intel/Septel
 * card code at the same time as another type of device.
 *
 * Authors: Gilbert HOYEK (gil_hoyek@hotmail.com), Elias M. KHOURY
 * (+961 3 485343);
 *
 * @(#) $Header: /home/dschepler/svn-test/cvsroot/qualnet/interfaces/lib-emulation/libpcap/src/pcap-septel.h,v 1.1.2.1 2009-08-22 00:35:58 mvarshney Exp $
 */

pcap_t *septel_create(const char *device, char *ebuf);

