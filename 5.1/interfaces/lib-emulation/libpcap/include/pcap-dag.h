/*
 * pcap-dag.c: Packet capture interface for Endace DAG card.
 *
 * The functionality of this code attempts to mimic that of pcap-linux as much
 * as possible.  This code is only needed when compiling in the DAG card code
 * at the same time as another type of device.
 *
 * Author: Richard Littin, Sean Irvine ({richard,sean}@reeltwo.com)
 *
 * @(#) $Header: /home/dschepler/svn-test/cvsroot/qualnet/interfaces/lib-emulation/libpcap/include/pcap-dag.h,v 1.1.10.2 2009-08-22 00:35:58 mvarshney Exp $ (LBL)
 */

pcap_t *dag_open_live(const char *device, int snaplen, int promisc, int to_ms, char *ebuf);

