/*
 * @(#) $Header: /home/dschepler/svn-test/cvsroot/qualnet/interfaces/lib-emulation/libpcap/src/dlpisubs.h,v 1.1.2.1 2009-08-22 00:35:58 mvarshney Exp $
 */

#ifndef dlpisubs_h
#define    dlpisubs_h

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Functions used by dlpisubs.c.
 */
int pcap_stats_dlpi(pcap_t *, struct pcap_stat *);
int pcap_process_pkts(pcap_t *, pcap_handler, u_char *, int, u_char *, int);
int pcap_process_mactype(pcap_t *, u_int);
#ifdef HAVE_SYS_BUFMOD_H
int pcap_conf_bufmod(pcap_t *, int, int);
#endif
int pcap_alloc_databuf(pcap_t *);
int strioctl(int, int, int, char *);

#ifdef __cplusplus
}
#endif

#endif
