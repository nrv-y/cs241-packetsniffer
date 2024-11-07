#include <pcap.h>

#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

extern pcap_t *pcap_handle;

extern int exit_flag;

void sniff(char *interface);
void dump(const unsigned char *data, int length);

#endif