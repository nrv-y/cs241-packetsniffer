#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

extern pthread_mutex_t analysis_mutex;

// structure to represent a linked list node that stores IP addresses
struct IpAddrList
{
    struct in_addr ip;
    struct IpAddrList *next;
};

// variables defined in the file but MEMORY is allocated elsewhere (extern)
extern int synCount;
extern struct IpAddrList *uniqueIpList;
extern int arpCount;
extern int googleCount;
extern int bbcCount;

void addIpToList(struct IpAddrList **list, struct in_addr ip);
int isIpInList(struct IpAddrList **list, struct in_addr ip);
int countIpAddresses(struct IpAddrList *list);
void freeIpAddrList(struct IpAddrList **list);
void ctrlCHandler(int signo);
void detectSynAttack(const struct pcap_pkthdr *header, const unsigned char *packet);
void detectARP(const struct pcap_pkthdr *header, const unsigned char *packet);
void detectBlacklistedURLs(const struct pcap_pkthdr *header, const unsigned char *packet);
void analyse(struct pcap_pkthdr *header, const unsigned char *packet);
#endif