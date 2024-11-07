#include "analysis.h"
#include "queue.h"
#include "dispatch.h"
#include "sniff.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

#include <stdlib.h>
#include <pthread.h>

// mutex lock to ensure thread safety for shared data
pthread_mutex_t analysis_mutex = PTHREAD_MUTEX_INITIALIZER;

// initialise linkedlist structure to store ip addresses
struct IpAddrList *uniqueIpList = NULL;

//(global) variables for counting occurences
int synCount = 0;

int arpCount = 0;

int googleCount = 0;
int bbcCount = 0;

// adds an ip address to the linked list structure if it is not already present
void addIpToList(struct IpAddrList **list, struct in_addr ip)
{ // double pointer repr. head of list

    if (!isIpInList(list, ip))
    {
        struct IpAddrList *newNode = (struct IpAddrList *)malloc(sizeof(struct IpAddrList));
        if (newNode == NULL)
        {
            fprintf(stderr, "Memory allocation error\n");
            exit(1);
        }

        newNode->ip = ip;
        newNode->next = *list;
        *list = newNode; // adds new ip to head if it isnt already in the list
    }
}

// helper function to check if an IP address is already in the linked list
int isIpInList(struct IpAddrList **list, struct in_addr ip)
{
    struct IpAddrList *current = *list;

    while (current != NULL)
    {
        if (current->ip.s_addr == ip.s_addr)
        {
            return 1;
        }
        current = current->next;
    }

    return 0;
}

// counts the number of IP addresses in the linked list
// used to return how many different ip addresses syn packets were recieved from
int countIpAddresses(struct IpAddrList *list)
{
    int count = 0;
    struct IpAddrList *current = list;

    while (current != NULL)
    {
        count++;
        current = current->next;
    }

    return count;
}

// memory management - free the memory allocated for the linked list

void freeIpAddrList(struct IpAddrList **list)
{
    struct IpAddrList *current = *list;
    struct IpAddrList *next;

    while (current != NULL)
    {
        next = current->next;
        free(current);
        current = next;
    }

    *list = NULL;
}

void detectSynAttack(const struct pcap_pkthdr *header, const unsigned char *packet)
{
    // extracts ip header from the packet
    struct ip *ipHeader = (struct ip *)(packet + 14);

    // if the packet contains a TCP HEADER
    if (ipHeader->ip_p == IPPROTO_TCP)
    {
        // extract tcp header
        struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + ((ipHeader->ip_hl) << 2));

        // check that its a syn packet and no ack is set
        if (tcpHeader->syn && !tcpHeader->ack)
        {
            synCount++;
            struct in_addr sourceIp = ipHeader->ip_src; // extract source ip address and add it to the list
            if (!isIpInList(&uniqueIpList, sourceIp))
            {
                addIpToList(&uniqueIpList, sourceIp);
            }
        }
    }
}

void detectARP(const struct pcap_pkthdr *header, const unsigned char *packet)
{
    // extract ethernet header from packet
    struct ether_header *ethHeader = (struct ether_header *)packet;

    // if the packet contains an ARP header, then extract it ((it starts fter the 14-byte ethernet header))
    if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP)
    {
        struct ether_arp *arpHeader = (struct ether_arp *)(packet + 14); // because ethernet header is 14 bytes, and C has contiguous memory layout

        if (ntohs(arpHeader->arp_op) == ARPOP_REPLY) // if the arp packet is an ARP REPLY then count it
        {
            arpCount++;
        }
    }
}
void detectBlacklistedURLs(const struct pcap_pkthdr *header, const unsigned char *packet)
{
    struct ip *ipHeader = (struct ip *)(packet + 14); // extract ip header

    if (ipHeader->ip_p == IPPROTO_TCP) // if it contains tcp header, extract it
    {
        struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + ((ipHeader->ip_hl) << 2));
        int tcpHeaderLength = tcpHeader->th_off << 2;

        if (tcpHeader->th_dport == htons(80) && tcpHeaderLength > 0) // if the tcp header is going to port 80 and has a payload, then we want to extract that payload
        {
            const char *payload = (const char *)(packet + 14 + ((ipHeader->ip_hl) << 2) + tcpHeaderLength);

            // Dynamically allocate a buffer for the payload so we dont modify packet directly and can use strstr
            char *payloadBuffer = malloc(header->len - (14 + ((ipHeader->ip_hl) << 2) + tcpHeaderLength) + 1);
            if (payloadBuffer == NULL)
            {
                // case of allocation failure
                return;
            }

            // copy payload data to the buffer
            strncpy(payloadBuffer, payload, header->len - (14 + ((ipHeader->ip_hl) << 2) + tcpHeaderLength));
            payloadBuffer[header->len - (14 + ((ipHeader->ip_hl) << 2) + tcpHeaderLength)] = '\0'; // Null terminator

            // check if the payload contains the blacklisted domains
            if (strstr(payloadBuffer, "Host: www.google.co.uk") || strstr(payloadBuffer, "Host: www.bbc.co.uk"))
            {
                // extracts the source and destination ip addresses from the ip header of the packet for the necessary output
                struct in_addr sourceIp = ipHeader->ip_src;
                struct in_addr destIp = ipHeader->ip_dst;

                printf("==============================\n");
                printf("Blacklisted URL violation detected\n");
                printf("Source IP address: %s\n", inet_ntoa(sourceIp));
                printf("Destination IP address: %s\n", inet_ntoa(destIp));

                // updates respective counts as necessary
                if (strstr(payloadBuffer, "Host: www.google.co.uk"))
                {
                    googleCount++;
                }

                if (strstr(payloadBuffer, "Host: www.bbc.co.uk"))
                {
                    bbcCount++;
                }

                printf("==============================\n");
            }

            free(payloadBuffer); // need to free the buffer since its dynamically allocated
        }
    }
}

// mutex locks around analysis function prevent race conditions if two threads try to modify shared data simultaneously
void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet)
{
    pthread_mutex_lock(&analysis_mutex); // acquires the mutex lock before performing analysis and releases it after analysis is complete

    detectSynAttack(header, packet);

    detectARP(header, packet);

    detectBlacklistedURLs(header, packet);

    pthread_mutex_unlock(&analysis_mutex);
}
