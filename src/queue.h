#ifndef CS241_QUEUE_H
#define CS241_QUEUE_H

#include <pcap.h>

// node structure represents an element in the queue, contains packet header and pakcet data and pointer to next node
typedef struct node
{
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    struct node *next;
} node;

// maintains linked list of nodes
typedef struct queue
{
    node *head;
    node *tail;
} queue;

void destroy_queue(queue *q);
queue *create_queue(void);
int isempty(const queue *q);
void enqueue(queue *q, struct pcap_pkthdr *header, const unsigned char *packet);
node *dequeue(queue *q);
void printqueue(const queue *q);

#endif
