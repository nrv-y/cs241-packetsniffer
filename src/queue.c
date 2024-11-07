#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

// frees memory allocated to queue since it was dynamically allocated
void destroy_queue(queue *q)
{
    free(q);
}

int isempty(const queue *q)
{
    return (q->head == NULL);
}

queue *create_queue(void)
{
    queue *q = (queue *)malloc(sizeof(queue));
    if (q == NULL)
    {
        perror("Failed to create queue");
        exit(EXIT_FAILURE);
    }
    q->head = NULL;
    q->tail = NULL;
    return q;
}

void enqueue(queue *q, struct pcap_pkthdr *header, const unsigned char *packet)
{
    node *new_node = (node *)malloc(sizeof(node));
    if (new_node == NULL)
    {
        perror("Failed to enqueue value");
        exit(EXIT_FAILURE);
    }

    // initialise new node in the queue with the given header and packet and then update the head and tail pointers
    new_node->header = header;
    new_node->packet = packet;
    new_node->next = NULL;

    if (isempty(q))
    {
        q->head = new_node;
        q->tail = new_node;
    }
    else
    {
        q->tail->next = new_node;
        q->tail = new_node;
    }
}

node *dequeue(queue *q)
{
    if (isempty(q))
    {
        fprintf(stderr, "Error: attempt to dequeue from an empty queue\n");
        exit(EXIT_FAILURE);
    }

    // dereference head node and update the head pointer
    node *head_node = q->head;
    q->head = q->head->next;

    // in the case that the queue becomes empty then update tail pointer to null to eliminate risk of accessing memory that should not be accessed
    if (q->head == NULL)
    {
        q->tail = NULL;
    }

    return head_node;
}

// printing queue function for testing purposes
void printqueue(const queue *q)
{
    if (isempty(q))
    {
        printf("The queue is empty\n");
    }
    else
    {
        const node *read_head = q->head;
        printf("The queue elements from head to tail are:\n");
        printf("%p", (void *)read_head->packet);
        while (read_head->next != NULL)
        {
            read_head = read_head->next;
            printf("--> %p", (void *)read_head->packet);
        }
        printf("\n");
    }
}
