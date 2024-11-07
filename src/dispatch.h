#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>

extern pthread_t threads[4];
extern pthread_mutex_t queue_mutex;
extern pthread_cond_t queue_cond;
extern struct queue *work_queue;

void *worker_thread(void *arg);

void create_threadpool();
void join_threadpool();

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet);

#endif
