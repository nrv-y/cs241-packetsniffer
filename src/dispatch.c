#include "dispatch.h"
#include "queue.h"
#include "sniff.h"

#include <signal.h>

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "analysis.h"

#define NUM_THREADS 4

pthread_t threads[4];

// mutex lock for the queue since its shared!
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

// condition variable for signaling to threads when the queue is not empty
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

struct queue *work_queue;

void *worker_thread(void *arg)
{
  // register ctrlC handler for exiting
  signal(SIGINT, ctrlCHandler);

  while (1)
  {
    pthread_mutex_lock(&queue_mutex);

    // wait until there is work in the queue or the exit signal is receieved
    while (isempty(work_queue) && !exit_flag)
    {
      pthread_cond_wait(&queue_cond, &queue_mutex); // send signal (bc queue has work now)
    }

    pthread_mutex_unlock(&queue_mutex);

    // exit the thread if exit signal is received
    if (exit_flag)
    {
      printf("Exiting Thread...\n");
      break;
    }

    // lock the queue and dequeue a packet for analysis
    pthread_mutex_lock(&queue_mutex);

    struct node *node = dequeue(work_queue);

    pthread_mutex_unlock(&queue_mutex);

    analyse(node->header, node->packet);

    // free the memory allocated for the packet and header so no memory leaks
    free(node->packet);
    free(node->header);
    free(node);
  }

  return NULL;
}

void create_threadpool() // initialises work queue and creates worker threads
{
  work_queue = create_queue();

  for (int i = 0; i < NUM_THREADS; ++i)
  {
    pthread_create(&threads[i], NULL, worker_thread, NULL);
  }
}

void join_threadpool() // join threads so all the threads finish their execution and avoid undefined behaviour
{
  // broadcast to wake up the waiting threads
  pthread_mutex_lock(&queue_mutex);
  pthread_cond_broadcast(&queue_cond); // signals threads to terminate even if they are waiting on queue_cond signal
  pthread_mutex_unlock(&queue_mutex);

  for (int i = 0; i < NUM_THREADS; ++i)
  {
    pthread_join(threads[i], (void **)NULL);
  }

  // destroy synchronisation objects so nomemory leaks
  pthread_mutex_destroy(&queue_mutex);
  pthread_cond_destroy(&queue_cond);
}

// function to dispatch packets to worker threads
void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet)
{

  pthread_mutex_lock(&queue_mutex); // lock work queue

  // allocate memory and copy header and packet data to new memory location so that the threads dont act on the same packt again and again
  bpf_u_int32 packet_length = header->caplen;
  unsigned char *copied_p = (unsigned char *)malloc(packet_length);
  memcpy(copied_p, packet, packet_length);

  struct pcap_pkthdr *copied_header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
  memcpy(copied_header, header, sizeof(struct pcap_pkthdr));

  // add the copied packet and copied header to the work queue so that they can be processed by the worker threads
  enqueue(work_queue, copied_header, copied_p);

  pthread_cond_signal(&queue_cond);   // signal work queue as not empty via conditon variable
  pthread_mutex_unlock(&queue_mutex); // unlock the work queue to other threads now since this thread is done with it
}
