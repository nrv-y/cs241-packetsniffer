#include "sniff.h"
#include "analysis.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include <signal.h>
#include "dispatch.h"
#include "analysis.h"

// global flag to signal application to exit, this acts as a shared variable different parts of the program (i.e. each thread) can check to see if the exit condition can be triggered
// as the CtrlC Handler runs asynchronously
int exit_flag = 0;
pcap_t *pcap_handle; // global handle for pcap

// this is the callback function for each captured packet, calls dispatch function which copies and enqueues packets for analysis later
void got_packet(unsigned char *user, struct pcap_pkthdr *header, const unsigned char *packet)
{
  dispatch(header, packet);
}

// signal handler so we can exit program and then print the desired output counts of detected attacks in the packets
void ctrlCHandler(int signo)
{
  printf("Received SIGINT. Setting exit_flag to 1...\n");
  exit_flag = 1;
  // breaks pcap loop to initiate the application exit
  pcap_breakloop(pcap_handle);
}

// Application main sniffing loop
void sniff(char *interface)
{
  signal(SIGINT, ctrlCHandler); // register the signal handler!!!!

  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);

  if (pcap_handle == NULL)
  {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  else
  {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }

  // creates threadpool for multithreading the packet analysis
  create_threadpool();

  // pcap_loop continuously calls got_packet() for each captured packet
  if (pcap_loop(pcap_handle, 0, (pcap_handler)got_packet, NULL) == -1)
  {
    fprintf(stderr, "An error has occured: %s\n", pcap_geterr(pcap_handle));
  }

  printf("Main sniffing loop: Exiting...\n"); // Print exit message
  join_threadpool();                          // join threadpool so all worker threads finish their tasks

  printf("\nIntrusion Detection Report:\n");
  printf("%d SYN packets detected from %d different IPs (syn attack)\n", synCount, countIpAddresses(uniqueIpList));
  printf("%d ARP responses (cache poisoning)\n", arpCount);
  printf("%d URL Blacklist violations (%d google and %d bbc)\n", (googleCount + bbcCount), googleCount, bbcCount);

  // free resources so no memory leaks :)
  freeIpAddrList(&uniqueIpList);
  destroy_queue(work_queue);

  pcap_close(pcap_handle);
}
