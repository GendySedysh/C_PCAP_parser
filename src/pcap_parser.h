#ifndef PCAP_PARSER
#define PCAP_PARSER

#include <stdio.h>
#include <argp.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <string.h>

typedef struct s_arguments
{
  char *input;
  int srcport;
  int dstport;
  char *srcaddr;
  char *dstaddr;
} t_arguments;

void PrintAllAndTcpPackets(char *input_file);
void PrintFilteredPackets(t_arguments arguments);

#endif