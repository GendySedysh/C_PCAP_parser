#include <stdio.h>
#include <argp.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

static char doc[] = "Example: pcap_parser <filename> --dstaddr=192.168.0.1 --srcport=80";
static char args_doc[] = "<filename>";

static struct argp_option options[] = {
    {"srcaddr",  's', "<ip-addr>", 0,  "set filter for source address " },
    {"dstaddr",  'd', "<ip-addr>", 0,  "set filter for destination address" },
    {"srcport",  'p', "<port>", 0,  "set filter for source port" },
    {"dstport",  'o', "<port>", 0,  "set filter for destination port" },
    { 0 }
};

struct arguments
{
  char *input;
  int srcport;
  int dstport;
  char *srcaddr;
  char *dstaddr;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'p':
      arguments->srcport = atoi(arg);
      break;
    case 'o':
      arguments->dstport = atoi(arg);
      break;
    case 's':
      arguments->srcaddr = arg;
      break;
    case 'd':
      arguments->dstaddr = arg;
      break;

    case ARGP_KEY_ARG:
      if (state->arg_num == 0) {
        arguments->input = arg;
      } else {
        return ARGP_ERR_UNKNOWN;
      }
      break;

    case ARGP_KEY_END:
      if (state->argc < 2){
          argp_usage(state);
      }
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

bool IsTCPPacket(const u_char *packet, struct pcap_pkthdr *header) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return false;
    }

    const u_char *ip_header;

    int ethernet_header_length = 14; /* Doesn't change */
    ip_header = packet + ethernet_header_length;

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        return false;
    }
    return true;
}

int main(int argc, char **argv) 
{
    struct arguments arguments;

    /* Default values. */
    arguments.srcport = 0;
    arguments.dstport = 0;
    arguments.srcaddr = "\0";
    arguments.dstaddr = "\0";
    arguments.input = "\0";

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // printf("input %s\n",arguments.input);
    // printf("srcaddr %s\n",arguments.srcaddr);
    // printf("dstaddr %s\n",arguments.dstaddr);
    // printf("srcport %d\n",arguments.srcport);
    // printf("dstport %d\n",arguments.dstport);

    unsigned int packet_counter = 0;
    unsigned int tcp_packet_counter = 0;
    struct pcap_pkthdr header; 
    const u_char *packet;

    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];  
    handle = pcap_open_offline(arguments.input, errbuf); 

    if (handle == NULL) {
        fprintf(stderr,"Couldn't open pcap file %s: %s\n", arguments.input, errbuf); 
        return(2); 
    } 

    while (packet = pcap_next(handle, &header)) { 
        if (IsTCPPacket(packet, &header)) {
            tcp_packet_counter++;
        }
        packet_counter++;
    } 
    pcap_close(handle);

    unsigned int filtered_packet_counter = 0;

    printf("Number of packets in file: %d\n", packet_counter);
    printf("Number TCP of packets in file: %d\n", tcp_packet_counter);
    return 0;
}