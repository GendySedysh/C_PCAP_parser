#include "pcap_parser.h"

static char doc[] = "Example: pcap_parser <filename> --dstaddr=192.168.0.1 --srcport=80";
static char args_doc[] = "<filename>";

static struct argp_option options[] = {
    {"srcaddr",  's', "<ip-addr>", 0,  "set filter for source address " },
    {"dstaddr",  'd', "<ip-addr>", 0,  "set filter for destination address" },
    {"srcport",  'p', "<port>", 0,  "set filter for source port" },
    {"dstport",  'o', "<port>", 0,  "set filter for destination port" },
    { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  struct s_arguments *arguments = state->input;

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

int main(int argc, char **argv) 
{
    struct s_arguments arguments;

    /* Default values. */
    arguments.srcport = 0;
    arguments.dstport = 0;
    arguments.srcaddr = "\0";
    arguments.dstaddr = "\0";
    arguments.input = "\0";

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    PrintAllAndTcpPackets(arguments.input);
    PrintFilteredPackets(arguments);
    return 0;
}