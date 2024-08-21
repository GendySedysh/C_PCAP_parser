#include "pcap_parser.h"

char *my_itoa(int num, char *str)
{
    if(str == NULL) {
        return NULL;
    }
    sprintf(str, "%d", num);
    return str;
}

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

void PrintAllAndTcpPackets(char *input_file) {
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];  
    handle = pcap_open_offline(input_file, errbuf); 

    if (handle == NULL) {
        fprintf(stderr,"Couldn't open pcap file %s: %s\n", input_file, errbuf); 
        exit(1);
    } 

    struct pcap_pkthdr header; 
    const u_char *packet;
    unsigned int packet_counter = 0;
    unsigned int tcp_packet_counter = 0;

    while (packet = pcap_next(handle, &header)) { 
        if (IsTCPPacket(packet, &header)) {
            tcp_packet_counter++;
        }
        packet_counter++;
    } 
    pcap_close(handle);

    printf("Number of packets in file: %d\n", packet_counter);
    printf("Number of TCP packets in file: %d\n", tcp_packet_counter);
}

char* AddParametrToFilter(char* filter, char* parametr, char* arg, short *counter) {
    if (*counter != 0) {
        strcat(filter, " and ");
    }
    strcat(filter, parametr);
    strcat(filter, arg);
    (*counter)++;

    return filter;
}

char* CreateFilter(t_arguments arguments) {
    char *filter = malloc(sizeof(char) * 100);
    short counter = 0;
    filter[0] = '\0';

    char port[5];
    if (arguments.dstport != 0) {
        AddParametrToFilter(filter, "dst port ", my_itoa(arguments.dstport, port), &counter);
    }

    if (arguments.srcport != 0) {
        AddParametrToFilter(filter, "src port ", my_itoa(arguments.srcport, port), &counter);
    }

    if (arguments.dstaddr[0] != '\0'){
        AddParametrToFilter(filter, "dst ", arguments.dstaddr, &counter);
    }

    if (arguments.srcaddr[0] != '\0'){
        AddParametrToFilter(filter, " src ", arguments.srcaddr, &counter);
    }

    return filter;
}

void PrintFilteredPackets(t_arguments arguments) {
    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip;

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(arguments.input, errbuf); 

    if (handle == NULL) {
        fprintf(stderr,"Couldn't open pcap file %s: %s\n", arguments.input, errbuf); 
        exit(1);
    }

    char *filter_exp = CreateFilter(arguments);
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        exit(1);
    }

    struct pcap_pkthdr header; 
    const u_char *packet;
    unsigned int filtered_packet_counter = 0;

    while (packet = pcap_next(handle, &header)) {
        filtered_packet_counter++;
    }
    pcap_close(handle);
    printf("Number of Filtered TCP packets in file: %d\n", filtered_packet_counter);
}