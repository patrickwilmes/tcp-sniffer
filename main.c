/*
 * Copyright (c) 2024, Patrick Wilmes <p.wilmes89@gmail.com>
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <net/ethernet.h> // contains ETH_P_ALL
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h> // for htons
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#define BUF_SIZE 65536

void print_ethernet_header(unsigned char *buffer);
void print_ip_header(unsigned char *buffer);
void print_tcp_packet(unsigned char *buffer);

int main(int argc, char **argv) {
    int raw_socket;
    struct sockaddr saddress;
    unsigned int saddress_len = sizeof(saddress);
    unsigned char *buffer = (unsigned char *) malloc(BUF_SIZE);

    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        fprintf(stderr, "Failed to create raw socket\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        // receive data from the socket
        ssize_t msg_len = recvfrom(raw_socket, buffer, BUF_SIZE, 0, &saddress, &saddress_len);
        if (msg_len < 0) {
            fprintf(stderr, "No data received due to error\n");
            return -1;
        }
        /*
         * The buffer contains the entire packet and should look something like this:
         * |ethernet header|ip header|tcp header|data segment|
         * To parse these headers correctly:
         * 1. Start at the beginning of the buffer to parse the Ethernet header.
         * 2. To parse the IP header, advance the pointer by the size of the Ethernet header.
         * 3. To parse the TCP header, advance the pointer by the size of both the Ethernet header and the IP header.
         * Note:
         * - The Ethernet header size is typically 14 bytes (ETH_HLEN).
         * - The IP header size can vary but is at least 20 bytes; you need to account for the IHL field to determine its exact size.
         * - The TCP header size also varies but is at least 20 bytes; the Data Offset field will give its exact size.
         */

        /*
         * We are passing in the original buffer.
         * The concern of figuring out the exact location where to start parsing
         * is one of the individual function.
         */
        print_ethernet_header(buffer);
        print_ip_header(buffer);
        print_tcp_packet(buffer);
    }

    close(raw_socket);
    free(buffer);
    return 0;
}

void print_ethernet_header(unsigned char *buffer) {
    struct ethhdr *eth = (struct ethhdr *)buffer;
    printf("\nEthernet Header\n");
    printf("   |-Destination Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("   |-Source Address     : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("   |-Protocol           : %u \n", (unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char *buffer) {
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;

    printf("\nIP Header\n");
    printf("   |-IP Version        : %d\n", (unsigned int)ip->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
    printf("   |-Type Of Service   : %d\n", (unsigned int)ip->tos);
    printf("   |-IP Total Length   : %d Bytes(Size of Packet)\n", ntohs(ip->tot_len));
    printf("   |-Identification    : %d\n", ntohs(ip->id));
    printf("   |-TTL               : %d\n", (unsigned int)ip->ttl);
    printf("   |-Protocol          : %d\n", (unsigned int)ip->protocol);
    printf("   |-Checksum          : %d\n", ntohs(ip->check));
    printf("   |-Source IP         : %s\n", inet_ntoa(source.sin_addr));
    printf("   |-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char *buffer) {
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    // calculate the ip header len as its variing
    struct tcphdr *tcp = (struct tcphdr *)(buffer + ip->ihl * 4 + sizeof(struct ethhdr));

    printf("\nTCP Header\n");
    printf("   |-Source Port      : %u\n", ntohs(tcp->source));
    printf("   |-Destination Port : %u\n", ntohs(tcp->dest));
    printf("   |-Sequence Number    : %u\n", ntohl(tcp->seq));
    printf("   |-Acknowledge Number : %u\n", ntohl(tcp->ack_seq));
    printf("   |-Header Length     : %d DWORDS or %d BYTES\n", (unsigned int)tcp->doff, (unsigned int)tcp->doff * 4);
    printf("   |-Urgent Flag          : %d\n", (unsigned int)tcp->urg);
    printf("   |-Acknowledgement Flag : %d\n", (unsigned int)tcp->ack);
    printf("   |-Push Flag            : %d\n", (unsigned int)tcp->psh);
    printf("   |-Reset Flag           : %d\n", (unsigned int)tcp->rst);
    printf("   |-Synchronise Flag     : %d\n", (unsigned int)tcp->syn);
    printf("   |-Finish Flag          : %d\n", (unsigned int)tcp->fin);
    printf("   |-Window         : %d\n", ntohs(tcp->window));
    printf("   |-Checksum       : %d\n", ntohs(tcp->check));
    printf("   |-Urgent Pointer : %d\n", tcp->urg_ptr);
}

