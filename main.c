#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>


#define MAX_TTL 32
#define PACKET_SIZE 4096
#define TIMEOUT_SEC 1

#define PROG_NAME "my_traceroute"

void print_usage() {
    printf("Usage: %s <hostname> [-m max_ttl]\n", PROG_NAME);
    exit(EXIT_FAILURE);
}

unsigned short calculate_checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len > 0) {
        sum += *buf & 0xFF;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short) (~sum);
}

int main(int argc, char *argv[]) {

    long max_ttl;

    switch (argc) {
        case 2:
            max_ttl = MAX_TTL;
            break ;
        case 4:
            if (strcmp(argv[2], "-m") != 0) {
                print_usage();
                return 1;
            }
            char *end;
            max_ttl = strtol(argv[3], &end, 10);
            if (max_ttl == 0) {
                print_usage();
                return 1;
            }
            break ;
        default:
            print_usage();
            return 1;
    }

    printf("max_ttl: %ld\n", max_ttl);

    char *target_host = argv[1];
    struct sockaddr_in target_addr;
    struct hostent *target_info;

    if ((target_info = gethostbyname(target_host)) == NULL) {
        perror("gethostbyname");
        exit(EXIT_FAILURE);
    }

    bzero((char *) &target_addr, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    bcopy((char *) target_info->h_addr, (char *) &target_addr.sin_addr.s_addr, target_info->h_length);

    int ttl;
    int sockfd;
    char packet[PACKET_SIZE];

    for (ttl = 1; ttl <= max_ttl; ++ttl) {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd < 0) {
            perror("socket");
            exit(EXIT_FAILURE);
        }

        packet[0] = ICMP_ECHO;      // type
        packet[1] = 0;              // code
        packet[2] = 0;              // checksum (part 1)
        packet[3] = 0;              // checksum (part 2)
        packet[4] = 0;              // identifier (part 1)
        packet[5] = getpid() & 0xFF;// identifier (part 2)
        packet[6] = ttl;            // sequence number (part 1)
        packet[7] = 0;              // sequence number (part 2)

        unsigned short *checksum_location = (unsigned short *) &packet[2];
        *checksum_location = calculate_checksum((unsigned short *) packet, 8);

        setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));

        bool f = true;
        struct sockaddr_in response_addr;
        socklen_t addr_len = sizeof(response_addr);
        char response[PACKET_SIZE];

        for (int i = 0; i < 3; ++i) {

            clock_t start, end;
            double t;
            start = clock();

            ssize_t bytes_sent = sendto(sockfd, packet, 8, 0,
                                        (struct sockaddr *) &target_addr, sizeof(target_addr));

            if (bytes_sent < 0) {
                perror("sendto");
                exit(EXIT_FAILURE);
            }

            struct timeval timeout;
            timeout.tv_sec = TIMEOUT_SEC;
            timeout.tv_usec = 0;

            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

            ssize_t bytes_received = recvfrom(sockfd, response, PACKET_SIZE, 0,
                                              (struct sockaddr *) &response_addr, &addr_len);

            if (bytes_received >= 0) {
                end = clock();
                t = ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
                if (f) {
                    printf("%d. %s  %.3f ms ", ttl, inet_ntoa(response_addr.sin_addr), t);
                    f = false;
                } else {
                    printf("%.3f ms ", t);
                }
            } else {
                if (f) {
                    printf("%d. *", ttl);
                    f = false;
                } else {
                    printf(" *");
                }

            }

            if (i == 2)
                printf("\n");

            fflush(stdout);
        }

        if (response_addr.sin_addr.s_addr == target_addr.sin_addr.s_addr) {
            printf("The target address is reached\n");
            break;
        }

        close(sockfd);
    }

    return 0;
}