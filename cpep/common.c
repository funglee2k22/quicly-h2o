
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <memory.h>
//#include "picotls/openssl.h"
#include <errno.h>
//#include <ev.h>
#include "common.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

typedef struct
{
    uint64_t target_offset;
    uint64_t acked_offset;
    quicly_stream_t *stream;
    int report_id;
    int report_second;
    uint64_t report_num_packets_sent;
    uint64_t report_num_packets_lost;
    uint64_t total_num_packets_sent;
    uint64_t total_num_packets_lost;
    //ev_timer report_timer; 
} server_stream;

ptls_context_t *get_tlsctx()
{
    static ptls_context_t tlsctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
        .require_dhe_on_psk = 1
    };

    return &tlsctx;
}

int create_tcp_listener(short port)
{ 
    int fd;
    struct sockaddr_in sa;
    
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket failed");
        return -1;
    }
     
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return -1;
    }


    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &(int){1}, sizeof(int)) != 0) {
        perror("setsockopt(IP_TRANSPARENT) failed");
        return -1;
    }
    
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (void *)&sa, sizeof(sa)) != 0) {
        perror("bind failed");
        return -1;
    }

    if (listen(fd, 128) != 0) {
        perror("listen failed");
        return -1;
    }

    return fd;
}

int create_udp_listener(short port)
{
    int fd;
    struct sockaddr_in sa;
    int reuseaddr = 1;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket failed");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return -1;
    }

    if (bind(fd, (void *)&sa, sizeof(sa)) != 0) {
        perror("bind failed");
        return -1;
    }

    return fd;
}


int create_udp_client_socket(char *hostname, short port, struct sockaddr_storage *sa, socklen_t *salen) 
{
    int fd = -1;
    struct sockaddr_in local;

    if (resolve_address((struct sockaddr *)sa, salen, hostname, port, AF_INET, SOCK_DGRAM, 0) != 0)
        return -1;

    if ((fd = socket(sa->ss_family, SOCK_DGRAM, 0)) == -1) {
        perror("socket(2) failed");
        return -1;
    }
    
    memset(&local, 0, sizeof(local)); 
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        perror("bind(2) failed");
        return -1;
    }

    return fd;
}


int send_quicly_msg(quicly_conn_t *conn, const void *data, size_t len)
{
    if (!quicly_connection_is_ready(conn)) { 
        fprintf(stderr, "quicly connection is not ready\n");
        return -1;
    } 
    
    ptls_iovec_t datagram = ptls_iovec_init(data, len);
    quicly_send_datagram_frames(conn, &datagram, 1);

    fprintf(stdout, "sent QUIC message of size: %ld\n", len);        
    return 0;
}

int get_original_dest_addr(int fd, struct sockaddr_storage *sa)
{
    socklen_t salen = sizeof(*sa);

#ifndef SO_ORIGINAL_DST 
#define SO_ORIGINAL_DST 80 
    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, sa, &salen) != 0) {
        perror("getsockopt(SO_ORIGINAL_DST) failed");
        return -1;
    }
#endif 
    return 0;
}


int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const short port, int family, int type,
                           int proto)
{
    struct addrinfo hints, *res;
    char str_port[10] = {0}; 
    int err;

    snprintf(str_port, sizeof(str_port), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(host, str_port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, str_port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }

    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}
