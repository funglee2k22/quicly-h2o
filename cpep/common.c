
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

ptls_context_t *get_tlsctx()
{
    static ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
                                    .get_time = &ptls_get_time,
                                    .key_exchanges = ptls_openssl_key_exchanges,
                                    .cipher_suites = ptls_openssl_cipher_suites,
                                    .require_dhe_on_psk = 1};
    return &tlsctx;
}


void _debug_printf(const char *function, int line, const char *fmt, ...)
{ 
    char buf[1024];
    va_list args;
    time_t current_time; 
    char time_string[50]; 
    

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    current_time = time(NULL);
    struct tm *time_info  = localtime(&current_time); 
    
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S" , time_info);
    fprintf(stdout, "%s, func: %s, line: %d, %s", time_string, function, line, buf);
    return;

}

int find_tcp_conn(conn_stream_pair_node_t *head, quicly_stream_t *stream)
{ 
    conn_stream_pair_node_t *p = head; 
    int i = 0; 
    while (p) {
        if (p->stream == stream)
            return p->fd;
	i++;
	p = p->next;
    }
    return -1;
}

int create_tcp_listener(short port)
{ 
    int fd;
    struct sockaddr_in sa;
    
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket failed");
        return -1;
    }
#if 0     
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return -1;
    }
#endif

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

int create_udp_client_socket(char *hostname, short port)
{
    int fd;
    struct sockaddr_in sa;
    struct hostent *hp;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket failed");
        return -1;
    }

    if ((hp = gethostbyname(hostname)) == NULL) {
        perror("gethostbyname failed");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, hp->h_addr, hp->h_length);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        perror("connect failed");
        return -1;
    }

    return fd;
}

int get_original_dest_addr(int fd, struct sockaddr_storage *sa)
{
    socklen_t salen = sizeof(*sa);

#ifndef SO_ORIGINAL_DST 
#define SO_ORIGINAL_DST 80
#endif

    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, sa, &salen) != 0) {
        perror("getsockopt(SO_ORIGINAL_DST) failed");
        return -1;
    }

    return 0;
}

bool send_dgrams_default(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams)
{
    for(size_t i = 0; i < num_dgrams; ++i) {
        struct msghdr mess = {
            .msg_name = dest,
            .msg_namelen = quicly_get_socklen(dest),
            .msg_iov = &dgrams[i], .msg_iovlen = 1
        };

        ssize_t bytes_sent;
        while ((bytes_sent = sendmsg(fd, &mess, 0)) == -1 && errno == EINTR);
        if (bytes_sent == -1) {
            perror("sendmsg failed");
            return false;
        }
    }

    return true;
}

bool send_dgrams(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams)
{
    for(size_t i = 0; i < num_dgrams; ++i) {
        struct msghdr mess = {
            .msg_name = dest,
            .msg_namelen = quicly_get_socklen(dest),
            .msg_iov = &dgrams[i], .msg_iovlen = 1
        };

        ssize_t bytes_sent;
        while ((bytes_sent = sendmsg(fd, &mess, 0)) == -1)
                ;

        if (bytes_sent == -1) {
            perror("sendmsg failed");
            return false;
        }

    }

    return true;
}

int quicly_send_msg(int quic_fd, quicly_stream_t *stream, void *buf, size_t len)
{ 
    if (stream == NULL || !quicly_sendstate_is_open(&stream->sendstate)) {
    	log_debug("stream: %ld, sendstate_is_open: 0 \n", stream->stream_id);
        return 0;
    }	

    quicly_streambuf_egress_write(stream, buf, len); 
    
    #define SEND_BATCH_SIZE 16
    quicly_address_t src, dst;
    struct iovec dgrams[SEND_BATCH_SIZE];
    uint8_t dgrams_buf[SEND_BATCH_SIZE * 1500];
    size_t num_dgrams = SEND_BATCH_SIZE;

    int quicly_res = quicly_send(stream->conn, &dst, &src, dgrams, &num_dgrams, &dgrams_buf, sizeof(dgrams_buf)); 

    if (quicly_res == 0) {
	if (num_dgrams == 0) { 
            log_debug("quicly_send() nothing to send.\n");
	    return 0;
	}
        if (!send_dgrams(quic_fd, &dst.sa, dgrams, num_dgrams)) { 
	    return -1;
	} 
    } else if (quicly_res == QUICLY_ERROR_FREE_CONNECTION) { 
        log_debug("quicly_send stream: %ld, ERROR_FREE_CONNECTION (res: 0x%4x).\n", stream->stream_id, quicly_res);
	//quicly_free(stream->conn);
	return -1;
    } else { 
        log_debug("quicly_send stream: %ld, failed with res: 0x%4x.\n", stream->stream_id, quicly_res);
        return -1;
    }
    
    return 0;
}
