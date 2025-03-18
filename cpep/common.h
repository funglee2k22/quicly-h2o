#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "quicly.h" 
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include <picotls/../../t/util.h>

typedef struct { 
    struct sockaddr_storage addr;
} pep_header_t;

typedef struct conn_stream_pair { 
    int fd;
    quicly_stream_t *stream;
} conn_stream_pair_t;

struct conn_stream_pair_node;
typedef struct conn_stream_pair_node { 
    int fd;
    quicly_stream_t *stream;
    struct conn_stream_pair_node *next;
} conn_stream_pair_node_t;

typedef struct pthread_work { 
    int tcp_fd;
    int quic_fd;
    quicly_conn_t *conn; 
    quicly_stream_t *stream; 
} worker_data_t; 

void __debug_printf(quicly_conn_t *conn, const char *function, int line, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

#ifdef quicly_debug_printf
#undef quicly_debug_printf
#endif 

#define quicly_debug_printf(conn, ...)  __debug_printf((conn), __FUNCTION__, __LINE__, __VA_ARGS__)

int find_tcp_conn(conn_stream_pair_node_t *head, quicly_stream_t *stream);

ptls_context_t *get_tlsctx();

int create_tcp_listener(short port);

int create_udp_client_socket(char *hostname, short port);

bool send_dgrams_default(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams);

