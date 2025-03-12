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
    quicly_stream_t *stream; 
} worker_data_t; 

int create_tcp_listener(short port);

int create_udp_client_socket(char *hostname, short port);

bool send_dgrams_default(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams);

