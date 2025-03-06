#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "quicly.h" 
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"


typedef struct { 
    struct sockaddr_storage addr;
} pep_header_t;


 

ptls_context_t *get_tlsctx(); 

int create_udp_listener(short port);
int create_udp_client_socket(char *hostname, short port, struct sockaddr_storage *sa, socklen_t *salen);

int create_tcp_listener(short port);
int create_tcp_client_socket(char *hostname, short port, struct sockaddr_storage *sa, socklen_t *salen);


int create_quic_client_stream(quicly_conn_t *client, quicly_stream_t *stream, char *host, struct sockaddr_storage *sa);
int create_quic_server_stream(quicly_conn_t *server, quicly_stream_t *stream, struct sockaddr_storage *sa);

int server_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);






