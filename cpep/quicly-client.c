
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

typedef struct { 
    struct sockaddr_in addr;
    short port; 
} pep_header_t;

typedef struct {
    int tcp_sk; //
    char *quic_srv; 
    short quic_srv_port;  
} thread_data_t;

//global variables 
static quicly_context_t ctx;  //the QUIC context
static quicly_cid_plaintext_t next_cid; // the CID seed 

int create_tcp_listener(short port); 
void run_loop(int fd); 
void *handle_client(void *data);

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
static int on_stream_ready(quicly_stream_t *stream);
static void on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
static void on_stop_sending(quicly_stream_t *stream, int err);
static void on_receive_reset(quicly_stream_t *stream, int err);

static int load_private_key(ptls_openssl_sign_certificate_t *psign_certificate, char *key_path); 
static int load_certificates(ptls_context_t *tlsctx, char *cert_path);
static int setup_ctx_quic(char *cert_path, char *key_path);

int create_udp_clt_socket(char *hostname, short port, struct sockaddr_storage *sa, socklen_t *salen);
int create_quic_clt_stream(quicly_conn_t *client, quicly_stream_t *stream, char *host, struct sockaddr_storage *sa);


int create_tcp_listener(short port) 
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY; 

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket() :");
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) { 
        perror("setsockopt (SO_REUSEADDR): ");
        close(fd);
        return -1;
    }

    //SOL_IP is not defained on MacOS 
    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &(int){1}, sizeof(int)) < 0) {  
        perror("setsockopt (IP_TRANSPARENT): ");
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 10) < 0) {
        perror("listen: ");
        close(fd);
        return -1;
    }

    return fd;
}



static void on_stop_sending(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive_reset(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, on_stop_sending, on_receive,
        on_receive_reset};
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;
    stream->callbacks = &stream_callbacks;
    return 0;
}

static void on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    fwrite(input.base, 1, input.len, stdout);
    fflush(stdout);
    
    /* initiate connection close after receiving all data */
    if (quicly_recvstate_transfer_complete(&stream->recvstate))
        quicly_close(stream->conn, 0, "");
    
    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);
}

static int on_stream_ready(quicly_stream_t *stream)
{
    /* send the input to the active stream */
    assert(stream != NULL);
    //TODO: implement this function
    return 0;
}
/*
*/
static int load_private_key(ptls_openssl_sign_certificate_t *psign_certificate, char *key_path)
{
    FILE *fp;
    if ((fp = fopen(key_path, "r")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", key_path, strerror(errno));
        return -1;
    }
    
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (pkey == NULL) {
        fprintf(stderr, "failed to load private key from file:%s\n", optarg);
        exit(1);
    }
            
    ptls_openssl_init_sign_certificate(psign_certificate, pkey);
    EVP_PKEY_free(pkey);

    return 0;
}

static int load_certificates(ptls_context_t *tlsctx, char *cert_path)
{
    int ret;
    if ((ret = ptls_load_certificates(tlsctx, cert_path)) != 0) {
        fprintf(stderr, "failed to load certificates from file %s:%d\n", cert_path, ret);
        return -1;
    }
    return 0; 
}

/*
 * setup the QUIC and quicly context
 * note: ctx is a global variable 
 */
static int setup_ctx_quic(char *cert_path, char *key_path)
{
    int ret = 0;
    //ctx is the global variable  
    ptls_openssl_sign_certificate_t sign_certificate; 
    ptls_context_t tlsctx = { 
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
    };
    quicly_stream_open_t stream_open = {on_stream_open};

    /* setup quic context */
    ctx = quicly_spec_context;
    ctx.tls = &tlsctx;
    quicly_amend_ptls_context(ctx.tls);
    ctx.stream_open = &stream_open;

    /* load certificates chain */
    if ((ret = load_certificates(&tlsctx, cert_path)) != 0) {
        fprintf(stderr, "failed to load certificates from file %s:%d\n", cert_path, ret);
        return ret;
    }

    /* load private key */
    if ((ret = load_private_key(&sign_certificate, key_path)) != 0) {
        fprintf(stderr, "failed to load private key from file:%s\n", key_path);
        return ret;
    }

    tlsctx.sign_certificate = &sign_certificate.super;

    if ((tlsctx.certificates.count != 0) != (tlsctx.sign_certificate != NULL)) {
        perror("TLS key and certificates must be used together");
        return -1;
    }

    return ret;
}
/* 
 * create a UDP client socket used by QUIC 
 * @param hostname the hostname of the server
 * @param port the listening port number of the server 
 * @return the file descriptor of the UDP socket 
 */
int create_udp_clt_socket(char *hostname, short port, struct sockaddr_storage *sa, socklen_t *salen) 
{
    int fd;
    struct sockaddr_in local; 
    if (resolve_address((struct sockaddr *)sa, salen, hostname, port, AF_INET, SOCK_DGRAM, 0) != 0)
        return -1;

    /* open socket, on the specified port (as a server), or on any port (as a client) */
    if ((fd = socket(sa.ss_family, SOCK_DGRAM, 0)) == -1) {
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

int create_quic_clt_stream(quicly_conn_t *client, quicly_stream_t *stream, 
                           char *host, struct sockaddr_storage *sa)  
{ 
    int ret = 0; 
   
    if ((ret = quicly_connect(&client, &ctx, host, (struct sockaddr *)&sa, NULL, &next_cid, ptls_iovec_init(NULL, 0), NULL,
                                  NULL, NULL)) != 0) {
        fprintf(stderr, "quicly_connect failed:%d\n", ret);
        return -1;
    }
    
    quicly_open_stream(client, &stream, 0);
    
    return 0; 
}

int create_quic_client(quicly_stream_t *stream, quicly_conn_t *client,
                       struct sockaddr_storge *sa, socklen_t *salen,
                       char *host, short port)
{   
    int quic_fd, ret = 0;
    quic_fd = create_udp_clt_socket(host, port, sa, salen); 
    if (quic_fd < 0) {
        perror("failed to create UDP socket for QUIC");
        return -1;
    }

    ret = create_quic_clt_stream(client, stream, host, sa);
    if (ret != 0) { 
        perror("failed to create QUIC stream");
        return -1;   
    }
    return 0;
} 
 

void *handle_client(void *data) 
{
    thread_data_t *d = (thread_data_t *)data;
    int clt_fd = d->tcp_sk;      //incoming TCP socket 
    char *quic_srv = d->quic_srv;
    short quic_port = d->quic_srv_port;
    quicly_stream_t *stream;
    quicly_conn_t *client = NULL;
    struct sockaddr_storage sa;
    socklen_t salen;
    int ret = 0;

    ret = create_quic_client(stream, client, &sa, &salen, quic_srv, quic_port); 
    if (ret != 0) {
        perror("failed to create QUIC client");
        goto error;
    }
    
    //fill pep header, send pep header, and setup pip between to sockets; 
    //TODO: 
    
error:
    close(clt_fd);
    free(data);
    return NULL;
}




int run_client_loop(int listen_fd, char *quic_srv, short quic_port)
{
    struct sockaddr_in tcp_remote_addr;
    socklen_t tcp_addr_len = sizeof(tcp_remote_addr); 
    int ret = 0;
    
    while (1) { 
        int client_fd = accept(listen_fd, (struct sockaddr *)&tcp_remote_addr, &tcp_addr_len);
        if (client_fd < 0) {
            perror("accept: ");
            close(listen_fd);
            return -1;
        } 
        printf("Accepted connection from %s:%d\n", inet_ntoa(tcp_remote_addr.sin_addr), ntohs(tcp_remote_addr.sin_port));
        //create a new thread to handle the connection
        pthread_t thread;
        thread_data_t *data = (thread_data_t *)malloc(sizeof(data));
        if (data == NULL) { 
            perror("Failed to allocated memory for thread data. malloc: ");
            close(client_fd);
            continue;
        } 

        data->tcp_sk = client_fd;
        data->quic_srv = quic_srv; 
        data->quic_srv_port = quic_port;

        if (pthread_create(&thread, NULL, handle_client, (void *)data) != 0) {
            perror("Failed to create thread: ");
            close(client_fd);
            free(data);
            continue;
        }
        pthread_detach(thread);
    }
    return 0;
}





int main(int argc, char **argv)
{ 
    char *host = "127.0.0.1";     //quic server address 
    short port = 4433, tcp_listen_port = 443;   //port is quic server listening UDP port 
    char *cert_path = "server.crt";
    char *key_path = "server.key";
    
    int tcp_fd, quic_fd;  
    quicly_stream_t *stream;
    quicly_conn_t *client = NULL;
    int ret = 0;

    //TODO: resolve command line options and arguments
    //setup the quic and quicly context 
    //ctx is a global variable will be modifed by this function.  
    if ((ret = setup_ctx_quic(cert_path, key_path)) != 0) {
        fprintf(stderr, "failed to setup quic context: %d.\n", ret);
        exit(1);
    }

    //create a TCP listener 
    tcp_fd = create_tcp_listener(tcp_listen_port);
    if (tcp_fd < 0) {
        perror("failed to create TCP listener and terminating");
        exit(1);
    }

    run_client_loop(tcp_fd, host, port); 

    // TODO: add ing SIGNAL handling here
    close(tcp_fd); 

    return 0;
}
