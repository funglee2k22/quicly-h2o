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
#include <ev.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "common.h"


static quicly_context_t server_ctx;
static quicly_cid_plaintext_t next_cid; 

static quicly_stream_open_t on_stream_open = {&server_on_stream_open};
static quicly_closed_by_remote_t closed_by_remote = {&server_on_conn_close};

static void server_on_stop_sending(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    if (quicly_sendstate_is_open(&stream->sendstate) && (input.len > 0)) {
        quicly_streambuf_egress_write(stream, input.base, input.len);
        
        /* shutdown the stream after echoing all data */
        if (quicly_recvstate_transfer_complete(&stream->recvstate))
            quicly_streambuf_egress_shutdown(stream);
    }

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);
}

static void server_on_receive_reset(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void server_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn, int err,
    uint64_t frame_type, const char *reason, size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        fprintf(stderr, "transport close:code=0x%" PRIx16 ";frame=%" PRIu64 ";reason=%.*s\n", 
                QUICLY_ERROR_GET_ERROR_CODE(err), frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "application close:code=0x%" PRIx16 ";reason=%.*s\n", 
                QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len, reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        fprintf(stderr, "stateless reset\n");
    } else 
        fprintf(stderr, "unexpected close:code=%d\n", err);
    return;
}

static int server_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, 
        quicly_streambuf_egress_shift, 
        quicly_streambuf_egress_emit, 
        server_on_stop_sending, 
        server_on_receive,
        server_on_receive_reset
    };
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;
    stream->callbacks = &stream_callbacks;
    return 0;
}

#define MSG_DONTWAIT 0x80 

static void server_read_cb(EV_P_ ev_io *w, int revents)
{
    // retrieve data
    uint8_t buf[4096];
    struct sockaddr sa;
    socklen_t salen = sizeof(sa);
    quicly_decoded_packet_t packet;
    ssize_t bytes_received;

    while((bytes_received = recvfrom(w->fd, buf, sizeof(buf), MSG_DONTWAIT, &sa, &salen)) != -1) {
        for(ssize_t offset = 0; offset < bytes_received; ) {
            size_t packet_len = quicly_decode_packet(&server_ctx, &packet, buf, bytes_received, &offset);
            if(packet_len == SIZE_MAX) {
                break;
            }
            server_handle_packet(&packet, &sa, salen);
        }
    }

    if(errno != EWOULDBLOCK && errno != 0) {
        perror("recvfrom failed");
    }

    server_send_pending();
}


static void server_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    //TODO: implement timeout handling
    printf("PEP Server Timeout\n");
}

void  setup_quicly_ctx(const char *cert, const char *key, const char *logfile)
{
    int ret = 0; 

    setup_session_cache(get_tlsctx());
    quicly_amend_ptls_context(get_tlsctx());
    
    server_ctx = quicly_spec_context;
    server_ctx.tls = get_tlsctx();
    server_ctx.stream_open = &on_stream_open;
    server_ctx.closed_by_remote = &closed_by_remote;
    server_ctx.transport_params.max_stream_data.uni = UINT32_MAX;
    server_ctx.transport_params.max_stream_data.bidi_local = UINT32_MAX;
    server_ctx.transport_params.max_stream_data.bidi_remote = UINT32_MAX;
    server_ctx.init_cc = &quicly_cc_cubic_init;
    server_ctx.initcwnd_packets = 10; 
    
    if (logfile)
        setup_log_event(server_ctx, logfile); 
    
    load_certificate_chain(server_ctx.tls, cert);
    load_private_key(server_ctx.tls, key);
   
    return; 
}




void run_server_loop(int quic_srv_fd)
{
    quicly_conn_t *conns[256] = {NULL}; 
    quicly_conn_t *client = NULL;
    quicly_stream_t *stream = NULL;

    int tcp_fd; 

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds); 
        FD_SET(quic_srv_fd, &readfds);
        if (tcp_fd > 0) {
            FD_SET(tcp_fd, &readfds);
        }

        if (select(tcp_fd > quic_srv_fd ? tcp_fd + 1 : quic_srv_fd + 1, &readfds, NULL, NULL, NULL) == -1) {
            perror("select failed");
            break;
        }

        if (tcp_fd > 0 && FD_ISSET(tcp_fd, &readfds)) {
            // handle TCP connection 
            from_tcp_to_quic(tcp_fd, quic_srv_fd, client, stream);
        }

        if (FD_ISSET(quic_srv_fd, &readfds)) {
            // handle QUIC connection 
            from_quic_to_tcp(quic_srv_fd, tcp_fd, client, stream);
        }
    }
    return; 
}


static ev_timer server_timeout; 

int main(int argc, char **argv)
{
    char *host = "127.0.0.1";     //quic server address 
    short udp_listen_port = 8443;   //port is quic server listening UDP port 
    char *cert_path = "server.crt";
    char *key_path = "server.key";
    int ret = 0;

    setup_quicly_ctx(cert_path, key_path, NULL); 
    
    int quic_srv_fd = create_udp_listener(udp_listen_port); 
    if (quic_srv_fd < 0) {
        fprintf(stderr, "failed to create UDP listener.\n");
        exit(1);
    } 

    int reuseaddr = 1;
    struct sockaddr_storage sa;
    socklen_t salen;
    memset(&sa, 0, sizeof(sa));
    sa.ss_family = AF_INET;
    ((struct sockaddr_in *)&sa)->sin_port = htons(udp_listen_port);
    salen = sizeof(struct sockaddr_in);

    setsockopt(quic_srv_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
    if (bind(quic_srv_fd, (struct sockaddr *)&sa, salen) != 0) {
        perror("bind(2) failed");
        exit(1);
    }

    printf("QPEP Server is running, pid = %" PRIu64 ", port = %d\n", 
            (uint64_t)getpid(), udp_listen_port);
    
    run_server_loop(quic_srv_fd);

    return 0;
     
}  

