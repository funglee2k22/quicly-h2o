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
#include <picotls/../../t/util.h>

static quicly_context_t server_ctx;
static quicly_cid_plaintext_t next_cid; 
quicly_conn_t *conns[256] = {NULL};
static size_t num_conns = 0;

conn_stream_pair_node_t mmap_head; 

static quicly_error_t server_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
static void server_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn,
	  int err, uint64_t frame_type, const char *reason, size_t reason_len);

static quicly_stream_open_t on_stream_open = {server_on_stream_open};
static quicly_closed_by_remote_t closed_by_remote = {server_on_conn_close};

static void server_on_stop_sending(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received STOP_SENDING: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    printf("func: %s, line: %d, entering\n", __func__, __LINE__); 
    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    int tcp_fd = find_tcp_conn(mmap_head.next, stream); 

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
    fprintf(stderr, "received RESET_STREAM: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void server_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn, int err,
    uint64_t frame_type, const char *reason, size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        fprintf(stderr, "transport close:code=0x%lu ;frame=%lu ;reason=%.*s\n", 
                QUICLY_ERROR_GET_ERROR_CODE(err), frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "application close:code=0x%lu ;reason=%.*s\n", 
                QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len, reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        fprintf(stderr, "stateless reset\n");
    } else 
        fprintf(stderr, "unexpected close:code=%d\n", err);
    return;
}

static quicly_error_t server_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
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

    quicly_debug_printf(stream->conn, "stream: %ld is openned.", stream->stream_id);

    return ret;
}

#define MSG_DONTWAIT 0x80 

static quicly_conn_t *find_conn(struct sockaddr *sa, socklen_t salen, quicly_decoded_packet_t *packet)
{
    for(size_t i = 0; i < num_conns; ++i) {
        if(quicly_is_destination(conns[i], NULL, sa, packet)) {
            return conns[i];
        }
    }
    return NULL;
}

#if 0 
static void append_conn(quicly_conn_t *conn)
{
    ++num_conns;
    conns = realloc(conns, sizeof(quicly_conn_t*) * num_conns);
    assert(conns != NULL);
    conns[num_conns - 1] = conn;

    *quicly_get_data(conn) = calloc(1, sizeof(int64_t));
}

static size_t remove_conn(size_t i)
{
    free(*quicly_get_data(conns[i]));
    quicly_free(conns[i]);
    memmove(conns + i, conns + i + 1, (num_conns - i - 1) * sizeof(quicly_conn_t*));
    --num_conns;
    return i - 1;
}
#endif 

int create_tcp_connection(const char *host, short port)
{
    int fd;
    struct sockaddr_in sa;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket failed");
        return -1;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, host, &sa.sin_addr);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("connect failed");
        close(fd);
        return -1;
    }

    return fd;
}

static void process_quicly_msg(int quic_fd, quicly_conn_t **conns, struct msghdr *msg, size_t dgram_len)
{
    size_t off = 0, i;

    fprintf(stderr, "func: %s, line: %d, received %ld bytes UDP message.\n", __func__, __LINE__, dgram_len);

    /* split UDP datagram into multiple QUIC packets */
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&server_ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off) == SIZE_MAX) { 
            return;
        } 

	    printf("decode len: %d, cid: %d, \n", decoded.datagram_size, decoded.cid); 
#if 0   
        fprintf(stderr, "decoded len: %d, cid: %d, msg.name: %s, msg.msg_iov[0].len: %d, msg: %s",
                decoded.datagram_size, decoded.cid, 
                inet_ntoa(((struct sockaddr_in *) msg ->msg_name)->sin_addr), 
                msg->msg_iov[0].iov_len, 
                msg->msg_iov[0].iov_base);
#endif 
        /* find the corresponding connection (TODO handle version negotiation, rebinding, retry, etc.) */
        for (i = 0; conns[i] != NULL; ++i)
            if (quicly_is_destination(conns[i], NULL, msg->msg_name, &decoded))
                break;
    
        if (conns[i] != NULL) {
            /* let the current connection handle ingress packets */
            quicly_receive(conns[i], NULL, msg->msg_name, &decoded);
    
        } else {
            /* assume that the packet is a new connection */
            quicly_accept(conns + i, &server_ctx, NULL, msg->msg_name, &decoded, NULL, &next_cid, NULL, NULL);
            quicly_debug_printf(conns[i], "accept new quic connection, and who will handle this message ?\n");
        }
    }
    
    return;
}

void run_server_loop(int quic_srv_fd) 
{
    fprintf(stdout, "starting server loop...\n"); 
    
    while (1) {
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
	
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(quic_srv_fd, &readfds); 

        if (select(quic_srv_fd + 1, &readfds, NULL, NULL, &tv) == -1) {
            fprintf(stderr, "func: %s, line: %d, select error on UDP server socket %d\n", __func__, __LINE__, quic_srv_fd);
            break;
        }
	    
        if (FD_ISSET(quic_srv_fd, &readfds)) {
            uint8_t buf[4096];
            struct sockaddr_storage sa;
            struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            ssize_t rret;
            while ((rret = recvmsg(quic_srv_fd, &msg, 0)) == -1 && errno == EINTR)
                ;
	        fprintf(stderr, "read %d bytes data from UDP sockets [%d]\n", rret, quic_srv_fd);
            if (rret > 0)
                process_quicly_msg(quic_srv_fd, conns, &msg, rret);
        } else { 
            printf("idling ....\n");
	}	
                
    }
error:
    close(quic_srv_fd);

}


void  setup_quicly_ctx(const char *cert, const char *key, const char *logfile)
{
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
    
    load_certificate_chain(server_ctx.tls, cert);
    load_private_key(server_ctx.tls, key);
   
    return; 
}

int main(int argc, char **argv)
{
    char *host = "127.0.0.1";     //quic server address 
    short udp_listen_port = 4433;   //port is quic server listening UDP port 
    char *cert_path = "server.crt";
    char *key_path = "server.key";

    setup_quicly_ctx(cert_path, key_path, NULL); 
    
    int quic_srv_fd = create_udp_listener(udp_listen_port); 
    if (quic_srv_fd < 0) {
        fprintf(stderr, "failed to create UDP listener.\n");
        exit(1);
    }

    printf("QPEP Server is running, pid: %lu, UDP listening port: %d, sk_fd: %d\n", 
            (uint64_t)getpid(), udp_listen_port, quic_srv_fd);
    
    run_server_loop(quic_srv_fd);

    return 0;
     
}  
