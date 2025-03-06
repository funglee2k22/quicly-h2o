
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
#include "common.h"


static quicly_context_t client_ctx;
static quicly_cid_plaintext_t next_cid; 

static void process_msg(quicly_conn_t **conns, struct msghdr *msg, size_t dgram_len)
{
    size_t off = 0, i;

    /* split UDP datagram into multiple QUIC packets */
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&client_ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off) == SIZE_MAX)
            return;
        /* find the corresponding connection (TODO handle version negotiation, rebinding, retry, etc.) */
        for (i = 0; conns[i] != NULL; ++i)
            if (quicly_is_destination(conns[i], NULL, msg->msg_name, &decoded))
                break;
        if (conns[i] != NULL) {
            /* let the current connection handle ingress packets */
            quicly_receive(conns[i], NULL, msg->msg_name, &decoded);
        }
    }
}


void from_tcp_to_quic(int tcp_fd, int quic_fd, quicly_conn_t *client, quicly_stream_t *stream)
{
    uint8_t buf[4096];
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    ssize_t rret;

    if ((rret = recvfrom(tcp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&sa, &salen)) == -1) {
        perror("recvfrom failed");
        return;
    } 

    if (quicly_send(client, stream, buf, sizeof(buf)) != 0) {
        perror("quicly_send failed");
        return;
    }

    return;
}



void from_quic_to_tcp(int quic_fd, int tcp_fd, quicly_conn_t *client, quicly_stream_t *stream)
{
    
    quicly_conn_t *conns[256] = {client}; 
    uint8_t buf[4096];
    struct sockaddr_storage sa;
    struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
    ssize_t rret;
    
    while ((rret = recvmsg(quic_fd, &msg, 0)) == -1 && errno == EINTR)
        ;
    
    if (rret > 0)
        process_msg(conns, &msg, rret);
    
    send(tcp_fd, buf, sizeof(buf), 0);
    
    return;
}   


/*
 *  thread to handle one set connections, TCP conn and QUIC conn 
 *  @param data the thread data 
 *  @return NULL
 */
 void handle_client(int tcp_fd, char *host, short port) 
{
    int ret = 0;

    struct sockaddr_storage orig_dst;
    if (get_original_dest_addr(tcp_fd, &orig_dst) != 0) {
        perror("failed to get original destination address");
        goto error;
    }

    int quic_fd;
    struct sockaddr_storage sa;
    socklen_t salen;

    quic_fd = create_udp_client_socket(host, port, &orig_dst, sizeof(orig_dst));
    if (quic_fd < 0) {
        perror("failed to create UDP socket for QUIC");
        goto error;
    }

    quicly_conn_t *client = NULL;
    quicly_stream_t *stream = NULL;
    if (create_quic_clt_stream(client, stream, host, &sa) != 0) {
        perror("failed to create QUIC stream");
        goto error;
    }

    // send the first message (pep header) to the server, server will use this infor
    // to a create a new TCP connection towards the Internet server.  
    pep_header_t pep_header = { .addr = orig_dst };

    if (send_quicly_message(stream, (void *) &pep_header, sizeof(pep_header)) != 0) {
        perror("failed to send PEP header");
        goto error;
    }

    // big select loop to handle both TCP and QUIC connections 
    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tcp_fd, &readfds);
        FD_SET(quic_fd, &readfds);

        if (select(tcp_fd > quic_fd ? tcp_fd + 1 : quic_fd + 1, &readfds, NULL, NULL, NULL) == -1) {
            perror("select failed");
            goto error;
        }

        if (FD_ISSET(tcp_fd, &readfds)) {
            // handle TCP connection 
            from_tcp_to_quic(tcp_fd, quic_fd, client, stream);
        }

        if (FD_ISSET(quic_fd, &readfds)) {
            // handle QUIC connection 
            from_quic_to_tcp(quic_fd, tcp_fd, client, stream);
        }
    }

    //TODO: add signal handling here and should send all the pending data before exit
    
error:
    close(tcp_fd);
    close(quic_fd); 

    return;
}


int run_client_loop(int listen_fd, char *quic_srv, short quic_port)
{
    struct sockaddr_in tcp_remote_addr;
    socklen_t tcp_addr_len = sizeof(tcp_remote_addr); 
    int ret = 0;
    pid_t pid;
    
    while (1) { 
        int client_fd = accept(listen_fd, (struct sockaddr *)&tcp_remote_addr, &tcp_addr_len);
        if (client_fd < 0) {
            perror("accept: ");
            close(listen_fd);
            return -1;
        }
        
        pid = fork();

        if (!pid) { 
            close(listen_fd);
            handle_client(client_fd, quic_srv, quic_port);
        } else if (pid > 0) { 
            close(client_fd);
        } else {
            perror("fork: ");
            close(listen_fd);
            return -1;
        }
    }
    return 0;
}

static void client_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn, int err,
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
    } else {
        fprintf(stderr, "unexpected close:code=%d\n", err);
    }
}

static void client_on_stop_sending(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void client_on_receive_reset(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
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

static int client_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, 
        quicly_streambuf_egress_shift, 
        quicly_streambuf_egress_emit, 
        client_on_stop_sending, 
        client_on_receive,
        client_on_receive_reset
    };
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;
    stream->callbacks = &stream_callbacks;
    return 0;
}


static quicly_stream_open_t stream_open = {&client_on_stream_open};
static quicly_closed_by_remote_t closed_by_remote = {&client_on_conn_close}; 

int setup_client_ctx()
{ 
    setup_session_cache(get_tlsctx()); 
    quicly_amend_ptls_context(get_tlsctx());
    
    client_ctx = quicly_spec_context;
    client_ctx.tls = get_tlsctx();
    client_ctx.stream_open = &stream_open;
    client_ctx.closed_by_remote = &closed_by_remote;
    client_ctx.transport_params.max_stream_data.uni = UINT32_MAX;
    client_ctx.transport_params.max_stream_data.bidi_local = UINT32_MAX;
    client_ctx.transport_params.max_stream_data.bidi_remote = UINT32_MAX;
    client_ctx.initcwnd_packets = 10;
    client_ctx.init_cc = &quicly_cc_cubic_init;

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

    setup_client_ctx(); 

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
