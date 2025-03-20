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

static void ctrl_stream_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{ 
    fprintf(stderr, "func: %s, line: %d, stream: [%d] received control message.\n",
             __func__, __LINE__, stream->stream_id);

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0) {
        fprintf(stderr, "no data in control stream receive buffer.\n");
        return;
    } 

    fprintf(stderr, "QUIC control stream [%d], bytes_received: %zu\n", stream->stream_id, input.len);
    fprintf(stderr, "ctrl msg: %.*s\n", (int)input.len, (char *)input.base);

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);

    return;
}

void *handle_isp_server(void *data)
{  
    quicly_conn_t *quic_conn = ((worker_data_t *) data)->conn; 
    quicly_stream_t *quic_stream = ((worker_data_t *) data)->stream;
    int tcp_fd = ((worker_data_t *) data)->tcp_fd;
    int quic_fd = ((worker_data_t *) data)->quic_fd;  /* quic_fd is not used here. */

    while (1) { 
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tcp_fd, &readfds);

        if (select(tcp_fd + 1, &readfds, NULL, NULL, NULL) == -1) {
            fprintf(stderr, "func: %s, line: %d, thread_id: %d, [tcp: %d -> stream: %d] select filed.",  
                __func__, __LINE__, pthread_self(), tcp_fd, quic_stream->stream_id);
            perror("select failed");
            goto error;
        }

        if (FD_ISSET(tcp_fd, &readfds)) {
            char buff[4096];
            int bytes_received = read(tcp_fd, buff, sizeof(buff)); 
            if (bytes_received < 0) { 
                quicly_debug_printf(quic_stream->conn, "[tcp: %d -> stream: %ld] tcp side error.\n", tcp_fd, quic_stream->stream_id);
                goto error;
            }
            
            if (!quicly_sendstate_is_open(&quic_stream->sendstate) && (bytes_received > 0))
                quicly_get_or_open_stream(quic_stream->conn, quic_stream->stream_id, &quic_stream);

            if (quic_stream && quicly_sendstate_is_open(&quic_stream->sendstate) && (bytes_received > 0)) {
                quicly_streambuf_egress_write(quic_stream, buff, bytes_received);
                
                /* shutdown the stream after echoing all data */
                //if (quicly_recvstate_transfer_complete(&quic_stream->recvstate))
                //    quicly_streambuf_egress_shutdown(quic_stream);
                
                fprintf(stdout, "[tcp: %d -> stream: %ld] write %d bytes to quic stream: %d.\n", 
                        tcp_fd, quic_stream->stream_id, bytes_received, quic_stream->stream_id);
            } else { 
                fprintf(stderr, "[tcp: %d -> stream: %ld] quic stream is closed or no data to write.\n", 
                        tcp_fd, quic_stream->stream_id);
                break; 
            }
        }
    }

error:
    close(tcp_fd);
    //TODO close QUIC stream also
    free(data);
    return NULL;
}

static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    printf("func: %s, line: %d, stream: [%d] received QUIC message.\n",
             __func__, __LINE__, stream->stream_id);

    if (stream->stream_id == 0) {
        /* control stream, handle it separately */
        ctrl_stream_on_receive(stream, off, src, len);
        return;
    }       
 
    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    if (input.len == 0) {
        fprintf(stderr, "no data in receive buffer.\n");
        return;
    }

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);

    fprintf(stderr, "QUIC stream [%d], bytes_received: %d,\n", stream->stream_id, input.len);

    int tcp_fd = find_tcp_conn(mmap_head.next, stream); 
    while (tcp_fd < 0) {
        fprintf(stderr, "no TCP connection found for QUIC stream [%d].\n", stream->stream_id);
        ////assume the first 16 bytes of QUIC message is the original destination address
        struct sockaddr_storage orig_dst;
        socklen_t len = sizeof(orig_dst);
        memcpy(&orig_dst, input.base, len);

        fprintf(stderr, "TCP original destination: %s:%d\n", 
                inet_ntoa(((struct sockaddr_in *)&orig_dst)->sin_addr), 
                ntohs(((struct sockaddr_in *)&orig_dst)->sin_port));
        
        tcp_fd = create_tcp_connection((struct sockaddr *)&orig_dst);
        if (tcp_fd < 0) {
            fprintf(stderr, "failed to create TCP connection to original destination.\n");
            break;     
        }

        conn_stream_pair_node_t  *node = (conn_stream_pair_node_t *)malloc(sizeof(conn_stream_pair_node_t));
        node->fd = tcp_fd;
        node->stream = stream;
        node->next = mmap_head.next;
        mmap_head.next = node;

        worker_data_t *data = (worker_data_t *)malloc(sizeof(worker_data_t));
        data->tcp_fd = tcp_fd;
        data->conn = stream->conn;
        data->stream = stream; 
        //data->quic_fd = stream->conn->sockfd;

        pthread_t worker_thread;
        pthread_create(&worker_thread, NULL, handle_isp_server, (void *)data);
    
        fprintf(stdout, "func: %s, line: %d, worker: %ld, handle [quic: %ld <- tcp: %d]\n", 
                           __func__, __LINE__, worker_thread, stream->stream_id, tcp_fd);
    }

    if (tcp_fd > 0 && input.len > 0) {
        ssize_t bytes_sent = send(tcp_fd, input.base, input.len, 0);    
        if (bytes_sent == -1) { 
            fprintf(stderr, "[stream: %ld -> tcp: %d], tcp send() failed\n", stream->stream_id, tcp_fd);
            close(tcp_fd);
            return;
        }
        fprintf(stdout, "[stream: %ld -> tcp: %d], bytes: %zu sent\n", stream->stream_id, tcp_fd, bytes_sent);
    }

    return;
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

    quicly_debug_printf(stream->conn, "stream: %ld is openned.\n", stream->stream_id);

    return ret;
}

int create_tcp_connection(struct sockaddr *sa)
{ 
    int fd;
   
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket failed");
        return -1;
    }

    
    if (connect(fd, sa, sizeof(struct sockaddr)) == -1) {
        perror("connect failed");
        close(fd);
        return -1;
    }

    return fd;
}

#if 0
int create_tcp_connection(char *host, short port)
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
#endif

static void process_quicly_msg(int quic_fd, quicly_conn_t **conns, struct msghdr *msg, size_t dgram_len)
{
    size_t off = 0, i;

    /* split UDP datagram into multiple QUIC packets */
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&server_ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off) == SIZE_MAX) { 
            return;
        } 

        for (i = 0; conns[i] != NULL; ++i)
            if (quicly_is_destination(conns[i], NULL, msg->msg_name, &decoded))
                break;

        if (conns[i] != NULL) {
            /* let the current connection handle ingress packets */
            quicly_debug_printf(conns[i], "reuse the current connection.\n"); 
            quicly_receive(conns[i], NULL, msg->msg_name, &decoded);
        } else {
            /* assume that the packet is a new connection */
            quicly_accept(conns + i, &server_ctx, NULL, msg->msg_name, &decoded, NULL, &next_cid, NULL, NULL);
            quicly_debug_printf(conns[i], "find a new connection.\n"); 
        }
    }
    
    return;
}

void run_server_loop(int quic_srv_fd) 
{
    fprintf(stdout, "starting server loop...\n"); 
    
    while (1) {
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0}; 
        fd_set readfds;

        do {
            FD_ZERO(&readfds);
            FD_SET(quic_srv_fd, &readfds); 
        } while (select(quic_srv_fd + 1, &readfds, NULL, NULL, &tv) == -1 && errno == EINTR);
        
        
        if (FD_ISSET(quic_srv_fd, &readfds)) {
            uint8_t buf[4096];
            struct sockaddr_storage sa;
            struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            ssize_t rret;
            while ((rret = recvmsg(quic_srv_fd, &msg, 0)) == -1 && errno == EINTR)
                ;
            fprintf(stderr, "read %ld bytes data from UDP sockets [%d]\n", rret, quic_srv_fd);
            if (rret > 0)
                process_quicly_msg(quic_srv_fd, conns, &msg, rret);
        } /* End of if (FD_ISSET(quic_srv_fd, &readfds)) */ 

        /* send QUIC packets, if any */
        for (size_t i = 0; conns[i] != NULL; ++i) {
            quicly_address_t dest, src;
            struct iovec dgrams[10];
            uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * server_ctx.transport_params.max_udp_payload_size];
            size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
            int ret = quicly_send(conns[i], &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));
            switch (ret) {
            case 0: {
                size_t j;
                for (j = 0; j != num_dgrams; ++j) {
                    struct msghdr mess = {.msg_name = &dest.sa, .msg_namelen = quicly_get_socklen(&dest.sa), 
                                          .msg_iov = &dgrams[j], .msg_iovlen = 1};
                    sendmsg(quic_srv_fd, &mess, MSG_DONTWAIT);
                }
                break;
            }
            case QUICLY_ERROR_FREE_CONNECTION:
                fprintf(stderr, "free connection\n");
                quicly_free(conns[i]);
                conns[i] = NULL;
                break;
            default:
                fprintf(stderr, "quicly_send returned with error %d\n", ret);
                goto error;
            }
        } /* End of for (size_t i = 0; conns[i] != NULL; ++i) */
                
    } /* End of While loop */

error:

    close(quic_srv_fd);

}


void  setup_quicly_ctx(const char *cert, const char *key, const char *logfile)
{
    setup_session_cache(get_tlsctx());
    quicly_amend_ptls_context(get_tlsctx()); 

    server_ctx = quicly_spec_context;
    server_ctx.tls = get_tlsctx();
    quicly_amend_ptls_context(server_ctx.tls);
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


    quicly_stream_open_t stream_open = {server_on_stream_open};

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
