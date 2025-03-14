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
quicly_conn_t **conns = {NULL};
static size_t num_conns = 0;

struct conn_map_t; 
typedef struct conn_map_t { 
    quicly_conn_t *conn;
    int tcp_fd; 
    struct conn_map_t *next; 
} conn_map_t; 

conn_map_t *conn_map_head = NULL;  

quicly_conn_t **conn = NULL;

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
    return 0;
}

#define MSG_DONTWAIT 0x80 


void handle_tcp_msg(int tcp_fd, quicly_conn_t *client)
{
    uint8_t buf[4096];
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    ssize_t rret;

    if ((rret = recvfrom(tcp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&sa, &salen)) == -1) {
        perror("recvfrom failed");
        return;
    }

    if (send_quicly_msg(client, buf, sizeof(buf)) != 0) {
        perror("quicly_send failed");
        return;
    }

    return;
}

static quicly_conn_t *find_conn(struct sockaddr *sa, socklen_t salen, quicly_decoded_packet_t *packet)
{
    for(size_t i = 0; i < num_conns; ++i) {
        if(quicly_is_destination(conns[i], NULL, sa, packet)) {
            return conns[i];
        }
    }
    return NULL;
}

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


static void handle_quicly_packet(quicly_decoded_packet_t *packet, struct sockaddr *sa, socklen_t salen)
{
    quicly_conn_t *conn = find_conn(sa, salen, packet);

    if(conn == NULL) {
        //new connect 
        int ret = quicly_accept(&conn, &server_ctx, 0, sa, packet, NULL, &next_cid, NULL, NULL);
        if(ret != 0) {
            fprintf(stderr, "quicly_accept failed with code %i\n", ret);
            return;
        }
        ++next_cid.master_id;
        fprintf(stdout, "got new connection \n");
        append_conn(conn); 

        // for new connection, the payload its the original destination IP and port 
        struct sockaddr *din = (struct sockaddr *) packet->octets.base; 
        //socklen_t din_len = packet->octets.len; 
        int tcp_fd = create_tcp_connection(inet_ntoa(((struct sockaddr_in *)din)->sin_addr), 
                            ntohs(((struct sockaddr_in *)din)->sin_port));

        if (tcp_fd < 0) {
            fprintf(stderr, "failed to create TCP connection.\n");
            exit(1);
        }

        //TODO: need to implement a hash map to store the connection pair. 
        conn_map_t *p = malloc(sizeof(conn_map_t)); 
        p->tcp_fd = tcp_fd;
        p->conn = conn;
        p->next = conn_map_head;
        conn_map_head = p; 
    
    } else {
        int ret = quicly_receive(conn, NULL, sa, packet);
        if(ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED) {
            fprintf(stderr, "quicly_receive returned %i\n", ret);
            exit(1);
        }
        conn_map_t *p = conn_map_head;
        int tcp_fd = -1; 
        while (p) { 
            if (p->conn == conn) {
                tcp_fd = p->tcp_fd;
                break;
            }
            p = p->next;
        } 
        if (tcp_fd > 0) {
            int ssize = send(tcp_fd, packet->octets.base, packet->octets.len, 0);
            fprintf(stdout, "send %d bytes through tcp fd %d\n", ssize, tcp_fd); 
        } else {
            fprintf(stdout, "could not find TCP Peer to send QUIC message \n");
        }
    }
}


void handle_quicly_msg(int quic_fd)
{ 
    uint8_t buf[4096];
    struct sockaddr sa;
    socklen_t salen = sizeof(sa);
    quicly_decoded_packet_t packet;
    ssize_t bytes_received;

    while((bytes_received = recvfrom(quic_fd, buf, sizeof(buf), MSG_DONTWAIT, &sa, &salen)) != -1) {
        fprintf(stdout, "received %ld bytes from %s, port: %d \n", 
            bytes_received, inet_ntoa(((struct sockaddr_in *)&sa)->sin_addr), ntohs(((struct sockaddr_in *)&sa)->sin_port));
            
        for(ssize_t offset = 0; offset < bytes_received; ) {
            size_t packet_len = quicly_decode_packet(&server_ctx, &packet, buf, bytes_received, &offset);
            if(packet_len == SIZE_MAX) {
                break;
            }

            handle_quicly_packet(&packet, &sa, salen);
        }
    }

    fprintf(stdout, "func: %s, line: %d \n", __func__, __LINE__);
    return;
}

void run_server_loop(int quic_srv_fd) 
{
    fprintf(stdout, "starting server loop...\n"); 
    
    while (1) { 
        fd_set readfds;
        int max_fd = quic_srv_fd;
        conn_map_t *p = conn_map_head;
        FD_ZERO(&readfds);
        FD_SET(quic_srv_fd, &readfds); 

        while (p) { 
            FD_SET(p->tcp_fd, &readfds);
            max_fd = (max_fd > p->tcp_fd) ? max_fd : p->tcp_fd;
            p = p->next;
        } 

        if (select(max_fd + 1, &readfds, NULL, NULL, NULL) == -1) {
            perror("select failed");
            break;
        }

        if (FD_ISSET(quic_srv_fd, &readfds)) {
            handle_quicly_msg(quic_srv_fd);   
        }        
                
        //if not quic message, then it must be a tcp message from Internet side
        p = conn_map_head;
        quicly_conn_t *client = NULL;
        while (p) { 
            if (FD_ISSET(p->tcp_fd, &readfds)) {
                client = p->conn;
                break;
            }
            p = p->next;
        }
        if (client) {
            handle_tcp_msg(p->tcp_fd, client);
        } else { 
            fprintf(stdout, "could not find peer to send TCP message from Internet side \n");
        }
    }
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
    short udp_listen_port = 8443;   //port is quic server listening UDP port 
    char *cert_path = "server.crt";
    char *key_path = "server.key";

    setup_quicly_ctx(cert_path, key_path, NULL); 
    
    int quic_srv_fd = create_udp_listener(udp_listen_port); 
    if (quic_srv_fd < 0) {
        fprintf(stderr, "failed to create UDP listener.\n");
        exit(1);
    }

    printf("QPEP Server is running, pid = %lu, UDP listening port = %d\n", 
            (uint64_t)getpid(), udp_listen_port);
    
    run_server_loop(quic_srv_fd);

    return 0;
     
}  

#if 0 
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
            if (client == NULL) {
                // create a new QUIC connection 
                client = quicly_accept(&server_ctx, &next_cid, NULL, NULL, NULL);
                if (client == NULL) {
                    perror("quicly_accept failed");
                    goto error;
                }
            } 
            from_quic_to_tcp(quic_srv_fd, tcp_fd, client, stream);
        }
    }
error:
    close(tcp_fd);
    close(quic_srv_fd);
    quicly_free(client);
    quicly_free(stream);
    return; 
}


static void process_msg(quicly_conn_t **conns, struct msghdr *msg, size_t dgram_len)
{
    size_t off = 0, i;

    /* split UDP datagram into multiple QUIC packets */
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&server_ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off) == SIZE_MAX)
            return;
       
        for (i = 0; conns[i] != NULL; ++i)
            if (quicly_is_destination(conns[i], NULL, msg->msg_name, &decoded))
                break;
        if (conns[i] != NULL) {
            /* let the current connection handle ingress packets */
            quicly_receive(conns[i], NULL, msg->msg_name, &decoded);
        }
    }
}


#endif
