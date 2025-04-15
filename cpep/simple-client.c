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
#include "pthread.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "common.h"
#include <picotls/../../t/util.h> 

static quicly_context_t client_ctx;
static quicly_cid_plaintext_t next_cid;
static ptls_iovec_t resumption_token; 

static quicly_error_t client_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
static quicly_stream_open_t stream_open = {client_on_stream_open};

conn_stream_pair_node_t mmap_head; 


static void client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    quicly_debug_printf(stream->conn, "stream: %ld received %zu bytes\n", stream->stream_id, input.len);

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);

    if (stream->stream_id == 0)
	    return;

   
    char buff[4096];
    memcpy(buff, input.base, len);
    int tcp_fd = find_tcp_conn(mmap_head.next, stream);

    if (tcp_fd < 0) { 
        quicly_debug_printf(stream->conn, "stream: %ld, could not find tcp_sk to write\n", stream->stream_id);
        return;
    }

    size_t bytes_sent = send(tcp_fd, buff, len, 0);    
    if (bytes_sent == -1) { 
        quicly_debug_printf(stream->conn, "stream: %ld -> tcp: %d, tcp send() failed\n", stream->stream_id, tcp_fd);
        return;
    }

    fprintf(stdout, "func: %s, line: %d, [stream: %ld -> tcp: %d], bytes: %ld sent\n", 
		    __func__, __LINE__,
		    stream->stream_id, tcp_fd, bytes_sent);

    /* initiate connection close after receiving all data */
    if (quicly_recvstate_transfer_complete(&stream->recvstate))
        quicly_close(stream->conn, 0, "");



    return;

}

static void client_on_stop_sending(quicly_stream_t *stream, quicly_error_t err)
{
    fprintf(stderr, "received STOP_SENDING: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    quicly_debug_printf(stream->conn, "stream: %ld received STOP_SENDING, and called quicly_close()\n", stream->stream_id);
}

static void client_on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    fprintf(stderr, "received RESET_STREAM: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    quicly_debug_printf(stream->conn, "stream: %ld received reset_stream, and called quicly_close()\n", stream->stream_id);
}


static quicly_error_t client_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
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
    
    quicly_debug_printf(stream->conn, "stream: %ld opened\n", stream->stream_id);
    return 0;
}
 
void setup_client_ctx()
{   
    setup_session_cache(get_tlsctx());
    quicly_amend_ptls_context(get_tlsctx());

    client_ctx = quicly_spec_context;
    client_ctx.tls = get_tlsctx();
    client_ctx.stream_open = &stream_open;
    client_ctx.transport_params.max_stream_data.uni = UINT32_MAX;
    client_ctx.transport_params.max_stream_data.bidi_local = UINT32_MAX;
    client_ctx.transport_params.max_stream_data.bidi_remote = UINT32_MAX;
    //client_ctx.init_cc = &quicly_cc_cubic_init;

    return; 
}

int create_quic_conn(char *srv, short port, quicly_conn_t **conn)
{ 
    struct sockaddr_in sa;
    struct hostent *hp;

    if ((hp = gethostbyname(srv)) == NULL) {
        fprintf(stderr, "func: %s, line: %d, gethostbyname failed\n", __func__, __LINE__);
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, hp->h_addr, hp->h_length);
   
    if (quicly_connect(conn, &client_ctx, srv, (struct sockaddr *)&sa, NULL, &next_cid, resumption_token, NULL, NULL, NULL) != 0) {
        fprintf(stderr, "quicly_connect failed\n");
        return -1;
    }

    quicly_debug_printf(*conn, "quicly_connect() successful\n");
    return 0;
}

void process_quic_msg(int quic_fd, quicly_conn_t *conn, struct msghdr *msg, ssize_t dgram_len)
{
    size_t off = 0; 
    
    while (off < dgram_len) { 
        quicly_decoded_packet_t decoded; 
        if (quicly_decode_packet(&client_ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off) == SIZE_MAX)
            return;
        
        if (!quicly_is_destination(conn, NULL, msg->msg_name, &decoded)) { 
            quicly_debug_printf(conn, "new connection ? \n");
            break;               
        } else { 
            quicly_receive(conn, NULL, msg->msg_name, &decoded);
        }
    }
    return ; 
}

int quicly_write_msg_to_buff(quicly_stream_t *stream, void *buf, size_t len)
{ 
    if (stream == NULL || !quicly_sendstate_is_open(&stream->sendstate)) {
	    quicly_debug_printf(stream->conn, "stream: %ld, sendstate_is_open: 0 \n", stream->stream_id);
        return 0;
    }	
    
    quicly_streambuf_egress_write(stream, buf, len);

    return 0;
}

int main(int argc, char **argv)
{ 
    char *srv = "127.0.0.1"; 
    short srv_port = 4433, tcp_lstn_port = 8443; 
    int tcp_fd;   
    
    setup_client_ctx(); 
    
    tcp_fd = create_tcp_listener(tcp_lstn_port);
    if (tcp_fd < 0) {
        fprintf(stderr, "failed to create tcp listener\n");
        return -1;
    }

    fprintf(stdout, "starting PEP-CPE with pid %d on TCP port %d\n", getpid(), tcp_lstn_port);

    int quic_fd = create_udp_client_socket(srv, srv_port);
    if (quic_fd < 0) {
        fprintf(stderr, "failed to create QUIC/udp client socket\n");
        return -1;
    }

    int ret = 0;
    quicly_conn_t *conn = NULL; 
    fprintf(stdout, "creating quic connection...\n");
    ret = create_quic_conn(srv, srv_port, &conn); 
    if (ret < 0) { 
        fprintf(stderr, "failed to create quic connection\n");
        return -1;
    }

    quicly_stream_t *ctrl_stream = NULL; 
    if ((ret = quicly_open_stream(conn, &ctrl_stream, 0)) != 0) { 
        fprintf(stderr, "quicly_open_stream() failed: %d\n", ret);
        return -1;
    } 
    
    quicly_write_msg_to_buff(ctrl_stream, "hello world!", strlen("hello world!"));

    worker_data_t *data = (worker_data_t *)malloc(sizeof(worker_data_t));
    data->quic_fd = quic_fd;
    data->conn = conn;

    pthread_t worker_thread;
    pthread_create(&worker_thread, NULL, quic_sk_watcher, (void *)data);

    fprintf(stdout, "func: %s, line: %d, quic_sk_watcher: %ld.\n", __func__, __LINE__, worker_thread);
    
    //TODO: adding a control thread to send ping-pong  
    run_loop(tcp_fd, quic_fd, conn); 
    
    return 0; 
}


