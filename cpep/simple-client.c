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

    quicly_debug_printf(stream->conn, "stream: %ld -> tcp: %d, bytes: %d sent\n", stream->stream_id, tcp_fd, bytes_sent);


    /* initiate connection close after receiving all data */
    if (quicly_recvstate_transfer_complete(&stream->recvstate))
        quicly_close(stream->conn, 0, "");

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);

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
    size_t off = 0, i; 
    
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


void *handle_client(void *data)
{  
    quicly_conn_t *quic_conn = ((worker_data_t *) data)->conn; 
    quicly_stream_t *quic_stream = ((worker_data_t *) data)->stream;
    int tcp_fd = ((worker_data_t *) data)->tcp_fd;
    int quic_fd = ((worker_data_t *) data)->quic_fd;

    struct sockaddr_storage orig_dst;
    socklen_t len = sizeof(orig_dst);

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

#ifdef SO_ORIGINAL_DST       	
    if (getsockopt(tcp_fd, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &len) != 0) {
        fprintf(stderr, "failed to get original destination address\n");
        goto error;
    }
#endif

    fprintf(stdout, "func: %s, line: %d, TCP orig dest. addr.: %s:%d\n", 
            __func__, __LINE__, 
            inet_ntoa(((struct sockaddr_in *)&orig_dst)->sin_addr), 
            ntohs(((struct sockaddr_in *)&orig_dst)->sin_port));

    //send the original destination address to QUIC server 
    if (quicly_send_msg(quic_fd, quic_stream, (void *)&orig_dst, len) != 0) { 
        quicly_debug_printf(quic_stream->conn, "sending original connection header failed.\n");
        goto error;
    }

    /* the following code only handle from tcp to quic 
     * the quic to tcp is handled in client_on_receive() 
     */
    while (1) { 
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(quic_fd, &readfds);
        FD_SET(tcp_fd, &readfds);

        if (select(tcp_fd > quic_fd ? tcp_fd + 1 : quic_fd + 1, &readfds, NULL, NULL, NULL) == -1) {
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
            
            int ret = quicly_send_msg(quic_fd, quic_stream, (void *)buff, bytes_received);
            if (ret != 0) { 
                quicly_debug_printf(quic_stream->conn, "[tcp: %d -> stream: %ld] failed to send to quic stream.\n", 
                    tcp_fd, quic_stream->stream_id);
		        goto error;
            }

	        fprintf(stdout, "[tcp: %d -> stream: %ld] write %d bytes to quic stream: %d.\n", 
	                    tcp_fd, quic_stream->stream_id, bytes_received, quic_stream->stream_id);
        }

        if (FD_ISSET(quic_fd, &readfds)) { 
            uint8_t buf[4096];
            struct sockaddr_storage sa; 
            struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            ssize_t rret = 0;
            while ((rret = recvmsg(quic_fd, &msg, 0)) == -1)
                ;
 
            fprintf(stdout, "[tcp: %d <- quic_sk_fd: %d] quic read %d bytes.\n", 
                    tcp_fd, quic_fd, rret);
            
            if (rret > 0)
                process_quic_msg(quic_fd, quic_conn, &msg, rret);
        }

        
    }

error:
    close(tcp_fd);
    //TODO close QUIC stream also
    return NULL;
}

void run_loop(int tcp_fd, int quic_fd, quicly_conn_t *quic)
{  
    struct sockaddr_in tcp_remote_addr;
    socklen_t tcp_addr_len = sizeof(tcp_remote_addr); 
    
    while (1) { 
        int client_fd = accept(tcp_fd, (struct sockaddr *)&tcp_remote_addr, &tcp_addr_len);
        if (client_fd < 0) {
            fprintf(stderr, "TCP accept failed.\n");
            close(tcp_fd);
            return;
        }

        quicly_stream_t *nstream = NULL; 
        if (quicly_open_stream(quic, &nstream, 0) != 0) {
            quicly_debug_printf(quic, "quicly_open_stream() failed\n");
            continue;  
        }

        conn_stream_pair_node_t  *node = (conn_stream_pair_node_t *)malloc(sizeof(conn_stream_pair_node_t));
        node->fd = client_fd;
        node->stream = nstream;
        node->next = mmap_head.next;
        mmap_head.next = node;
        
        worker_data_t *data = (worker_data_t *)malloc(sizeof(worker_data_t));
        data->tcp_fd = client_fd;
        data->quic_fd = quic_fd;
        data->conn = quic;
        data->stream = nstream; 
        
        pthread_t worker_thread;
        pthread_create(&worker_thread, NULL, handle_client, (void *)data);
	
	    fprintf(stdout, "func: %s, line: %d, worker: %p.\n", __func__, __LINE__, worker_thread);
    }

    return;
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
        fprintf(stderr, "quicly_open_stream() failed:%d\n", ret);
        return -1;
    } 

    //Debug only 
    { 
        if (quicly_send_msg(quic_fd, ctrl_stream, "hello world!\n", strlen("hello world!\n")) != 0) { 
            fprintf(stderr, "sending hello world on ctrl_stream %d failed.\n", ctrl_stream->stream_id); 
	    return -1;
        }
    }
    
    //TODO: adding a control thread to send ping-pong  
    run_loop(tcp_fd, quic_fd, conn); 
    
    return 0; 
}


