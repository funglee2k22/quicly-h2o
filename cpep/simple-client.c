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
    
    quicly_debug_printf(stream->conn, "stream: %d received %zu bytes\n", stream->stream_id, input.len);
    
    //TODO write code to send data to tcp side. 
#if 0
    fwrite(input.base, 1, input.len, stdout);
    fflush(stdout);
    
    /* initiate connection close after receiving all data */
    if (quicly_recvstate_transfer_complete(&stream->recvstate))
        quicly_close(stream->conn, 0, "");
#endif
    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);
}


static void client_on_stop_sending(quicly_stream_t *stream, quicly_error_t err)
{
    fprintf(stderr, "received STOP_SENDING: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    quicly_debug_printf(stream->conn, "stream: %d received STOP_SENDING, and called quicly_close()\n", stream->stream_id);
}

static void client_on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    fprintf(stderr, "received RESET_STREAM: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    quicly_debug_printf(stream->conn, "stream: %d received reset_stream, and called quicly_close()\n", stream->stream_id);
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
    
    quicly_debug_printf(stream->conn, "stream: %d opened\n", stream->stream_id);
    return 0;
}
 
void setup_client_ctx()
{   
    setup_session_cache(get_tlsctx());
    quicly_amend_ptls_context(get_tlsctx());

    client_ctx = quicly_spec_context;
    client_ctx.tls = get_tlsctx();
    client_ctx.stream_open = &stream_open;
    //client_ctx.init_cc = &quicly_cc_cubic_init;

    return; 
}

int create_quic_conn(char *srv, short port, quicly_conn_t *conn)
{ 
    struct sockaddr_storage sas;
    socklen_t salen; 
    char str_port[10];
    itoa(port, str_port, 10);

    if(resolve_address((void*)&sas, &salen, srv, str_port, AF_INET, SOCK_DGRAM, IPPROTO_UDP) != 0) {
        exit(-1);
    }

    if (quicly_connect(conn, &client_ctx, srv, (struct sockaddr *)&sas, NULL, &next_cid, resumption_token, NULL, NULL, NULL) != 0) {
        fprintf(stderr, "quicly_connect failed\n");
        return -1;
    }

    quicly_debug_printf(conn, "quicly_connect() successful\n");
    return 0;
}

bool send_dgrams(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams)
{       
    for(size_t i = 0; i < num_dgrams; ++i) {
        struct msghdr mess = {
            .msg_name = dest,
            .msg_namelen = quicly_get_socklen(dest),
            .msg_iov = &dgrams[i], .msg_iovlen = 1
        };  
            
        ssize_t bytes_sent;
        while ((bytes_sent = sendmsg(fd, &mess, 0)) == -1 && errno == EINTR);
        if (bytes_sent == -1) {
            perror("sendmsg failed");
            return false;
        }   
    }   
    
    return true;
}       

int quicly_send_msg(int quic_fd, quicly_stream_t *stream, void *buf, size_t len)
{ 
    quicly_streambuf_egress_write(stream, buf, len); 
    
    #define SEND_BATCH_SIZE 16
    quicly_address_t src, dst;
    struct iovec dgrams[SEND_BATCH_SIZE];
    size_t num_dgrams;
    uint8_t dgrams_buf[SEND_BATCH_SIZE * client_ctx.transport_params.max_udp_payload_size];
    size_t num_dgrams = SEND_BATCH_SIZE;

    int quicly_res = quicly_send(stream->conn, &dst, &src, dgrams, &num_dgrams, &dgrams_buf, sizeof(dgrams_buf)); 
    if (quicly_res != 0) { 
        quicly_debug_printf(stream->conn, "quicly_send failed with res: %d.\n", quicly_res);
        return -1; 
    } else if (num_dgrams == 0) { 
        quicly_debug_printf(stream->conn, "quicly_send() nothing to send.");
        return 0;
    }

    if (!send_dgrams(quic_fd, &dst.sa, dgrams, num_dgrams)) { 
        return -1;
    }
    return 0;
}

void *handle_client(void *data)
{   
    quicly_stream_t *quic_stream = ((worker_data_t *) data)->stream;
    int tcp_fd = ((worker_data_t *) data)->tcp_fd;
    int quic_fd = ((worker_data_t *) data)->quic_fd;

    struct sockaddr_storage orig_dst;
    socklen_t len = sizeof(orig_dst);

#ifdef SO_ORIGINAL_DST 
    if (getsockopt(tcp_fd, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &len) != 0) {
        fprintf(stderr, "failed to get original destination address\n");
        return NULL;
    }
#endif

    //send the original destination address to QUIC server 
    if (quicly_send_msg(quic_fd, quic_stream, (void *)&orig_dst, len) != 0) { 
        quicly_debug_printf(quic_stream->conn, "sending original connection header failed.\n");
        return NULL;
    }

    /* the following code only handle from tcp to quic 
     * the quic to tcp is handled in client_on_receive() 
     */
    while (1) { 
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tcp_fd, &readfds);
        
        if (select(tcp_fd, &readfds, NULL, NULL, NULL) == -1) {
            perror("select failed");
                goto error;
            }    
        if (FD_ISSET(tcp_fd, &readfds)) {
            char buff[4096];
            int bytes_received = read(tcp_fd, buff, sizeof(buff)); 
            if (bytes_received < 0) { 
                quicly_debug_printf(quic_stream->conn, "[tcp: %d, stream: %d] tcp side error.\n", tcp_fd, quic_stream->stream_id);
                goto error;
            }

            int ret = quicly_send_msg(quic_fd, quic_stream, (void *)buff, bytes_received);
            if (!ret) { 
                quicly_debug_printf(quic_stream->conn, "[tcp: %d, stream: %d] failed to send to quic stream.", 
                    tcp_fd, quic_stream->stream_id);
                goto error;
            }
        }

    }

error:
    close(tcp_fd);
    //TODO close QUIC stream also 
    return;
}



void run_loop(int tcp_fd, int quic_fd, quicly_conn_t *quic)
{  
    struct sockaddr_in tcp_remote_addr;
    socklen_t tcp_addr_len = sizeof(tcp_remote_addr); 
    pid_t pid;
    
    while (1) { 
        int client_fd = accept(tcp_fd, (struct sockaddr *)&tcp_remote_addr, &tcp_addr_len);
        if (client_fd < 0) {
            fprintf(stderr, "TCP accept failed.\n");
            close(tcp_fd);
            return -1;
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
        data->stream = nstream; 
        
        pthread_t worker_thread;
        pthread_create(&worker_thread, NULL, handle_client, (void *)data);
    
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

    fprintf(stdout, "starting PEP ISP with pid %lu on port %d\n", getpid(), tcp_lstn_port);

    int quic_fd = create_udp_client_socket(srv, srv_port);
    if (quic_fd < 0) {
        fprintf(stderr, "failed to create QUIC/udp client socket\n");
        return -1;
    }

    int ret = 0;
    quicly_conn_t *conn = NULL; 
    fprintf(stdout, "creating quic connection...\n");
    ret = create_quic_conn(srv, srv_port, conn); 
    if (ret < 0) { 
        fprintf(stderr, "failed to create quic connection\n");
        return -1;
    }

    fprintf(stdout, "creating ctrl stream...\n");
    quicly_stream_t *ctrl_stream = NULL; 
    if ((ret = quicly_open_stream(conn, &ctrl_stream, 0)) != 0) { 
        fprintf(stderr, "quicly_open_stream() failed:%d\n", ret);
        return -1;
    }
    
    //TODO: adding a control thread to send ping-pong  
    runloop(tcp_fd, quic_fd, conn); 
    
    return 0; 
}


