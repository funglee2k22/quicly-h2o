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
    fprintf(stdout, "func: %s, line: %d, stream: %ld received %zu bytes\n", __func__, __LINE__, stream->stream_id, input.len);
    
    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);
   
    char buff[4096];
    memcpy(buff, input.base, len);

    fprintf(stdout, "func: %s, line: %d, stream: %ld, received bytes: %ld \n, msg: [%s]\n", 
		    __func__, __LINE__,
		    stream->stream_id, len, buff);

    /* initiate connection close after receiving all data */
    if (quicly_recvstate_transfer_complete(&stream->recvstate))
        quicly_close(stream->conn, 0, "");

    return;

}

static void client_on_stop_sending(quicly_stream_t *stream, quicly_error_t err)
{
    fprintf(stderr, "received STOP_SENDING: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    log_debug("stream: %ld received STOP_SENDING, and called quicly_close()\n", stream->stream_id);
}

static void client_on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    fprintf(stderr, "received RESET_STREAM: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    log_debug("stream: %ld received reset_stream, and called quicly_close()\n", stream->stream_id);
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
    
    log_debug("stream: %ld opened\n", stream->stream_id);
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

    log_debug("quicly_connect() successful\n");
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
        return 1;
    }	
    
    quicly_streambuf_egress_write(stream, buf, len);

    return 0;
}

void handle_client(int quic_fd, quicly_stream_t *quic_stream) 
{
    int i = 0;
    while (1) { 
        fd_set readfds; 
	struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
	
	do { 
            FD_ZERO(&readfds);
            FD_SET(quic_fd, &readfds);
	} while (select(quic_fd + 1, &readfds, NULL, NULL, &tv) == -1);

        if (FD_ISSET(quic_fd, &readfds)) {
            uint8_t buf[4096];
            struct sockaddr_storage sa; 
            struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            ssize_t rret = 0;
            while ((rret = recvmsg(quic_fd, &msg, 0)) == -1)
                ;

            fprintf(stdout, "[quic_sk_fd: %d] quic read %ld bytes.\n", quic_fd, rret);
            if (rret > 0)
                process_quic_msg(quic_fd, quic_stream->conn, &msg, rret);
        } else { 
   	    char temp[1024] = {0};
            sprintf(temp, "test iter: %d \n", i++);
            quicly_write_msg_to_buff(quic_stream, (void *)temp, strlen(temp) + 1);	
        } 
        //if anything needs to be sent
        quicly_address_t dest, src;
        struct iovec dgrams[10];
        uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * client_ctx.transport_params.max_udp_payload_size];
        size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);

        int ret = quicly_send(quic_stream->conn, &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));
	
	if (ret == 0 && num_dgrams > 0) {
	    //someting to send;
            size_t j;
            for (j = 0; j != num_dgrams; ++j) {
                struct msghdr mess = {.msg_name = &dest.sa, .msg_namelen = quicly_get_socklen(&dest.sa), 
                                          .msg_iov = &dgrams[j], .msg_iovlen = 1};
                sendmsg(quic_fd, &mess, MSG_DONTWAIT);
	    }
	} else if (ret == QUICLY_ERROR_FREE_CONNECTION) { 
	    fprintf(stdout, "func: %s, line: %d, ret: %d, connection closed.\n", __func__, __LINE__, ret);
	} else if (ret == 0 && num_dgrams == 0) {
            fprintf(stdout, "func: %s, line: %d, ret: %d, nums_dgrams: %d, nothing to send.\n",
			    __func__, __LINE__, ret, num_dgrams);
	}
    }

    return;
}


int main(int argc, char **argv)
{ 
    char *srv = "127.0.0.1"; 
    short srv_port = 4433, tcp_lstn_port = 8443; 
    int tcp_fd;   
    
    setup_client_ctx(); 
    
    int quic_fd = create_udp_client_socket(srv, srv_port);
    if (quic_fd < 0) {
        fprintf(stderr, "failed to create QUIC/udp client socket\n");
        return -1;
    }

    int ret = 0;
    quicly_conn_t *conn = NULL; 
    ret = create_quic_conn(srv, srv_port, &conn); 
    if (ret < 0) { 
        fprintf(stderr, "failed to create quic connection\n");
        return -1;
    }


    quicly_stream_t *nstream = NULL; 
    if (quicly_open_stream(conn, &nstream, 0) != 0) {
        fprintf(stderr, "quicly_open_stream() failed\n");
    	return -1;
    }


    if (!quicly_connection_is_ready(conn)) { 
 	log_debug("connection is not ready\n");
    } 

    handle_client(quic_fd, nstream);

    return 0; 
}


