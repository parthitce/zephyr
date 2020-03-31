#ifndef ZEPHYR_INCLUDE_NET_TFTP_H_
#define ZEPHYR_INCLUDE_NET_TFTP_H_

#include <zephyr.h>
#include <net/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

enum tftp_final_call {
        TFTP_DATA_MORE = 0,
        TFTP_DATA_FINAL = 1,
};

struct tftp_response {
        u8_t recv_buf[512];
        u32_t recv_buf_len;
};

typedef void (*tftp_response_cb_t)(struct tftp_response *rsp,
                                 enum tftp_final_call final_data,
                                 void *user_data);

struct tftp_request {
        struct sockaddr_in server;
        const char *remote_file;
        const char *mode;
        void *user_data;
        tftp_response_cb_t response;
};

/* Name: tftp_get
 * Description: This function gets "file" from the remote server.
 */
int tftp_get(struct tftp_request *req);

/* Name: tftp_get
 * Description: This function puts "file" to the remote server.
 */
int tftp_put(struct tftp_request *req);

#endif /* ZEPHYR_INCLUDE_NET_TFTP_H_ */
