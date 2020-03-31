/*
 * Copyright (c) 2020 InnBlue
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(tftp_client, LOG_LEVEL_DBG);

/* Public / Internal TFTP header file. */
#include <net/tftp.h>
#include "tftp_client.h"

/* TFTP Request Buffer / Size variables. */
static u8_t   tftpc_request_buffer[TFTPC_MAX_BUF_SIZE];
static u32_t  tftpc_request_size;

/* TFTP Request block number property. */
static u32_t  tftpc_block_no;
static u32_t  tftpc_index;

/* Global mutex to protect critical resources. */
K_MUTEX_DEFINE(tftpc_lock);

/* Default TFTP Server (the user can provide an override via API). */
static struct sockaddr_in def_srv = {
	.sin_family = AF_INET,
	.sin_port   = htons(TFTPC_DEF_SERVER_PORT)
};

/* Name: make_request
 * Description: This function takes in a given list of parameters and
 * returns a read request packet. This packet can be sent
 * out directly to the TFTP server.
 */
static inline void make_request(const char *remote_file, const char *mode,
			u8_t request_type)
{
	/* Default Mode. */
	const char def_mode[] = "octet";

	/* Populate the read request with the provided params. Note that this
	 * is created per RFC1350.
	 */

	/* Fill in the "Read" Opcode. Also keep tabs on the request size. */
	insert_u16(tftpc_request_buffer, request_type);
	tftpc_request_size = 2;

	/* Copy in the name of the remote file, the file we need to get
	 * from the server. Add an upper bound to ensure no buffers overflow.
	 */
	strncpy(tftpc_request_buffer + tftpc_request_size, remote_file,
			TFTP_MAX_FILENAME_SIZE);
	tftpc_request_size += strlen(remote_file);

	/* Fill in 0. */
	tftpc_request_buffer[tftpc_request_size] = 0x0;
	tftpc_request_size++;

	/* Default to "Octet" if mode not specified. */
	if (mode == NULL)
		mode = def_mode;

	/* Copy the mode of operation. For now, we only support "Octet"
	 * and the user should ensure that this is the case. Otherwise
	 * we will run into problems.
	 */
	strncpy(tftpc_request_buffer + tftpc_request_size, mode,
			TFTP_MAX_MODE_SIZE);
	tftpc_request_size += strlen(mode);

	/* Fill in 0. */
	tftpc_request_buffer[tftpc_request_size] = 0x0;
	tftpc_request_size++;
}

/* Name: send_err
 * Description: This function sends an Error report to the TFTP Server.
 */
static inline int send_err(int sock, int err_code, char *err_string)
{
	printk("Client Error. Sending code: %d(%s) \n", err_code, err_string);

	/* Fill in the "Err" Opcode and the actual error code. */
	insert_u16(tftpc_request_buffer, ERROR_OPCODE);
	insert_u16(tftpc_request_buffer + 2, err_code);
	tftpc_request_size = 4;

	/* Copy the Error String. */
	strcpy(tftpc_request_buffer + 4, err_string);
	tftpc_request_size += strlen(err_string);

	/* Lets send this request buffer out. Size of request buffer
	 * is 4 bytes.
	 */
	return send(sock, tftpc_request_buffer, tftpc_request_size, 0);
}

/* Name: tftpc_recv_data
 * Description: This function tries to get data from the TFTP Server
 * (either response or data). Times out eventually.
 */
static int tftpc_recv_data(int sock)
{
	int     stat;
	stat = recv(sock, tftpc_request_buffer, TFTPC_MAX_BUF_SIZE, 0);
	tftpc_request_size = stat;
	return stat;
}


/* Name: tftpc_process_resp
 * Description: This function will process the data received from the
 * TFTP Server (a file or part of the file) and place it in the user buffer.
 */
static int tftpc_process_resp(int sock, struct tftp_request *req)
{
	u16_t    block_no;
	u32_t    cpy_size;
	bool     sendack = true;
	tftp_response_cb_t tftp_response_cb;
	struct tftp_response rsp;

	tftp_response_cb = req->response;

	/* Get the block number as received in the packet. */
	block_no = extract_u16(tftpc_request_buffer + 2);

	/* Is this the block number we are looking for? */
	if (block_no == tftpc_block_no) {

		printk("Server sent Block Number: %d \n", tftpc_block_no);
		
		cpy_size = tftpc_request_size - TFTP_HEADER_SIZE;

		memset(&rsp, 0, sizeof(rsp));
		
		/* Perform the actual copy and update the index. */
		memcpy(rsp.recv_buf,
			tftpc_request_buffer + TFTP_HEADER_SIZE, cpy_size);
		rsp.recv_buf_len = cpy_size; 
			

		if (cpy_size == 512) {	
			tftp_response_cb(&rsp, TFTP_DATA_MORE, req->user_data);
		} else {
			tftp_response_cb(&rsp, TFTP_DATA_FINAL, req->user_data);
		}
		/* Was there any problem? */
		if (sendack == true) {

			/* Now we are in a position to ack this data. */
			send_ack(sock, block_no);
		} else {

			/* Send Error :-( */
			send_err(sock, 0x3, "Buffer Overflow");

			/* Log the error. */
			printk("However, it seems that the actual file has larger \
				  size. Exiting \n!");

			return TFTPC_BUFFER_OVERFLOW;
		}

		/* We recevied a "block" of data. Lets update the global
		 * book-keeping variable that tracks the number of blocks
		 * received.
		 */
		tftpc_block_no++;

		/* Because we are RFC1350 compliant, the block size will
		 * always be 512. If it is equal to 512, we will assume
		 * that the transfer is still in progress. If we have
		 * block size less than 512, we will conclude the transfer.
		 */
		return (tftpc_request_size - TFTP_HEADER_SIZE ==
				TFTP_BLOCK_SIZE) ?
				(TFTPC_DATA_RX_SUCCESS) :
				(TFTPC_OP_COMPLETED);
	} else if (tftpc_block_no > block_no) {

		printk("Server send duplicate (already acked) block again. \
				 Block Number: %d \n", block_no);
		printk("Client already trying to receive Block Number: \
				 %d", tftpc_block_no);

		/* Re-ACK the data. */
		send_ack(sock, block_no);

		/* OK - This means that we just received a block of data
		 * that has already been received and acked by the TFTP
		 * client.
		 */
		return TFTPC_DUPLICATE_DATA;
	}

	/* Don't know what's going on. */
	return TFTPC_UNKNOWN_FAILURE;
}

/* Name: tftp_send_request
 * Description: This function sends out a request to the TFTP Server
 * (Read / Write) and waits for a response. Once we get some response
 * from the server, it is interpreted and ensured to be correct.
 * If not, we keep on poking the server for data until we eventually
 * give up.
 */
static int tftp_send_request(int sock, u8_t request,
		const char *remote_file, const char *mode)
{
	u8_t    no_of_retransmists = 0;
	s32_t   stat;
	u16_t   server_response    = -1;

	/* Socket connection successfully - Create the Read Request
	 * Packet (RRQ).
	 */
	make_request(remote_file, mode, request);

	do {

		/* Send this request to the TFTP Server. */
		stat = send(sock, tftpc_request_buffer, tftpc_request_size, 0);

		/* Data sent successfully? */
		if (stat > 0) {

			/* We have been able to send the Read Request to the
			 * TFTP Server. The server will respond to our
			 * message with data or error, And we need to handle
			 * these cases correctly.
			 * Lets try to get this data from the TFTP Server.
			 */
			stat = tftpc_recv_data(sock);

			/* Lets check if we were able to get response from the
			 * server and if the response was Ok or not.
			 */
			if (stat > 0) {

				/* Ok - We were able to get response of our read
				 * request from the TFTP Server. Lets check and
				 * see what the TFTP Server has to say about our
				 * request.
				 */
				server_response =
						extract_u16(tftpc_request_buffer);

				/* Did we get some err? */
				if (server_response == ERROR_OPCODE) {

					/* The server responded with some errors
					 * here. Lets get to know about the specific
					 * error and log it. Nothing else we can do
					 * here really and so should exit.
					 */
					printk("tftp_get failure - Server returned: %d \n",
							extract_u16(tftpc_request_buffer + 2));

					break;
				}

				/* Did we get some data? */
				if (server_response == DATA_OPCODE) {

					/* Good News - TFTP Server responded with data.
					 * Lets talk to the server and get all data.
					 */
					printk("tftp_get success - Server returned: %d \n",
							 extract_u16(tftpc_request_buffer + 2));

					break;
				}

				/* Did we get some data? */
				if (server_response == ACK_OPCODE) {

					/* Good News - TFTP Server acked our request. */
					printk("tftp_get success - Server returned: %d \n",
							extract_u16(tftpc_request_buffer + 2));

					break;
				}
			}
		}

		/* No of times we had to re-tx this "request". */
		no_of_retransmists++;

		/* Log this out. */
		printk("tftp_send_request was either unable to get data \
				 from the TFTP Server.");
		printk("Or failed to get any valid data.");
		printk("no_of_retransmists = %d \n", no_of_retransmists);
		printk("Are we re-transmitting: %s \n",
				 (no_of_retransmists < TFTP_REQ_RETX) ?
				 "yes" : "no");

	} while (no_of_retransmists < TFTP_REQ_RETX);

	/* Status? */
	return server_response;
}

/* Name: tftp_connect
 * Description: This function connects with the TFTP Server.
 */
static inline s8_t tftp_connect(s32_t sock, struct sockaddr_in *server)
{
	/* If the server information is not provided by the user, we
	 * have to use the default server.
	 */
	if (server == NULL) {

		/* Have to use the default server. Populate the IP address. */
		inet_pton(AF_INET, TFTPC_DEF_SERVER_IP, &def_srv.sin_addr);

		/* Update the pointer. */
		server = &def_srv;
	}

	/* Connect with the TFTP Server. */
	return connect(sock, (struct sockaddr *) server, sizeof(struct sockaddr_in));
}

/* Name: tftp_get
 * Description: This function gets "file" from the remote server.
 */
int tftp_get(struct tftp_request *req)
{

	s32_t   stat               = TFTPC_UNKNOWN_FAILURE;
	s32_t   sock;
	u16_t   server_response;
	u8_t    no_of_retransmists = 0;

	/* Re-init the global "block number" variable. */
	tftpc_block_no = 1;
	tftpc_index    = 0;

	/* Create Socket for TFTP. Use IPv4 / UDP as L4 / L3
	 * communication layers.
	 */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	/* Valid sock descriptor? If not, best to tell the
	 * caller about it.
	 */
	if (sock < 0) {
		printk("Failed to create UDP socket (IPv4): %d \n", errno);
		return -errno;
	}

	/* Connect with the address.  */
	stat = tftp_connect(sock, &req->server);
	if (stat < 0) {
		printk("Cannot connect to UDP remote (IPv4): %d \n", errno);
		return -errno;
	}
	
	/* Obtain Global Lock before accessing critical resources. */
	if (k_mutex_lock(&tftpc_lock, K_FOREVER) != 0) {
		printk("Failed to obtain TFTP Client Semaphore \n");
		return -errno;
	}

	/* Send out the request to the TFTP Server. */
	server_response = tftp_send_request(sock, RRQ_OPCODE,
				 req->remote_file, req->mode);

	do {
		/* Did the server respond with data? */
		if (server_response == DATA_OPCODE) {

			/* Good News - TFTP Server responded with data. Lets talk
			 * to the server and get all data.
			 */
			stat = tftpc_process_resp(sock, req);

			/* Lets get more data if data was successful or we got
			 * a duplicate packet.
			 */
			if ((stat == TFTPC_DATA_RX_SUCCESS) ||
				(stat == TFTPC_DUPLICATE_DATA)) {

recv:
				/* Receive data from the server. */
				stat = tftpc_recv_data(sock);

				/* There are two possibilities at this point.
				 * - We got the data successfully.
				 * - We timed out trying to get data.
				 * The first case is Ok, but the second case needs
				 * special handling. Like before, if we time out
				 * getting data, we will re-tx. However, in this
				 * case, we will re-tx ack of the previous block.
				 */
				if (stat > 0) {

					/* Log. */
					printk("Recevied data of size: %d \n", stat);

					/* Response? */
					server_response = extract_u16(tftpc_request_buffer);
				} else {

					/* Log. */
					printk("Timed out while receiving data from the \
						 server: %d \n", stat);

					/* Re-TX update. */
					no_of_retransmists++;

					/* Should we re-tx? */
					if (no_of_retransmists <
								TFTP_REQ_RETX) {

						printk("Re-transmisting the ack and waiting for \
							 data again. ");

						/* Bad News - We timed out. Lets send out an ack
						 * of the previous block.
						 */
						send_ack(sock, tftpc_block_no);

						goto recv;
					} else {
						printk("No more retransmits available. Exiting");
						break;
					}
				}
			} else if (stat == TFTPC_OP_COMPLETED) {
				/* Able to read the file successfully. */
				printk("TFTP Client was able to read the file successfully");

				break;
			}
		} else if (server_response == ERROR_OPCODE) {
			/* The server responded with some errors here. Lets get to
			 * know about the specific error and log it. Nothing else
			 * we can do here really and so should exit.
			 */
			printk("tftp_get failure - Server returned: %d \n",
						extract_u16(tftpc_request_buffer + 2));

			break;
		}
	} while (stat > 0);

	/* Release the lock. */
	k_mutex_unlock(&tftpc_lock);

	/* Close out this socket. */
	close(sock);

	/* Stat? */
	return stat;
}

/* Name: tftp_put
 * Description: This function puts "file" to the remote server.
 */
int tftp_put(struct tftp_request *req)
{
	/* TODO */
	return 0;
}
