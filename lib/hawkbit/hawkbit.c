/*
 * Copyright (c) 2020 Linumiz
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>

LOG_MODULE_REGISTER(hawkbit);

#include <zephyr.h>
#include <logging/log_ctrl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/socket.h>
#include <net/net_mgmt.h>
#include <net/net_ip.h>
#include <net/net_event.h>
#include <net/http_client.h>
#include <net/dns_resolve.h>
#include <drivers/flash.h>
#include <power/reboot.h>
#include <tinycrypt/sha256.h>
#include <data/json.h>
#include <fs/nvs.h>

#include "include/hawkbit.h"
#include "hawkbit_priv.h"
#include "hawkbit_firmware.h"
#include "hawkbit_device.h"

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#define CA_CERTIFICATE_TAG 1
#include <net/tls_credentials.h>
#endif

#define NETWORK_TIMEOUT 	K_SECONDS(2)
#define HAWKBIT_RECV_TIMEOUT 	K_SECONDS(300)
#define RECV_BUFFER_SIZE	1200
#define URL_BUFFER_SIZE		300
#define STATUS_BUFFER_SIZE	200
#define DEPLOYMENT_BASE_SIZE    50
#define DOWNLOAD_HTTP_SIZE	200
#define CANCEL_BASE_SIZE	50

#define HTTP_HEADER_CONTENT_TYPE_JSON	"application/json;charset=UTF-8"
#define FLASH_BANK_SIZE			DT_FLASH_AREA_IMAGE_1_SIZE

#define HAWKBIT_SERVER CONFIG_HAWKBIT_SERVER

static int poll_sleep = K_SECONDS(CONFIG_HAWKBIT_POLL_INTERVAL);

static struct nvs_fs fs;
#define ADDRESS_ID	1

struct hawkbit_download {
	size_t http_content_size;
	size_t downloaded_size;
	int download_progress;
	int download_status;
};

static struct hawkbit_context {
	struct http_request http_req;
	struct k_sem semaphore;
	struct flash_img_context flash_ctx;
	enum hawkbit_response code_status;
	u8_t url_buffer[URL_BUFFER_SIZE];
	size_t url_buffer_size;
	u8_t status_buffer[STATUS_BUFFER_SIZE];
	size_t status_buffer_size;
	struct hawkbit_download dl;
	u8_t recv_buf_tcp[RECV_BUFFER_SIZE];
	int sock;
	s32_t action_id; 
} hb_context;

struct hawkbit_device_acid {
	u32_t current;
	u32_t update;
};

static s32_t json_action_id;

typedef enum {
	HAWKBIT_ACTION_ID_CURRENT = 0,
	HAWKBIT_ACTION_ID_UPDATE,
} hawkbit_dev_acid_t;

static union {
	struct hawkbit_ctl_res base;
        struct hawkbit_dep_res dep;
	struct hawkbit_cancel cancel;
} hawkbit_results;


static const struct json_obj_descr json_href_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_href, href, JSON_TOK_STRING),
};

static const struct json_obj_descr json_status_result_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_status_result, finished,
			    JSON_TOK_STRING),
};

static const struct json_obj_descr json_status_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_status, execution, 
			    JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_status, result,
			      json_status_result_descr),
};

static const struct json_obj_descr json_ctl_res_sleep_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_ctl_res_sleep, sleep,
			    JSON_TOK_STRING),
};

static const struct json_obj_descr json_ctl_res_polling_descr[] = {
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_ctl_res_polling, polling,
			      json_ctl_res_sleep_descr),
};

static const struct json_obj_descr json_ctl_res_links_descr[] = {
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_ctl_res_links, 
			deploymentBase, json_href_descr),
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_ctl_res_links, 
			cancelAction, json_href_descr),
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_ctl_res_links, 
			configData, json_href_descr),
};

static const struct json_obj_descr json_ctl_res_descr[] = {
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_ctl_res, config,
			      json_ctl_res_polling_descr),
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_ctl_res, _links,
			      json_ctl_res_links_descr),
};

static const struct json_obj_descr json_cfg_data_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_cfg_data, VIN, 
			    JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct hawkbit_cfg_data, hwRevision, 
			    JSON_TOK_STRING),
};

static const struct json_obj_descr json_cfg_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_cfg, mode, JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_cfg, data, json_cfg_data_descr),
	JSON_OBJ_DESCR_PRIM(struct hawkbit_cfg, id, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct hawkbit_cfg, time, JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_cfg, status, json_status_descr),
};

static const struct json_obj_descr json_close_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_close, id, JSON_TOK_STRING),
        JSON_OBJ_DESCR_PRIM(struct hawkbit_close, time, JSON_TOK_STRING),
        JSON_OBJ_DESCR_OBJECT(struct hawkbit_close, status, json_status_descr),
};	

static const struct json_obj_descr json_dep_res_hashes_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_res_hashes, sha1,
			    JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_res_hashes, md5,
			    JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_res_hashes, sha256,
			    JSON_TOK_STRING),
};

static const struct json_obj_descr json_dep_res_links_descr[] = {
	JSON_OBJ_DESCR_OBJECT_NAMED(struct hawkbit_dep_res_links,
				    "download-http", download_http,
				    json_href_descr),
	JSON_OBJ_DESCR_OBJECT_NAMED(struct hawkbit_dep_res_links,
				    "md5sum-http", md5sum_http,
				    json_href_descr),
};

static const struct json_obj_descr json_dep_res_arts_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_res_arts, filename,
			    JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_dep_res_arts, hashes,
			      json_dep_res_hashes_descr),
 	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_res_arts, size,
                            JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_dep_res_arts, _links,
			      json_dep_res_links_descr),
};

static const struct json_obj_descr json_dep_res_chunk_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_res_chunk, part,
			    JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_res_chunk, version,
			    JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_res_chunk, name,
			    JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJ_ARRAY(struct hawkbit_dep_res_chunk, artifacts,
				HAWKBIT_DEP_MAX_CHUNK_ARTS, num_artifacts,
				json_dep_res_arts_descr,
				ARRAY_SIZE(json_dep_res_arts_descr)),
};

static const struct json_obj_descr json_dep_res_deploy_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_res_deploy, download,
			    JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_res_deploy, update,
			    JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJ_ARRAY(struct hawkbit_dep_res_deploy, chunks,
				 HAWKBIT_DEP_MAX_CHUNKS, num_chunks,
				 json_dep_res_chunk_descr,
				 ARRAY_SIZE(json_dep_res_chunk_descr)),
};

static const struct json_obj_descr json_dep_res_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_res, id, JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_dep_res, deployment,
			      json_dep_res_deploy_descr),
};

static const struct json_obj_descr json_dep_fbk_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hawkbit_dep_fbk, id, JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJECT(struct hawkbit_dep_fbk, status,
			      json_status_descr),
};

static bool start_http_client()
{
	struct addrinfo *addr;
	struct addrinfo hints;
	int resolve_attempts = 10;
	int ret = -1;

	if (IS_ENABLED(CONFIG_NET_IPV6)) {
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_STREAM;
	} else if (IS_ENABLED(CONFIG_NET_IPV4)) {
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
	}

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	int protocol = IPPROTO_TLS_1_2;
	char port[] = CONFIG_HAWKBIT_PORT;
#else
	int protocol = IPPROTO_TCP;
	char port[] = CONFIG_HAWKBIT_PORT;
#endif
	while (resolve_attempts--) {
		ret = getaddrinfo(HAWKBIT_SERVER, port, &hints, &addr);
		if (ret == 0) {
			break;
		}
		k_sleep(K_SECONDS(1));
	}
	if (ret != 0) {
		LOG_ERR("Could not resolve dns");
		return false;
	}
	
	hb_context.sock = socket(addr->ai_family, SOCK_STREAM, protocol);
	if (hb_context.sock < 0) {
		LOG_ERR("Failed to create TCP socket");
		return false;
	}

#if defined (CONFIG_NET_SOCKETS_SOCKOPT_TLS)
        sec_tag_t sec_tag_opt[] = {
                CA_CERTIFICATE_TAG,
        };
        if (setsockopt(hb_context.sock, SOL_TLS, TLS_SEC_TAG_LIST,
                         sec_tag_opt, sizeof(sec_tag_opt)) < 0) {
		LOG_ERR("Failed to set TLS_TAG option");
		return false;
	}

        if (setsockopt(hb_context.sock, SOL_TLS, TLS_HOSTNAME,
                         HAWKBIT_SERVER, sizeof(HAWKBIT_SERVER)) < 0) {
		return false;
	}	
#endif

	if (connect(hb_context.sock, addr->ai_addr, addr->ai_addrlen) < 0) {
		LOG_ERR("Failed to connect to TCP socket");
		return false;
	}	

	return true;
}

static void cleanup_connection(void) 
{
	if (close(hb_context.sock) < 0) {
		LOG_ERR("Could not close the socket");
	}

	hb_context.sock = 0;
}

static int atoi_n(const char *s, int len)
{
	int i, val = 0;

	for (i = 0; i < len; i++) {
		if (*s < '0' || *s > '9')
			return val;
		val = (val * 10) + (*s - '0');
		s++;
	}

	return val;
}

char* itoa_n(int val, int base){

    static char buf[32] = {0};

    int i = 30;

    for(; val && i ; --i, val /= base)

        buf[i] = "0123456789abcdef"[val % base];

    return &buf[i+1];

}

static int hawkbit_time2sec(const char *s)
{
	int sec = 0;

	/* Time: HH:MM:SS */
	sec = atoi_n(s,2) * 60 * 60;
	sec += atoi_n(s + 3, 2) * 60;
	sec += atoi_n(s + 6, 2);

	if (sec < 0) {
		return -1;
	} else {
		return sec;
	}
}

static const char *hawkbit_status_finished(enum hawkbit_status_fini f)
{
	switch (f) {
	case HAWKBIT_STATUS_FINISHED_SUCCESS:
		return "success";
	case HAWKBIT_STATUS_FINISHED_FAILURE:
		return "failure";
	case HAWKBIT_STATUS_FINISHED_NONE:
		return "none";
	default:
		LOG_ERR("%d is invalid", (int)f);
		return NULL;
	}
}

static const char *hawkbit_status_execution(enum hawkbit_status_exec e)
{
	switch (e) {
	case HAWKBIT_STATUS_EXEC_CLOSED:
		return "closed";
	case HAWKBIT_STATUS_EXEC_PROCEEDING:
		return "proceeding";
	case HAWKBIT_STATUS_EXEC_CANCELED:
		return "canceled";
	case HAWKBIT_STATUS_EXEC_SCHEDULED:
		return "scheduled";
	case HAWKBIT_STATUS_EXEC_REJECTED:
		return "rejected";
	case HAWKBIT_STATUS_EXEC_RESUMED:
		return "resumed";
	case HAWKBIT_STATUS_EXEC_NONE:
		return "none";
	default:
		LOG_ERR("%d is invalid", (int)e);
		return NULL;
	}
}



/**
 * @brief Update an ACID of a given type on flash
 *
 * @param type ACID type to update
 * @param acid New ACID value
 * @return 0 on success, negative on error.
 */

static int hawkbit_device_acid_update(hawkbit_dev_acid_t type,
					u32_t new_value) 
{
	
	struct hawkbit_device_acid device_action_id;
	int ret;

	ret = nvs_read(&fs, ADDRESS_ID, &device_action_id, 
			sizeof(device_action_id));
	if (ret < 0) {
		LOG_ERR("Failed to read device action id");
		return ret;
	}
	if (type == HAWKBIT_ACTION_ID_UPDATE) {
		device_action_id.update = new_value;
	} else {
		device_action_id.current = new_value;
	}

	ret = nvs_write(&fs, ADDRESS_ID, &device_action_id,
                                        sizeof(device_action_id));
	if (ret < 0) {
		LOG_ERR("Failed to write device id");
		return -EIO;	
	}

	return 0;
}


/*
 * Update sleep interval, based on results from hawkbit base polling
 * resource
 */
static void hawkbit_update_sleep(struct hawkbit_ctl_res *hawkbit_res)
{
	const char *sleep = hawkbit_res->config.polling.sleep;
	int len;

	if (strlen(sleep) != HAWKBIT_SLEEP_LENGTH) {
		LOG_ERR("Invalid poll sleep: %s", sleep);
	} else {
		len = hawkbit_time2sec(sleep);
		if (len > 0 &&  poll_sleep != K_SECONDS(len)) {
			LOG_INF("New poll sleep %d seconds", len);
			poll_sleep = K_SECONDS(len);
		}
	}
}

/*
 * Find URL component for the device cancel operation and action id
 */
static int hawkbit_find_cancelAction_base(struct hawkbit_ctl_res *res, 
				 	  char *cancel_base)
{
	const char *href;
	char *helper;
	size_t len;

	href = res->_links.cancelAction.href;
	if (!href) {
		*cancel_base = '\0';
		return 0;	
	}

	helper = strstr(href, "cancelAction/");
	if (!helper) {
		/* A badly formatted cancel base is a server error */
		LOG_ERR("missing cancelBase/ in href %s", href);
		return -EINVAL;
	}

	len = strlen(helper);
	if (len > CANCEL_BASE_SIZE - 1) {
		/* Lack of memory is an application error */
		LOG_ERR("cancelBase %s is too big (len %zu, max %zu)",
				helper, len, CANCEL_BASE_SIZE -1);
		return -ENOMEM;
	}

	strncpy(cancel_base, helper, CANCEL_BASE_SIZE);
	
	helper = strtok(helper, "/");
	helper = strtok(NULL, "/");
	hb_context.action_id = atoi(helper);
	if (hb_context.action_id < 0) {
		LOG_ERR("Negative action ID: %d", hb_context.action_id);	
		return -EINVAL;
	}
	
	return 0;
}

/*
 * Find URL component for the device's deployment operations
 * resource
 */

static int hawkbit_find_deployment_base(struct hawkbit_ctl_res *res,
					char *deployment_base)
{
	const char *href;
	const char *helper;
	size_t len;

	href = res->_links.deploymentBase.href;
	if (!href) {
		*deployment_base = '\0';
		return 0;		
	}

	helper = strstr(href, "deploymentBase/");
	if (!helper) {
		/* A badly formatted deployment base is a server error */
		LOG_ERR("missing deploymentBase/ in href %s", href);
		return -EINVAL;
	}

	len = strlen(helper);
	if (len > DEPLOYMENT_BASE_SIZE -1) {
		/* Lack of memory is an application error */
		LOG_ERR("deploymentBase %s is too big (len %zu, max %zu)",
				helper, len, DEPLOYMENT_BASE_SIZE -1);
		return -ENOMEM;
	}

	strncpy(deployment_base, helper, DEPLOYMENT_BASE_SIZE);
	return 0;
}

/*
 * Find URL component for this device's deployment operations
 * resource.
 */

static int hawkbit_parse_deployment(struct hawkbit_dep_res *res,
				    int *json_action_id,
				    char *download_http,
				    s32_t *file_size)
{
	const char *href;
	const char *helper;
	size_t len;
	struct hawkbit_dep_res_chunk *chunk;
	struct hawkbit_dep_res_arts *artifact;
	size_t num_chunks, num_artifacts;
	s32_t size;

	hb_context.action_id = strtol(res->id, NULL, 10);
	if (hb_context.action_id < 0) {
		LOG_ERR("negative action ID: %d", hb_context.action_id);
		return -EINVAL;
	}

	*json_action_id = hb_context.action_id;

	num_chunks = res->deployment.num_chunks;
	if (num_chunks != 1) {
		LOG_ERR("expecting one chunk (got %d)", num_chunks);
		return -ENOSPC;
	}

	chunk = &res->deployment.chunks[0];
	if (strcmp("bApp", chunk->part)) {
		LOG_ERR("only part 'bApp' is supported; got %s",chunk->part);
		return -EINVAL;
	}

	num_artifacts = chunk->num_artifacts;
	if (num_artifacts != 1) {
		LOG_ERR("expecting one artifact (got %d)", num_artifacts);
		return -EINVAL;
	}

	artifact = &chunk->artifacts[0];
	size = artifact->size;
	
	if (size > FLASH_BANK_SIZE) {
		LOG_ERR("artifact file size too big (got %d, max is %d)",
				size, FLASH_BANK_SIZE);
		return -ENOSPC;
	}
	/*
	 * Find the download-http href. We only support the DEFAULT
	 * tenant on the same hawkbit server.
	 */

	href = artifact->_links.download_http.href;
	if (!href) {
		LOG_ERR("missing expected download-http href");
		return -EINVAL;
	}
	helper = strstr(href, "/DEFAULT/controller/v1");
	if (!helper) {
		LOG_ERR("unexpected download-http href format: %s", helper);
		return -EINVAL;
	}
	len = strlen(helper);
	if (len == 0) {
		LOG_ERR("empty download-http");
		return -EINVAL;
	} else if (len > DOWNLOAD_HTTP_SIZE - 1) {
		LOG_ERR("download-http %s is too big (len: %zu, max: %zu)",
				helper, len, DOWNLOAD_HTTP_SIZE - 1);
		return -ENOMEM;
	}	
	/* Success. */
	strncpy(download_http, helper, DOWNLOAD_HTTP_SIZE);
	*file_size = size;
	return 0;
}


static const char *str_or_null(const char *str)
{
	if (str) {
		return str;
	} else {
		return "NULL";
	}
}

static void hawkbit_dump_base(struct hawkbit_ctl_res *r)
{
	LOG_INF("config.polling.sleep=%s",
		log_strdup(str_or_null(r->config.polling.sleep)));
	LOG_INF("_links.deploymentBase.href=%s",
		log_strdup(str_or_null(r->_links.deploymentBase.href)));
	LOG_INF("_links.configData.href=%s",
		log_strdup(str_or_null(r->_links.configData.href)));
	LOG_INF("_links.cancelAction.href=%s",
		log_strdup(str_or_null(r->_links.cancelAction.href)));
}

static void hawkbit_dump_deployment(struct hawkbit_dep_res *d)
{
	struct hawkbit_dep_res_chunk *c = &d->deployment.chunks[0];
	struct hawkbit_dep_res_arts *a  = &c->artifacts[0];
	struct hawkbit_dep_res_links *l = &a->_links;

	LOG_INF("id=%s", log_strdup(str_or_null(d->id)));
	LOG_INF("download=%s", 
		log_strdup(str_or_null(d->deployment.download)));
	LOG_INF("update=%s", 
		log_strdup(str_or_null(d->deployment.update)));
	LOG_INF("chunks[0].part=%s", log_strdup(str_or_null(c->part)));
	LOG_INF("chunks[0].name=%s", log_strdup(str_or_null(c->name)));
	LOG_INF("chunks[0].version=%s", 
		log_strdup(str_or_null(c->version)));
	LOG_INF("chunks[0].artifacts[0].filename=%s",
		log_strdup(str_or_null(a->filename)));
	LOG_INF("chunks[0].artifacts[0].hashes.sha1=%s",
		log_strdup(str_or_null(a->hashes.sha1)));
	LOG_INF("chunks[0].artifacts[0].hashes.md5=%s",
		log_strdup(str_or_null(a->hashes.md5)));
	LOG_INF("chunks[0].artifacts[0].hashes.sha256=%s",
		log_strdup(str_or_null(a->hashes.sha256)));
	LOG_INF("chunks[0].size=%d", a->size);
	LOG_INF("download-http=%s", 
		log_strdup(str_or_null(l->download_http.href)));
	LOG_INF("md5sum =%s", 
		log_strdup(str_or_null(l->md5sum_http.href)));
}

int hawkbit_init(void) 
{
	int ret = 0, rc = 0;
	struct hawkbit_device_acid init_action_id;
	bool image_ok;
	struct flash_pages_info info;
	
	fs.offset = DT_FLASH_AREA_STORAGE_OFFSET;
	rc = flash_get_page_info_by_offs(device_get_binding
			(DT_FLASH_DEV_NAME), fs.offset, &info);

	if (rc) {
		LOG_ERR("Unable to get storage page info");
		return -EIO;
	}
	fs.sector_size = info.size;
	fs.sector_count = 3U;

	rc = nvs_init(&fs, DT_FLASH_DEV_NAME);
	if (rc) {
		LOG_ERR("Storage flash Init failed");
		return -ENODEV;
	}

	rc = nvs_read(&fs, ADDRESS_ID, &init_action_id, sizeof(init_action_id)); 
	LOG_INF("ACID: current %d, update %d",
			init_action_id.current, init_action_id.update);
	image_ok = boot_is_img_confirmed();
	LOG_INF("Image is %s confirmed OK", image_ok ? "" : " not");
	if (!image_ok) {
		ret = boot_write_img_confirmed();
		if (ret < 0) {
			LOG_ERR("Couldn't confirm this image: %d", ret);
			return ret;
		}
		LOG_INF("Marked image as OK");
		ret = boot_erase_img_bank(DT_FLASH_AREA_IMAGE_1_ID);
		if (ret) {
			LOG_ERR("Failed to erase second slot");
			return ret;
		} else {
			LOG_INF("Erased second slot");
		}
		
		if (init_action_id.update != -1) {
			ret = hawkbit_device_acid_update(HAWKBIT_ACTION_ID_CURRENT,
				init_action_id.update);	
		}

	}
	return ret;
}

static void response_cb(struct http_response *rsp,
		        enum http_final_call final_data,
		        void *user_data)
{
	int ret;
	u8_t *body_data = NULL;
	static size_t body_len = 0;
	int downloaded;
	u8_t request_type = atoi(user_data);
	enum hawkbit_http_request type = (int)(request_type);

	switch(type) {
	case HAWKBIT_PROBE:
                if (hb_context.dl.http_content_size == 0) {
                        body_data = rsp->body_start;
                        body_len = strlen(rsp->recv_buf);
                        body_len -= (rsp->body_start - rsp->recv_buf);
                        hb_context.dl.http_content_size = rsp->content_length;
                }

		if (hb_context.dl.http_content_size == body_len) {
			body_data[body_len] = '\0';

			ret = json_obj_parse(body_data, body_len, json_ctl_res_descr,
                                            ARRAY_SIZE(json_ctl_res_descr),
                                             &hawkbit_results.base);
                        if (ret < 0) {
                                LOG_ERR("JSON parse error");
                        }
			body_len = 0;
		}

		break;

	case HAWKBIT_CONFIG_DEVICE:
		if (strcmp(rsp->http_status, "OK") < 0) {
			LOG_ERR("Failed to update device attributes");
		}
		break;

	case HAWKBIT_CLOSE:
		if (strcmp(rsp->http_status, "OK") < 0) {
			LOG_ERR("Failed to cancel the update");
		}  
		break;

	case HAWKBIT_PROBE_DEPLOYMENT_BASE:
		if (hb_context.dl.http_content_size == 0) {
			body_data = rsp->body_start;
			body_len = strlen(rsp->recv_buf);
			body_len -= (rsp->body_start - rsp->recv_buf);
			hb_context.dl.http_content_size = rsp->content_length;

		}
		
                if (hb_context.dl.http_content_size == body_len) {
                        body_data[body_len] = '\0';

                        ret = json_obj_parse(body_data, body_len, json_dep_res_descr,
                                            ARRAY_SIZE(json_dep_res_descr),
                                             &hawkbit_results.dep);
                        if (ret < 0) {
                                LOG_ERR("DeploymentBase JSON parse error: 0x%x", ret);
                        }
			body_len = 0;
                }
		break;

        case HAWKBIT_REPORT:
                if (strcmp(rsp->http_status, "OK") < 0) {
                        LOG_ERR("Failed to update device feedback");
                        printk("HTTP_STATUS: %s, size: %d \n", 
				rsp->http_status, sizeof(rsp->http_status));
                } else {
                        printk("Device feedback succeed \n");
                }
                break;

	case HAWKBIT_DOWNLOAD:
		if (hb_context.dl.http_content_size == 0) {
			body_data = rsp->body_start;
			body_len = rsp->data_len;
			body_len -= (rsp->body_start - rsp->recv_buf);
			hb_context.dl.http_content_size = rsp->content_length;
		}
		
		if (rsp->body_found == 1) {
			if (body_data == NULL) {
				body_data = rsp->recv_buf;
				body_len = rsp->data_len;
			}
		}
		
		ret = flash_img_buffered_write(&hb_context.flash_ctx,
				body_data, body_len, final_data == HTTP_DATA_FINAL);
		if (ret < 0) {
			LOG_INF("flash write error");
		}
		
		hb_context.dl.downloaded_size = flash_img_bytes_written(&hb_context.flash_ctx);

		downloaded = hb_context.dl.downloaded_size * 100 /
				hb_context.dl.http_content_size;

		if (downloaded > hb_context.dl.download_progress) {
			hb_context.dl.download_progress = downloaded;
			LOG_INF("Download percentage: %d%% ", 
					hb_context.dl.download_progress);
		}

		if (hb_context.dl.http_content_size == body_len) {
			body_len = 0;	
		}
		
		if (final_data == HTTP_DATA_FINAL) {
        		k_sem_give(&hb_context.semaphore);
		}
			
		break;
	}
}

static bool send_request(enum http_method method, 
		         enum hawkbit_http_request type,
			 enum hawkbit_status_fini finished,
			 enum hawkbit_status_exec execution)
{
	int ret = 0;

	struct hawkbit_cfg cfg;
	struct hawkbit_close close;
	struct hawkbit_dep_fbk feedback;
	char acid[11];
	const char *fini = hawkbit_status_finished(finished);
	const char *exec = hawkbit_status_execution(execution);
	char *device_id = k_malloc(DEVICE_ID_MAX_SIZE);
	
	if (device_id == NULL) {
		return false;
	}

        if (!hawkbit_get_device_identity(device_id, DEVICE_ID_MAX_SIZE)) {
                hb_context.code_status = HAWKBIT_METADATA_ERROR;
        }

	memset(&hb_context.http_req, 0, sizeof(hb_context.http_req));
	memset(&hb_context.recv_buf_tcp, 0, sizeof(hb_context.recv_buf_tcp));
        hb_context.http_req.url = hb_context.url_buffer;
        hb_context.http_req.method = method;
        hb_context.http_req.host = CONFIG_HAWKBIT_SERVER;
	hb_context.http_req.port = CONFIG_HAWKBIT_PORT;
        hb_context.http_req.protocol = "HTTP/1.1";
        hb_context.http_req.response = response_cb;
        hb_context.http_req.recv_buf = hb_context.recv_buf_tcp;
        hb_context.http_req.recv_buf_len = sizeof(hb_context.recv_buf_tcp);

	switch (type) {
	case HAWKBIT_PROBE:
		ret = http_client_req(hb_context.sock, &hb_context.http_req, 
				      HAWKBIT_RECV_TIMEOUT, "0");	
		if (ret < 0) {
			LOG_ERR("Unable to send http request");
			return false;
		}
		break;

	case HAWKBIT_CONFIG_DEVICE:
		memset(&cfg, 0, sizeof(cfg));
		cfg.mode = "merge";
		cfg.data.VIN = "JH4TB2H26CC000000";
		cfg.data.hwRevision = "3";
		cfg.id = "";
		cfg.time = "";
        	cfg.status.execution = exec;
        	cfg.status.result.finished = fini;

        	ret = json_obj_encode_buf(json_cfg_descr, 
				ARRAY_SIZE(json_cfg_descr),
                                &cfg, hb_context.status_buffer,
                		hb_context.status_buffer_size -1);
        	if (ret)  {
                	LOG_ERR("Can't encode the json script");
                	return false;
        	}

        	hb_context.http_req.content_type_value = 
			HTTP_HEADER_CONTENT_TYPE_JSON;
        	hb_context.http_req.payload = 
			hb_context.status_buffer;
        	hb_context.http_req.payload_len = 
			strlen(hb_context.status_buffer);

	        ret = http_client_req(hb_context.sock, &hb_context.http_req,
                             HAWKBIT_RECV_TIMEOUT, "1");
        
		if (ret < 0) {
                	LOG_ERR("Unable to send http request");
                	return false;
        	}
		break;

	case HAWKBIT_CLOSE:
		memset(&close, 0, sizeof(close));
		memset(&hb_context.status_buffer, 0, 
				sizeof(hb_context.status_buffer));
		close.id = itoa_n(hb_context.action_id, 10);
		close.time = "";
        	close.status.execution = exec;	
        	close.status.result.finished = fini;
        	ret = json_obj_encode_buf(json_close_descr, 
				ARRAY_SIZE(json_close_descr),
                                &close, hb_context.status_buffer,
                		hb_context.status_buffer_size -1);
		if (ret)  {
                	LOG_ERR("Can't encode the json script");
                	return false;
        	}

        	hb_context.http_req.content_type_value = 
			HTTP_HEADER_CONTENT_TYPE_JSON;
        	hb_context.http_req.payload = 
			hb_context.status_buffer;
        	hb_context.http_req.payload_len = 
			strlen(hb_context.status_buffer);

	        ret = http_client_req(hb_context.sock, &hb_context.http_req,
                             HAWKBIT_RECV_TIMEOUT, "2");
        
		if (ret < 0) {
                	LOG_ERR("Unable to send http request");
                	return false;
        	}
		break;

	case HAWKBIT_PROBE_DEPLOYMENT_BASE:
		hb_context.http_req.content_type_value = NULL;
		ret = http_client_req(hb_context.sock, &hb_context.http_req, 
				      HAWKBIT_RECV_TIMEOUT, "3");	
		if (ret < 0) {
			LOG_ERR("Unable to send http request");
			return false;
		}
		break;

	case HAWKBIT_REPORT:
		if (!fini || !exec) {
			return -EINVAL;
		}

		LOG_INF("Reporting deployment feedback %s (%s) for action %d",
				fini, exec, json_action_id);
		
		/* Build JSON */
		memset(&feedback, 0, sizeof(feedback));
		snprintk(acid, sizeof(acid), "%d", json_action_id);
		feedback.id = acid;
		feedback.status.result.finished = fini;
		feedback.status.execution = exec;
		
		ret = json_obj_encode_buf(json_dep_fbk_descr, 
				ARRAY_SIZE(json_dep_fbk_descr),
				&feedback,  hb_context.status_buffer,
                                hb_context.status_buffer_size -1);
		if (ret) {
			LOG_ERR("Can't encode response: %d", ret);
			return ret;
		}	

		printk("JSON response: %s \n", hb_context.status_buffer);
                
		hb_context.http_req.content_type_value =
                        HTTP_HEADER_CONTENT_TYPE_JSON;
                hb_context.http_req.payload =
                        hb_context.status_buffer;
                hb_context.http_req.payload_len =
                        strlen(hb_context.status_buffer);

                ret = http_client_req(hb_context.sock, 
				      &hb_context.http_req,
                            	      HAWKBIT_RECV_TIMEOUT, "4");

                if (ret < 0) {
                        LOG_ERR("Unable to send http request");
                        return false;
                }
		
		break;

	case HAWKBIT_DOWNLOAD:
		printk("print from hawkbit download send request case \n");
		ret = http_client_req(hb_context.sock, 
				      &hb_context.http_req,
                                      HAWKBIT_RECV_TIMEOUT, "5");
                if (ret < 0) {
                        LOG_ERR("Unable to send image download request");
                        return false;
                }
		break;
	}

	k_free(device_id);	
	return true;	
}


enum hawkbit_response hawkbit_probe(void)
{
	int ret;
	s32_t file_size = 0;
	struct hawkbit_device_acid device_action_id;	

	char *device_id = k_malloc(DEVICE_ID_MAX_SIZE);
	char *firmware_version = k_malloc(BOOT_IMG_VER_STRLEN_MAX);
	char *deployment_base = k_malloc(DEPLOYMENT_BASE_SIZE);
	char *download_http = k_malloc(DOWNLOAD_HTTP_SIZE);
	char *cancel_base = k_malloc(CANCEL_BASE_SIZE);

	if ((device_id == NULL) || (firmware_version == NULL) ||
	    (deployment_base == NULL) || (download_http == NULL) ||
	    		(cancel_base == NULL)) {
		LOG_ERR("Could not alloc probe memory");
		hb_context.code_status = HAWKBIT_METADATA_ERROR;
		goto error;	
	}

	k_sem_init(&hb_context.semaphore, 0, 1);

	if (!boot_is_img_confirmed()) {
		LOG_ERR("The current image is not confirmed");
		hb_context.code_status = HAWKBIT_UNCONFIRMED_IMAGE;
		goto error;
	}

	if (!hawkbit_get_firmware_version(firmware_version, BOOT_IMG_VER_STRLEN_MAX)) {
		hb_context.code_status = HAWKBIT_METADATA_ERROR;
		goto error;
	}

	if (!hawkbit_get_device_identity(device_id, DEVICE_ID_MAX_SIZE)) {
		hb_context.code_status = HAWKBIT_METADATA_ERROR;
		goto error;
	}

	if (!start_http_client()) {
		hb_context.code_status = HAWKBIT_NETWORKING_ERROR;
		goto error;
	}

	/*
	 * Query the hawkbit base polling resource.
	 */

	LOG_INF("Polling target data from Hawkbit");

	memset(hb_context.url_buffer, 0, sizeof(hb_context.url_buffer));
	hb_context.dl.http_content_size = 0;
	hb_context.url_buffer_size = URL_BUFFER_SIZE; 
	snprintk(hb_context.url_buffer, hb_context.url_buffer_size, "%s/%s-%s",
		 HAWKBIT_JSON_URL, CONFIG_BOARD, device_id);	
	memset(&hawkbit_results.base, 0, sizeof(hawkbit_results.base));
	
	if (!send_request(HTTP_GET, HAWKBIT_PROBE, 
		HAWKBIT_STATUS_FINISHED_NONE, HAWKBIT_STATUS_EXEC_NONE)) {
		LOG_ERR("Send request failed");
		hb_context.code_status = HAWKBIT_NETWORKING_ERROR;
		goto cleanup;
	} 
	
	if (hawkbit_results.base.config.polling.sleep) {
		/* Update the sleep time. */
		hawkbit_update_sleep(&hawkbit_results.base);
	}

	hawkbit_dump_base(&hawkbit_results.base);

	if (hawkbit_results.base._links.cancelAction.href) {
		ret = hawkbit_find_cancelAction_base(&hawkbit_results.base,
                        				cancel_base);
		memset(hb_context.url_buffer, 0, sizeof(hb_context.url_buffer));
       	 	hb_context.dl.http_content_size = 0;
        	hb_context.url_buffer_size = URL_BUFFER_SIZE;
        	snprintk(hb_context.url_buffer, hb_context.url_buffer_size, 
			"%s/%s-%s/%s/feedback", HAWKBIT_JSON_URL, CONFIG_BOARD, device_id,
					cancel_base);
        	memset(&hawkbit_results.cancel, 0, sizeof(hawkbit_results.cancel));
        
		if (!send_request(HTTP_POST, HAWKBIT_CLOSE,
               		HAWKBIT_STATUS_FINISHED_SUCCESS, 
			HAWKBIT_STATUS_EXEC_CLOSED)) {
                	LOG_ERR("Send request failed");
                	hb_context.code_status = HAWKBIT_NETWORKING_ERROR;
                	goto cleanup;
        	}
		
		hb_context.code_status = HAWKBIT_CANCEL_UPDATE;
		goto cleanup;

	}

	if (hawkbit_results.base._links.configData.href) {
		memset(hb_context.url_buffer, 0, sizeof(hb_context.url_buffer));
		hb_context.dl.http_content_size = 0;
		hb_context.url_buffer_size = URL_BUFFER_SIZE;
		snprintk(hb_context.url_buffer, hb_context.url_buffer_size, 
			 "%s/%s-%s/configData", HAWKBIT_JSON_URL, CONFIG_BOARD, 
			 device_id);
	
		if (!send_request(HTTP_PUT, HAWKBIT_CONFIG_DEVICE,
				HAWKBIT_STATUS_FINISHED_SUCCESS, 
				HAWKBIT_STATUS_EXEC_CLOSED)) {
			LOG_ERR("Unable to send controller attributes");
			hb_context.code_status = HAWKBIT_NETWORKING_ERROR;
			goto cleanup;
		}
	}

	ret = hawkbit_find_deployment_base(&hawkbit_results.base,
		       			   deployment_base);
     	if (ret < 0) {
		hb_context.code_status = HAWKBIT_METADATA_ERROR;
		goto cleanup;
	}	

	if (strlen(deployment_base) == 0) {
		hb_context.code_status = HAWKBIT_NO_UPDATE;
		goto cleanup; 
	}
	
	memset(hb_context.url_buffer, 0, sizeof(hb_context.url_buffer));
	hb_context.dl.http_content_size = 0;
	hb_context.url_buffer_size = URL_BUFFER_SIZE;
	snprintk(hb_context.url_buffer, hb_context.url_buffer_size, 
	         "%s/%s-%s/%s", HAWKBIT_JSON_URL, CONFIG_BOARD, device_id, 
		 deployment_base);
	printk("URL_BUFFER_deploymentbase: %s \n", hb_context.url_buffer);	
	memset(&hawkbit_results.dep, 0, sizeof(hawkbit_results.dep));
	
	if (!send_request(HTTP_GET, HAWKBIT_PROBE_DEPLOYMENT_BASE,
			HAWKBIT_STATUS_FINISHED_NONE, HAWKBIT_STATUS_EXEC_NONE)) {
		LOG_ERR("Send request failed");
		hb_context.code_status = HAWKBIT_NETWORKING_ERROR;
		goto cleanup;
	}
		
	hawkbit_dump_deployment(&hawkbit_results.dep);
	
	hb_context.dl.http_content_size = 0;
	ret = hawkbit_parse_deployment(&hawkbit_results.dep, &json_action_id,
			download_http, &file_size);
	if (ret < 0) {
		LOG_ERR("Unable to parse deployment base");
		goto cleanup;
	}

	nvs_read(&fs, ADDRESS_ID, &device_action_id, 
			sizeof(device_action_id));
	
	if (device_action_id.update == (u32_t)json_action_id) {
		LOG_ERR("Preventing repeated attempt to install %d", json_action_id);
	
		hb_context.dl.http_content_size = 0;
		memset(hb_context.url_buffer, 0, sizeof(hb_context.url_buffer));
        	hb_context.url_buffer_size = URL_BUFFER_SIZE;
		snprintk(hb_context.url_buffer, hb_context.url_buffer_size, 
		         "%s/%s-%s/deploymentBase/%d/feedback", HAWKBIT_JSON_URL, 
			 CONFIG_BOARD, device_id, json_action_id);
		
		printk("Hawkbit Feedback: %s \n", hb_context.url_buffer);

	        if (!send_request(HTTP_POST, HAWKBIT_REPORT,
			       HAWKBIT_STATUS_FINISHED_SUCCESS,
			       HAWKBIT_STATUS_EXEC_CLOSED)) {
        	        LOG_ERR("Error when querying from hawkbit");
                	hb_context.code_status = HAWKBIT_NETWORKING_ERROR;
                	goto cleanup;
	        }
		hb_context.code_status = HAWKBIT_OK;
		goto cleanup;
	} 

	printk("Ready to install update \n");

        hb_context.dl.http_content_size = 0;
        memset(hb_context.url_buffer, 0, sizeof(hb_context.url_buffer));
        hb_context.url_buffer_size = URL_BUFFER_SIZE;	
	
	snprintk(hb_context.url_buffer, hb_context.url_buffer_size, "%s",
			download_http);

	flash_img_init(&hb_context.flash_ctx);			

        if (!send_request(HTTP_GET, HAWKBIT_DOWNLOAD,
                HAWKBIT_STATUS_FINISHED_NONE, HAWKBIT_STATUS_EXEC_NONE)) {
                LOG_ERR("Send request failed");
                hb_context.code_status = HAWKBIT_NETWORKING_ERROR;
                goto cleanup;
        }
	
	printk("Triggering OTA update \n");

	boot_request_upgrade(false);
	
	hawkbit_device_acid_update(HAWKBIT_ACTION_ID_UPDATE, json_action_id);

	hb_context.dl.http_content_size = 0;

cleanup:
	cleanup_connection();

error:
	k_free(device_id);
	k_free(firmware_version);
	k_free(deployment_base);
	k_free(download_http);
	k_free(cancel_base);


	return hb_context.code_status;
}

static void autohandler(struct k_delayed_work *work)
{
	switch(hawkbit_probe()) {
	case HAWKBIT_UNCONFIRMED_IMAGE:
		LOG_ERR("Image in unconfirmed. Rebooting to revert back to previous"
			"confirmed image.");

		sys_reboot(SYS_REBOOT_WARM);
		break;

	case HAWKBIT_NO_UPDATE:
		LOG_INF("No update found");
		break;

	case HAWKBIT_CANCEL_UPDATE:
		LOG_INF("Hawkbit update Cancelled from server");
		break;

	case HAWKBIT_OK:
		LOG_INF("Image is already updated");
		break;

	case HAWKBIT_UPDATE_INSTALLED:
		LOG_INF("");
		break;

	default:
		break;
	}

	k_delayed_work_submit(work, poll_sleep);
}



void hawkbit_autohandler(void)
{
	static struct k_delayed_work work;

	k_delayed_work_init(&work, autohandler);
	k_delayed_work_submit(&work, K_NO_WAIT);
}
