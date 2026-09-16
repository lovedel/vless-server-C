#ifndef VLESS_SERVER_H
#define VLESS_SERVER_H

#include <pthread.h>
#include <stdint.h>
#include <ws.h>

/* VLESS command type */
#define VLESS_CMD_TCP  0x01
#define VLESS_CMD_UDP  0x02

/* VLESS address type */
#define VLESS_ADDR_IPV4   0x01
#define VLESS_ADDR_DOMAIN 0x02
#define VLESS_ADDR_IPV6   0x03

/* Proxy type */
#define PROXY_DIRECT 0
#define PROXY_SOCKS5 1
#define PROXY_HTTP   2
#define PROXY_HTTPS  3

/* VLESS protocol version */
#define VLESS_VERSION 0x01

struct vless_proxy_config
{
	int    type;
	char   host[256];
	int    port;
	char   username[128];
	char   password[128];
};

struct vless_conn_ctx
{
	ws_cli_conn_t            client;
	int                      remote_fd;
	int                      resp_header_pending;
	unsigned char            resp_version;
	int                      parsed;
	struct vless_proxy_config proxy_cfg;
	pthread_mutex_t          mtx;
	int                      closed;
	pthread_t                remote_thread;
};

struct vless_config
{
	char                 uuid[37];
	int                  listen_port;
	struct vless_proxy_config proxy;
};

extern struct vless_config vless_cfg;

#endif /* VLESS_SERVER_H */
