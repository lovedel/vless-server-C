#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <ws.h>
#include "vless_server.h"

#define VLESS_LISTEN_PORT 28787
#define VLESS_UUID        "03cbc571-2867-423e-8f0a-7ea9dde7f239"
#define DNS_SERVER        "223.5.5.5"
#define DNS_PORT          53
#define SOCK_BUF_SIZE     16384


struct vless_config vless_cfg =
{
	.uuid    = VLESS_UUID,
	.listen_port = VLESS_LISTEN_PORT,
	.proxy.type = PROXY_DIRECT,
};

/* ---------- helpers ---------- */

static int format_uuid(const unsigned char *data, char *out, size_t out_len)
{
	if (out_len < 37)
		return (-1);
	snprintf(out, out_len,
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		data[0], data[1], data[2], data[3],
		data[4], data[5], data[6], data[7],
		data[8], data[9], data[10], data[11],
		data[12], data[13], data[14], data[15]);
	return (0);
}

/* Base64url decode (no padding required) */
static int base64url_decode(const char *input, size_t input_len,
	unsigned char *output, size_t *output_len)
{
	size_t i, j;
	int val, chunks;
	unsigned char quad[4];

	chunks = 0;
	*output_len = 0;

	for (i = 0, j = 0; i < input_len; i++)
	{
		char c = input[i];
		if (c == '-') c = '+';
		if (c == '_') c = '/';
		if (c == '=') break;
		if (isspace((unsigned char)c)) continue;

		if (c >= 'A' && c <= 'Z')      val = c - 'A';
		else if (c >= 'a' && c <= 'z') val = c - 'a' + 26;
		else if (c >= '0' && c <= '9') val = c - '0' + 52;
		else if (c == '+')             val = 62;
		else if (c == '/')             val = 63;
		else return (-1);

		quad[chunks++] = (unsigned char)val;
		if (chunks == 4)
		{
			output[j++] = (unsigned char)((quad[0] << 2) | ((quad[1] & 0x30) >> 4));
			output[j++] = (unsigned char)(((quad[1] & 0x0F) << 4) | ((quad[2] & 0x3C) >> 2));
			output[j++] = (unsigned char)(((quad[2] & 0x03) << 6) | quad[3]);
			chunks = 0;
		}
	}
	if (chunks == 2)
		output[j++] = (unsigned char)((quad[0] << 2) | ((quad[1] & 0x30) >> 4));
	else if (chunks == 3)
	{
		output[j++] = (unsigned char)((quad[0] << 2) | ((quad[1] & 0x30) >> 4));
		output[j++] = (unsigned char)(((quad[1] & 0x0F) << 4) | ((quad[2] & 0x3C) >> 2));
	}
	*output_len = j;
	return (0);
}

/* ---------- proxy URL parser ---------- */

static int parse_proxy_url(const char *url, struct vless_proxy_config *cfg)
{
	const char *p, *host_start, *port_str;
	char buf[1024];
	size_t len;

	memset(cfg, 0, sizeof(*cfg));
	if (!url || strlen(url) < 8)
		return (-1);

	strncpy(buf, url, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	p = buf;
	while (*p == '/') p++;

	if (!strncasecmp(p, "socks5://", 9))      { cfg->type = PROXY_SOCKS5; p += 9; }
	else if (!strncasecmp(p, "socks://", 8))   { cfg->type = PROXY_SOCKS5; p += 8; }
	else if (!strncasecmp(p, "http://", 7))    { cfg->type = PROXY_HTTP;   p += 7; }
	else if (!strncasecmp(p, "https://", 8))   { cfg->type = PROXY_HTTPS;  p += 8; }
	else return (-1);

	/* user:pass@ */
	{
		const char *at = strrchr(p, '@');
		if (at)
		{
			len = (size_t)(at - p);
			if (len >= sizeof(cfg->username))
				return (-1);

			/* copy raw credential portion into username temporarily */
			memcpy(cfg->username, p, len);
			cfg->username[len] = '\0';
			p = at + 1;

			if (cfg->type == PROXY_SOCKS5)
			{
				unsigned char decoded[256];
				size_t decoded_len = 0;
				if (base64url_decode(cfg->username, strlen(cfg->username),
						decoded, &decoded_len) == 0 && decoded_len > 0)
				{
					char *sep = memchr(decoded, ':', decoded_len);
					if (sep)
					{
						size_t ulen = (size_t)(sep - (char *)decoded);
						size_t plen = decoded_len - ulen - 1;
						if (ulen < sizeof(cfg->username) && plen < sizeof(cfg->password))
						{
							memcpy(cfg->username, decoded, ulen);
							cfg->username[ulen] = '\0';
							memcpy(cfg->password, sep + 1, plen);
							cfg->password[plen] = '\0';
						}
					}
				}
			}
			else
			{
				char *sep = strchr(cfg->username, ':');
				if (sep)
				{
					size_t plen = strlen(sep + 1);
					if (plen >= sizeof(cfg->password))
						return (-1);
					strcpy(cfg->password, sep + 1);
					*sep = '\0';
				}
			}
		}
	}

	/* host:port */
	host_start = p;
	port_str = strrchr(p, ':');
	if (!port_str)
	{
		switch (cfg->type)
		{
			case PROXY_SOCKS5: cfg->port = 1080; break;
			case PROXY_HTTP:   cfg->port = 80;   break;
			case PROXY_HTTPS:  cfg->port = 443;  break;
			default:           cfg->port = 0;    break;
		}
		len = strlen(host_start);
		if (len >= sizeof(cfg->host)) return (-1);
		strncpy(cfg->host, host_start, sizeof(cfg->host) - 1);
	}
	else
	{
		len = (size_t)(port_str - host_start);
		if (len >= sizeof(cfg->host)) return (-1);
		memcpy(cfg->host, host_start, len);
		cfg->host[len] = '\0';
		cfg->port = atoi(port_str + 1);
	}

	if (!cfg->host[0] || cfg->port <= 0 || cfg->port > 65535)
		return (-1);
	return (0);
}

/* ---------- socket utilities ---------- */

static int send_all(int fd, const void *buf, size_t len)
{
	const char *p = (const char *)buf;
	size_t sent = 0;
	ssize_t r;
	while (sent < len)
	{
		r = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
		if (r <= 0)
		{
			if (r < 0 && errno == EINTR) continue;
			return (-1);
		}
		sent += (size_t)r;
	}
	return (0);
}

static ssize_t recv_timeout(int fd, void *buf, size_t len, int timeout_ms)
{
	struct timeval tv;
	ssize_t r;
	tv.tv_sec  = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	r = recv(fd, buf, len, 0);
	tv.tv_sec = 10; tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return r;
}

static int connect_tcp(const char *host, int port)
{
	struct addrinfo hints, *res, *rp;
	char port_str[8];
	int fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(port_str, sizeof(port_str), "%d", port);

	if (getaddrinfo(host, port_str, &hints, &res) != 0)
		return (-1);

	for (rp = res; rp; rp = rp->ai_next)
	{
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0) continue;
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

/* Base64 standard encode (for HTTP proxy auth) */
static const char b64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode_std(const unsigned char *in, size_t len, char *out)
{
	size_t i, j;
	for (i = 0, j = 0; i < len; i += 3)
	{
		unsigned int n = ((unsigned int)in[i] << 16) |
			(((i+1) < len ? (unsigned int)in[i+1] : 0) << 8) |
			((i+2) < len ? (unsigned int)in[i+2] : 0);
		out[j++] = b64_table[(n >> 18) & 0x3F];
		out[j++] = b64_table[(n >> 12) & 0x3F];
		out[j++] = ((i+1) < len) ? b64_table[(n >> 6) & 0x3F] : '=';
		out[j++] = ((i+2) < len) ? b64_table[n & 0x3F] : '=';
	}
	out[j] = '\0';
}

/* ---------- SOCKS5 ---------- */

static int connect_socks5(int proxy_fd, const char *target_host,
	int target_port, const char *user, const char *pass)
{
	unsigned char buf[1024];
	size_t len;
	int has_auth = (user && user[0]) || (pass && pass[0]);

	if (has_auth) { buf[0]=5; buf[1]=2; buf[2]=0; buf[3]=2; len=4; }
	else          { buf[0]=5; buf[1]=1; buf[2]=0;           len=3; }
	if (send_all(proxy_fd, buf, len) < 0) return (-1);
	if (recv_timeout(proxy_fd, buf, 2, 10000) != 2) return (-1);
	if (buf[0] != 5) return (-1);

	if (buf[1] == 2)
	{
		size_t ulen = strlen(user ? user : "");
		size_t plen = strlen(pass ? pass : "");
		if (ulen > 255 || plen > 255) return (-1);
		buf[0] = 1;
		buf[1] = (unsigned char)ulen;
		memcpy(buf + 2, user, ulen);
		buf[2 + ulen] = (unsigned char)plen;
		memcpy(buf + 3 + ulen, pass, plen);
		len = 3 + ulen + plen;
		if (send_all(proxy_fd, buf, len) < 0) return (-1);
		if (recv_timeout(proxy_fd, buf, 2, 10000) != 2) return (-1);
		if (buf[1] != 0) return (-1);
	}
	else if (buf[1] != 0) return (-1);

	/* CONNECT */
	len = strlen(target_host);
	if (len > 255) return (-1);
	buf[0]=5; buf[1]=1; buf[2]=0; buf[3]=3;
	buf[4] = (unsigned char)len;
	memcpy(buf + 5, target_host, len);
	buf[5+len]   = (unsigned char)(target_port >> 8);
	buf[5+len+1] = (unsigned char)(target_port & 0xFF);
	len += 7;
	if (send_all(proxy_fd, buf, len) < 0) return (-1);
	if (recv_timeout(proxy_fd, buf, 4, 10000) != 4) return (-1);
	if (buf[1] != 0) return (-1);

	/* skip bind addr */
	if (buf[3] == 1) { if (recv_timeout(proxy_fd, buf, 6, 10000) != 6) return (-1); }
	else if (buf[3] == 3)
	{
		unsigned char dl;
		if (recv_timeout(proxy_fd, &dl, 1, 10000) != 1) return (-1);
		if (recv_timeout(proxy_fd, buf, dl + 2, 10000) != (ssize_t)(dl + 2)) return (-1);
	}
	else if (buf[3] == 4) { if (recv_timeout(proxy_fd, buf, 18, 10000) != 18) return (-1); }
	else return (-1);

	return (0);
}

/* ---------- HTTP CONNECT ---------- */

static int connect_http_proxy(int proxy_fd, const char *target_host,
	int target_port, const char *user, const char *pass)
{
	char request[2048];
	char response[1024];
	char auth_b64[256];
	char auth_raw[512];
	ssize_t r;
	char *p;
	int status = 0;

	snprintf(request, sizeof(request),
		"CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n",
		target_host, target_port, target_host, target_port);

	if ((user && user[0]) || (pass && pass[0]))
	{
		snprintf(auth_raw, sizeof(auth_raw), "%s:%s",
			user ? user : "", pass ? pass : "");
		base64_encode_std((const unsigned char *)auth_raw, strlen(auth_raw), auth_b64);
		strncat(request, "Proxy-Authorization: Basic ", sizeof(request) - strlen(request) - 1);
		strncat(request, auth_b64, sizeof(request) - strlen(request) - 1);
		strncat(request, "\r\n", sizeof(request) - strlen(request) - 1);
	}
	strncat(request, "User-Agent: vless-server\r\n\r\n",
		sizeof(request) - strlen(request) - 1);

	if (send_all(proxy_fd, request, strlen(request)) < 0) return (-1);

	p = response;
	while (1)
	{
		r = recv_timeout(proxy_fd, p, sizeof(response) - (size_t)(p - response) - 1, 10000);
		if (r <= 0) return (-1);
		p += r;
		*p = '\0';
		if (strstr(response, "\r\n\r\n") || strstr(response, "\n\n")) break;
		if ((size_t)(p - response) >= sizeof(response) - 1) return (-1);
	}

	if (sscanf(response, "HTTP/%*d.%*d %d", &status) != 1 &&
		sscanf(response, "HTTP/%*d %d", &status) != 1)
		return (-1);
	if (status < 200 || status >= 300) return (-1);
	return (0);
}

/* ---------- open remote ---------- */

static int open_remote_connection(const struct vless_proxy_config *proxy,
	const char *target_host, int target_port)
{
	int fd;
	if (!proxy || proxy->type == PROXY_DIRECT)
		return connect_tcp(target_host, target_port);

	fd = connect_tcp(proxy->host, proxy->port);
	if (fd < 0) return (-1);

	switch (proxy->type)
	{
		case PROXY_SOCKS5:
			if (connect_socks5(fd, target_host, target_port,
				proxy->username, proxy->password) < 0)
			{ close(fd); return (-1); }
			break;
		case PROXY_HTTP:
		case PROXY_HTTPS:
			if (connect_http_proxy(fd, target_host, target_port,
				proxy->username, proxy->password) < 0)
			{ close(fd); return (-1); }
			break;
		default:
			close(fd); return (-1);
	}
	return fd;
}

/* ---------- VLESS header ---------- */

struct vless_header
{
	unsigned char version;
	unsigned char opt_len;
	unsigned char cmd;
	int           is_udp;
	int           port;
	char          hostname[256];
	int           address_type;
	size_t        raw_index;
};

static int parse_vless_header(const unsigned char *chunk, size_t chunk_len,
	const char *expected_uuid, struct vless_header *vh)
{
	size_t cmd_idx, port_idx, addr_idx, addr_val_idx, addr_len;
	char uuid_str[37];

	memset(vh, 0, sizeof(*vh));
	if (chunk_len < 24) return (-1);

	vh->version = chunk[0];
	if (format_uuid(chunk + 1, uuid_str, sizeof(uuid_str)) < 0) return (-1);
	if (strcasecmp(uuid_str, expected_uuid) != 0) return (-2);

	vh->opt_len = chunk[17];
	cmd_idx = 18 + vh->opt_len;
	if (cmd_idx >= chunk_len) return (-1);

	vh->cmd = chunk[cmd_idx];
	if (vh->cmd == VLESS_CMD_TCP)      vh->is_udp = 0;
	else if (vh->cmd == VLESS_CMD_UDP) vh->is_udp = 1;
	else return (-3);

	port_idx = cmd_idx + 1;
	if (port_idx + 2 > chunk_len) return (-1);
	vh->port = ((int)chunk[port_idx] << 8) | chunk[port_idx + 1];

	addr_idx = port_idx + 2;
	if (addr_idx >= chunk_len) return (-1);
	vh->address_type = chunk[addr_idx];
	addr_val_idx = addr_idx + 1;

	switch (vh->address_type)
	{
		case VLESS_ADDR_IPV4:
			addr_len = 4;
			if (addr_val_idx + addr_len > chunk_len) return (-1);
			{
				struct in_addr a4;
				memcpy(&a4, chunk + addr_val_idx, 4);
				if (!inet_ntop(AF_INET, &a4, vh->hostname, sizeof(vh->hostname)))
					return (-1);
			}
			break;
		case VLESS_ADDR_DOMAIN:
			if (addr_val_idx >= chunk_len) return (-1);
			addr_len = chunk[addr_val_idx];
			addr_val_idx += 1;
			if (addr_val_idx + addr_len > chunk_len) return (-1);
			if (addr_len >= sizeof(vh->hostname)) return (-1);
			memcpy(vh->hostname, chunk + addr_val_idx, addr_len);
			vh->hostname[addr_len] = '\0';
			break;
		case VLESS_ADDR_IPV6:
			addr_len = 16;
			if (addr_val_idx + addr_len > chunk_len) return (-1);
			{
				struct in6_addr a6;
				memcpy(&a6, chunk + addr_val_idx, 16);
				if (!inet_ntop(AF_INET6, &a6, vh->hostname, sizeof(vh->hostname)))
					return (-1);
			}
			break;
		default:
			return (-4);
	}
	if (!vh->hostname[0]) return (-1);
	vh->raw_index = addr_val_idx + addr_len;
	return (0);
}

/* ---------- remote → WS forwarding thread ---------- */

static void *remote_to_ws(void *arg)
{
	struct vless_conn_ctx *ctx = (struct vless_conn_ctx *)arg;
	unsigned char buf[SOCK_BUF_SIZE + 2];
	unsigned char sendbuf[SOCK_BUF_SIZE + 2];
	ssize_t n;
	size_t sendlen;

	while (1)
	{
		int fd;
		pthread_mutex_lock(&ctx->mtx);
		if (ctx->closed || ctx->remote_fd < 0)
		{
			pthread_mutex_unlock(&ctx->mtx);
			break;
		}
		fd = ctx->remote_fd;
		pthread_mutex_unlock(&ctx->mtx);

		n = recv(fd, buf + 2, SOCK_BUF_SIZE, 0);
		if (n <= 0) break;

		pthread_mutex_lock(&ctx->mtx);
		if (ctx->resp_header_pending)
		{
			buf[0] = ctx->resp_version;
			buf[1] = 0x00;
			sendlen = 2 + (size_t)n;
			ctx->resp_header_pending = 0;
			memcpy(sendbuf, buf, sendlen);
		}
		else
		{
			sendlen = (size_t)n;
			memcpy(sendbuf, buf + 2, sendlen);
		}
		pthread_mutex_unlock(&ctx->mtx);

		if (ws_sendframe_bin(ctx->client, (const char *)sendbuf, sendlen) < 0)
			break;
	}

	pthread_mutex_lock(&ctx->mtx);
	ctx->closed = 1;
	if (ctx->remote_fd >= 0) { close(ctx->remote_fd); ctx->remote_fd = -1; }
	pthread_mutex_unlock(&ctx->mtx);

	ws_close_client(ctx->client);
	return NULL;
}

/* ---------- wsServer callbacks ---------- */

void onopen(ws_cli_conn_t client)
{
	struct vless_conn_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) return;
	ctx->client    = client;
	ctx->remote_fd = -1;
	pthread_mutex_init(&ctx->mtx, NULL);
	ws_set_connection_context(client, ctx);
}

void onclose(ws_cli_conn_t client)
{
	struct vless_conn_ctx *ctx = ws_get_connection_context(client);
	if (!ctx) return;

	pthread_mutex_lock(&ctx->mtx);
	ctx->closed = 1;
	if (ctx->remote_fd >= 0) shutdown(ctx->remote_fd, SHUT_RDWR);
	pthread_mutex_unlock(&ctx->mtx);

	if (ctx->remote_thread && !pthread_equal(ctx->remote_thread, pthread_self()))
	{
		int rc = pthread_join(ctx->remote_thread, NULL);
		(void)rc;
	}

	if (ctx->remote_fd >= 0) close(ctx->remote_fd);
	pthread_mutex_destroy(&ctx->mtx);
	free(ctx);
	ws_set_connection_context(client, NULL);
}

void onmessage(ws_cli_conn_t client,
	const unsigned char *msg, uint64_t size, int type)
{
	struct vless_conn_ctx *ctx = ws_get_connection_context(client);
	struct vless_header vh;
	char target_host[256];
	int target_port, remote_fd;
	(void)type;

	if (!ctx || ctx->closed) return;

	if (!ctx->parsed)
	{
		if (parse_vless_header(msg, (size_t)size, vless_cfg.uuid, &vh) < 0)
		{
			fprintf(stderr, "VLESS: bad header: size=%lu first4=%02x %02x %02x %02x\n", (unsigned long)size, size>0?msg[0]:0, size>1?msg[1]:0, size>2?msg[2]:0, size>3?msg[3]:0);
			ws_close_client(client);
			return;
		}
		ctx->parsed = 1;
		ctx->resp_version = vh.version;

		if (vh.is_udp)
		{
			if (vh.port != DNS_PORT)
			{
				fprintf(stderr, "VLESS: UDP port %d not supported\n", vh.port);
				ws_close_client(client);
				return;
			}
			snprintf(target_host, sizeof(target_host), "%s", DNS_SERVER);
			target_port = DNS_PORT;
		}
		else
		{
			snprintf(target_host, sizeof(target_host), "%s", vh.hostname);
			target_port = vh.port;
		}

		remote_fd = open_remote_connection(&ctx->proxy_cfg, target_host, target_port);
		if (remote_fd < 0)
		{
			fprintf(stderr, "VLESS: connect failed %s:%d\n", target_host, target_port);
			ws_close_client(client);
			return;
		}

		pthread_mutex_lock(&ctx->mtx);
		ctx->remote_fd = remote_fd;
		ctx->resp_header_pending = 1;
		pthread_mutex_unlock(&ctx->mtx);

		if (pthread_create(&ctx->remote_thread, NULL, remote_to_ws, ctx) != 0)
		{
			pthread_mutex_lock(&ctx->mtx);
			ctx->closed = 1;
			close(ctx->remote_fd);
			ctx->remote_fd = -1;
			pthread_mutex_unlock(&ctx->mtx);
			ws_close_client(client);
			return;
		}
		/* Not detached: onclose() must join it before free'ing ctx. */

		if (vh.raw_index < (size_t)size)
		{
			pthread_mutex_lock(&ctx->mtx);
			int fd = ctx->remote_fd;
			pthread_mutex_unlock(&ctx->mtx);
			if (fd >= 0 && send_all(fd, msg + vh.raw_index, (size_t)size - vh.raw_index) < 0)
			{
				ws_close_client(client);
				return;
			}
		}
	}
	else
	{
		int fd, closed;
		pthread_mutex_lock(&ctx->mtx);
		fd = ctx->remote_fd;
		closed = ctx->closed;
		pthread_mutex_unlock(&ctx->mtx);
		if (closed || fd < 0) return;
		if (send_all(fd, msg, (size_t)size) < 0)
			ws_close_client(client);
	}
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	int opt, opt_idx;
	int port = VLESS_LISTEN_PORT;
	const char *proxy_url = NULL;
	const char *uuid_str = NULL;
	static struct option long_opts[] =
	{
		{ "port",  required_argument, 0, 'p' },
		{ "uuid",  required_argument, 0, 'u' },
		{ "proxy", required_argument, 0, 'P' },
		{ "help",  no_argument,       0, 'h' },
		{ 0, 0, 0, 0 },
	};

	signal(SIGPIPE, SIG_IGN);

	while ((opt = getopt_long(argc, argv, "p:u:P:h", long_opts, &opt_idx)) != -1)
	{
		switch (opt)
		{
			case 'p': port = atoi(optarg); break;
			case 'u': uuid_str = optarg;   break;
			case 'P': proxy_url = optarg;  break;
			case 'h':
			default:
				fprintf(stderr, "Usage: %s [-p|--port port] [-u|--uuid uuid] [-P|--proxy url]\n", argv[0]);
				return (opt == 'h' ? 0 : 1);
		}
	}

	if (uuid_str)
	{
		if (strlen(uuid_str) != 36)
		{
			fprintf(stderr, "Invalid UUID length: %s\n", uuid_str);
			return (1);
		}
		memset(vless_cfg.uuid, 0, sizeof(vless_cfg.uuid));
		strncpy(vless_cfg.uuid, uuid_str, sizeof(vless_cfg.uuid) - 1);
	}

	vless_cfg.listen_port = port;
	if (proxy_url)
	{
		if (parse_proxy_url(proxy_url, &vless_cfg.proxy) < 0)
		{
			fprintf(stderr, "Invalid proxy URL: %s\n", proxy_url);
			return 1;
		}
	}

	printf("vless-server listening on 0.0.0.0:%d\n", port);
	printf("uuid: %s\n", vless_cfg.uuid);
	if (vless_cfg.proxy.type != PROXY_DIRECT)
		printf("outbound proxy: type=%d host=%s port=%d\n",
			vless_cfg.proxy.type, vless_cfg.proxy.host, vless_cfg.proxy.port);
	else
		printf("outbound proxy: direct\n");

	ws_socket(&(struct ws_server){
		.host         = "0.0.0.0",
		.port         = (uint16_t)port,
		.thread_loop  = 1,
		.timeout_ms   = 1000,
		.evs.onopen    = onopen,
		.evs.onclose   = onclose,
		.evs.onmessage = onmessage,
		.context       = &vless_cfg,
	});

	/* .thread_loop = 1 makes ws_socket() non-blocking; wait forever. */
	while (1)
		pause();

	return (0);
}
