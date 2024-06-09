#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <mint/sysbind.h>
#include <gem.h>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/rand_drbg.h>

#include "transprt.h"
#include <ldg.h>

/* prototypes */

void timing_set_system(int value);

TPL *tpl;
DRV_LIST *drivers;

#define TCP_LAYER_DEFAULT 0
#define TCP_LAYER_MINTNET 1
#define TCP_LAYER_STIK 2
static int used_tcp_layer = TCP_LAYER_DEFAULT;

static const int16_t STIK_RECV_MAXSIZE = 19200;
static const uint16_t STIK_SEND_MAXSIZE = 1920;

static short *ldg_aes_global;
static short ldg_aes_global_init = 0;

#define OPENSSL_ERR_NET_CONN_RESET -1
#define OPENSSL_ERR_NET_SEND_FAILED -1
#define OPENSSL_ERR_NET_RECV_FAILED -1
#define OPENSSL_ERR_SSL_WANT_READ -1
#define OPENSSL_ERR_SSL_WANT_WRITE -1
#define OPENSSL_ERR_NET_CONN_RESET -1

/* helper functions */

static void my_wait(unsigned long delay)
{
	if (ldg_aes_global_init)
	{
		mt_evnt_timer(delay, ldg_aes_global);
	}
}

static int my_stick_send(void *ctx, const unsigned char *buf, size_t len)
{
	int16_t cn = (int16_t) * ((int *) ctx);
	int16_t ret = E_NORMAL;
	int16_t rem = 0;
	int sen = 0;
	unsigned char *ptr = (unsigned char *) buf;

	while (len >= STIK_SEND_MAXSIZE && ret > E_NODATA)
	{
		short i;

		ret = TCP_send(cn, ptr, STIK_SEND_MAXSIZE);

		i = 0;
		while (ret == E_OBUFFULL && i <= 100)
		{
			my_wait(50);
			ret = TCP_send(cn, ptr, STIK_SEND_MAXSIZE);
			++i;
		}

		if (ret == E_NORMAL)
		{
			sen += STIK_SEND_MAXSIZE;
			ptr += STIK_SEND_MAXSIZE;
			len -= STIK_SEND_MAXSIZE;
		}
	}
	if (len > 0 && ret > E_NODATA)
	{
		short i;

		rem = (int16_t) len;

		ret = TCP_send(cn, ptr, rem);

		i = 0;
		while (ret == E_OBUFFULL && i <= 100)
		{
			my_wait(50);
			ret = TCP_send(cn, ptr, rem);
			++i;
		}

		if (ret == E_NORMAL)
		{
			sen += len;
		}
	}

	if (ret < 0)
	{
		if (ret == E_REFUSE || ret == E_RRESET)
		{
			return OPENSSL_ERR_NET_CONN_RESET;
		}

		return OPENSSL_ERR_NET_SEND_FAILED;
	} else if (ret != E_NORMAL)
	{
		return ret;
	}

	return sen;
}


static int my_stick_recv(void *ctx, unsigned char *buf, size_t len)
{
	int16_t cn = (int16_t) * ((int *) ctx);
	int16_t ret = E_NORMAL;
	int16_t get = 0;
	int rec = 0;
	unsigned char *ptr = buf;
	unsigned char *end = (buf + len);

	while (ret > E_EOF && ptr < end)
	{
		ret = CNbyte_count(cn);

		if (ret >= E_NORMAL)
		{
			get = ret;

			if (get > STIK_RECV_MAXSIZE)
			{
				get = STIK_RECV_MAXSIZE;
			}

			if ((ptr + get) > end)
			{
				get = (end - ptr);
			}
		} else if (ret == E_NODATA)
		{
			my_wait(20);
		}

		if (get > 0)
		{
			ret = CNget_block(cn, ptr, get);

			if (ret > E_NORMAL)
			{
				rec += ret;
				ptr += ret;
			}
		}
	}

	if (ret < 0)
	{
		if (ret == E_REFUSE || ret == E_RRESET)
		{
			return OPENSSL_ERR_NET_CONN_RESET;
		}

		return OPENSSL_ERR_NET_RECV_FAILED;
	}

	return rec;
}


static int my_mintnet_recv(void *ctx, unsigned char *buf, size_t len)
{
	int fd = *((int *) ctx);
	int ret = read(fd, buf, len);

	if (ret < 0)
	{
		if (errno == EAGAIN || errno == EINTR)
		{
			return OPENSSL_ERR_SSL_WANT_READ;
		}

		if (errno == EPIPE || errno == ECONNRESET)
		{
			return OPENSSL_ERR_NET_CONN_RESET;
		}

		return OPENSSL_ERR_NET_RECV_FAILED;
	}

	return ret;
}

static int my_mintnet_send(void *ctx, const unsigned char *buf, size_t len)
{
	int fd = *((int *) ctx);
	int ret = write(fd, buf, len);

	if (ret < 0)
	{
		if (errno == EAGAIN || errno == EINTR)
		{
			return OPENSSL_ERR_SSL_WANT_WRITE;
		}

		if (errno == EPIPE || errno == ECONNRESET)
		{
			return OPENSSL_ERR_NET_CONN_RESET;
		}

		return OPENSSL_ERR_NET_SEND_FAILED;
	}

	return ret;
}

/* PolarSSSL version */

static const char *CDECL get_version(void)
{
	return OPENSSL_VERSION_TEXT;
}

static void CDECL set_aes_global(short *aes_global)
{
	ldg_aes_global = aes_global;
	ldg_aes_global_init = 1;
}

/* certificate functions */

typedef struct {
	X509_INFO *info;
} ldg_x509_crt;

static unsigned long CDECL get_sizeof_x509_crt_struct(void)
{
	return sizeof(ldg_x509_crt);
}

static void CDECL ldg_x509_crt_init(ldg_x509_crt *crt)
{
	crt->info = X509_INFO_new();
}

static int CDECL ldg_x509_crt_parse(ldg_x509_crt *chain, const unsigned char *buf, size_t len)
{
	/* XXX */
	(void)chain;
	(void)buf;
	(void)len;
	return 0;
}

static int CDECL ldg_x509_crt_info(char *buf, size_t size, const ldg_x509_crt *crt)
{
	/* XXX */
	(void)buf;
	(void)size;
	(void)crt;
	return 0;
}

static void CDECL ldg_x509_crt_free(ldg_x509_crt *crt)
{
	X509_INFO_free(crt->info);
	crt->info = 0;
}

/* private key functions */

/** A context for random number generation (RNG).
 */
typedef struct {
	int entropy; /* XXX */
} ldg_entropy_context;

typedef struct  {
	RAND_DRBG *drbg;
} ldg_ctr_drbg_context;

typedef struct {
	ldg_entropy_context entropy;
	ldg_ctr_drbg_context drbg;
} rng_context_t;

typedef struct {
	int pk; /* XXX */
	rng_context_t rng;
} ldg_pk_context;

static unsigned long CDECL get_sizeof_pk_context_struct(void)
{
	return sizeof(ldg_pk_context);
}

static void CDECL ldg_pk_init(ldg_pk_context *pk)
{
	(void)pk; /* XXX */
	RAND_DRBG_free(pk->rng.drbg.drbg);
	pk->rng.drbg.drbg = 0;
}

static int CDECL ldg_pk_parse(ldg_pk_context *pk, const unsigned char *key, size_t keylen)
{
	pk->rng.drbg.drbg = RAND_DRBG_new(0, 0, NULL);
	(void)key;
	(void)keylen;
	/* XXX */
	return 0;
}

static void CDECL ldg_pk_free(ldg_pk_context *pk)
{
	(void)pk; /* XXX */
}

/* entropy functions */

static unsigned long CDECL get_sizeof_entropy_context_struct(void)
{
	return sizeof(ldg_entropy_context);
}

static unsigned long CDECL get_sizeof_ctr_drbg_context_struct(void)
{
	return sizeof(ldg_ctr_drbg_context);
}

static int ldg_entropy_init(ldg_entropy_context *ctx, ldg_ctr_drbg_context *ctr, const char *app_name)
{
	int ret = 0;

	/* entropy_init(ctx); */
	ctr->drbg = RAND_DRBG_new(0, 0, NULL);
	
	(void)ctx;
	(void)app_name; /* XXX */

	return ret;
}

static void CDECL ldg_entropy_free(ldg_entropy_context *ctx, ldg_ctr_drbg_context *ctr)
{
	if (ctr != NULL)
	{
		RAND_DRBG_free(ctr->drbg);
		ctr->drbg = 0;
	}
	if (ctx != NULL)
	{
		/* XXX */
	}
}

/* ssl layer functions */

typedef struct {
	SSL *ssl;
	SSL_CTX *ctx;
	SSL_CONF_CTX *conf;
	int server_fd;
	ldg_x509_crt server_cert;
} ldg_ssl_context;

static unsigned long CDECL get_sizeof_ssl_context_struct(void)
{
	return sizeof(ldg_ssl_context);
}

static int CDECL ldg_ssl_init(ldg_ssl_context *ssl, ldg_ctr_drbg_context *ctr, int *server_fd, const char *servername,
					   ldg_x509_crt *cacert, ldg_x509_crt *cert, ldg_pk_context *pk)
{
	int ret;
	
	ssl->ctx = SSL_CTX_new(TLS_client_method());
	ssl->ssl = SSL_new(ssl->ctx);
	ssl->conf = SSL_CONF_CTX_new();
	ssl->server_cert.info = 0;
	ctr->drbg = 0;
	if (ssl->ctx == 0 || ssl->ssl == 0 || ssl->conf == 0)
	{
		ret = -1; /* XXX */
		goto exit;
	}
	ssl->server_fd = *server_fd;
    SSL_set_connect_state(ssl->ssl);

	SSL_CTX_set_verify(ssl->ctx, cacert == NULL ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);

#if defined(OPENSSL_DEBUG_C)
	SSL_set_debug(ssl->ssl, 1);
#endif
	if (used_tcp_layer == TCP_LAYER_STIK)
	{
		/* mbedtls_ssl_set_bio(&ssl->ssl, server_fd, my_stick_send, my_stick_recv, NULL); XXX */
	} else
	{
		/* mbedtls_ssl_set_bio(&ssl->ssl, server_fd, my_mintnet_send, my_mintnet_recv, NULL); */
	}
	(void)my_mintnet_send;
	(void)my_mintnet_recv;
	(void)my_stick_send;
	(void)my_stick_recv;
	
	if (cacert && cacert->info)
		SSL_CTX_add1_chain_cert(ssl->ctx, cacert->info->x509);
	if (cert != NULL && pk != NULL)
	{
		ret = 0; /* mbedtls_ssl_conf_own_cert(&ssl->conf, cert, &pk->pk); XXX */
		if (ret != 0)
			goto exit;
	}

	if (servername)
	{
		ret = SSL_set1_host(ssl->ssl, servername);
		if (ret != 0)
			goto exit;
	}

	return 0;

exit:
	SSL_free(ssl->ssl);
	ssl->ssl = 0;
	SSL_CTX_free(ssl->ctx);
	ssl->ctx = 0;
	SSL_CONF_CTX_free(ssl->conf);
	ssl->conf = 0;
	return ret;
}

static void CDECL ldg_ssl_set_minmax_version(ldg_ssl_context *ssl, int minor_min, int minor_max)
{
	if (minor_min < (TLS1_VERSION & 0xff)) /* TLS v1.0 */
	{
		minor_min = TLS1_VERSION & 0xff;
	}
	if (minor_max > (TLS_MAX_VERSION & 0xff)) /* TLS v1.3 */
	{
		minor_max = TLS_MAX_VERSION & 0xff;
	}
	if (minor_min > minor_max)
	{
		minor_min = minor_max;
	}

	SSL_CTX_set_min_proto_version(ssl->ctx, (SSL3_VERSION_MAJOR << 8) | minor_min);
	SSL_CTX_set_max_proto_version(ssl->ctx, (SSL3_VERSION_MAJOR << 8) | minor_max);
}

static void CDECL ldg_ssl_set_ciphersuite(ldg_ssl_context *ssl, const int *wished_ciphersuites)
{
	(void)ssl; /* XXX */
	(void)wished_ciphersuites;
	/* mbedtls_ssl_conf_ciphersuites(ssl->conf, wished_ciphersuites); */
}

static int CDECL ldg_ssl_handshake(ldg_ssl_context *ssl)
{
	int ret = 0;
	struct timeval timer;

	if (!SSL_CONF_CTX_finish(ssl->conf))
	{
		ret = -1; /* XXX */
		return ret;
	}
	
	if (used_tcp_layer == TCP_LAYER_MINTNET)
	{
		timer.tv_sec = 30;
		timer.tv_usec = 0;

		setsockopt(ssl->server_fd, SOL_SOCKET, SO_RCVTIMEO, (void *) &timer, sizeof(timer));
	}

#if 0 /* XXX */
	while ((ret = mbedtls_ssl_handshake(&ssl->ssl)) != 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			break;
		}
	}
#endif

	if (ret == 0 && used_tcp_layer == TCP_LAYER_MINTNET)
	{
		timer.tv_sec = 0;
		timer.tv_usec = 0;

		setsockopt(ssl->server_fd, SOL_SOCKET, SO_RCVTIMEO, (void *) &timer, sizeof(timer));
	}

	return ret;
}

static const char *CDECL ldg_ssl_get_version(ldg_ssl_context *ssl)
{
	int version = SSL_SESSION_get_protocol_version(SSL_get_session(ssl->ssl));
	
	switch (version)
	{
		case SSL3_VERSION: return "SSLv3";
		case TLS1_VERSION: return "TLSv1";
		case TLS1_1_VERSION: return "TLSv1.1";
		case TLS1_2_VERSION: return "TLSv1.2";
		case TLS1_3_VERSION: return "TLSv1.4";
		case DTLS1_VERSION: return "DTLSv1";
		case DTLS1_2_VERSION: return "DTLSv1.2";
	}
	return "unknown";
}

static const char *CDECL ldg_ssl_get_ciphersuite(ldg_ssl_context *ssl)
{
	return SSL_get_cipher_name(ssl->ssl);
}

static int CDECL ldg_ssl_get_verify_result(ldg_ssl_context *ssl)
{
	return SSL_get_verify_mode(ssl->ssl);
}

static const ldg_x509_crt *CDECL ldg_ssl_get_peer_cert(ldg_ssl_context *ssl)
{
	if (ssl->server_cert.info == 0)
		ssl->server_cert.info = X509_INFO_new();
	ssl->server_cert.info->x509 = SSL_get_peer_certificate(ssl->ssl);
	return &ssl->server_cert;
}

static int CDECL ldg_ssl_read(ldg_ssl_context *ssl, unsigned char *buf, size_t len)
{
	(void)ssl;
	(void)buf;
	(void)len;
	/* return mbedtls_ssl_read(ssl->ssl, buf, len); */
	return 0; /* XXX */
}

static int CDECL ldg_ssl_write(ldg_ssl_context *ssl, const unsigned char *buf, size_t len)
{
	(void)ssl;
	(void)buf;
	(void)len;
	/* return mbedtls_ssl_write(ssl->ssl, buf, len); */
	return 0; /* XXX */
}

static int CDECL ldg_ssl_close_notify(ldg_ssl_context *ssl)
{
	(void)ssl;
	/* return mbedtls_ssl_close_notify(ssl->ssl); */
	return 0;
}

static void CDECL ldg_ssl_free(ldg_ssl_context *ssl)
{
	SSL_free(ssl->ssl);
	ssl->ssl = 0;
	SSL_CTX_free(ssl->ctx);
	ssl->ctx = 0;
	SSL_CONF_CTX_free(ssl->conf);
	ssl->conf = 0;
	X509_INFO_free(ssl->server_cert.info);
	ssl->server_cert.info = 0;
}

/* net functions */

typedef struct
{
	long id;							/* Identification code */
	long value;							/* Value of the cookie */
} COOKJAR;

static int xget_cookie(long cookie, void *value)
{
	COOKJAR *cookiejar;
	short i = 0;

	/* Get pointer to cookie jar */
	cookiejar = (COOKJAR *) (Setexc(0x05A0 / 4, (void (*)(void)) -1));

	if (cookiejar)
	{
		for (i = 0; cookiejar[i].id; i++)
		{
			if (cookiejar[i].id == cookie)
			{
				if (value)
				{
					*(long *) value = cookiejar[i].value;
				}

				return TRUE;
			}
		}
	}

	return FALSE;
}

static void CDECL force_tcp_layer(int value)
{
	if (value == TCP_LAYER_MINTNET)
	{
		used_tcp_layer = TCP_LAYER_MINTNET;
	} else if (value == TCP_LAYER_STIK)
	{
		used_tcp_layer = TCP_LAYER_STIK;
	} else
	{
		used_tcp_layer = TCP_LAYER_DEFAULT;
	}
}


static int netdb_errno(int h_errno)
{
	switch (h_errno)
	{
	case NETDB_INTERNAL:
	case NETDB_SUCCESS:
		return -EERROR;
	case TRY_AGAIN:
		return -EAGAIN;
	case NO_RECOVERY:
		return -ECONNREFUSED;
	case NO_DATA:
		return -ENODATA;
	case HOST_NOT_FOUND:
		return -EHOSTUNREACH;
	}
	return -h_errno;
}


static int CDECL ldg_gethostbyname(const char *hostname, char **realname, uint32_t *alist, size_t lsize)
{
	struct hostent *hp;

	if (realname)
		*realname = 0;
	switch (used_tcp_layer)
	{
	case TCP_LAYER_MINTNET:
		hp = gethostbyname(hostname);
		if (hp)
		{
			if (alist)
			{
				size_t i;

				for (i = 0; i < lsize && hp->h_addr_list[i]; i++)
				{
					if (hp->h_length == sizeof(*alist) && hp->h_addrtype == AF_INET)
						memcpy(&alist[i], hp->h_addr_list[i], hp->h_length);
					else
						alist[i] = 0;
				}
				for (; i < lsize; i++)
					alist[i] = 0;
			}
			if (realname && hp->h_aliases && hp->h_aliases[0])
				*realname = strdup(hp->h_aliases[0]);
			return 0;
		}
		return netdb_errno(h_errno);
	case TCP_LAYER_STIK:
		if (tpl)
			return resolve(hostname, realname, alist, lsize);
		break;
	}
	return -ENOSYS;
}


static void CDECL ldg_freehostname(char *hostname)
{
	if (hostname)
	{
		switch (used_tcp_layer)
		{
		case TCP_LAYER_MINTNET:
			free(hostname);
			break;
		case TCP_LAYER_STIK:
			if (tpl)
				KRfree(hostname);
			break;
		}
	}
}

static int ldg_get_min_tls_version(void)
{
	return TLS1_VERSION & 0xff;
}

static int ldg_get_max_tls_version(void)
{
	return TLS_MAX_VERSION & 0xff;
}

/* ldg functions table */

static PROC const LibFunc[] = {
	{ "get_version", "const char* get_version();", get_version },

	{ "set_aes_global", "void set_aes_global(short *aes_global);", set_aes_global },
	{ "force_tcp_layer", "void force_tcp_layer(int value);", force_tcp_layer },

	{ "get_sizeof_x509_crt_struct", "unsigned long get_sizeof_x509_crt_struct();", get_sizeof_x509_crt_struct },
	{ "get_sizeof_pk_context_struct", "unsigned long get_sizeof_pk_context_struct();", get_sizeof_pk_context_struct },
	{ "get_sizeof_entropy_context_struct", "unsigned long get_sizeof_entropy_context_struct();", get_sizeof_entropy_context_struct },
	{ "get_sizeof_ctr_drbg_context_struct", "unsigned long get_sizeof_ctr_drbg_context_struct();", get_sizeof_ctr_drbg_context_struct },
	{ "get_sizeof_ssl_context_struct", "unsigned long get_sizeof_ssl_context_struct();", get_sizeof_ssl_context_struct },

	{ "ldg_x509_crt_init", "void ldg_x509_crt_init(x509_crt *crt);", ldg_x509_crt_init },
	{ "ldg_x509_crt_parse", "int ldg_x509_crt_parse(x509_crt *chain, const unsigned char *buf, size_t len);", ldg_x509_crt_parse },
	{ "ldg_x509_crt_info", "int ldg_x509_crt_info(char *buf, size_t size, const x509_crt *crt);", ldg_x509_crt_info },
	{ "ldg_x509_crt_free", "void ldg_x509_crt_free(x509_crt *crt);", ldg_x509_crt_free },

	{ "ldg_pk_init", "void ldg_pk_init(pk_context *pk);", ldg_pk_init },
	{ "ldg_pk_parse", "int ldg_pk_parse(pk_context *pk, const unsigned char *key, size_t keylen);", ldg_pk_parse },
	{ "ldg_pk_free", "void ldg_pk_free(pk_context *pk);", ldg_pk_free },

	{ "ldg_entropy_init", "int ldg_entropy_init(entropy_context *ctx, ctr_drbg_context *ctr, const char *app_name);", ldg_entropy_init },
	{ "ldg_entropy_free", "void ldg_entropy_free(entropy_context *ctx, ctr_drbg_context *ctr);", ldg_entropy_free },

	{ "ldg_ssl_init", "int ldg_ssl_init(ssl_context *ssl, ctr_drbg_context *ctr, int *server_fd, const char *servername, x509_crt *cacert, x509_crt *cert, pk_context *pk);", ldg_ssl_init },
	{ "ldg_ssl_set_minmax_version", "int ldg_ssl_set_minmax_version(ssl_context *ssl, int min, int max);", ldg_ssl_set_minmax_version },
	{ "ldg_ssl_set_ciphersuite", "void ldg_ssl_set_ciphersuite(ssl_context *ssl, const int *wished_ciphersuites);", ldg_ssl_set_ciphersuite },
	{ "ldg_ssl_handshake", "int ldg_ssl_handshake(ssl_context *ssl);", ldg_ssl_handshake },
	{ "ldg_ssl_get_version", "const char* ldg_ssl_get_version(ssl_context *ssl);", ldg_ssl_get_version },
	{ "ldg_ssl_get_ciphersuite", "const char* ldg_ssl_get_ciphersuite(ssl_context *ssl);", ldg_ssl_get_ciphersuite },
	{ "ldg_ssl_get_verify_result", "int ldg_ssl_get_verify_result(ssl_context *ssl);", ldg_ssl_get_verify_result },
	{ "ldg_ssl_get_peer_cert", "const x509_crt* ldg_ssl_get_peer_cert(ssl_context *ssl);", ldg_ssl_get_peer_cert },
	{ "ldg_ssl_read", "int ldg_ssl_read( ssl_context *ssl, unsigned char *buf, size_t len);", ldg_ssl_read },
	{ "ldg_ssl_write", "int ldg_ssl_write(ssl_context *ssl, const unsigned char *buf, size_t len);", ldg_ssl_write },
	{ "ldg_ssl_close_notify", "int ldg_ssl_close_notify(ssl_context *ssl);", ldg_ssl_close_notify },
	{ "ldg_ssl_free", "void ldg_ssl_free(ssl_context *ssl);", ldg_ssl_free },

	/* new in Release 9 */
	{ "ldg_gethostbyname", "int ldg_gethostbyname(const char *hostname, char **realname, uint32_t *alist, size_t lsize);", ldg_gethostbyname },
	{ "ldg_freehostname", "void ldg_freehostname(char *hostname);", ldg_freehostname },
	{ "ldg_get_min_tls_version", "int ldg_get_min_tls_version();", ldg_get_min_tls_version },
	{ "ldg_get_max_tls_version", "int ldg_get_max_tls_version();", ldg_get_max_tls_version },
};

/* main function: init and memory configuration */

static void search_tcp_layer(void)
{
	used_tcp_layer = TCP_LAYER_DEFAULT;

	/* timing_set_system(1); XXX */

	if (xget_cookie(0x4D694E54L, NULL))	/* 'MiNT' */
	{
#if defined(OPENSSL_DEBUG_C)
		(void) Cconws("MiNTnet detected\n\r");
#endif
		/* timing_set_system(0); XXX */
		used_tcp_layer = TCP_LAYER_MINTNET;
	} else if (xget_cookie(0x4D616758L, NULL) && xget_cookie(0x53434B4DL, NULL))	/* 'MagX' and 'SCKM' */
	{
#if defined(OPENSSL_DEBUG_C)
		(void) Cconws("MagiCNet detected\n\r");
#endif
		used_tcp_layer = TCP_LAYER_MINTNET;
	} else if (xget_cookie(0x5354694BL, NULL))	/* 'STiK' */
	{
#if defined(OPENSSL_DEBUG_C)
		(void) Cconws("STinG/STiK detected\n\r");
#endif
		used_tcp_layer = TCP_LAYER_STIK;
	}
}

static short stick_init(void)
{
	unsigned long cookieval;

	if (xget_cookie(0x5354694BL, &cookieval) == 0)	/* 'STiK' */
	{
#if defined(OPENSSL_DEBUG_C)
		(void) Cconws("STinG/STiK is not loaded or enabled!\n\r");
#endif
		return -1;
	}

	drivers = (DRV_LIST *) cookieval;

	if (strcmp(drivers->magic, STIK_DRVR_MAGIC) != 0)
	{
#if defined(OPENSSL_DEBUG_C)
		(void) Cconws("STinG/STiK structures corrupted!\n\r");
#endif
		return -1;
	}

	tpl = (TPL *) get_dftab(TRANSPORT_DRIVER);

	if (tpl == (TPL *) NULL)
	{
#if defined(OPENSSL_DEBUG_C)
		(void) Cconws("Transport Driver not found!\n\r");
#endif
		return -1;
	}

	return 0;
}

static LDGLIB LibLdg = { 9, sizeof(LibFunc) / sizeof(LibFunc[0]), LibFunc, "SSL/TLS functions from openssl", LDG_NOT_SHARED, 0, 0 };

int main(void)
{
	ldg_init(&LibLdg);

#if 0
	platform_set_malloc_free((void *) ldg_Malloc, (void *) ldg_Free);
#endif

#if defined(OPENSSL_DEBUG_C)
	(void) Cconws("openssl.ldg (");
	(void) Cconws(OPENSSL_VERSION_TEXT);
	(void) Cconws(") debug mode enabled\n\r");
#endif

	search_tcp_layer();
	stick_init();

	return 0;
}
