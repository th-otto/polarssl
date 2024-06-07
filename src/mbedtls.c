#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

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

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"
#endif
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/version.h"

#include "transprt.h"
#include "ldg.h"

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

/* debug functions */

#if defined(MBEDTLS_DEBUG_C)
static void CDECL my_debug(void *ctx, int level, const char *filename, int line, const char *str)
{
	(void) ctx;
	(void) level;
	(void) filename;
	(void) line;
	(void) Cconws(str);
	(void) Cconws("\r\n");
}
#endif


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
			return MBEDTLS_ERR_NET_CONN_RESET;
		}

		return MBEDTLS_ERR_NET_SEND_FAILED;
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
			return MBEDTLS_ERR_NET_CONN_RESET;
		}

		return MBEDTLS_ERR_NET_RECV_FAILED;
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
			return MBEDTLS_ERR_SSL_WANT_READ;
		}

		if (errno == EPIPE || errno == ECONNRESET)
		{
			return MBEDTLS_ERR_NET_CONN_RESET;
		}

		return MBEDTLS_ERR_NET_RECV_FAILED;
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
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		}

		if (errno == EPIPE || errno == ECONNRESET)
		{
			return MBEDTLS_ERR_NET_CONN_RESET;
		}

		return MBEDTLS_ERR_NET_SEND_FAILED;
	}

	return ret;
}

/* PolarSSSL version */

static const char *CDECL get_version(void)
{
	return MBEDTLS_VERSION_STRING;
}

static void CDECL set_aes_global(short *aes_global)
{
	ldg_aes_global = aes_global;
	ldg_aes_global_init = 1;
}

/* certificate functions */

static unsigned long CDECL get_sizeof_x509_crt_struct(void)
{
	return sizeof(mbedtls_x509_crt);
}

static void CDECL ldg_x509_crt_init(mbedtls_x509_crt *crt)
{
	mbedtls_x509_crt_init(crt);
}

static int CDECL ldg_x509_crt_parse(mbedtls_x509_crt *chain, const unsigned char *buf, size_t len)
{
	return mbedtls_x509_crt_parse(chain, buf, len);
}

static int CDECL ldg_x509_crt_info(char *buf, size_t size, const mbedtls_x509_crt *crt)
{
	return mbedtls_x509_crt_info(buf, size, "", crt);
}

static void CDECL ldg_x509_crt_free(mbedtls_x509_crt *crt)
{
	mbedtls_x509_crt_free(crt);
}

/* private key functions */

/** A context for random number generation (RNG).
 */
typedef struct {
	mbedtls_entropy_context entropy;
#if defined(MBEDTLS_CTR_DRBG_C)
	mbedtls_ctr_drbg_context drbg;
#elif defined(MBEDTLS_HMAC_DRBG_C)
	mbedtls_hmac_drbg_context drbg;
#else
#error "No DRBG available"
#endif
} rng_context_t;

typedef struct {
	mbedtls_pk_context pk;
	rng_context_t rng;
} my_pk_context;

static unsigned long CDECL get_sizeof_pk_context_struct(void)
{
	return sizeof(my_pk_context);
}

static void CDECL ldg_pk_init(my_pk_context *pk)
{
	mbedtls_pk_init(&pk->pk);
}

static void rng_init(rng_context_t *rng)
{
#if defined(MBEDTLS_CTR_DRBG_C)
	mbedtls_ctr_drbg_init(&rng->drbg);
#elif defined(MBEDTLS_HMAC_DRBG_C)
	mbedtls_hmac_drbg_init(&rng->drbg);
#endif

	mbedtls_entropy_init(&rng->entropy);
}

static int rng_get(void *p_rng, unsigned char *output, size_t output_len)
{
	rng_context_t *rng = p_rng;

#if defined(MBEDTLS_CTR_DRBG_C)
	return mbedtls_ctr_drbg_random(&rng->drbg, output, output_len);
#elif defined(MBEDTLS_HMAC_DRBG_C)
	return mbedtls_hmac_drbg_random(&rng->drbg, output, output_len);
#endif
}

static int CDECL ldg_pk_parse(my_pk_context *pk, const unsigned char *key, size_t keylen)
{
	rng_init(&pk->rng);
	return mbedtls_pk_parse_key(&pk->pk, key, keylen, NULL, 0, rng_get, &pk->rng);
}

static void CDECL ldg_pk_free(my_pk_context *pk)
{
	mbedtls_pk_free(&pk->pk);
}

/* entropy functions */

static unsigned long CDECL get_sizeof_entropy_context_struct(void)
{
	return sizeof(mbedtls_entropy_context);
}

static unsigned long CDECL get_sizeof_ctr_drbg_context_struct(void)
{
	return sizeof(mbedtls_ctr_drbg_context);
}

static int ldg_entropy_init(mbedtls_entropy_context *ctx, mbedtls_ctr_drbg_context *ctr, const char *app_name)
{
	int ret;

	mbedtls_entropy_init(ctx);
	mbedtls_ctr_drbg_init(ctr);
	
#if defined(MBEDTLS_USE_PSA_CRYPTO)
	if (psa_crypto_init() != PSA_SUCCESS)
	{
		return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
	}
#endif

	ret = mbedtls_ctr_drbg_seed(ctr, mbedtls_entropy_func, ctx, (const unsigned char *) app_name, strlen(app_name));

	return ret;
}

static void CDECL ldg_entropy_free(mbedtls_entropy_context *ctx, mbedtls_ctr_drbg_context *ctr)
{
	if (ctr != NULL)
	{
		mbedtls_ctr_drbg_free(ctr);
	}
	if (ctx != NULL)
	{
		mbedtls_entropy_free(ctx);
	}
#if defined(MBEDTLS_USE_PSA_CRYPTO)
	mbedtls_psa_crypto_free();
#endif
}

/* ssl layer functions */

typedef struct {
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
} my_ssl_context;

static unsigned long CDECL get_sizeof_ssl_context_struct(void)
{
	return sizeof(my_ssl_context);
}

static int CDECL ldg_ssl_init(my_ssl_context *ssl, mbedtls_ctr_drbg_context *ctr, int *server_fd, const char *servername,
					   mbedtls_x509_crt *cacert, mbedtls_x509_crt *cert, my_pk_context *pk)
{
	int ret;
	
	mbedtls_ssl_init(&ssl->ssl);
	mbedtls_ssl_config_init(&ssl->conf);
	ret = mbedtls_ssl_config_defaults(&ssl->conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0)
		goto exit;

	mbedtls_ssl_conf_authmode(&ssl->conf, cacert == NULL ? MBEDTLS_SSL_VERIFY_NONE : MBEDTLS_SSL_VERIFY_OPTIONAL);

	mbedtls_ssl_conf_rng(&ssl->conf, mbedtls_ctr_drbg_random, ctr);
#if defined(MBEDTLS_DEBUG_C)
	mbedtls_ssl_conf_dbg(&ssl->conf, my_debug, stdout);
#endif
	if (used_tcp_layer == TCP_LAYER_STIK)
	{
		mbedtls_ssl_set_bio(&ssl->ssl, server_fd, my_stick_send, my_stick_recv, NULL);
	} else
	{
		mbedtls_ssl_set_bio(&ssl->ssl, server_fd, my_mintnet_send, my_mintnet_recv, NULL);
	}
	mbedtls_ssl_conf_ca_chain(&ssl->conf, cacert, NULL);
	if (cert != NULL && pk != NULL)
	{
		ret = mbedtls_ssl_conf_own_cert(&ssl->conf, cert, &pk->pk);
		if (ret != 0)
			goto exit;
	}
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
	ret = mbedtls_ssl_set_hostname(&ssl->ssl, servername);
	if (ret != 0)
		goto exit;
#endif

	return 0;

exit:
	mbedtls_ssl_free(&ssl->ssl);
	mbedtls_ssl_config_free(&ssl->conf);
	return ret;
}

#ifndef MBEDTLS_SSL_MAJOR_VERSION_3
#define MBEDTLS_SSL_MAJOR_VERSION_3             3
#endif
#ifndef MBEDTLS_SSL_MINOR_VERSION_3
#define MBEDTLS_SSL_MINOR_VERSION_3 (MBEDTLS_SSL_VERSION_TLS1_2 & 0xff)
#endif
#ifndef MBEDTLS_SSL_MINOR_VERSION_4
#define MBEDTLS_SSL_MINOR_VERSION_4 (MBEDTLS_SSL_VERSION_TLS1_3 & 0xff)
#endif

static void CDECL ldg_ssl_set_minmax_version(my_ssl_context *ssl, int minor_min, int minor_max)
{
#ifdef MBEDTLS_SSL_MINOR_VERSION_0
	if (minor_min < MBEDTLS_SSL_MINOR_VERSION_0) /* TLS v1.0 */
	{
		minor_min = MBEDTLS_SSL_MINOR_VERSION_0;
	}
#else
	if (minor_min < MBEDTLS_SSL_MINOR_VERSION_3) /* TLS v1.2 */
	{
		minor_min = MBEDTLS_SSL_MINOR_VERSION_3;
	}
#endif
	if (minor_max > MBEDTLS_SSL_MINOR_VERSION_4) /* TLS v1.3 */
	{
		minor_max = MBEDTLS_SSL_MINOR_VERSION_4;
	}
	if (minor_min > minor_max)
	{
		minor_min = minor_max;
	}

	mbedtls_ssl_conf_min_tls_version(&ssl->conf, (MBEDTLS_SSL_MAJOR_VERSION_3 << 8) | minor_min);
	mbedtls_ssl_conf_max_tls_version(&ssl->conf, (MBEDTLS_SSL_MAJOR_VERSION_3 << 8) | minor_max);
}

static void CDECL ldg_ssl_set_ciphersuite(my_ssl_context *ssl, const int *wished_ciphersuites)
{
	mbedtls_ssl_conf_ciphersuites(&ssl->conf, wished_ciphersuites);
}

static int CDECL ldg_ssl_handshake(my_ssl_context *ssl)
{
	int ret;
	struct timeval timer;

	ret = mbedtls_ssl_setup(&ssl->ssl, &ssl->conf);
	if (ret != 0)
		return ret;
	
	if (used_tcp_layer == TCP_LAYER_MINTNET)
	{
		timer.tv_sec = 30;
		timer.tv_usec = 0;

		setsockopt((int) (ssl->ssl.p_bio), SOL_SOCKET, SO_RCVTIMEO, (void *) &timer, sizeof(timer));
	}

	while ((ret = mbedtls_ssl_handshake(&ssl->ssl)) != 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			break;
		}
	}

	if (ret == 0 && used_tcp_layer == TCP_LAYER_MINTNET)
	{
		timer.tv_sec = 0;
		timer.tv_usec = 0;

		setsockopt((int) (ssl->ssl.p_bio), SOL_SOCKET, SO_RCVTIMEO, (void *) &timer, sizeof(timer));
	}

	return ret;
}

static const char *CDECL ldg_ssl_get_version(my_ssl_context *ssl)
{
	return mbedtls_ssl_get_version(&ssl->ssl);
}

static const char *CDECL ldg_ssl_get_ciphersuite(my_ssl_context *ssl)
{
	return mbedtls_ssl_get_ciphersuite(&ssl->ssl);
}

static int CDECL ldg_ssl_get_verify_result(my_ssl_context *ssl)
{
	return mbedtls_ssl_get_verify_result(&ssl->ssl);
}

static const mbedtls_x509_crt *CDECL ldg_ssl_get_peer_cert(my_ssl_context *ssl)
{
	return mbedtls_ssl_get_peer_cert(&ssl->ssl);
}

static int CDECL ldg_ssl_read(my_ssl_context *ssl, unsigned char *buf, size_t len)
{
	return mbedtls_ssl_read(&ssl->ssl, buf, len);
}

static int CDECL ldg_ssl_write(my_ssl_context *ssl, const unsigned char *buf, size_t len)
{
	return mbedtls_ssl_write(&ssl->ssl, buf, len);
}

static int CDECL ldg_ssl_close_notify(my_ssl_context *ssl)
{
	return mbedtls_ssl_close_notify(&ssl->ssl);
}

static void CDECL ldg_ssl_free(my_ssl_context *ssl)
{
	mbedtls_ssl_free(&ssl->ssl);
	mbedtls_ssl_config_free(&ssl->conf);
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
#ifdef MBEDTLS_SSL_MINOR_VERSION_0
	return MBEDTLS_SSL_MINOR_VERSION_0;
#else
	return MBEDTLS_SSL_MINOR_VERSION_3;
#endif
}

static int ldg_get_max_tls_version(void)
{
	return MBEDTLS_SSL_MINOR_VERSION_4;
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

	timing_set_system(1);

	if (xget_cookie(0x4D694E54L, NULL))	/* 'MiNT' */
	{
#if defined(MBEDTLS_DEBUG_C)
		(void) Cconws("MiNTnet detected\n\r");
#endif
		timing_set_system(0);
		used_tcp_layer = TCP_LAYER_MINTNET;
	} else if (xget_cookie(0x4D616758L, NULL) && xget_cookie(0x53434B4DL, NULL))	/* 'MagX' and 'SCKM' */
	{
#if defined(MBEDTLS_DEBUG_C)
		(void) Cconws("MagiCNet detected\n\r");
#endif
		used_tcp_layer = TCP_LAYER_MINTNET;
	} else if (xget_cookie(0x5354694BL, NULL))	/* 'STiK' */
	{
#if defined(MBEDTLS_DEBUG_C)
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
#if defined(MBEDTLS_DEBUG_C)
		(void) Cconws("STinG/STiK is not loaded or enabled!\n\r");
#endif
		return -1;
	}

	drivers = (DRV_LIST *) cookieval;

	if (strcmp(drivers->magic, STIK_DRVR_MAGIC) != 0)
	{
#if defined(MBEDTLS_DEBUG_C)
		(void) Cconws("STinG/STiK structures corrupted!\n\r");
#endif
		return -1;
	}

	tpl = (TPL *) get_dftab(TRANSPORT_DRIVER);

	if (tpl == (TPL *) NULL)
	{
#if defined(MBEDTLS_DEBUG_C)
		(void) Cconws("Transport Driver not found!\n\r");
#endif
		return -1;
	}

	return 0;
}

static LDGLIB LibLdg = { 9, sizeof(LibFunc) / sizeof(LibFunc[0]), LibFunc, "SSL/TLS functions from mbebTLS", LDG_NOT_SHARED, 0, 0 };

int main(void)
{
	ldg_init(&LibLdg);

#if 0
	platform_set_malloc_free((void *) ldg_Malloc, (void *) ldg_Free);
#endif

#if defined(MBEDTLS_DEBUG_C)
	(void) Cconws("MbedTLS.ldg (");
	(void) Cconws(get_version());
	(void) Cconws(") debug mode enabled\n\r");
#endif

	search_tcp_layer();
	stick_init();

	return 0;
}
