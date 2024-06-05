#if !defined(POLARSSL_CONFIG_FILE)
#include <polarssl/config.h>
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#include <stdio.h>
#define polarssl_printf     printf
#define polarssl_fprintf    fprintf
#define polarssl_malloc     malloc
#define polarssl_free       free
#define polarssl_exit       exit
#define polarssl_fprintf    fprintf
#define polarssl_printf     printf
#define polarssl_snprintf   snprintf
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#include <inttypes.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define assert(a) if( !( a ) )                                      \
{                                                                   \
    polarssl_fprintf( stderr, "Assertion Failed at %s:%d - %s\n",   \
                             __FILE__, __LINE__, #a );              \
    polarssl_exit( 1 );                                             \
}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if !defined(POLARSSL_NO_DEFAULT_ENTROPY_SOURCES) &&   \
      ( !defined(POLARSSL_NO_PLATFORM_ENTROPY)  ||     \
         defined(POLARSSL_HAVEGE_C)             ||     \
         defined(POLARSSL_TIMING_C) )
#define ENTROPY_HAVE_DEFAULT
#endif

static int unhexify( unsigned char *obuf, const char *ibuf )
{
    unsigned char c, c2;
    int len = strlen( ibuf ) / 2;
    assert( strlen( ibuf ) % 2 == 0 ); // must be even number of bytes

    while( *ibuf != 0 )
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

static void hexify( unsigned char *obuf, const unsigned char *ibuf, int len )
{
    unsigned char l, h;

    while( len != 0 )
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

/**
 * Allocate and zeroize a buffer.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *zero_alloc( size_t len )
{
    void *p;
    size_t actual_len = ( len != 0 ) ? len : 1;

    p = polarssl_malloc( actual_len );
    assert( p != NULL );

    memset( p, 0x00, actual_len );

    return( p );
}

/**
 * Allocate and fill a buffer from hex data.
 *
 * The buffer is sized exactly as needed. This allows to detect buffer
 * overruns (including overreads) when running the test suite under valgrind.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *unhexify_alloc( const char *ibuf, size_t *olen )
{
    unsigned char *obuf;

    *olen = strlen( ibuf ) / 2;

    if( *olen == 0 )
        return( zero_alloc( *olen ) );

    obuf = polarssl_malloc( *olen );
    assert( obuf != NULL );

    (void) unhexify( obuf, ibuf );

    return( obuf );
}

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

/**
 * This function only returns zeros
 *
 * rng_state shall be NULL.
 */
static int rnd_zero_rand( void *rng_state, unsigned char *output, size_t len )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    memset( output, 0, len );

    return( 0 );
}

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;

/**
 * This function returns random based on a buffer it receives.
 *
 * rng_state shall be a pointer to a rnd_buf_info structure.
 *
 * The number of bytes released from the buffer on each call to
 * the random function is specified by per_call. (Can be between
 * 1 and 4)
 *
 * After the buffer is empty it will return rand();
 */
static int rnd_buffer_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_buf_info *info = (rnd_buf_info *) rng_state;
    size_t use_len;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    use_len = len;
    if( len > info->length )
        use_len = info->length;

    if( use_len )
    {
        memcpy( output, info->buf, use_len );
        info->buf += use_len;
        info->length -= use_len;
    }

    if( len - use_len > 0 )
        return( rnd_std_rand( NULL, output + use_len, len - use_len ) );

    return( 0 );
}

/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4], *out = output;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += ( ( ( info->v1 << 4 ) ^ ( info->v1 >> 5 ) )
                            + info->v1 ) ^ ( sum + k[sum & 3] );
            sum += delta;
            info->v1 += ( ( ( info->v0 << 4 ) ^ ( info->v0 >> 5 ) )
                            + info->v0 ) ^ ( sum + k[( sum>>11 ) & 3] );
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( out, result, use_len );
        len -= use_len;
        out += 4;
    }

    return( 0 );
}


#if defined(POLARSSL_BIGNUM_C)

#include "polarssl/x509.h"
#include "polarssl/x509_crt.h"
#include "polarssl/x509_crl.h"
#include "polarssl/x509_csr.h"
#include "polarssl/pem.h"
#include "polarssl/oid.h"
#include "polarssl/base64.h"

#if POLARSSL_X509_MAX_INTERMEDIATE_CA > 19
#error "The value of POLARSSL_X509_MAX_INTERMEDIATE_C is larger \
than the current threshold 19. To test larger values, please \
adapt the script tests/data_files/dir-max/long.sh."
#endif

int verify_none( void *data, x509_crt *crt, int certificate_depth, int *flags )
{
    ((void) data);
    ((void) crt);
    ((void) certificate_depth);
    *flags |= BADCERT_OTHER;

    return 0;
}

int verify_all( void *data, x509_crt *crt, int certificate_depth, int *flags )
{
    ((void) data);
    ((void) crt);
    ((void) certificate_depth);
    *flags = 0;

    return 0;
}

#if defined(POLARSSL_X509_CRT_PARSE_C)
typedef struct {
    char buf[512];
    char *p;
} verify_print_context;

void verify_print_init( verify_print_context *ctx )
{
    memset( ctx, 0, sizeof( verify_print_context ) );
    ctx->p = ctx->buf;
}

#if defined(_MSC_VER) && !defined snprintf
#define snprintf _snprintf
#endif

#define SAFE_SNPRINTF                               \
do                                                  \
{                                                   \
    if( ret < 0 || (size_t) ret > n )               \
    {                                               \
        p[n - 1] = '\0';                            \
        return( -1 );                               \
    }                                               \
                                                    \
    n -= (unsigned int) ret;                        \
    p += (unsigned int) ret;                        \
} while( 0 )

int verify_print( void *data, x509_crt *crt, int certificate_depth, int *flags )
{
    int ret;
    verify_print_context *ctx = (verify_print_context *) data;
    char *p = ctx->p;
    size_t n = ctx->buf + sizeof( ctx->buf ) - ctx->p;
    ((void) flags);

    ret = polarssl_snprintf( p, n, "depth %d - serial ", certificate_depth );
    SAFE_SNPRINTF;

    ret = x509_serial_gets( p, n, &crt->serial );
    SAFE_SNPRINTF;

    ret = polarssl_snprintf( p, n, " - subject " );
    SAFE_SNPRINTF;

    ret = x509_dn_gets( p, n, &crt->subject );
    SAFE_SNPRINTF;

    ret = polarssl_snprintf( p, n, "\n" );
    SAFE_SNPRINTF;

    ctx->p = p;

    return( 0 );
}
#endif /* POLARSSL_X509_CRT_PARSE_C */

/* strsep() not available on Windows */
char *mystrsep(char **stringp, const char *delim)
{
    const char *p;
    char *ret = *stringp;

    if( *stringp == NULL )
        return( NULL );

    for( ; ; (*stringp)++ )
    {
        if( **stringp == '\0' )
        {
            *stringp = NULL;
            goto done;
        }

        for( p = delim; *p != '\0'; p++ )
            if( **stringp == *p )
            {
                **stringp = '\0';
                (*stringp)++;
                goto done;
            }
    }

done:
    return( ret );
}
#endif /* defined(POLARSSL_BIGNUM_C) */


#include <string.h>

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#include <stdio.h>
#define polarssl_exit       exit
#define polarssl_free       free
#define polarssl_malloc     malloc
#define polarssl_fprintf    fprintf
#define polarssl_printf     printf
#endif

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
#include "polarssl/memory_buffer_alloc.h"
#endif

static int test_errors = 0;

#if defined(POLARSSL_BIGNUM_C)

#define TEST_SUITE_ACTIVE

static int test_assert( int correct, const char *test )
{
    if( correct )
        return( 0 );

    test_errors++;
    if( test_errors == 1 )
        polarssl_printf( "FAILED\n" );
    polarssl_printf( "  %s\n", test );

    return( 1 );
}

#define TEST_ASSERT( TEST )                         \
        do { test_assert( (TEST) ? 1 : 0, #TEST );  \
             if( test_errors) goto exit;            \
        } while (0)

int verify_string( char **str )
{
    if( (*str)[0] != '"' ||
        (*str)[strlen( *str ) - 1] != '"' )
    {
        polarssl_printf( "Expected string (with \"\") for parameter and got: %s\n", *str );
        return( -1 );
    }

    (*str)++;
    (*str)[strlen( *str ) - 1] = '\0';

    return( 0 );
}

int verify_int( char *str, int *value )
{
    size_t i;
    int minus = 0;
    int digits = 1;
    int hex = 0;

    for( i = 0; i < strlen( str ); i++ )
    {
        if( i == 0 && str[i] == '-' )
        {
            minus = 1;
            continue;
        }

        if( ( ( minus && i == 2 ) || ( !minus && i == 1 ) ) &&
            str[i - 1] == '0' && str[i] == 'x' )
        {
            hex = 1;
            continue;
        }

        if( ! ( ( str[i] >= '0' && str[i] <= '9' ) ||
                ( hex && ( ( str[i] >= 'a' && str[i] <= 'f' ) ||
                           ( str[i] >= 'A' && str[i] <= 'F' ) ) ) ) )
        {
            digits = 0;
            break;
        }
    }

    if( digits )
    {
        if( hex )
            *value = strtol( str, NULL, 16 );
        else
            *value = strtol( str, NULL, 10 );

        return( 0 );
    }

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "-1" ) == 0 )
    {
        *value = ( -1 );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "ASN1_CONSTRUCTED | ASN1_SEQUENCE" ) == 0 )
    {
        *value = ( ASN1_CONSTRUCTED | ASN1_SEQUENCE );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_RSASSA_PSS_SUPPORT
#ifdef POLARSSL_X509_USE_C
    if( strcmp( str, "ASN1_GENERALIZED_TIME" ) == 0 )
    {
        *value = ( ASN1_GENERALIZED_TIME );
        return( 0 );
    }
#endif // POLARSSL_X509_USE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "ASN1_SEQUENCE" ) == 0 )
    {
        *value = ( ASN1_SEQUENCE );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_RSASSA_PSS_SUPPORT
#ifdef POLARSSL_X509_USE_C
    if( strcmp( str, "ASN1_UTC_TIME" ) == 0 )
    {
        *value = ( ASN1_UTC_TIME );
        return( 0 );
    }
#endif // POLARSSL_X509_USE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_CN_MISMATCH" ) == 0 )
    {
        *value = ( BADCERT_CN_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_CN_MISMATCH + BADCERT_NOT_TRUSTED" ) == 0 )
    {
        *value = ( BADCERT_CN_MISMATCH + BADCERT_NOT_TRUSTED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_EXPIRED" ) == 0 )
    {
        *value = ( BADCERT_EXPIRED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "BADCERT_EXPIRED | BADCRL_EXPIRED" ) == 0 )
    {
        *value = ( BADCERT_EXPIRED | BADCRL_EXPIRED );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_FUTURE" ) == 0 )
    {
        *value = ( BADCERT_FUTURE );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "BADCERT_MISSING" ) == 0 )
    {
        *value = ( BADCERT_MISSING );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_NOT_TRUSTED" ) == 0 )
    {
        *value = ( BADCERT_NOT_TRUSTED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "BADCERT_NOT_TRUSTED" ) == 0 )
    {
        *value = ( BADCERT_NOT_TRUSTED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_OTHER" ) == 0 )
    {
        *value = ( BADCERT_OTHER );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "BADCERT_OTHER | 0x8000" ) == 0 )
    {
        *value = ( BADCERT_OTHER | 0x8000 );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_REVOKED" ) == 0 )
    {
        *value = ( BADCERT_REVOKED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_REVOKED | BADCERT_CN_MISMATCH" ) == 0 )
    {
        *value = ( BADCERT_REVOKED | BADCERT_CN_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_REVOKED | BADCRL_EXPIRED" ) == 0 )
    {
        *value = ( BADCERT_REVOKED | BADCRL_EXPIRED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_REVOKED | BADCRL_EXPIRED | BADCERT_CN_MISMATCH" ) == 0 )
    {
        *value = ( BADCERT_REVOKED | BADCRL_EXPIRED | BADCERT_CN_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_REVOKED | BADCRL_FUTURE" ) == 0 )
    {
        *value = ( BADCERT_REVOKED | BADCRL_FUTURE );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_REVOKED | BADCRL_FUTURE | BADCERT_CN_MISMATCH" ) == 0 )
    {
        *value = ( BADCERT_REVOKED | BADCRL_FUTURE | BADCERT_CN_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_REVOKED|BADCRL_FUTURE" ) == 0 )
    {
        *value = ( BADCERT_REVOKED|BADCRL_FUTURE );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCRL_EXPIRED" ) == 0 )
    {
        *value = ( BADCRL_EXPIRED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCRL_FUTURE" ) == 0 )
    {
        *value = ( BADCRL_FUTURE );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCRL_NOT_TRUSTED" ) == 0 )
    {
        *value = ( BADCRL_NOT_TRUSTED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CHECK_KEY_USAGE
    if( strcmp( str, "KU_DIGITAL_SIGNATURE" ) == 0 )
    {
        *value = ( KU_DIGITAL_SIGNATURE );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CHECK_KEY_USAGE
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CHECK_KEY_USAGE
    if( strcmp( str, "KU_DIGITAL_SIGNATURE|KU_KEY_ENCIPHERMENT" ) == 0 )
    {
        *value = ( KU_DIGITAL_SIGNATURE|KU_KEY_ENCIPHERMENT );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CHECK_KEY_USAGE
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CHECK_KEY_USAGE
    if( strcmp( str, "KU_KEY_CERT_SIGN" ) == 0 )
    {
        *value = ( KU_KEY_CERT_SIGN );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CHECK_KEY_USAGE
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CHECK_KEY_USAGE
    if( strcmp( str, "KU_KEY_CERT_SIGN|KU_CRL_SIGN" ) == 0 )
    {
        *value = ( KU_KEY_CERT_SIGN|KU_CRL_SIGN );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CHECK_KEY_USAGE
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CHECK_KEY_USAGE
    if( strcmp( str, "KU_KEY_ENCIPHERMENT|KU_KEY_AGREEMENT" ) == 0 )
    {
        *value = ( KU_KEY_ENCIPHERMENT|KU_KEY_AGREEMENT );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CHECK_KEY_USAGE
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_ASN1_INVALID_LENGTH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_ASN1_INVALID_LENGTH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_USE_C
    if( strcmp( str, "POLARSSL_ERR_OID_BUF_TOO_SMALL" ) == 0 )
    {
        *value = ( POLARSSL_ERR_OID_BUF_TOO_SMALL );
        return( 0 );
    }
#endif // POLARSSL_X509_USE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
    if( strcmp( str, "POLARSSL_ERR_PEM_INVALID_DATA + POLARSSL_ERR_BASE64_INVALID_CHARACTER" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PEM_INVALID_DATA + POLARSSL_ERR_BASE64_INVALID_CHARACTER );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_FS_IO
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PEM_NO_HEADER_FOOTER_PRESENT" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PEM_NO_HEADER_FOOTER_PRESENT );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_PUBKEY" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_PUBKEY );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_INVALID_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_INVALID_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_KEY_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_KEY_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_KEY_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_KEY_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_KEY_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_KEY_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_UNKNOWN_PK_ALG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_UNKNOWN_PK_ALG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CHECK_KEY_USAGE
    if( strcmp( str, "POLARSSL_ERR_X509_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_BAD_INPUT_DATA );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CHECK_KEY_USAGE
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE
    if( strcmp( str, "POLARSSL_ERR_X509_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_BAD_INPUT_DATA );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_CERT_VERIFY_FAILED" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_CERT_VERIFY_FAILED" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_FATAL_ERROR" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_FATAL_ERROR );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "POLARSSL_ERR_X509_FEATURE_UNAVAILABLE + POLARSSL_ERR_OID_NOT_FOUND" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_FEATURE_UNAVAILABLE + POLARSSL_ERR_OID_NOT_FOUND );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_RSASSA_PSS_SUPPORT
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_RSASSA_PSS_SUPPORT
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_INVALID_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_INVALID_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_RSASSA_PSS_SUPPORT
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_RSASSA_PSS_SUPPORT
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_RSASSA_PSS_SUPPORT
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_RSASSA_PSS_SUPPORT
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_OID_NOT_FOUND" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_OID_NOT_FOUND );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_RSASSA_PSS_SUPPORT
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_DATE" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_DATE );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_USE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_DATE" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_DATE );
        return( 0 );
    }
#endif // POLARSSL_X509_USE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_EXTENSIONS" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_EXTENSIONS );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_INVALID_LENGTH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_INVALID_LENGTH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_NAME+POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_NAME+POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA " ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA  );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_INVALID_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_INVALID_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_INVALID_LENGTH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_INVALID_LENGTH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_SIG_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_SIG_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_SIG_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_SIG_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_UNKNOWN_SIG_ALG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_UNKNOWN_SIG_ALG );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_UNKNOWN_SIG_ALG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_UNKNOWN_SIG_ALG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_UNKNOWN_SIG_ALG + POLARSSL_ERR_OID_NOT_FOUND" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_UNKNOWN_SIG_ALG + POLARSSL_ERR_OID_NOT_FOUND );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CSR_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_UNKNOWN_VERSION" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_UNKNOWN_VERSION );
        return( 0 );
    }
#endif // POLARSSL_X509_CSR_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_UNKNOWN_VERSION" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_UNKNOWN_VERSION );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_UNKNOWN_VERSION" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_UNKNOWN_VERSION );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "POLARSSL_MD_SHA1" ) == 0 )
    {
        *value = ( POLARSSL_MD_SHA1 );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_RSASSA_PSS_SUPPORT
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "POLARSSL_MD_SHA256" ) == 0 )
    {
        *value = ( POLARSSL_MD_SHA256 );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_RSASSA_PSS_SUPPORT
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_X509_MAX_INTERMEDIATE_CA" ) == 0 )
    {
        *value = ( POLARSSL_X509_MAX_INTERMEDIATE_CA );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_X509_MAX_INTERMEDIATE_CA+1" ) == 0 )
    {
        *value = ( POLARSSL_X509_MAX_INTERMEDIATE_CA+1 );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_X509_MAX_INTERMEDIATE_CA-1" ) == 0 )
    {
        *value = ( POLARSSL_X509_MAX_INTERMEDIATE_CA-1 );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C


    polarssl_printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509_cert_info( char *crt_file, char *result_str )
{
    x509_crt   crt;
    char buf[2000];
    int res;

    x509_crt_init( &crt );
    memset( buf, 0, 2000 );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );
    res = x509_crt_info( buf, 2000, "", &crt );

    TEST_ASSERT( res != -1 );
    TEST_ASSERT( res != -2 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );

exit:
    x509_crt_free( &crt );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRL_PARSE_C
void test_suite_x509_crl_info( char *crl_file, char *result_str )
{
    x509_crl   crl;
    char buf[2000];
    int res;

    x509_crl_init( &crl );
    memset( buf, 0, 2000 );

    TEST_ASSERT( x509_crl_parse_file( &crl, crl_file ) == 0 );
    res = x509_crl_info( buf, 2000, "", &crl );

    TEST_ASSERT( res != -1 );
    TEST_ASSERT( res != -2 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );

exit:
    x509_crl_free( &crl );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRL_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRL_PARSE_C
void test_suite_x509_crl_parse( char *crl_file, int result )
{
    x509_crl crl;
    char buf[2000];

    x509_crl_init( &crl );
    memset( buf, 0, 2000 );

    TEST_ASSERT( x509_crl_parse_file( &crl, crl_file ) == result );

exit:
    x509_crl_free( &crl );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRL_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CSR_PARSE_C
void test_suite_x509_csr_info( char *csr_file, char *result_str )
{
    x509_csr   csr;
    char buf[2000];
    int res;

    x509_csr_init( &csr );
    memset( buf, 0, 2000 );

    TEST_ASSERT( x509_csr_parse_file( &csr, csr_file ) == 0 );
    res = x509_csr_info( buf, 2000, "", &csr );

    TEST_ASSERT( res != -1 );
    TEST_ASSERT( res != -2 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );

exit:
    x509_csr_free( &csr );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CSR_PARSE_C */

#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509_verify_info( int flags, char *prefix, char *result_str )
{
    char buf[2000];
    int res;

    memset( buf, 0, sizeof( buf ) );

    res = x509_crt_verify_info( buf, sizeof( buf ), prefix, flags );

    TEST_ASSERT( res >= 0 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );

exit:
    return;
}
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
void test_suite_x509_verify( char *crt_file, char *ca_file, char *crl_file,
                  char *cn_name_str, int result, int flags_result,
                  char *verify_callback )
{
    x509_crt   crt;
    x509_crt   ca;
    x509_crl    crl;
    int         flags = 0;
    int         res;
    int (*f_vrfy)(void *, x509_crt *, int, int *) = NULL;
    char *      cn_name = NULL;

    x509_crt_init( &crt );
    x509_crt_init( &ca );
    x509_crl_init( &crl );

    if( strcmp( cn_name_str, "NULL" ) != 0 )
        cn_name = cn_name_str;

    if( strcmp( verify_callback, "NULL" ) == 0 )
        f_vrfy = NULL;
    else if( strcmp( verify_callback, "verify_none" ) == 0 )
        f_vrfy = verify_none;
    else if( strcmp( verify_callback, "verify_all" ) == 0 )
        f_vrfy = verify_all;
    else
        TEST_ASSERT( "No known verify callback selected" == 0 );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );
    TEST_ASSERT( x509_crt_parse_file( &ca, ca_file ) == 0 );
    TEST_ASSERT( x509_crl_parse_file( &crl, crl_file ) == 0 );

    res = x509_crt_verify( &crt, &ca, &crl, cn_name, &flags, f_vrfy, NULL );

    TEST_ASSERT( res == ( result ) );
    TEST_ASSERT( flags == ( flags_result ) );

exit:
    x509_crt_free( &crt );
    x509_crt_free( &ca );
    x509_crl_free( &crl );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */
#endif /* POLARSSL_X509_CRL_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509_verify_callback( char *crt_file, char *ca_file,
                           int exp_ret, char *exp_vrfy_out )
{
    int ret;
    x509_crt crt;
    x509_crt ca;
    int flags = 0;
    verify_print_context vrfy_ctx;

    x509_crt_init( &crt );
    x509_crt_init( &ca );
    verify_print_init( &vrfy_ctx );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );
    TEST_ASSERT( x509_crt_parse_file( &ca, ca_file ) == 0 );

    ret = x509_crt_verify( &crt, &ca, NULL, NULL, &flags,
                                   verify_print, &vrfy_ctx );

    TEST_ASSERT( ret == exp_ret );
    TEST_ASSERT( strcmp( vrfy_ctx.buf, exp_vrfy_out ) == 0 );

exit:
    x509_crt_free( &crt );
    x509_crt_free( &ca );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509_dn_gets( char *crt_file, char *entity, char *result_str )
{
    x509_crt   crt;
    char buf[2000];
    int res = 0;

    x509_crt_init( &crt );
    memset( buf, 0, 2000 );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );
    if( strcmp( entity, "subject" ) == 0 )
        res =  x509_dn_gets( buf, 2000, &crt.subject );
    else if( strcmp( entity, "issuer" ) == 0 )
        res =  x509_dn_gets( buf, 2000, &crt.issuer );
    else
        TEST_ASSERT( "Unknown entity" == 0 );

    TEST_ASSERT( res != -1 );
    TEST_ASSERT( res != -2 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );

exit:
    x509_crt_free( &crt );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509_time_expired( char *crt_file, char *entity, int result )
{
    x509_crt   crt;

    x509_crt_init( &crt );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );

    if( strcmp( entity, "valid_from" ) == 0 )
        TEST_ASSERT( x509_time_expired( &crt.valid_from ) == result );
    else if( strcmp( entity, "valid_to" ) == 0 )
        TEST_ASSERT( x509_time_expired( &crt.valid_to ) == result );
    else
        TEST_ASSERT( "Unknown entity" == 0 );

exit:
    x509_crt_free( &crt );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509_time_future( char *crt_file, char *entity, int result )
{
    x509_crt   crt;

    x509_crt_init( &crt );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );

    if( strcmp( entity, "valid_from" ) == 0 )
        TEST_ASSERT( x509_time_future( &crt.valid_from ) == result );
    else if( strcmp( entity, "valid_to" ) == 0 )
        TEST_ASSERT( x509_time_future( &crt.valid_to ) == result );
    else
        TEST_ASSERT( "Unknown entity" == 0 );

exit:
    x509_crt_free( &crt );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
void test_suite_x509parse_crt_file( char *crt_file, int result )
{
    x509_crt crt;

    x509_crt_init( &crt );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == result );

exit:
    x509_crt_free( &crt );
}
#endif /* POLARSSL_X509_CRT_PARSE_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509parse_crt( char *crt_data, char *result_str, int result )
{
    x509_crt   crt;
    unsigned char buf[2000];
    unsigned char output[2000];
    int data_len, res;

    x509_crt_init( &crt );
    memset( buf, 0, 2000 );
    memset( output, 0, 2000 );

    data_len = unhexify( buf, crt_data );

    TEST_ASSERT( x509_crt_parse( &crt, buf, data_len ) == ( result ) );
    if( ( result ) == 0 )
    {
        res = x509_crt_info( (char *) output, 2000, "", &crt );

        TEST_ASSERT( res != -1 );
        TEST_ASSERT( res != -2 );

        TEST_ASSERT( strcmp( (char *) output, result_str ) == 0 );
    }

exit:
    x509_crt_free( &crt );
}
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_X509_CRL_PARSE_C
void test_suite_x509parse_crl( char *crl_data, char *result_str, int result )
{
    x509_crl   crl;
    unsigned char buf[2000];
    unsigned char output[2000];
    int data_len, res;

    x509_crl_init( &crl );
    memset( buf, 0, 2000 );
    memset( output, 0, 2000 );

    data_len = unhexify( buf, crl_data );

    TEST_ASSERT( x509_crl_parse( &crl, buf, data_len ) == ( result ) );
    if( ( result ) == 0 )
    {
        res = x509_crl_info( (char *) output, 2000, "", &crl );

        TEST_ASSERT( res != -1 );
        TEST_ASSERT( res != -2 );

        TEST_ASSERT( strcmp( (char *) output, result_str ) == 0 );
    }

exit:
    x509_crl_free( &crl );
}
#endif /* POLARSSL_X509_CRL_PARSE_C */

#ifdef POLARSSL_X509_CSR_PARSE_C
void test_suite_x509_csr_parse( char *csr_der_hex, char *ref_out, int ref_ret )
{
    x509_csr csr;
    unsigned char *csr_der = NULL;
    char my_out[1000];
    size_t csr_der_len;
    int my_ret;

    x509_csr_init( &csr );
    memset( my_out, 0, sizeof( my_out ) );
    csr_der = unhexify_alloc( csr_der_hex, &csr_der_len );

    my_ret = x509_csr_parse_der( &csr, csr_der, csr_der_len );
    TEST_ASSERT( my_ret == ref_ret );

    if( ref_ret == 0 )
    {
        size_t my_out_len = x509_csr_info( my_out, sizeof( my_out ), "", &csr );
        TEST_ASSERT( my_out_len == strlen( ref_out ) );
        TEST_ASSERT( strcmp( my_out, ref_out ) == 0 );
    }

exit:
    x509_csr_free( &csr );
    polarssl_free( csr_der );
}
#endif /* POLARSSL_X509_CSR_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509_crt_parse_path( char *crt_path, int ret, int nb_crt )
{
    x509_crt chain, *cur;
    int i;

    x509_crt_init( &chain );

    TEST_ASSERT( x509_crt_parse_path( &chain, crt_path ) == ret );

    /* Check how many certs we got */
    for( i = 0, cur = &chain; cur != NULL; cur = cur->next )
        if( cur->raw.p != NULL )
            i++;

    TEST_ASSERT( i == nb_crt );

exit:
    x509_crt_free( &chain );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509_crt_verify_max( char *ca_file, char *chain_dir, int nb_int,
                                  int ret_chk, int flags_chk )
{
    char file_buf[128];
    int ret;
    int flags;
    x509_crt trusted, chain;

    /*
     * We expect chain_dir to contain certificates 00.crt, 01.crt, etc.
     * with NN.crt signed by NN-1.crt
     */

    x509_crt_init( &trusted );
    x509_crt_init( &chain );

    /* Load trusted root */
    TEST_ASSERT( x509_crt_parse_file( &trusted, ca_file ) == 0 );

    /* Load a chain with nb_int intermediates (from 01 to nb_int),
     * plus one "end-entity" cert (nb_int + 1) */
    ret = snprintf( file_buf, sizeof file_buf, "%s/c%02d.pem", chain_dir,
                                                            nb_int + 1 );
    TEST_ASSERT( ret > 0 && (size_t) ret < sizeof file_buf );
    TEST_ASSERT( x509_crt_parse_file( &chain, file_buf ) == 0 );

    /* Try to verify that chain */
    ret = x509_crt_verify( &chain, &trusted, NULL, NULL, &flags,
                                   NULL, NULL );
    TEST_ASSERT( ret == ret_chk );
    TEST_ASSERT( flags == flags_chk );

exit:
    x509_crt_free( &chain );
    x509_crt_free( &trusted );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509_crt_verify_chain(  char *chain_paths, char *trusted_ca, int flags_result )
{
    char* act;
    int flags;
    int result, res;
    x509_crt trusted, chain;

    result = flags_result ? POLARSSL_ERR_X509_CERT_VERIFY_FAILED : 0;

    x509_crt_init( &chain );
    x509_crt_init( &trusted );

    while( ( act = mystrsep( &chain_paths, " " ) ) != NULL )
        TEST_ASSERT( x509_crt_parse_file( &chain, act ) == 0 );
    TEST_ASSERT( x509_crt_parse_file( &trusted, trusted_ca ) == 0 );

    res = x509_crt_verify( &chain, &trusted, NULL, NULL, &flags, NULL, NULL );

    TEST_ASSERT( res == result );
    TEST_ASSERT( flags == flags_result );

exit:
    x509_crt_free( &trusted );
    x509_crt_free( &chain );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_X509_USE_C
void test_suite_x509_oid_desc( char *oid_str, char *ref_desc )
{
    x509_buf oid;
    const char *desc = NULL;
    unsigned char buf[20];
    int ret;

    memset( buf, 0, sizeof buf );

    oid.tag = ASN1_OID;
    oid.len = unhexify( buf, oid_str );
    oid.p   = buf;

    ret = oid_get_extended_key_usage( &oid, &desc );

    if( strcmp( ref_desc, "notfound" ) == 0 )
    {
        TEST_ASSERT( ret != 0 );
        TEST_ASSERT( desc == NULL );
    }
    else
    {
        TEST_ASSERT( ret == 0 );
        TEST_ASSERT( desc != NULL );
        TEST_ASSERT( strcmp( desc, ref_desc ) == 0 );
    }

exit:
    return;
}
#endif /* POLARSSL_X509_USE_C */

#ifdef POLARSSL_X509_USE_C
void test_suite_x509_oid_numstr( char *oid_str, char *numstr, int blen, int ret )
{
    x509_buf oid;
    unsigned char oid_buf[20];
    char num_buf[100];

    memset( oid_buf, 0x00, sizeof oid_buf );
    memset( num_buf, 0x2a, sizeof num_buf );

    oid.tag = ASN1_OID;
    oid.len = unhexify( oid_buf, oid_str );
    oid.p   = oid_buf;

    TEST_ASSERT( (size_t) blen <= sizeof num_buf );

    TEST_ASSERT( oid_get_numeric_string( num_buf, blen, &oid ) == ret );

    if( ret >= 0 )
    {
        TEST_ASSERT( num_buf[ret] == 0 );
        TEST_ASSERT( strcmp( num_buf, numstr ) == 0 );
    }

exit:
    return;
}
#endif /* POLARSSL_X509_USE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CHECK_KEY_USAGE
void test_suite_x509_check_key_usage( char *crt_file, int usage, int ret )
{
    x509_crt crt;

    x509_crt_init( &crt );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );

    TEST_ASSERT( x509_crt_check_key_usage( &crt, usage ) == ret );

exit:
    x509_crt_free( &crt );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */
#endif /* POLARSSL_X509_CHECK_KEY_USAGE */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE
void test_suite_x509_check_extended_key_usage( char *crt_file, char *usage_hex, int ret )
{
    x509_crt crt;
    char oid[50];
    size_t len;

    x509_crt_init( &crt );

    len = unhexify( (unsigned char *) oid, usage_hex );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );

    TEST_ASSERT( x509_crt_check_extended_key_usage( &crt, oid, len ) == ret );

exit:
    x509_crt_free( &crt );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */
#endif /* POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE */

#ifdef POLARSSL_X509_USE_C
void test_suite_x509_get_time( int tag,  char *time_str, int ret,
                    int year, int mon, int day,
                    int hour, int min, int sec )
{
    x509_time time;
    unsigned char buf[17];
    unsigned char* start = buf;
    unsigned char* end = buf;

    memset( &time, 0x00, sizeof( time ) );
    *end = (unsigned char)tag; end++;
    if( tag == ASN1_UTC_TIME )
        *end = 13;
    else
        *end = 15;
    end++;
    memcpy( end, time_str, (size_t)*(end - 1) );
    end += *(end - 1);

    TEST_ASSERT( x509_get_time( &start, end, &time ) == ret );
    if( ret == 0 )
    {
        TEST_ASSERT( year == time.year );
        TEST_ASSERT( mon  == time.mon  );
        TEST_ASSERT( day  == time.day  );
        TEST_ASSERT( hour == time.hour );
        TEST_ASSERT( min  == time.min  );
        TEST_ASSERT( sec  == time.sec  );
    }

exit:
    return;
}
#endif /* POLARSSL_X509_USE_C */

#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT
void test_suite_x509_parse_rsassa_pss_params( char *hex_params, int params_tag,
                                   int ref_msg_md, int ref_mgf_md,
                                   int ref_salt_len, int ref_ret )
{
    int my_ret;
    x509_buf params;
    md_type_t my_msg_md, my_mgf_md;
    int my_salt_len;

    params.p = unhexify_alloc( hex_params, &params.len );
    params.tag = params_tag;

    my_ret = x509_get_rsassa_pss_params( &params, &my_msg_md, &my_mgf_md,
                                         &my_salt_len );

    TEST_ASSERT( my_ret == ref_ret );

    if( ref_ret == 0 )
    {
        TEST_ASSERT( my_msg_md == (md_type_t) ref_msg_md );
        TEST_ASSERT( my_mgf_md == (md_type_t) ref_mgf_md );
        TEST_ASSERT( my_salt_len == ref_salt_len );
    }

exit:
    polarssl_free( params.p );
}
#endif /* POLARSSL_X509_CRT_PARSE_C */
#endif /* POLARSSL_X509_RSASSA_PSS_SUPPORT */

#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_SELF_TEST
void test_suite_x509_selftest()
{
    TEST_ASSERT( x509_self_test( 0 ) == 0 );

exit:
    return;
}
#endif /* POLARSSL_X509_CRT_PARSE_C */
#endif /* POLARSSL_SELF_TEST */


#endif /* defined(POLARSSL_BIGNUM_C) */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "POLARSSL_CERTS_C" ) == 0 )
    {
#if defined(POLARSSL_CERTS_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECDSA_C" ) == 0 )
    {
#if defined(POLARSSL_ECDSA_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_C" ) == 0 )
    {
#if defined(POLARSSL_ECP_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP192R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP192R1_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP256R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP256R1_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP384R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP384R1_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_HAVE_TIME" ) == 0 )
    {
#if defined(POLARSSL_HAVE_TIME)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_MD4_C" ) == 0 )
    {
#if defined(POLARSSL_MD4_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_MD5_C" ) == 0 )
    {
#if defined(POLARSSL_MD5_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_PEM_PARSE_C" ) == 0 )
    {
#if defined(POLARSSL_PEM_PARSE_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_PKCS1_V15" ) == 0 )
    {
#if defined(POLARSSL_PKCS1_V15)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_RSA_C" ) == 0 )
    {
#if defined(POLARSSL_RSA_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_SHA1_C" ) == 0 )
    {
#if defined(POLARSSL_SHA1_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_SHA256_C" ) == 0 )
    {
#if defined(POLARSSL_SHA256_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_SHA512_C" ) == 0 )
    {
#if defined(POLARSSL_SHA512_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3" ) == 0 )
    {
#if defined(POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_X509_CHECK_KEY_USAGE" ) == 0 )
    {
#if defined(POLARSSL_X509_CHECK_KEY_USAGE)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_X509_RSASSA_PSS_SUPPORT" ) == 0 )
    {
#if defined(POLARSSL_X509_RSASSA_PSS_SUPPORT)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_X509_USE_C" ) == 0 )
    {
#if defined(POLARSSL_X509_USE_C)
        return( 0 );
#else
        return( 1 );
#endif
    }


    return( 1 );
}

int dispatch_test(int cnt, char *params[50])
{
    int ret;
    ((void) cnt);
    ((void) params);

#if defined(TEST_SUITE_ACTIVE)
    if( strcmp( params[0], "x509_cert_info" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];

        if( cnt != 3 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );

        test_suite_x509_cert_info( param1, param2 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_crl_info" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRL_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];

        if( cnt != 3 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );

        test_suite_x509_crl_info( param1, param2 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRL_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_crl_parse" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRL_PARSE_C

        char *param1 = params[1];
        int param2;

        if( cnt != 3 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );

        test_suite_x509_crl_parse( param1, param2 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRL_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_csr_info" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CSR_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];

        if( cnt != 3 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );

        test_suite_x509_csr_info( param1, param2 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CSR_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_verify_info" ) == 0 )
    {
    #ifdef POLARSSL_X509_CRT_PARSE_C

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );

        test_suite_x509_verify_info( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_verify" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C
    #ifdef POLARSSL_X509_CRL_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        int param5;
        int param6;
        char *param7 = params[7];

        if( cnt != 8 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );

        test_suite_x509_verify( param1, param2, param3, param4, param5, param6, param7 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */
    #endif /* POLARSSL_X509_CRL_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_verify_callback" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];

        if( cnt != 5 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );

        test_suite_x509_verify_callback( param1, param2, param3, param4 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_dn_gets" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        char *param3 = params[3];

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );

        test_suite_x509_dn_gets( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_time_expired" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509_time_expired( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_time_future" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509_time_future( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509parse_crt_file" ) == 0 )
    {
    #ifdef POLARSSL_X509_CRT_PARSE_C
    #ifdef POLARSSL_FS_IO

        char *param1 = params[1];
        int param2;

        if( cnt != 3 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );

        test_suite_x509parse_crt_file( param1, param2 );
        return ( 0 );
    #endif /* POLARSSL_X509_CRT_PARSE_C */
    #endif /* POLARSSL_FS_IO */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509parse_crt" ) == 0 )
    {
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509parse_crt( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509parse_crl" ) == 0 )
    {
    #ifdef POLARSSL_X509_CRL_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509parse_crl( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_X509_CRL_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_csr_parse" ) == 0 )
    {
    #ifdef POLARSSL_X509_CSR_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509_csr_parse( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_X509_CSR_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_crt_parse_path" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        int param2;
        int param3;

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509_crt_parse_path( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_crt_verify_max" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;

        if( cnt != 6 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );

        test_suite_x509_crt_verify_max( param1, param2, param3, param4, param5 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_crt_verify_chain" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509_crt_verify_chain( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_oid_desc" ) == 0 )
    {
    #ifdef POLARSSL_X509_USE_C

        char *param1 = params[1];
        char *param2 = params[2];

        if( cnt != 3 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );

        test_suite_x509_oid_desc( param1, param2 );
        return ( 0 );
    #endif /* POLARSSL_X509_USE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_oid_numstr" ) == 0 )
    {
    #ifdef POLARSSL_X509_USE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        int param4;

        if( cnt != 5 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );

        test_suite_x509_oid_numstr( param1, param2, param3, param4 );
        return ( 0 );
    #endif /* POLARSSL_X509_USE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_check_key_usage" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C
    #ifdef POLARSSL_X509_CHECK_KEY_USAGE

        char *param1 = params[1];
        int param2;
        int param3;

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509_check_key_usage( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */
    #endif /* POLARSSL_X509_CHECK_KEY_USAGE */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_check_extended_key_usage" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C
    #ifdef POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509_check_extended_key_usage( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */
    #endif /* POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_get_time" ) == 0 )
    {
    #ifdef POLARSSL_X509_USE_C

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;
        int param6;
        int param7;
        int param8;
        int param9;

        if( cnt != 10 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );

        test_suite_x509_get_time( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( 0 );
    #endif /* POLARSSL_X509_USE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_parse_rsassa_pss_params" ) == 0 )
    {
    #ifdef POLARSSL_X509_CRT_PARSE_C
    #ifdef POLARSSL_X509_RSASSA_PSS_SUPPORT

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        int param5;
        int param6;

        if( cnt != 7 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );

        test_suite_x509_parse_rsassa_pss_params( param1, param2, param3, param4, param5, param6 );
        return ( 0 );
    #endif /* POLARSSL_X509_CRT_PARSE_C */
    #endif /* POLARSSL_X509_RSASSA_PSS_SUPPORT */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_selftest" ) == 0 )
    {
    #ifdef POLARSSL_X509_CRT_PARSE_C
    #ifdef POLARSSL_SELF_TEST


        if( cnt != 1 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_x509_selftest(  );
        return ( 0 );
    #endif /* POLARSSL_X509_CRT_PARSE_C */
    #endif /* POLARSSL_SELF_TEST */

        return ( 3 );
    }
    else

    {
        polarssl_fprintf( stdout, "FAILED\nSkipping unknown test function '%s'\n", params[0] );
        fflush( stdout );
        return( 1 );
    }
#else
    return( 3 );
#endif
    return( ret );
}

/** Retrieve one input line into buf, which must have room for len
 * bytes. The trailing line break (if any) is stripped from the result.
 * Lines beginning with the character '#' are skipped. Lines that are
 * more than len-1 bytes long including the trailing line break are
 * truncated; note that the following bytes remain in the input stream.
 *
 * \return 0 on success, -1 on error or end of file
 */
int get_line( FILE *f, char *buf, size_t len )
{
    char *ret;

    do
    {
        ret = fgets( buf, len, f );
        if( ret == NULL )
            return( -1 );
    }
    while( buf[0] == '#' );

    ret = buf + strlen( buf );
    if( ret-- > buf && *ret == '\n' )
        *ret = '\0';
    if( ret-- > buf && *ret == '\r' )
        *ret = '\0';

    return( 0 );
}

int parse_arguments( char *buf, size_t len, char *params[50] )
{
    int cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while( *p != '\0' && p < buf + len )
    {
        if( *p == '\\' )
        {
            p++;
            p++;
            continue;
        }
        if( *p == ':' )
        {
            if( p + 1 < buf + len )
            {
                cur = p + 1;
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    // Replace newlines, question marks and colons in strings
    for( i = 0; i < cnt; i++ )
    {
        p = params[i];
        q = params[i];

        while( *p != '\0' )
        {
            if( *p == '\\' && *(p + 1) == 'n' )
            {
                p += 2;
                *(q++) = '\n';
            }
            else if( *p == '\\' && *(p + 1) == ':' )
            {
                p += 2;
                *(q++) = ':';
            }
            else if( *p == '\\' && *(p + 1) == '?' )
            {
                p += 2;
                *(q++) = '?';
            }
            else
                *(q++) = *(p++);
        }
        *q = '\0';
    }

    return( cnt );
}

int main()
{
    int ret, i, cnt, total_errors = 0, total_tests = 0, total_skipped = 0;
    const char *filename = "suites/test_suite_x509parse.data";
    FILE *file;
    char buf[5000];
    char *params[50];

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

    file = fopen( filename, "r" );
    if( file == NULL )
    {
        polarssl_fprintf( stderr, "Failed to open\n" );
        return( 1 );
    }

    while( !feof( file ) )
    {
        int skip = 0;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        polarssl_fprintf( stdout, "%s%.66s", test_errors ? "\n" : "", buf );
        polarssl_fprintf( stdout, " " );
        for( i = strlen( buf ) + 1; i < 67; i++ )
            polarssl_fprintf( stdout, "." );
        polarssl_fprintf( stdout, " " );
        fflush( stdout );

        total_tests++;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        cnt = parse_arguments( buf, strlen(buf), params );

        if( strcmp( params[0], "depends_on" ) == 0 )
        {
            for( i = 1; i < cnt; i++ )
                if( dep_check( params[i] ) != 0 )
                    skip = 1;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            cnt = parse_arguments( buf, strlen(buf), params );
        }

        if( skip == 0 )
        {
            test_errors = 0;
            ret = dispatch_test( cnt, params );
        }

        if( skip == 1 || ret == 3 )
        {
            total_skipped++;
            polarssl_fprintf( stdout, "----\n" );
            fflush( stdout );
        }
        else if( ret == 0 && test_errors == 0 )
        {
            polarssl_fprintf( stdout, "PASS\n" );
            fflush( stdout );
        }
        else if( ret == 2 )
        {
            polarssl_fprintf( stderr, "FAILED: FATAL PARSE ERROR\n" );
            fclose(file);
            polarssl_exit( 2 );
        }
        else
            total_errors++;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        if( strlen(buf) != 0 )
        {
            polarssl_fprintf( stderr, "Should be empty %d\n", (int) strlen(buf) );
            return( 1 );
        }
    }
    fclose(file);

    polarssl_fprintf( stdout, "\n----------------------------------------------------------------------------\n\n");
    if( total_errors == 0 )
        polarssl_fprintf( stdout, "PASSED" );
    else
        polarssl_fprintf( stdout, "FAILED" );

    polarssl_fprintf( stdout, " (%d / %d tests (%d skipped))\n",
             total_tests - total_errors, total_tests, total_skipped );

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(POLARSSL_MEMORY_DEBUG)
    memory_buffer_alloc_status();
#endif
    memory_buffer_alloc_free();
#endif

    return( total_errors != 0 );
}


