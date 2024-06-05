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


#if defined(POLARSSL_PK_C)

#include "polarssl/pk.h"

/* For error codes */
#include "polarssl/ecp.h"
#include "polarssl/rsa.h"

/* For detecting 64-bit compilation */
#include "polarssl/bignum.h"

static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len );

#define RSA_KEY_SIZE 512
#define RSA_KEY_LEN   64

static int pk_genkey( pk_context *pk )
{
    ((void) pk);

#if defined(POLARSSL_RSA_C) && defined(POLARSSL_GENPRIME)
    if( pk_get_type( pk ) == POLARSSL_PK_RSA )
        return rsa_gen_key( pk_rsa( *pk ), rnd_std_rand, NULL, RSA_KEY_SIZE, 3 );
#endif
#if defined(POLARSSL_ECP_C)
    if( pk_get_type( pk ) == POLARSSL_PK_ECKEY ||
        pk_get_type( pk ) == POLARSSL_PK_ECKEY_DH ||
        pk_get_type( pk ) == POLARSSL_PK_ECDSA )
    {
        int ret;
        if( ( ret = ecp_use_known_dp( &pk_ec( *pk )->grp,
                                      POLARSSL_ECP_DP_SECP192R1 ) ) != 0 )
            return( ret );

        return ecp_gen_keypair( &pk_ec( *pk )->grp, &pk_ec( *pk )->d,
                                &pk_ec( *pk )->Q, rnd_std_rand, NULL );
    }
#endif
    return( -1 );
}

#if defined(POLARSSL_RSA_C)
int rsa_decrypt_func( void *ctx, int mode, size_t *olen,
                       const unsigned char *input, unsigned char *output,
                       size_t output_max_len )
{
    return( rsa_pkcs1_decrypt( (rsa_context *) ctx, NULL, NULL, mode, olen,
                               input, output, output_max_len ) );
}
int rsa_sign_func( void *ctx,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                   int mode, md_type_t md_alg, unsigned int hashlen,
                   const unsigned char *hash, unsigned char *sig )
{
    return( rsa_pkcs1_sign( (rsa_context *) ctx, f_rng, p_rng, mode,
                            md_alg, hashlen, hash, sig ) );
}
size_t rsa_key_len_func( void *ctx )
{
    return( ((const rsa_context *) ctx)->len );
}
#endif /* POLARSSL_RSA_C */
#endif /* defined(POLARSSL_PK_C) */


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

#if defined(POLARSSL_PK_C)

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

#ifdef POLARSSL_RSA_C
    if( strcmp( str, "-1" ) == 0 )
    {
        *value = ( -1 );
        return( 0 );
    }
#endif // POLARSSL_RSA_C
#ifdef POLARSSL_ECDSA_C
    if( strcmp( str, "POLARSSL_ECP_DP_SECP192R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_SECP192R1 );
        return( 0 );
    }
#endif // POLARSSL_ECDSA_C
#ifdef POLARSSL_PK_PARSE_C
#ifdef POLARSSL_FS_IO
    if( strcmp( str, "POLARSSL_ERR_ECP_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
        return( 0 );
    }
#endif // POLARSSL_PK_PARSE_C
#endif // POLARSSL_FS_IO
#ifdef POLARSSL_ECDSA_C
    if( strcmp( str, "POLARSSL_ERR_ECP_VERIFY_FAILED" ) == 0 )
    {
        *value = ( POLARSSL_ERR_ECP_VERIFY_FAILED );
        return( 0 );
    }
#endif // POLARSSL_ECDSA_C
#ifdef POLARSSL_RSA_C
    if( strcmp( str, "POLARSSL_ERR_PK_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_BAD_INPUT_DATA );
        return( 0 );
    }
#endif // POLARSSL_RSA_C
    if( strcmp( str, "POLARSSL_ERR_PK_TYPE_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_TYPE_MISMATCH );
        return( 0 );
    }
#ifdef POLARSSL_RSA_C
    if( strcmp( str, "POLARSSL_ERR_RSA_INVALID_PADDING" ) == 0 )
    {
        *value = ( POLARSSL_ERR_RSA_INVALID_PADDING );
        return( 0 );
    }
#endif // POLARSSL_RSA_C
#ifdef POLARSSL_PK_PARSE_C
#ifdef POLARSSL_FS_IO
    if( strcmp( str, "POLARSSL_ERR_RSA_KEY_CHECK_FAILED" ) == 0 )
    {
        *value = ( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        return( 0 );
    }
#endif // POLARSSL_PK_PARSE_C
#endif // POLARSSL_FS_IO
#ifdef POLARSSL_RSA_C
    if( strcmp( str, "POLARSSL_ERR_RSA_VERIFY_FAILED" ) == 0 )
    {
        *value = ( POLARSSL_ERR_RSA_VERIFY_FAILED );
        return( 0 );
    }
#endif // POLARSSL_RSA_C
#ifdef POLARSSL_RSA_C
    if( strcmp( str, "POLARSSL_MD_NONE" ) == 0 )
    {
        *value = ( POLARSSL_MD_NONE );
        return( 0 );
    }
#endif // POLARSSL_RSA_C
#ifdef POLARSSL_RSA_C
    if( strcmp( str, "POLARSSL_MD_SHA1" ) == 0 )
    {
        *value = ( POLARSSL_MD_SHA1 );
        return( 0 );
    }
#endif // POLARSSL_RSA_C
#ifdef POLARSSL_RSA_C
    if( strcmp( str, "POLARSSL_MD_SHA256" ) == 0 )
    {
        *value = ( POLARSSL_MD_SHA256 );
        return( 0 );
    }
#endif // POLARSSL_RSA_C
    if( strcmp( str, "POLARSSL_PK_ECDSA" ) == 0 )
    {
        *value = ( POLARSSL_PK_ECDSA );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_PK_ECKEY" ) == 0 )
    {
        *value = ( POLARSSL_PK_ECKEY );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_PK_ECKEY_DH" ) == 0 )
    {
        *value = ( POLARSSL_PK_ECKEY_DH );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_PK_RSA" ) == 0 )
    {
        *value = ( POLARSSL_PK_RSA );
        return( 0 );
    }
#ifdef POLARSSL_RSA_C
    if( strcmp( str, "POLARSSL_PK_RSASSA_PSS" ) == 0 )
    {
        *value = ( POLARSSL_PK_RSASSA_PSS );
        return( 0 );
    }
#endif // POLARSSL_RSA_C
#ifdef POLARSSL_RSA_C
    if( strcmp( str, "RSA_SALT_LEN_ANY" ) == 0 )
    {
        *value = ( RSA_SALT_LEN_ANY );
        return( 0 );
    }
#endif // POLARSSL_RSA_C


    polarssl_printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

void test_suite_pk_utils( int type, int size, int len, char *name )
{
    pk_context pk;

    pk_init( &pk );

    TEST_ASSERT( pk_init_ctx( &pk, pk_info_from_type( type ) ) == 0 );
    TEST_ASSERT( pk_genkey( &pk ) == 0 );

    TEST_ASSERT( (int) pk_get_type( &pk ) == type );
    TEST_ASSERT( pk_can_do( &pk, type ) );
    TEST_ASSERT( pk_get_size( &pk ) == (unsigned) size );
    TEST_ASSERT( pk_get_len( &pk ) == (unsigned) len );
    TEST_ASSERT( strcmp( pk_get_name( &pk), name ) == 0 );

exit:
    pk_free( &pk );
}

#ifdef POLARSSL_PK_PARSE_C
#ifdef POLARSSL_FS_IO
void test_suite_pk_check_pair( char *pub_file, char *prv_file, int ret )
{
    pk_context pub, prv, alt;

    pk_init( &pub );
    pk_init( &prv );
    pk_init( &alt );

    TEST_ASSERT( pk_parse_public_keyfile( &pub, pub_file ) == 0 );
    TEST_ASSERT( pk_parse_keyfile( &prv, prv_file, NULL ) == 0 );

    TEST_ASSERT( pk_check_pair( &pub, &prv ) == ret );

#if defined(POLARSSL_RSA_C)
    if( pk_get_type( &prv ) == POLARSSL_PK_RSA )
    {
        TEST_ASSERT( pk_init_ctx_rsa_alt( &alt, pk_rsa( prv ),
                     rsa_decrypt_func, rsa_sign_func, rsa_key_len_func ) == 0 );
        TEST_ASSERT( pk_check_pair( &pub, &alt ) == ret );
    }
#endif

    pk_free( &pub );
    pk_free( &prv );
    pk_free( &alt );

exit:
    return;
}
#endif /* POLARSSL_PK_PARSE_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_RSA_C
void test_suite_pk_rsa_verify_test_vec( char *message_hex_string, int digest,
                       int mod, int radix_N, char *input_N, int radix_E,
                       char *input_E, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char result_str[1000];
    rsa_context *rsa;
    pk_context pk;
    int msg_len;

    pk_init( &pk );

    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( result_str, 0x00, 1000 );

    TEST_ASSERT( pk_init_ctx( &pk, pk_info_from_type( POLARSSL_PK_RSA ) ) == 0 );
    rsa = pk_rsa( pk );

    rsa->len = mod / 8;
    TEST_ASSERT( mpi_read_string( &rsa->N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mpi_read_string( &rsa->E, radix_E, input_E ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );
    unhexify( result_str, result_hex_str );

    if( md_info_from_type( digest ) != NULL )
        TEST_ASSERT( md( md_info_from_type( digest ), message_str, msg_len, hash_result ) == 0 );

    TEST_ASSERT( pk_verify( &pk, digest, hash_result, 0,
                            result_str, pk_get_len( &pk ) ) == result );

exit:
    pk_free( &pk );
}
#endif /* POLARSSL_RSA_C */

#ifdef POLARSSL_RSA_C
void test_suite_pk_rsa_verify_ext_test_vec( char *message_hex_string, int digest,
                       int mod, int radix_N, char *input_N, int radix_E,
                       char *input_E, char *result_hex_str,
                       int pk_type, int mgf1_hash_id, int salt_len,
                       int result )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char result_str[1000];
    rsa_context *rsa;
    pk_context pk;
    pk_rsassa_pss_options pss_opts;
    void *options;
    int msg_len;
    size_t hash_len;

    pk_init( &pk );

    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( result_str, 0x00, 1000 );

    TEST_ASSERT( pk_init_ctx( &pk, pk_info_from_type( POLARSSL_PK_RSA ) ) == 0 );
    rsa = pk_rsa( pk );

    rsa->len = mod / 8;
    TEST_ASSERT( mpi_read_string( &rsa->N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mpi_read_string( &rsa->E, radix_E, input_E ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );
    unhexify( result_str, result_hex_str );

    if( digest != POLARSSL_MD_NONE )
    {
        TEST_ASSERT( md( md_info_from_type( digest ),
                     message_str, msg_len, hash_result ) == 0 );
        hash_len = 0;
    }
    else
    {
        memcpy( hash_result, message_str, msg_len );
        hash_len = msg_len;
    }

    if( mgf1_hash_id < 0 )
    {
        options = NULL;
    }
    else
    {
        options = &pss_opts;

        pss_opts.mgf1_hash_id = mgf1_hash_id;
        pss_opts.expected_salt_len = salt_len;
    }

    TEST_ASSERT( pk_verify_ext( pk_type, options, &pk,
                                digest, hash_result, hash_len,
                                result_str, pk_get_len( &pk ) ) == result );

exit:
    pk_free( &pk );
}
#endif /* POLARSSL_RSA_C */

#ifdef POLARSSL_ECDSA_C
void test_suite_pk_ec_test_vec( int type, int id, char *key_str,
                     char *hash_str, char * sig_str, int ret )
{
    pk_context pk;
    ecp_keypair *eckey;
    unsigned char hash[100], sig[500], key[500];
    size_t hash_len, sig_len, key_len;

    pk_init( &pk );

    memset( hash, 0, sizeof( hash ) );  hash_len = unhexify(hash, hash_str);
    memset( sig, 0, sizeof( sig ) );    sig_len = unhexify(sig, sig_str);
    memset( key, 0, sizeof( key ) );    key_len = unhexify(key, key_str);

    TEST_ASSERT( pk_init_ctx( &pk, pk_info_from_type( type ) ) == 0 );

    TEST_ASSERT( pk_can_do( &pk, POLARSSL_PK_ECDSA ) );
    eckey = pk_ec( pk );

    TEST_ASSERT( ecp_use_known_dp( &eckey->grp, id ) == 0 );
    TEST_ASSERT( ecp_point_read_binary( &eckey->grp, &eckey->Q,
                                        key, key_len ) == 0 );

    TEST_ASSERT( pk_verify( &pk, POLARSSL_MD_NONE,
                            hash, hash_len, sig, sig_len ) == ret );

exit:
    pk_free( &pk );
}
#endif /* POLARSSL_ECDSA_C */

void test_suite_pk_sign_verify( int type, int sign_ret, int verify_ret )
{
    pk_context pk;
    unsigned char hash[50], sig[5000];
    size_t sig_len;

    pk_init( &pk );

    memset( hash, 0x2a, sizeof hash );
    memset( sig, 0, sizeof sig );

    TEST_ASSERT( pk_init_ctx( &pk, pk_info_from_type( type ) ) == 0 );
    TEST_ASSERT( pk_genkey( &pk ) == 0 );

    TEST_ASSERT( pk_sign( &pk, POLARSSL_MD_NONE, hash, sizeof hash,
                          sig, &sig_len, rnd_std_rand, NULL ) == sign_ret );

    TEST_ASSERT( pk_verify( &pk, POLARSSL_MD_NONE,
                            hash, sizeof hash, sig, sig_len ) == verify_ret );

exit:
    pk_free( &pk );
}

#ifdef POLARSSL_RSA_C
void test_suite_pk_rsa_encrypt_test_vec( char *message_hex, int mod,
                            int radix_N, char *input_N,
                            int radix_E, char *input_E,
                            char *result_hex, int ret )
{
    unsigned char message[1000];
    unsigned char output[1000];
    unsigned char result[1000];
    size_t msg_len, olen, res_len;
    rnd_pseudo_info rnd_info;
    rsa_context *rsa;
    pk_context pk;

    memset( &rnd_info,  0, sizeof( rnd_pseudo_info ) );
    memset( message,    0, sizeof( message ) );
    memset( output,     0, sizeof( output ) );
    memset( result,     0, sizeof( result ) );

    msg_len = unhexify( message, message_hex );
    res_len = unhexify( result, result_hex );

    pk_init( &pk );
    TEST_ASSERT( pk_init_ctx( &pk, pk_info_from_type( POLARSSL_PK_RSA ) ) == 0 );
    rsa = pk_rsa( pk );

    rsa->len = mod / 8;
    TEST_ASSERT( mpi_read_string( &rsa->N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mpi_read_string( &rsa->E, radix_E, input_E ) == 0 );

    TEST_ASSERT( pk_encrypt( &pk, message, msg_len,
                             output, &olen, sizeof( output ),
                             rnd_pseudo_rand, &rnd_info ) == ret );
    TEST_ASSERT( olen == res_len );
    TEST_ASSERT( memcmp( output, result, olen ) == 0 );

exit:
    pk_free( &pk );
}
#endif /* POLARSSL_RSA_C */

#ifdef POLARSSL_RSA_C
void test_suite_pk_rsa_decrypt_test_vec( char *cipher_hex, int mod,
                            int radix_P, char *input_P,
                            int radix_Q, char *input_Q,
                            int radix_N, char *input_N,
                            int radix_E, char *input_E,
                            char *clear_hex, int ret )
{
    unsigned char clear[1000];
    unsigned char output[1000];
    unsigned char cipher[1000];
    size_t clear_len, olen, cipher_len;
    rnd_pseudo_info rnd_info;
    mpi P1, Q1, H, G;
    rsa_context *rsa;
    pk_context pk;

    pk_init( &pk );
    mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );

    memset( &rnd_info,  0, sizeof( rnd_pseudo_info ) );
    memset( clear,      0, sizeof( clear ) );
    memset( cipher,     0, sizeof( cipher ) );

    clear_len = unhexify( clear, clear_hex );
    cipher_len = unhexify( cipher, cipher_hex );

    /* init pk-rsa context */
    TEST_ASSERT( pk_init_ctx( &pk, pk_info_from_type( POLARSSL_PK_RSA ) ) == 0 );
    rsa = pk_rsa( pk );

    /* load public key */
    rsa->len = mod / 8;
    TEST_ASSERT( mpi_read_string( &rsa->N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mpi_read_string( &rsa->E, radix_E, input_E ) == 0 );

    /* load private key */
    TEST_ASSERT( mpi_read_string( &rsa->P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mpi_read_string( &rsa->Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mpi_sub_int( &P1, &rsa->P, 1 ) == 0 );
    TEST_ASSERT( mpi_sub_int( &Q1, &rsa->Q, 1 ) == 0 );
    TEST_ASSERT( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
    TEST_ASSERT( mpi_gcd( &G, &rsa->E, &H  ) == 0 );
    TEST_ASSERT( mpi_inv_mod( &rsa->D , &rsa->E, &H  ) == 0 );
    TEST_ASSERT( mpi_mod_mpi( &rsa->DP, &rsa->D, &P1 ) == 0 );
    TEST_ASSERT( mpi_mod_mpi( &rsa->DQ, &rsa->D, &Q1 ) == 0 );
    TEST_ASSERT( mpi_inv_mod( &rsa->QP, &rsa->Q, &rsa->P ) == 0 );

    /* decryption test */
    memset( output, 0, sizeof( output ) );
    olen = 0;
    TEST_ASSERT( pk_decrypt( &pk, cipher, cipher_len,
                             output, &olen, sizeof( output ),
                             rnd_pseudo_rand, &rnd_info ) == ret );
    if( ret == 0 )
    {
        TEST_ASSERT( olen == clear_len );
        TEST_ASSERT( memcmp( output, clear, olen ) == 0 );
    }

exit:
    mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
    pk_free( &pk );
}
#endif /* POLARSSL_RSA_C */

void test_suite_pk_ec_nocrypt( int type )
{
    pk_context pk;
    unsigned char output[100];
    unsigned char input[100];
    rnd_pseudo_info rnd_info;
    size_t olen = 0;
    int ret = POLARSSL_ERR_PK_TYPE_MISMATCH;

    pk_init( &pk );

    memset( &rnd_info,  0, sizeof( rnd_pseudo_info ) );
    memset( output,     0, sizeof( output ) );
    memset( input,      0, sizeof( input ) );

    TEST_ASSERT( pk_init_ctx( &pk, pk_info_from_type( type ) ) == 0 );

    TEST_ASSERT( pk_encrypt( &pk, input, sizeof( input ),
                             output, &olen, sizeof( output ),
                             rnd_pseudo_rand, &rnd_info ) == ret );

    TEST_ASSERT( pk_decrypt( &pk, input, sizeof( input ),
                             output, &olen, sizeof( output ),
                             rnd_pseudo_rand, &rnd_info ) == ret );

exit:
    pk_free( &pk );
}

#ifdef POLARSSL_RSA_C
#ifdef POLARSSL_HAVE_INT64
void test_suite_pk_rsa_overflow( )
{
    pk_context pk;
    size_t hash_len = (size_t)-1;

    pk_init( &pk );

    TEST_ASSERT( pk_init_ctx( &pk, pk_info_from_type( POLARSSL_PK_RSA ) ) == 0 );

#if defined(POLARSSL_PKCS1_V21)
    TEST_ASSERT( pk_verify_ext( POLARSSL_PK_RSASSA_PSS, NULL, &pk,
                    POLARSSL_MD_NONE, NULL, hash_len, NULL, 0 ) ==
                 POLARSSL_ERR_PK_BAD_INPUT_DATA );
#endif /* POLARSSL_PKCS1_V21 */

    TEST_ASSERT( pk_verify( &pk, POLARSSL_MD_NONE, NULL, hash_len,
                    NULL, 0 ) == POLARSSL_ERR_PK_BAD_INPUT_DATA );

    TEST_ASSERT( pk_sign( &pk, POLARSSL_MD_NONE, NULL, hash_len, NULL, 0,
                    rnd_std_rand, NULL ) == POLARSSL_ERR_PK_BAD_INPUT_DATA );

exit:
    pk_free( &pk );
}
#endif /* POLARSSL_RSA_C */
#endif /* POLARSSL_HAVE_INT64 */

#ifdef POLARSSL_RSA_C
void test_suite_pk_rsa_alt( )
{
    /*
     * An rsa_alt context can only do private operations (decrypt, sign).
     * Test it against the public operations (encrypt, verify) of a
     * corresponding rsa context.
     */
    rsa_context raw;
    pk_context rsa, alt;
    pk_debug_item dbg_items[10];
    unsigned char hash[50], sig[1000];
    unsigned char msg[50], ciph[1000], test[1000];
    size_t sig_len, ciph_len, test_len;
    int ret = POLARSSL_ERR_PK_TYPE_MISMATCH;

    rsa_init( &raw, RSA_PKCS_V15, POLARSSL_MD_NONE );
    pk_init( &rsa ); pk_init( &alt );

    memset( hash, 0x2a, sizeof hash );
    memset( sig, 0, sizeof sig );
    memset( msg, 0x2a, sizeof msg );
    memset( ciph, 0, sizeof ciph );
    memset( test, 0, sizeof test );

    /* Initiliaze PK RSA context with random key */
    TEST_ASSERT( pk_init_ctx( &rsa,
                              pk_info_from_type( POLARSSL_PK_RSA ) ) == 0 );
    TEST_ASSERT( pk_genkey( &rsa ) == 0 );

    /* Extract key to the raw rsa context */
    TEST_ASSERT( rsa_copy( &raw, pk_rsa( rsa ) ) == 0 );

    /* Initialize PK RSA_ALT context */
    TEST_ASSERT( pk_init_ctx_rsa_alt( &alt, (void *) &raw,
                 rsa_decrypt_func, rsa_sign_func, rsa_key_len_func ) == 0 );

    /* Test administrative functions */
    TEST_ASSERT( pk_can_do( &alt, POLARSSL_PK_RSA ) );
    TEST_ASSERT( pk_get_size( &alt ) == RSA_KEY_SIZE );
    TEST_ASSERT( pk_get_len( &alt ) == RSA_KEY_LEN );
    TEST_ASSERT( pk_get_type( &alt ) == POLARSSL_PK_RSA_ALT );
    TEST_ASSERT( strcmp( pk_get_name( &alt ), "RSA-alt" ) == 0 );

    /* Test signature */
    TEST_ASSERT( pk_sign( &alt, POLARSSL_MD_NONE, hash, sizeof hash,
                          sig, &sig_len, rnd_std_rand, NULL ) == 0 );
#if defined(POLARSSL_HAVE_INT64)
    TEST_ASSERT( pk_sign( &alt, POLARSSL_MD_NONE, hash, (size_t)-1,
                          NULL, NULL, rnd_std_rand, NULL ) ==
                 POLARSSL_ERR_PK_BAD_INPUT_DATA );
#endif /* POLARSSL_HAVE_INT64 */
    TEST_ASSERT( sig_len == RSA_KEY_LEN );
    TEST_ASSERT( pk_verify( &rsa, POLARSSL_MD_NONE,
                            hash, sizeof hash, sig, sig_len ) == 0 );

    /* Test decrypt */
    TEST_ASSERT( pk_encrypt( &rsa, msg, sizeof msg,
                             ciph, &ciph_len, sizeof ciph,
                             rnd_std_rand, NULL ) == 0 );
    TEST_ASSERT( pk_decrypt( &alt, ciph, ciph_len,
                             test, &test_len, sizeof test,
                             rnd_std_rand, NULL ) == 0 );
    TEST_ASSERT( test_len == sizeof msg );
    TEST_ASSERT( memcmp( test, msg, test_len ) == 0 );

    /* Test forbidden operations */
    TEST_ASSERT( pk_encrypt( &alt, msg, sizeof msg,
                             ciph, &ciph_len, sizeof ciph,
                             rnd_std_rand, NULL ) == ret );
    TEST_ASSERT( pk_verify( &alt, POLARSSL_MD_NONE,
                            hash, sizeof hash, sig, sig_len ) == ret );
    TEST_ASSERT( pk_debug( &alt, dbg_items ) == ret );

exit:
    rsa_free( &raw );
    pk_free( &rsa ); pk_free( &alt );
}
#endif /* POLARSSL_RSA_C */


#endif /* defined(POLARSSL_PK_C) */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

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
    if( strcmp( str, "POLARSSL_GENPRIME" ) == 0 )
    {
#if defined(POLARSSL_GENPRIME)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_HAVE_INT64" ) == 0 )
    {
#if defined(POLARSSL_HAVE_INT64)
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
    if( strcmp( str, "POLARSSL_PKCS1_V21" ) == 0 )
    {
#if defined(POLARSSL_PKCS1_V21)
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


    return( 1 );
}

int dispatch_test(int cnt, char *params[50])
{
    int ret;
    ((void) cnt);
    ((void) params);

#if defined(TEST_SUITE_ACTIVE)
    if( strcmp( params[0], "pk_utils" ) == 0 )
    {

        int param1;
        int param2;
        int param3;
        char *param4 = params[4];

        if( cnt != 5 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );

        test_suite_pk_utils( param1, param2, param3, param4 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pk_check_pair" ) == 0 )
    {
    #ifdef POLARSSL_PK_PARSE_C
    #ifdef POLARSSL_FS_IO

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

        test_suite_pk_check_pair( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_PK_PARSE_C */
    #endif /* POLARSSL_FS_IO */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pk_rsa_verify_test_vec" ) == 0 )
    {
    #ifdef POLARSSL_RSA_C

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        char *param8 = params[8];
        int param9;

        if( cnt != 10 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );

        test_suite_pk_rsa_verify_test_vec( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( 0 );
    #endif /* POLARSSL_RSA_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pk_rsa_verify_ext_test_vec" ) == 0 )
    {
    #ifdef POLARSSL_RSA_C

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        char *param8 = params[8];
        int param9;
        int param10;
        int param11;
        int param12;

        if( cnt != 13 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 13 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );
        if( verify_int( params[10], &param10 ) != 0 ) return( 2 );
        if( verify_int( params[11], &param11 ) != 0 ) return( 2 );
        if( verify_int( params[12], &param12 ) != 0 ) return( 2 );

        test_suite_pk_rsa_verify_ext_test_vec( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12 );
        return ( 0 );
    #endif /* POLARSSL_RSA_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pk_ec_test_vec" ) == 0 )
    {
    #ifdef POLARSSL_ECDSA_C

        int param1;
        int param2;
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        int param6;

        if( cnt != 7 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );

        test_suite_pk_ec_test_vec( param1, param2, param3, param4, param5, param6 );
        return ( 0 );
    #endif /* POLARSSL_ECDSA_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pk_sign_verify" ) == 0 )
    {

        int param1;
        int param2;
        int param3;

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_pk_sign_verify( param1, param2, param3 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pk_rsa_encrypt_test_vec" ) == 0 )
    {
    #ifdef POLARSSL_RSA_C

        char *param1 = params[1];
        int param2;
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        char *param7 = params[7];
        int param8;

        if( cnt != 9 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 9 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );

        test_suite_pk_rsa_encrypt_test_vec( param1, param2, param3, param4, param5, param6, param7, param8 );
        return ( 0 );
    #endif /* POLARSSL_RSA_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pk_rsa_decrypt_test_vec" ) == 0 )
    {
    #ifdef POLARSSL_RSA_C

        char *param1 = params[1];
        int param2;
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        char *param11 = params[11];
        int param12;

        if( cnt != 13 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 13 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );
        if( verify_string( &param10 ) != 0 ) return( 2 );
        if( verify_string( &param11 ) != 0 ) return( 2 );
        if( verify_int( params[12], &param12 ) != 0 ) return( 2 );

        test_suite_pk_rsa_decrypt_test_vec( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12 );
        return ( 0 );
    #endif /* POLARSSL_RSA_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pk_ec_nocrypt" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );

        test_suite_pk_ec_nocrypt( param1 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pk_rsa_overflow" ) == 0 )
    {
    #ifdef POLARSSL_RSA_C
    #ifdef POLARSSL_HAVE_INT64


        if( cnt != 1 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_pk_rsa_overflow(  );
        return ( 0 );
    #endif /* POLARSSL_RSA_C */
    #endif /* POLARSSL_HAVE_INT64 */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pk_rsa_alt" ) == 0 )
    {
    #ifdef POLARSSL_RSA_C


        if( cnt != 1 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_pk_rsa_alt(  );
        return ( 0 );
    #endif /* POLARSSL_RSA_C */

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
    const char *filename = "suites/test_suite_pk.data";
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


