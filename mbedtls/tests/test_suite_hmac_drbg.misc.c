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


#if defined(POLARSSL_HMAC_DRBG_C)

#include "polarssl/hmac_drbg.h"

typedef struct
{
    unsigned char *p;
    size_t len;
} entropy_ctx;

int entropy_func( void *data, unsigned char *buf, size_t len )
{
    entropy_ctx *ctx = (entropy_ctx *) data;

    if( len > ctx->len )
        return( -1 );

    memcpy( buf, ctx->p, len );

    ctx->p += len;
    ctx->len -= len;

    return( 0 );
}
#endif /* defined(POLARSSL_HMAC_DRBG_C) */


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

#if defined(POLARSSL_HMAC_DRBG_C)

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

    if( strcmp( str, "POLARSSL_MD_SHA224" ) == 0 )
    {
        *value = ( POLARSSL_MD_SHA224 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_MD_SHA512" ) == 0 )
    {
        *value = ( POLARSSL_MD_SHA512 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_MD_SHA256" ) == 0 )
    {
        *value = ( POLARSSL_MD_SHA256 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_MD_SHA1" ) == 0 )
    {
        *value = ( POLARSSL_MD_SHA1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_MD_SHA384" ) == 0 )
    {
        *value = ( POLARSSL_MD_SHA384 );
        return( 0 );
    }
#ifdef POLARSSL_FS_IO
    if( strcmp( str, "POLARSSL_ERR_HMAC_DRBG_FILE_IO_ERROR" ) == 0 )
    {
        *value = ( POLARSSL_ERR_HMAC_DRBG_FILE_IO_ERROR );
        return( 0 );
    }
#endif // POLARSSL_FS_IO


    polarssl_printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

void test_suite_hmac_drbg_entropy_usage( int md_alg )
{
    unsigned char out[16];
    unsigned char buf[1024];
    const md_info_t *md_info;
    hmac_drbg_context ctx;
    entropy_ctx entropy;
    size_t last_len, i, reps = 10;

    memset( buf, 0, sizeof( buf ) );
    memset( out, 0, sizeof( out ) );

    entropy.len = sizeof( buf );
    entropy.p = buf;

    md_info = md_info_from_type( md_alg );
    TEST_ASSERT( md_info != NULL );

    /* Init must use entropy */
    last_len = entropy.len;
    TEST_ASSERT( hmac_drbg_init( &ctx, md_info, entropy_func, &entropy,
                                 NULL, 0 ) == 0 );
    TEST_ASSERT( entropy.len < last_len );

    /* By default, PR is off and reseed_interval is large,
     * so the next few calls should not use entropy */
    last_len = entropy.len;
    for( i = 0; i < reps; i++ )
    {
        TEST_ASSERT( hmac_drbg_random( &ctx, out, sizeof( out ) - 4 ) == 0 );
        TEST_ASSERT( hmac_drbg_random_with_add( &ctx, out, sizeof( out ) - 4,
                                                buf, 16 ) == 0 );
    }
    TEST_ASSERT( entropy.len == last_len );

    /* While at it, make sure we didn't write past the requested length */
    TEST_ASSERT( out[sizeof( out ) - 4] == 0 );
    TEST_ASSERT( out[sizeof( out ) - 3] == 0 );
    TEST_ASSERT( out[sizeof( out ) - 2] == 0 );
    TEST_ASSERT( out[sizeof( out ) - 1] == 0 );

    /* Set reseed_interval to the number of calls done,
     * so the next call should reseed */
    hmac_drbg_set_reseed_interval( &ctx, 2 * reps );
    TEST_ASSERT( hmac_drbg_random( &ctx, out, sizeof( out ) ) == 0 );
    TEST_ASSERT( entropy.len < last_len );

    /* The new few calls should not reseed */
    last_len = entropy.len;
    for( i = 0; i < reps / 2; i++ )
    {
        TEST_ASSERT( hmac_drbg_random( &ctx, out, sizeof( out ) ) == 0 );
        TEST_ASSERT( hmac_drbg_random_with_add( &ctx, out, sizeof( out ) ,
                                                buf, 16 ) == 0 );
    }
    TEST_ASSERT( entropy.len == last_len );

    /* Now enable PR, so the next few calls should all reseed */
    hmac_drbg_set_prediction_resistance( &ctx, POLARSSL_HMAC_DRBG_PR_ON );
    TEST_ASSERT( hmac_drbg_random( &ctx, out, sizeof( out ) ) == 0 );
    TEST_ASSERT( entropy.len < last_len );

    /* Finally, check setting entropy_len */
    hmac_drbg_set_entropy_len( &ctx, 42 );
    last_len = entropy.len;
    TEST_ASSERT( hmac_drbg_random( &ctx, out, sizeof( out ) ) == 0 );
    TEST_ASSERT( (int) last_len - entropy.len == 42 );

    hmac_drbg_set_entropy_len( &ctx, 13 );
    last_len = entropy.len;
    TEST_ASSERT( hmac_drbg_random( &ctx, out, sizeof( out ) ) == 0 );
    TEST_ASSERT( (int) last_len - entropy.len == 13 );

exit:
    hmac_drbg_free( &ctx );
}

#ifdef POLARSSL_FS_IO
void test_suite_hmac_drbg_seed_file( int md_alg, char *path, int ret )
{
    const md_info_t *md_info;
    hmac_drbg_context ctx;

    md_info = md_info_from_type( md_alg );
    TEST_ASSERT( md_info != NULL );

    TEST_ASSERT( hmac_drbg_init( &ctx, md_info, rnd_std_rand, NULL,
                                 NULL, 0 ) == 0 );

    TEST_ASSERT( hmac_drbg_write_seed_file( &ctx, path ) == ret );
    TEST_ASSERT( hmac_drbg_update_seed_file( &ctx, path ) == ret );

exit:
    hmac_drbg_free( &ctx );
}
#endif /* POLARSSL_FS_IO */

void test_suite_hmac_drbg_buf( int md_alg )
{
    unsigned char out[16];
    unsigned char buf[100];
    const md_info_t *md_info;
    hmac_drbg_context ctx;
    size_t i;

    memset( buf, 0, sizeof( buf ) );
    memset( out, 0, sizeof( out ) );

    md_info = md_info_from_type( md_alg );
    TEST_ASSERT( md_info != NULL );
    TEST_ASSERT( hmac_drbg_init_buf( &ctx, md_info, buf, sizeof( buf ) ) == 0 );

    /* Make sure it never tries to reseed (would segfault otherwise) */
    hmac_drbg_set_reseed_interval( &ctx, 3 );
    hmac_drbg_set_prediction_resistance( &ctx, POLARSSL_HMAC_DRBG_PR_ON );

    for( i = 0; i < 30; i++ )
        TEST_ASSERT( hmac_drbg_random( &ctx, out, sizeof( out ) ) == 0 );

exit:
    hmac_drbg_free( &ctx );
}

void test_suite_hmac_drbg_no_reseed( int md_alg,
                          char *entropy_hex, char *custom_hex,
                          char *add1_hex, char *add2_hex,
                          char *output_hex )
{
    unsigned char data[1024];
    unsigned char entropy[512];
    unsigned char custom[512];
    unsigned char add1[512];
    unsigned char add2[512];
    unsigned char output[512];
    unsigned char my_output[512];
    size_t custom_len, add1_len, add2_len, out_len;
    entropy_ctx p_entropy;
    const md_info_t *md_info;
    hmac_drbg_context ctx;

    memset( my_output, 0, sizeof my_output );

    custom_len = unhexify( custom, custom_hex );
    add1_len = unhexify( add1, add1_hex );
    add2_len = unhexify( add2, add2_hex );
    out_len = unhexify( output, output_hex );
    p_entropy.len = unhexify( entropy, entropy_hex );
    p_entropy.p = entropy;

    md_info = md_info_from_type( md_alg );
    TEST_ASSERT( md_info != NULL );

    /* Test the simplified buffer-based variant */
    memcpy( data, entropy, p_entropy.len );
    memcpy( data + p_entropy.len, custom, custom_len );
    TEST_ASSERT( hmac_drbg_init_buf( &ctx, md_info,
                                     data, p_entropy.len + custom_len ) == 0 );
    TEST_ASSERT( hmac_drbg_random_with_add( &ctx, my_output, out_len,
                                            add1, add1_len ) == 0 );
    TEST_ASSERT( hmac_drbg_random_with_add( &ctx, my_output, out_len,
                                            add2, add2_len ) == 0 );

    /* clear for second run */
    hmac_drbg_free( &ctx );

    TEST_ASSERT( memcmp( my_output, output, out_len ) == 0 );

    /* And now the normal entropy-based variant */
    TEST_ASSERT( hmac_drbg_init( &ctx, md_info, entropy_func, &p_entropy,
                                 custom, custom_len ) == 0 );
    TEST_ASSERT( hmac_drbg_random_with_add( &ctx, my_output, out_len,
                                            add1, add1_len ) == 0 );
    TEST_ASSERT( hmac_drbg_random_with_add( &ctx, my_output, out_len,
                                            add2, add2_len ) == 0 );
    TEST_ASSERT( memcmp( my_output, output, out_len ) == 0 );

exit:
    hmac_drbg_free( &ctx );
}

void test_suite_hmac_drbg_nopr( int md_alg,
                     char *entropy_hex, char *custom_hex,
                     char *add1_hex, char *add2_hex, char *add3_hex,
                     char *output_hex )
{
    unsigned char entropy[512];
    unsigned char custom[512];
    unsigned char add1[512];
    unsigned char add2[512];
    unsigned char add3[512];
    unsigned char output[512];
    unsigned char my_output[512];
    size_t custom_len, add1_len, add2_len, add3_len, out_len;
    entropy_ctx p_entropy;
    const md_info_t *md_info;
    hmac_drbg_context ctx;

    memset( my_output, 0, sizeof my_output );

    custom_len = unhexify( custom, custom_hex );
    add1_len = unhexify( add1, add1_hex );
    add2_len = unhexify( add2, add2_hex );
    add3_len = unhexify( add3, add3_hex );
    out_len = unhexify( output, output_hex );
    p_entropy.len = unhexify( entropy, entropy_hex );
    p_entropy.p = entropy;

    md_info = md_info_from_type( md_alg );
    TEST_ASSERT( md_info != NULL );

    TEST_ASSERT( hmac_drbg_init( &ctx, md_info, entropy_func, &p_entropy,
                                 custom, custom_len ) == 0 );
    TEST_ASSERT( hmac_drbg_reseed( &ctx, add1, add1_len ) == 0 );
    TEST_ASSERT( hmac_drbg_random_with_add( &ctx, my_output, out_len,
                                            add2, add2_len ) == 0 );
    TEST_ASSERT( hmac_drbg_random_with_add( &ctx, my_output, out_len,
                                            add3, add3_len ) == 0 );

    TEST_ASSERT( memcmp( my_output, output, out_len ) == 0 );

exit:
    hmac_drbg_free( &ctx );
}

void test_suite_hmac_drbg_pr( int md_alg,
                   char *entropy_hex, char *custom_hex,
                   char *add1_hex, char *add2_hex,
                   char *output_hex )
{
    unsigned char entropy[512];
    unsigned char custom[512];
    unsigned char add1[512];
    unsigned char add2[512];
    unsigned char output[512];
    unsigned char my_output[512];
    size_t custom_len, add1_len, add2_len, out_len;
    entropy_ctx p_entropy;
    const md_info_t *md_info;
    hmac_drbg_context ctx;

    memset( my_output, 0, sizeof my_output );

    custom_len = unhexify( custom, custom_hex );
    add1_len = unhexify( add1, add1_hex );
    add2_len = unhexify( add2, add2_hex );
    out_len = unhexify( output, output_hex );
    p_entropy.len = unhexify( entropy, entropy_hex );
    p_entropy.p = entropy;

    md_info = md_info_from_type( md_alg );
    TEST_ASSERT( md_info != NULL );

    TEST_ASSERT( hmac_drbg_init( &ctx, md_info, entropy_func, &p_entropy,
                                 custom, custom_len ) == 0 );
    hmac_drbg_set_prediction_resistance( &ctx, POLARSSL_HMAC_DRBG_PR_ON );
    TEST_ASSERT( hmac_drbg_random_with_add( &ctx, my_output, out_len,
                                            add1, add1_len ) == 0 );
    TEST_ASSERT( hmac_drbg_random_with_add( &ctx, my_output, out_len,
                                            add2, add2_len ) == 0 );

    TEST_ASSERT( memcmp( my_output, output, out_len ) == 0 );

exit:
    hmac_drbg_free( &ctx );
}

#ifdef POLARSSL_SELF_TEST
void test_suite_hmac_drbg_selftest( )
{
    TEST_ASSERT( hmac_drbg_self_test( 0 ) == 0 );

exit:
    return;
}
#endif /* POLARSSL_SELF_TEST */


#endif /* defined(POLARSSL_HMAC_DRBG_C) */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "POLARSSL_SHA256_C" ) == 0 )
    {
#if defined(POLARSSL_SHA256_C)
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
    if( strcmp( str, "POLARSSL_SHA512_C" ) == 0 )
    {
#if defined(POLARSSL_SHA512_C)
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
    if( strcmp( params[0], "hmac_drbg_entropy_usage" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );

        test_suite_hmac_drbg_entropy_usage( param1 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "hmac_drbg_seed_file" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO

        int param1;
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_hmac_drbg_seed_file( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "hmac_drbg_buf" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );

        test_suite_hmac_drbg_buf( param1 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "hmac_drbg_no_reseed" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        char *param6 = params[6];

        if( cnt != 7 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_hmac_drbg_no_reseed( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "hmac_drbg_nopr" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        char *param6 = params[6];
        char *param7 = params[7];

        if( cnt != 8 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );

        test_suite_hmac_drbg_nopr( param1, param2, param3, param4, param5, param6, param7 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "hmac_drbg_pr" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        char *param6 = params[6];

        if( cnt != 7 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_hmac_drbg_pr( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "hmac_drbg_selftest" ) == 0 )
    {
    #ifdef POLARSSL_SELF_TEST


        if( cnt != 1 )
        {
            polarssl_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_hmac_drbg_selftest(  );
        return ( 0 );
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
    const char *filename = "suites/test_suite_hmac_drbg.misc.data";
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


