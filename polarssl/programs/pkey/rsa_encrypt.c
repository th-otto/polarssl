/*
 *  RSA simple data encryption program
 *
 *  Copyright (C) 2006-2011, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define polarssl_fprintf    fprintf
#define polarssl_printf     printf
#define polarssl_exit       exit
#endif

#if defined(POLARSSL_BIGNUM_C) && defined(POLARSSL_RSA_C) && \
    defined(POLARSSL_ENTROPY_C) && defined(POLARSSL_FS_IO) && \
    defined(POLARSSL_CTR_DRBG_C)
#include "polarssl/rsa.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#include <stdio.h>
#include <string.h>
#endif

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_RSA_C) ||  \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_FS_IO) || \
    !defined(POLARSSL_CTR_DRBG_C)
int main( void )
{
    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_ENTROPY_C and/or POLARSSL_FS_IO and/or "
           "POLARSSL_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int return_val, exit_val;
    size_t i;
    rsa_context rsa;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    unsigned char input[1024];
    unsigned char buf[512];
    const char *pers = "rsa_encrypt";

    exit_val = 0;

    if( argc != 2 )
    {
        polarssl_printf( "usage: rsa_encrypt <string of max 100 characters>\n" );

#if defined(_WIN32)
        polarssl_printf( "\n" );
#endif

        polarssl_exit( 1 );
    }

    polarssl_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    rsa_init( &rsa, RSA_PKCS_V15, 0 );

    return_val = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                                (const unsigned char *) pers,
                                strlen( pers ) );

    if( return_val != 0 )
    {
        exit_val = 1;
        polarssl_printf( " failed\n  ! ctr_drbg_init returned %d\n",
                         return_val );
        goto exit;
    }

    polarssl_printf( "\n  . Reading public key from rsa_pub.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_pub.txt", "rb" ) ) == NULL )
    {
        exit_val = 1;
        polarssl_printf( " failed\n  ! Could not open rsa_pub.txt\n" \
                         "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    if( ( return_val = mpi_read_file( &rsa.N, 16, f ) ) != 0 ||
        ( return_val = mpi_read_file( &rsa.E, 16, f ) ) != 0 )
    {
        exit_val = 1;
        polarssl_printf( " failed\n  ! mpi_read_file returned %d\n\n",
                         return_val );
        goto exit;
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;

    fclose( f );

    if( strlen( argv[1] ) > 100 )
    {
        exit_val = 1;
        polarssl_printf( " Input data larger than 100 characters.\n\n" );
        goto exit;
    }

    memcpy( input, argv[1], strlen( argv[1] ) );

    /*
     * Calculate the RSA encryption of the hash.
     */
    polarssl_printf( "\n  . Generating the RSA encrypted value" );
    fflush( stdout );

    if( ( return_val = rsa_pkcs1_encrypt( &rsa, ctr_drbg_random, &ctr_drbg,
                                          RSA_PUBLIC, strlen( argv[1] ),
                                          input, buf ) ) != 0 )
    {
        exit_val = 1;
        polarssl_printf( " failed\n  ! rsa_pkcs1_encrypt returned %d\n\n",
                         return_val );
        goto exit;
    }

    /*
     * Write the signature into result-enc.txt
     */
    if( ( f = fopen( "result-enc.txt", "wb+" ) ) == NULL )
    {
        exit_val = 1;
        polarssl_printf( " failed\n  ! Could not create %s\n\n", "result-enc.txt" );
        goto exit;
    }

    for( i = 0; i < rsa.len; i++ )
        polarssl_fprintf( f, "%02X%s", buf[i],
                 ( i + 1 ) % 16 == 0 ? "\r\n" : " " );

    fclose( f );

    polarssl_printf( "\n  . Done (created \"%s\")\n\n", "result-enc.txt" );

exit:
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );
    rsa_free( &rsa );

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( exit_val );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_RSA_C && POLARSSL_ENTROPY_C &&
          POLARSSL_FS_IO && POLARSSL_CTR_DRBG_C */
