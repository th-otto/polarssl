/*
 *  RSA/SHA-256 signature creation program
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
#define polarssl_fprintf    fprintf
#define polarssl_printf     printf
#define polarssl_snprintf   snprintf
#endif

#if defined(POLARSSL_BIGNUM_C) && defined(POLARSSL_RSA_C) && \
    defined(POLARSSL_SHA256_C) && defined(POLARSSL_FS_IO)
#include "polarssl/rsa.h"
#include "polarssl/sha1.h"

#include <stdio.h>
#include <string.h>
#endif

#if defined _MSC_VER && !defined snprintf
#define snprintf _snprintf
#endif

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_RSA_C) ||  \
    !defined(POLARSSL_SHA256_C) || !defined(POLARSSL_FS_IO)
int main( void )
{
    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_SHA256_C and/or POLARSSL_FS_IO not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int ret;
    size_t i;
    rsa_context rsa;
    unsigned char hash[32];
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];
    char filename[512];

    rsa_init( &rsa, RSA_PKCS_V15, 0 );
    ret = 1;

    if( argc != 2 )
    {
        polarssl_printf( "usage: rsa_sign <filename>\n" );

#if defined(_WIN32)
        polarssl_printf( "\n" );
#endif

        goto exit;
    }

    polarssl_printf( "\n  . Reading private key from rsa_priv.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_priv.txt", "rb" ) ) == NULL )
    {
        ret = 1;
        polarssl_printf( " failed\n  ! Could not open rsa_priv.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    if( ( ret = mpi_read_file( &rsa.N , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.E , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.D , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.P , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.Q , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DP, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DQ, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.QP, 16, f ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! mpi_read_file returned %d\n\n", ret );
        goto exit;
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;

    fclose( f );

    polarssl_printf( "\n  . Checking the private key" );
    fflush( stdout );
    if( ( ret = rsa_check_privkey( &rsa ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! rsa_check_privkey failed with -0x%0x\n", -ret );
        goto exit;
    }

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the RSA signature of the hash.
     */
    polarssl_printf( "\n  . Generating the RSA/SHA-256 signature" );
    fflush( stdout );

    if( ( ret = sha1_file( argv[1], hash ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! Could not open or read %s\n\n", argv[1] );
        goto exit;
    }

    if( ( ret = rsa_pkcs1_sign( &rsa, NULL, NULL, RSA_PRIVATE, POLARSSL_MD_SHA256,
                                20, hash, buf ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! rsa_pkcs1_sign returned -0x%0x\n\n", -ret );
        goto exit;
    }

    /*
     * Write the signature into <filename>.sig
     */
    polarssl_snprintf( filename, sizeof( filename ), "%s.sig", argv[1] );

    if( ( f = fopen( filename, "wb+" ) ) == NULL )
    {
        ret = 1;
        polarssl_printf( " failed\n  ! Could not create %s\n\n", filename );
        goto exit;
    }

    for( i = 0; i < rsa.len; i++ )
        polarssl_fprintf( f, "%02X%s", buf[i],
                 ( i + 1 ) % 16 == 0 ? "\r\n" : " " );

    fclose( f );

    polarssl_printf( "\n  . Done (created \"%s\")\n\n", filename );

exit:

    rsa_free( &rsa );

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_RSA_C && POLARSSL_SHA256_C &&
          POLARSSL_FS_IO */
