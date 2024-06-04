include ../configvars

LOCAL_CFLAGS = -I../include $(WARNING_CFLAGS)

OBJS =  aes.o aesni.o arc4.o asn1parse.o asn1write.o base64.o bignum.o blowfish.o camellia.o ccm.o certs.o cipher.o cipher_wrap.o ctr_drbg.o debug.o des.o dhm.o \
      ecdh.o ecdsa.o ecp.o ecp_curves.o entropy.o entropy_poll.o error.o gcm.o havege.o hmac_drbg.o md.o md_wrap.o md2.o md4.o md5.o memory_buffer_alloc.o net.o \
      oid.o padlock.o pbkdf2.o pem.o pkcs5.o pkcs11.o pkcs12.o pk.o pk_wrap.o pkparse.o pkwrite.o platform.o ripemd160.o rsa.o sha1.o sha256.o sha512.o \
      ssl_cache.o ssl_cli.o ssl_srv.o ssl_ciphersuites.o ssl_tls.o threading.o timing.o version.o version_features.o \
      x509.o x509_create.o x509_crl.o x509_crt.o x509_csr.o x509write_crt.o x509write_csr.o xtea.o \
      timing_alt.o

LIBS = libpolarssl_000.a libpolarssl_020.a libpolarssl_v4e.a libpolarssl.a libmbedtls.a

all: $(LIBS)

libpolarssl_000.a: clean
	$(CC) $(LOCAL_CFLAGS) -m68000 -c *.c
	$(AR) -rcs $@ *.o

libpolarssl_020.a: clean
	$(CC) $(LOCAL_CFLAGS) -m68020-60 -c *.c
	$(AR) -rcs $@ *.o

libpolarssl_v4e.a: clean
	$(CC) $(LOCAL_CFLAGS) -mcpu=5475 -c *.c
	$(AR) -rcs $@ *.o

libpolarssl.a: libpolarssl_000.a
	ln -s $< $@

libmbedtls.a: libpolarssl.a
	ln -s $< $@

install: $(LIBS)
	cp libpolarssl_000.a $(DESTDIR)/lib/libpolarssl.a
	cp libpolarssl_020.a $(DESTDIR)/lib/m68020-60/libpolarssl.a
	cp libpolarssl_v4e.a $(DESTDIR)/lib/m5475/libpolarssl.a

uninstall::

clean:
	rm -f *.o *.a
