include ../../configvars
include ../../silent.mak

LOCAL_CFLAGS = $(CFLAGS) -I../include $(WARNING_CFLAGS)

OBJS = aes.o aesni.o arc4.o asn1parse.o asn1write.o base64.o bignum.o blowfish.o camellia.o ccm.o certs.o cipher.o cipher_wrap.o ctr_drbg.o debug.o des.o dhm.o \
      ecdh.o ecdsa.o ecp.o ecp_curves.o entropy.o entropy_poll.o error.o gcm.o havege.o hmac_drbg.o md.o md_wrap.o md2.o md4.o md5.o memory_buffer_alloc.o net.o \
      oid.o padlock.o pbkdf2.o pem.o pkcs5.o pkcs11.o pkcs12.o pk.o pk_wrap.o pkparse.o pkwrite.o platform.o ripemd160.o rsa.o sha1.o sha256.o sha512.o \
      ssl_cache.o ssl_cli.o ssl_srv.o ssl_ciphersuites.o ssl_tls.o threading.o timing.o version.o version_features.o \
      x509.o x509_create.o x509_crl.o x509_crt.o x509_csr.o x509write_crt.o x509write_csr.o xtea.o \
      timing_alt.o

all::

ifneq ($(CROSSPREFIX),)
define CC_TEMPLATE
build/68000/$(1).o: .dirs $(1).c
	$(AM_V_CC)$(CC) $(LOCAL_CFLAGS) $(CFLAGS_m68000) -c $(1).c -o $$@
build/68020/$(1).o: .dirs $(1).c
	$(AM_V_CC)$(CC) $(LOCAL_CFLAGS) $(CFLAGS_m68020) -c $(1).c -o $$@
build/coldfire/$(1).o: .dirs $(1).c
	$(AM_V_CC)$(CC) $(LOCAL_CFLAGS) $(CFLAGS_coldire) -c $(1).c -o $$@
endef
define AR_TEMPLATE
build/68000/$(1): $$(addprefix build/68000/,$$(notdir $(2)))
	$(AM_V_AR)$(AR) $(ARFLAGS) $$@ $$^
build/68020/$(1): $$(addprefix build/68020/,$$(notdir $(2)))
	$(AM_V_AR)$(AR) $(ARFLAGS) $$@ $$^
build/coldfire/$(1): $$(addprefix build/coldfire/,$$(notdir $(2)))
	$(AM_V_AR)$(AR) $(ARFLAGS) $$@ $$^
LIBS += build/68000/$(1) build/68020/$(1) build/coldfire/$(1)
endef
else
define CC_TEMPLATE
build/host/$(1).o: .dirs $(1).c
	$(AM_V_CC)$(CC) $(LOCAL_CFLAGS) -c $(1).c -o $$@
endef
define AR_TEMPLATE
build/host/$(1): $$(addprefix build/host/,$$(notdir $(2)))
	$(AM_V_AR)$(AR) $(ARFLAGS) $$@ $$^
LIBS += build/host/$(1)
endef
endif
$(foreach f,$(OBJS:.o=),$(eval $(call CC_TEMPLATE,$(f))))

$(eval $(call AR_TEMPLATE,libpolarssl.a,$(OBJS)))

all:: $(LIBS)


.dirs:
	@mkdir -p build/68000
	@mkdir -p build/68020
	@mkdir -p build/coldfire
	@mkdir -p build/host
	@touch $@

install: $(LIBS)
	cp build/68000/libpolarssl.a $(DESTDIR)/usr/lib/libpolarssl.a
	cp build/68020/libpolarssl.a $(DESTDIR)/usr/lib/m68020-60/libpolarssl.a
	cp build/coldfire/libpolarssl.a $(DESTDIR)/usr/lib/m5475/libpolarssl.a

uninstall::

clean:
	rm -rf build *.a .dirs
