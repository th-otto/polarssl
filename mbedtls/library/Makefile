include ../../configvars
include ../../silent.mak

ifndef MBEDTLS_PATH
MBEDTLS_PATH := ..
endif

GENERATED_FILES := \
	error.c version_features.c \
	ssl_debug_helpers_generated.c \
	psa_crypto_driver_wrappers.h \
	psa_crypto_driver_wrappers_no_static.c

ifneq ($(GENERATED_FILES),$(wildcard $(GENERATED_FILES)))
    include $(MBEDTLS_PATH)/framework/exported.make
endif

# Also see "include/mbedtls/mbedtls_config.h"

# Include ../include for public headers and . for private headers.
# Note that . needs to be included explicitly for the sake of library
# files that are not in the /library directory (which currently means
# under /3rdparty).
LOCAL_CFLAGS = $(CFLAGS) -I. -I../include $(WARNING_CFLAGS)
LOCAL_LDFLAGS =

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

# MicroBlaze specific options:
# CFLAGS += -mno-xl-soft-mul -mxl-barrel-shift

# To compile on Plan9:
# CFLAGS += -D_BSD_EXTENSION

PERL ?= perl

PYTHON ?= $(shell if type python3 >/dev/null 2>/dev/null; then echo python3; else echo python; fi)

OBJS_CRYPTO= \
	     aes.o \
	     aesni.o \
	     aesce.o \
	     aria.o \
	     asn1parse.o \
	     asn1write.o \
	     base64.o \
	     bignum.o \
	     bignum_core.o \
	     bignum_mod.o \
	     bignum_mod_raw.o \
	     block_cipher.o \
	     camellia.o \
	     ccm.o \
	     chacha20.o \
	     chachapoly.o \
	     cipher.o \
	     cipher_wrap.o \
	     cmac.o \
	     constant_time.o \
	     ctr_drbg.o \
	     des.o \
	     dhm.o \
	     ecdh.o \
	     ecdsa.o \
	     ecjpake.o \
	     ecp.o \
	     ecp_curves.o \
	     ecp_curves_new.o \
	     entropy.o \
	     entropy_poll.o \
	     error.o \
	     gcm.o \
	     hkdf.o \
	     hmac_drbg.o \
	     lmots.o \
	     lms.o \
	     md.o \
	     md5.o \
	     memory_buffer_alloc.o \
	     nist_kw.o \
	     oid.o \
	     padlock.o \
	     pem.o \
	     pk.o \
	     pk_ecc.o \
	     pk_wrap.o \
	     pkcs12.o \
	     pkcs5.o \
	     pkparse.o \
	     pkwrite.o \
	     platform.o \
	     platform_util.o \
	     poly1305.o \
	     psa_crypto.o \
	     psa_crypto_aead.o \
	     psa_crypto_cipher.o \
	     psa_crypto_client.o \
	     psa_crypto_driver_wrappers_no_static.o \
	     psa_crypto_ecp.o \
	     psa_crypto_ffdh.o \
	     psa_crypto_hash.o \
	     psa_crypto_mac.o \
	     psa_crypto_pake.o \
	     psa_crypto_rsa.o \
	     psa_crypto_se.o \
	     psa_crypto_slot_management.o \
	     psa_crypto_storage.o \
	     psa_its_file.o \
	     psa_util.o \
	     ripemd160.o \
	     rsa.o \
	     rsa_alt_helpers.o \
	     sha1.o \
	     sha256.o \
	     sha512.o \
	     sha3.o \
	     threading.o \
	     timing.o \
	     timing_alt.o \
	     version.o \
	     version_features.o \
	     # This line is intentionally left blank

include ../3rdparty/Makefile.inc
LOCAL_CFLAGS+=$(THIRDPARTY_INCLUDES)
OBJS_CRYPTO+=$(THIRDPARTY_CRYPTO_OBJECTS)

OBJS_X509= \
	   x509.o \
	   x509_create.o \
	   x509_crl.o \
	   x509_crt.o \
	   x509_csr.o \
	   x509write.o \
	   x509write_crt.o \
	   x509write_csr.o \
	   pkcs7.o \
	   # This line is intentionally left blank

OBJS_TLS= \
	  debug.o \
	  mps_reader.o \
	  mps_trace.o \
	  net_sockets.o \
	  ssl_cache.o \
	  ssl_ciphersuites.o \
	  ssl_client.o \
	  ssl_cookie.o \
	  ssl_debug_helpers_generated.o \
	  ssl_msg.o \
	  ssl_ticket.o \
	  ssl_tls.o \
	  ssl_tls12_client.o \
	  ssl_tls12_server.o \
	  ssl_tls13_keys.o \
	  ssl_tls13_client.o \
	  ssl_tls13_server.o \
	  ssl_tls13_generic.o \
	  # This line is intentionally left blank

.PHONY: all static clean

LIBS = libmbedcrypto.a libmbedx509.a libmbedtls.a \

ifneq ($(CROSSPREFIX),)
LIBS += \
	libmbedcrypto_000.a libmbedx509_000.a libmbedtls_000.a \
	libmbedcrypto_020.a libmbedx509_020.a libmbedtls_020.a \
	libmbedcrypto_v4e.a libmbedx509_v4e.a libmbedtls_v4e.a \
	$(empty)
endif

all: static

ifneq ($(CROSSPREFIX),)
define CC_TEMPLATE
build/68000/$$(notdir $(1).o): .dirs $(1).c
	$(AM_V_CC)$(CC) $(CFLAGS_m68000) $(LOCAL_CFLAGS) -c $(1).c -o $$@
build/68020/$$(notdir $(1).o): .dirs $(1).c
	$(AM_V_CC)$(CC) $(CFLAGS_m68020) $(LOCAL_CFLAGS)  -c $(1).c -o $$@
build/coldfire/$$(notdir $(1).o): .dirs $(1).c
	$(AM_V_CC)$(CC) $(CFLAGS_coldfire) $(LOCAL_CFLAGS) -c $(1).c -o $$@
endef
else
define CC_TEMPLATE
build/host/$$(notdir $(1).o): .dirs $(1).c
	$(AM_V_CC)$(CC) $(LOCAL_CFLAGS) -c $(1).c -o $$@
endef
endif
$(foreach f,$(OBJS_TLS:.o=) $(OBJS_X509:.o=) $(OBJS_CRYPTO:.o=),$(eval $(call CC_TEMPLATE,$(f))))

static: $(LIBS)

# tls
ifneq ($(CROSSPREFIX),)
libmbedtls_000.a: $(addprefix build/68000/,$(OBJS_TLS))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^
libmbedtls_020.a: $(addprefix build/68020/,$(OBJS_TLS))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^
libmbedtls_v4e.a: $(addprefix build/coldfire/,$(OBJS_TLS))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^
libmbedtls.a: libmbedtls_000.a
	ln -sf $< $@

# x509
libmbedx509_000.a: $(addprefix build/68000/,$(OBJS_X509))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^
libmbedx509_020.a: $(addprefix build/68020/,$(OBJS_X509))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^
libmbedx509_v4e.a: $(addprefix build/coldfire/,$(OBJS_X509))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^
libmbedx509.a: libmbedx509_000.a
	ln -sf $< $@

# crypto
libmbedcrypto_000.a: $(addprefix build/68000/,$(notdir $(OBJS_CRYPTO)))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^
libmbedcrypto_020.a: $(addprefix build/68020/,$(notdir $(OBJS_CRYPTO)))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^
libmbedcrypto_v4e.a: $(addprefix build/coldfire/,$(notdir $(OBJS_CRYPTO)))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^
libmbedcrypto.a: libmbedcrypto_000.a
	ln -sf $< $@

else

libmbedtls.a: $(addprefix build/host/,$(OBJS_TLS))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^
libmbedx509.a: $(addprefix build/host/,$(OBJS_X509))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^
libmbedcrypto.a: $(addprefix build/host/,$(notdir $(OBJS_CRYPTO)))
	$(AM_V_AR)$(AR) $(ARFLAGS) $@ $^

endif



.PHONY: generated_files
generated_files: $(GENERATED_FILES)

# See root Makefile
GEN_FILES ?=
ifdef GEN_FILES
gen_file_dep =
else
gen_file_dep = |
endif

error.c: $(gen_file_dep) ../scripts/generate_errors.pl
error.c: $(gen_file_dep) ../scripts/data_files/error.fmt
error.c: $(gen_file_dep) $(filter-out %config%,$(wildcard ../include/mbedtls/*.h))
error.c:
	@echo "  Gen   $@"
	$(PERL) ../scripts/generate_errors.pl

ssl_debug_helpers_generated.c: $(gen_file_dep) ../scripts/generate_ssl_debug_helpers.py
ssl_debug_helpers_generated.c: $(gen_file_dep) $(filter-out %config%,$(wildcard ../include/mbedtls/*.h))
ssl_debug_helpers_generated.c:
	@echo "  Gen   $@"
	$(PYTHON) ../scripts/generate_ssl_debug_helpers.py --mbedtls-root .. .

version_features.c: $(gen_file_dep) ../scripts/generate_features.pl
version_features.c: $(gen_file_dep) ../scripts/data_files/version_features.fmt
## The generated file only depends on the options that are present in mbedtls_config.h,
## not on which options are set. To avoid regenerating this file all the time
## when switching between configurations, don't declare mbedtls_config.h as a
## dependency. Remove this file from your working tree if you've just added or
## removed an option in mbedtls_config.h.
#version_features.c: ../include/mbedtls/mbedtls_config.h
version_features.c:
	@echo "  Gen   $@"
	$(PERL) ../scripts/generate_features.pl

GENERATED_WRAPPER_FILES = \
                    psa_crypto_driver_wrappers.h \
                    psa_crypto_driver_wrappers_no_static.c
$(GENERATED_WRAPPER_FILES): ../scripts/generate_driver_wrappers.py
$(GENERATED_WRAPPER_FILES): ../scripts/data_files/driver_templates/psa_crypto_driver_wrappers.h.jinja
$(GENERATED_WRAPPER_FILES): ../scripts/data_files/driver_templates/psa_crypto_driver_wrappers_no_static.c.jinja
$(GENERATED_WRAPPER_FILES):
	@echo "  Gen   $(GENERATED_WRAPPER_FILES)"
	$(PYTHON) ../scripts/generate_driver_wrappers.py

psa_crypto.o:psa_crypto_driver_wrappers.h

.dirs:
	@mkdir -p build/68000
	@mkdir -p build/68020
	@mkdir -p build/coldfire
	@mkdir -p build/host
	@touch $@

clean:
	rm -f *.o libmbed*
	rm -rf build .dirs

neat: clean
	rm -f $(GENERATED_FILES)
