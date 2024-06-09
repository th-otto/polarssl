include ../configvars
include ../silent.mak

LOCAL_CFLAGS  = $(CFLAGS) $(WARNING_CFLAGS)
LDFLAGS = -s
LDLIBS  = -lldg -lgem -lz

# list header files here
HEADER =

# list C files here
COBJS = main.c mbedtls.c openssl.c

# list assembler files here
SOBJS =

SRCFILES = $(HEADER) $(COBJS) $(SOBJS)

OBJS = $(COBJS:.c=.o)

all: \
	build/68000/polarssl.ldg build/68020/polarssl.ldg build/coldfire/polarssl.ldg \
	build/68000/mbedtls.ldg build/68020/mbedtls.ldg build/coldfire/mbedtls.ldg \
	build/68000/openssl.ldg build/68020/openssl.ldg build/coldfire/openssl.ldg \
	$(empty)

define CC_TEMPLATE
build/68000/$(1).o: .dirs $(1).c
	$(AM_V_CC)$(CC) $(CFLAGS_m68000) $(LOCAL_CFLAGS) $(2) -c $(1).c -o $$@
build/68020/$(1).o: .dirs $(1).c
	$(AM_V_CC)$(CC) $(CFLAGS_m68020) $(LOCAL_CFLAGS) $(2) -c $(1).c -o $$@
build/coldfire/$(1).o: .dirs $(1).c
	$(AM_V_CC)$(CC) $(CFLAGS_coldfire) $(LOCAL_CFLAGS) $(2) -c $(1).c -o $$@
endef
$(eval $(call CC_TEMPLATE,main,-I../polarssl/include))
$(eval $(call CC_TEMPLATE,mbedtls,-I../mbedtls/include))
$(eval $(call CC_TEMPLATE,openssl,-I../openssl/include))


#############################

STACK = -Wl,--stack,2k

clean:
	rm -rf build .dirs

.dirs:
	@mkdir -p build/68000
	@mkdir -p build/68020
	@mkdir -p build/coldfire
	@touch $@

build/68000/polarssl.ldg: build/68000/main.o ../polarssl/library/build/68000/libpolarssl.a
	$(AM_V_CCLD)$(CC) $(CFLAGS_m68000) $(CFLAGS) build/68000/main.o ../polarssl/library/build/68000/libpolarssl.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/68020/polarssl.ldg: build/68020/main.o ../polarssl/library/build/68020/libpolarssl.a
	$(AM_V_CCLD)$(CC) $(CFLAGS_m68020) $(CFLAGS) build/68020/main.o ../polarssl/library/build/68020/libpolarssl.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/coldfire/polarssl.ldg: build/coldfire/main.o ../polarssl/library/build/coldfire/libpolarssl.a
	$(AM_V_CCLD)$(CC) $(CFLAGS_coldfire) $(CFLAGS) build/coldfire/main.o ../polarssl/library/build/coldfire/libpolarssl.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@


build/68000/mbedtls.ldg: build/68000/mbedtls.o ../mbedtls/library/build/68000/libmbedtls.a ../mbedtls/library/build/68000/libmbedcrypto.a ../mbedtls/library/build/68000/libmbedx509.a
	$(AM_V_CCLD)$(CC) $(CFLAGS_m68000) $(CFLAGS) build/68000/mbedtls.o ../mbedtls/library/build/68000/libmbedtls.a ../mbedtls/library/build/68000/libmbedcrypto.a ../mbedtls/library/build/68000/libmbedx509.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/68020/mbedtls.ldg: build/68020/mbedtls.o ../mbedtls/library/build/68020/libmbedtls.a ../mbedtls/library/build/68020/libmbedcrypto.a ../mbedtls/library/build/68020/libmbedx509.a
	$(AM_V_CCLD)$(CC) $(CFLAGS_m68020) $(CFLAGS) build/68020/mbedtls.o ../mbedtls/library/build/68020/libmbedtls.a ../mbedtls/library/build/68020/libmbedcrypto.a ../mbedtls/library/build/68020/libmbedx509.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/coldfire/mbedtls.ldg: build/coldfire/mbedtls.o ../mbedtls/library/build/coldfire/libmbedtls.a ../mbedtls/library/build/coldfire/libmbedcrypto.a ../mbedtls/library/build/coldfire/libmbedx509.a
	$(AM_V_CCLD)$(CC) $(CFLAGS_coldfire) $(CFLAGS) build/coldfire/mbedtls.o ../mbedtls/library/build/coldfire/libmbedtls.a ../mbedtls/library/build/coldfire/libmbedcrypto.a ../mbedtls/library/build/coldfire/libmbedx509.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@


build/68000/openssl.ldg: build/68000/openssl.o ../openssl/build/68000/libssl.a ../openssl/build/68000/libcrypto.a
	$(AM_V_CCLD)$(CC) $(CFLAGS_m68000) $(CFLAGS) build/68000/openssl.o ../openssl/build/68000/libssl.a ../openssl/build/68000/libcrypto.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/68020/openssl.ldg: build/68020/openssl.o ../openssl/build/68020/libssl.a ../openssl/build/68020/libcrypto.a
	$(AM_V_CCLD)$(CC) $(CFLAGS_m68020) $(CFLAGS) build/68020/openssl.o ../openssl/build/68020/libssl.a ../openssl/build/68020/libcrypto.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/coldfire/openssl.ldg: build/coldfire/openssl.o ../openssl/build/coldfire/libssl.a ../openssl/build/coldfire/libcrypto.a
	$(AM_V_CCLD)$(CC) $(CFLAGS_coldfire) $(CFLAGS) build/coldfire/openssl.o ../openssl/build/coldfire/libssl.a ../openssl/build/coldfire/libcrypto.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@
