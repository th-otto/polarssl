include ../configvars

LOCAL_CFLAGS  = $(CFLAGS) $(WARNING_CFLAGS)
LDFLAGS = -s
LDLIBS  = -lldg -lgem -lz

# list header files here
HEADER =

# list C files here
COBJS = main.c mbedtls.c

# list assembler files here
SOBJS =

SRCFILES = $(HEADER) $(COBJS) $(SOBJS)

OBJS = $(COBJS:.c=.o)

all: build_polarssl build_mbedtls

define CC_TEMPLATE
build/68000/$(1).o: .dirs $(1).c
	$(CC) $(LOCAL_CFLAGS) $(MBEDTLS_INCLUDES) $(CFLAGS_m68000) -c $(1).c -o $$@
build/68020/$(1).o: .dirs $(1).c
	$(CC) $(LOCAL_CFLAGS) $(MBEDTLS_INCLUDES) $(CFLAGS_m68020) -c $(1).c -o $$@
build/coldfire/$(1).o: .dirs $(1).c
	$(CC) $(LOCAL_CFLAGS) $(MBEDTLS_INCLUDES) $(CFLAGS_coldire) -c $(1).c -o $$@
endef
$(foreach f,$(OBJS:.o=),$(eval $(call CC_TEMPLATE,$(f))))


build_polarssl: 
	$(MAKE) MBEDTLS_INCLUDES=-I../polarssl/include build/68000/polarssl.ldg build/68020/polarssl.ldg build/coldfire/polarssl.ldg

build_mbedtls: 
	$(MAKE) MBEDTLS_INCLUDES=-I../mbedtls/include build/68000/mbedtls.ldg build/68020/mbedtls.ldg build/coldfire/mbedtls.ldg


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
	$(CC) build/68000/main.o $(CFLAGS) $(CFLAGS_m68000) ../polarssl/library/build/68000/libpolarssl.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/68020/polarssl.ldg: build/68020/main.o ../polarssl/library/build/68020/libpolarssl.a
	$(CC) build/68020/main.o $(CFLAGS) $(CFLAGS_m68020) ../polarssl/library/build/68020/libpolarssl.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/coldfire/polarssl.ldg: build/coldfire/main.o ../polarssl/library/build/coldfire/libpolarssl.a
	$(CC) build/coldfire/main.o $(CFLAGS) $(CFLAGS_coldfire) ../polarssl/library/build/coldfire/libpolarssl.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@


build/68000/mbedtls.ldg: build/68000/mbedtls.o ../mbedtls/library/build/68000/libmbedtls.a ../mbedtls/library/build/68000/libmbedcrypto.a ../mbedtls/library/build/68000/libmbedx509.a
	$(CC) build/68000/mbedtls.o $(CFLAGS) $(CFLAGS_m68000) ../mbedtls/library/build/68000/libmbedtls.a ../mbedtls/library/build/68000/libmbedcrypto.a ../mbedtls/library/build/68000/libmbedx509.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/68020/mbedtls.ldg: build/68020/mbedtls.o ../mbedtls/library/build/68020/libmbedtls.a ../mbedtls/library/build/68020/libmbedcrypto.a ../mbedtls/library/build/68020/libmbedx509.a
	$(CC) build/68020/mbedtls.o $(CFLAGS) $(CFLAGS_m68020) ../mbedtls/library/build/68020/libmbedtls.a ../mbedtls/library/build/68020/libmbedcrypto.a ../mbedtls/library/build/68020/libmbedx509.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/coldfire/mbedtls.ldg: build/coldfire/mbedtls.o ../mbedtls/library/build/coldfire/libmbedtls.a ../mbedtls/library/build/coldfire/libmbedcrypto.a ../mbedtls/library/build/coldfire/libmbedx509.a
	$(CC) build/coldfire/mbedtls.o $(CFLAGS) $(CFLAGS_coldfire) ../mbedtls/library/build/coldfire/libmbedtls.a ../mbedtls/library/build/coldfire/libmbedcrypto.a ../mbedtls/library/build/coldfire/libmbedx509.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@
