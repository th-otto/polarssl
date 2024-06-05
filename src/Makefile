include ../configvars

LOCAL_CFLAGS  = $(CFLAGS) -I../polarssl/include $(WARNING_CFLAGS)
LDFLAGS = -s
LDLIBS  = -lldg -lgem -lz

TARGET = polarssl.ldg

# list header files here
HEADER =

# list C files here
COBJS = main.c

# list assembler files here
SOBJS =

SRCFILES = $(HEADER) $(COBJS) $(SOBJS)

OBJS = $(COBJS:.c=.o)

all: build/68000/$(TARGET) build/68020/$(TARGET) build/coldfire/$(TARGET)

define CC_TEMPLATE
build/68000/$(1).o: .dirs $(1).c
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS_m68000) -c $(1).c -o $$@
build/68020/$(1).o: .dirs $(1).c
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS_m68020) -c $(1).c -o $$@
build/coldfire/$(1).o: .dirs $(1).c
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS_coldire) -c $(1).c -o $$@
endef
$(foreach f,$(OBJS:.o=),$(eval $(call CC_TEMPLATE,$(f))))

#############################

STACK = -Wl,--stack,2k

clean:
	rm -rf build .dirs

.dirs:
	@mkdir -p build/68000
	@mkdir -p build/68020
	@mkdir -p build/coldfire
	@touch $@

build/68000/$(TARGET): $(addprefix build/68000/,$(OBJS)) ../polarssl/library/libpolarssl_000.a
	$(CC) $(addprefix build/68000/,$(OBJS)) $(CFLAGS) $(CFLAGS_m68000) ../polarssl/library/libpolarssl_000.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/68020/$(TARGET): $(addprefix build/68020/,$(OBJS)) ../polarssl/library/libpolarssl_020.a
	$(CC) $(addprefix build/68020/,$(OBJS)) $(CFLAGS) $(CFLAGS_m68020) ../polarssl/library/libpolarssl_020.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@

build/coldfire/$(TARGET): $(addprefix build/coldfire/,$(OBJS)) ../polarssl/library/libpolarssl_v4e.a
	$(CC) $(addprefix build/coldfire/,$(OBJS)) $(CFLAGS) $(CFLAGS_coldfire) ../polarssl/library/libpolarssl_v4e.a $(LDLIBS) $(LDFLAGS) $(STACK) -o $@
