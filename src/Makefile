
CFLAGS  =  -Wall -O2 -fomit-frame-pointer -I../mbedtls-1.3.22/include
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

#############################
CROSSPREFIX=m68k-atari-mint-

CC = $(CROSSPREFIX)gcc
AS = $(CC)
AR = $(CROSSPREFIX)ar
RANLIB = $(CROSSPREFIX)ranlib
STRIP = $(CROSSPREFIX)strip
FLAGS = $(CROSSPREFIX)flags
STACK = -Wl,--stack,2k

OBJS = $(COBJS:.c=.o)

all: $(TARGET)
	rm -f ./build/68000/*.o
	rm -f ./build/68020/*.o
	rm -f ./build/coldfire/*.o
	@echo All done

clean:
	-@rm -f ./build/68000/$(OBJS)
	-@rm -f ./build/68000/$(TARGET)
	-@rm -f ./build/68020/$(OBJS)
	-@rm -f ./build/68020/$(TARGET)
	-@rm -f ./build/coldfire/$(OBJS)
	-@rm -f ./build/coldfire/$(TARGET)
	@echo Cleaned

new: clean
	-@rm -f $(TARGET)
	$(MAKE) all


.SUFFIXES:
.SUFFIXES: .c .S .o

.c.o:
	$(CC) $(CFLAGS) -m68000 -c $*.c -o ./build/68000/$*.o
	$(CC) $(CFLAGS) -m68020-60 -c $*.c -o ./build/68020/$*.o
	$(CC) $(CFLAGS) -mcpu=5475 -c $*.c -o ./build/coldfire/$*.o

$(TARGET): $(OBJS)
	$(CC) ./build/68000/*.o $(CFLAGS) -m68000 ../mbedtls-1.3.22/library/libpolarssl_000.a $(LDLIBS) $(LDFLAGS) $(STACK) -o ./build/68000/$(TARGET)
	$(CC) ./build/68020/*.o $(CFLAGS) -m68020-60 ../mbedtls-1.3.22/library/libpolarssl_020.a $(LDLIBS) $(LDFLAGS) $(STACK) -o ./build/68020/$(TARGET)
	$(CC) ./build/coldfire/*.o $(CFLAGS) -mcpu=5475 ../mbedtls-1.3.22/library/libpolarssl_v4e.a $(LDLIBS) $(LDFLAGS) $(STACK) -o ./build/coldfire/$(TARGET)
