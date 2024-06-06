# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS

ifndef MBEDTLS_PATH
MBEDTLS_PATH := ..
endif

include $(MBEDTLS_PATH)/framework/exported.make

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I$(MBEDTLS_TEST_PATH)/include -I$(MBEDTLS_PATH)/include
LOCAL_CXXFLAGS = $(CFLAGS) $(WARNING_CXXFLAGS) -I$(MBEDTLS_PATH)/include -I$(MBEDTLS_PATH)/tests/include
LOCAL_LDFLAGS = ${MBEDTLS_TEST_OBJS} 		\
		-L$(MBEDTLS_PATH)/library			\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

include $(MBEDTLS_PATH)/3rdparty/Makefile.inc
LOCAL_CFLAGS+=$(THIRDPARTY_INCLUDES)

MBEDLIBS=$(MBEDTLS_PATH)/library/libmbedcrypto.a $(MBEDTLS_PATH)/library/libmbedx509.a $(MBEDTLS_PATH)/library/libmbedtls.a

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

## Usage: $(call remove_enabled_options,PREPROCESSOR_INPUT)
## Remove the preprocessor symbols that are set in the current configuration
## from PREPROCESSOR_INPUT. Also normalize whitespace.
## Example:
##   $(call remove_enabled_options,MBEDTLS_FOO MBEDTLS_BAR)
## This expands to an empty string "" if MBEDTLS_FOO and MBEDTLS_BAR are both
## enabled, to "MBEDTLS_FOO" if MBEDTLS_BAR is enabled but MBEDTLS_FOO is
## disabled, etc.
##
## This only works with a Unix-like shell environment (Bourne/POSIX-style shell
## and standard commands) and a Unix-like compiler (supporting -E). In
## other environments, the output is likely to be empty.
define remove_enabled_options
$(strip $(shell
  exec 2>/dev/null;
  { echo '#include <mbedtls/build_info.h>'; echo $(1); } |
  $(CC) $(LOCAL_CFLAGS) $(CFLAGS) -E - |
  tail -n 1
))
endef

  DLEXT ?= so
  EXEXT=
  SHARED_SUFFIX=

PYTHON ?= $(shell if type python3 >/dev/null 2>/dev/null; then echo python3; else echo python; fi)

# See root Makefile
GEN_FILES ?= yes
ifdef GEN_FILES
gen_file_dep =
else
gen_file_dep = |
endif

default: all

$(MBEDLIBS):
	$(MAKE) -C $(MBEDTLS_PATH)/library

neat: clean
	rm -f $(GENERATED_FILES)

# Auxiliary modules used by tests and some sample programs
MBEDTLS_CORE_TEST_OBJS = $(patsubst %.c,%.o,$(wildcard \
    ${MBEDTLS_TEST_PATH}/src/*.c \
    ${MBEDTLS_TEST_PATH}/src/drivers/*.c \
  ))
# Additional auxiliary modules for TLS testing
MBEDTLS_TLS_TEST_OBJS = $(patsubst %.c,%.o,$(wildcard \
    ${MBEDTLS_TEST_PATH}/src/test_helpers/*.c \
  ))

MBEDTLS_TEST_OBJS = $(MBEDTLS_CORE_TEST_OBJS) $(MBEDTLS_TLS_TEST_OBJS)
