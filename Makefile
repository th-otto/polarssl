SUBDIRS = polarssl/library polarssl/programs polarssl/tests
SUBDIRS += mbedtls/library mbedtls/programs mbedtls/tests
SUBDIRS += src

all clean:
	@for i in $(SUBDIRS); do \
		echo $(MAKE) -C $$i $@; \
		$(MAKE) -C $$i $@ || exit 1; \
	done
