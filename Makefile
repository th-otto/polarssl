SUBDIRS = polarssl/library polarssl/programs polarssl/tests src

all clean:
	@for i in $(SUBDIRS); do \
		echo $(MAKE) -C $$i $@; \
		$(MAKE) -C $$i $@ || exit 1; \
	done
