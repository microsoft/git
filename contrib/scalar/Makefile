D:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

ifneq ($(D),$(CURDIR)/contrib/scalar)

# This Makefile expects to be sourced from Git's top-level directory

scalar scalar.exe Documentation/scalar.html Documentation/scalar.1:
	$(MAKE) -C "$(D)/../.." -f contrib/scalar/Makefile "$@"

all:
	$(MAKE) -C "$(D)/../.." -f contrib/scalar/Makefile all-scalar

scalar.1 scalar.html:
	$(MAKE) -C "$(D)/../.." -f contrib/scalar/Makefile Documentation/"$@"

.PHONY: all scalar.1 scalar.html FORCE

else

# Okay, we're running in Git's top-level directory. Good.

include Makefile

all-scalar: scalar$X

all:: all-scalar

docs:: Documentation/scalar.html Documentation/scalar.1

scalar$X: scalar.o $(GITLIBS)
	$(QUIET_LINK)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -o $@ $< \
		$(GITLIBS) $(EXTLIBS)

scalar.o: contrib/scalar/scalar.c
	$(QUIET_CC)$(CC) $(ALL_CFLAGS) -o $@ -c $<

Documentation/scalar.html: contrib/scalar/scalar.txt
	$(QUIET_SUBDIR0)Documentation $(QUIET_SUBDIR1) \
		MAN_TXT=../contrib/scalar/scalar.txt \
		../contrib/scalar/scalar.html
	mv contrib/scalar/scalar.html $@

Documentation/scalar.1: contrib/scalar/scalar.txt
	$(QUIET_SUBDIR0)Documentation $(QUIET_SUBDIR1) \
		MAN_TXT=../contrib/scalar/scalar.txt \
		../contrib/scalar/scalar.1

.PHONY: all-scalar FORCE

endif
