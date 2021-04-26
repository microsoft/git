CC = cc
RM = rm -f
MV = mv

CFLAGS = -g -O2 -Wall
LDFLAGS =
EXTLIBS = -lz

DESTDIR_SQ = $(subst ','\'',$(DESTDIR))

QUIET_SUBDIR0  = +$(MAKE) -C # space to separate -C and subdir
QUIET_SUBDIR1  =

ifneq ($(findstring s,$(MAKEFLAGS)),s)
ifndef V
	QUIET_CC       = @echo '   ' CC $@;
	QUIET_LINK     = @echo '   ' LINK $@;
	QUIET_GEN      = @echo '   ' GEN $@;
	QUIET_SUBDIR0  = +@subdir=
	QUIET_SUBDIR1  = ;$(NO_SUBDIR) echo '   ' SUBDIR $$subdir; \
			 $(MAKE) $(PRINT_DIR) -C $$subdir
	QUIET          = @

	export V
	export QUIET_GEN
	export QUIET_BUILT_IN
endif
endif

all:

include ../../config.mak.uname
-include ../../config.mak.autogen
-include ../../config.mak

TARGETS = scalar$(X) scalar.o json-parser.o
GITLIBS = ../../common-main.o ../../libgit.a ../../xdiff/lib.a

all: scalar$X ../../bin-wrappers/scalar

$(GITLIBS):
	$(QUIET_SUBDIR0)../.. $(QUIET_SUBDIR1) $(subst ../../,,$@)

$(TARGETS): $(GITLIBS) scalar.c json-parser.c json-parser.h
	$(QUIET_SUBDIR0)../.. $(QUIET_SUBDIR1) $(patsubst %,contrib/scalar/%,$@)

clean:
	$(RM) $(TARGETS) ../../bin-wrappers/scalar
	$(RM) scalar.1 scalar.html scalar.xml

../../bin-wrappers/scalar: ../../wrap-for-bin.sh Makefile
	@mkdir -p ../../bin-wrappers
	$(QUIET_GEN)sed -e '1s|#!.*/sh|#!$(SHELL_PATH_SQ)|' \
	     -e 's|@@BUILD_DIR@@|$(shell cd ../.. && pwd)|' \
	     -e 's|@@PROG@@|contrib/scalar/scalar$(X)|' < $< > $@ && \
	chmod +x $@

test: all
	$(MAKE) -C t

docs: scalar.html scalar.1

scalar.html: | scalar.1 # prevent them from trying to build `doc.dep` in parallel

scalar.html scalar.1: scalar.txt
	$(QUIET_SUBDIR0)../../Documentation$(QUIET_SUBDIR1) \
		MAN_TXT=../contrib/scalar/scalar.txt \
		../contrib/scalar/$@
	$(QUIET)test scalar.1 != "$@" || mv ../../Documentation/$@ .

.PHONY: all clean test docs FORCE
