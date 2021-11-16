# The default target of this Makefile is...
all::

# Import tree-wide shared Makefile behavior and libraries
include ../../shared.mak

include ../../config.mak.uname
-include ../../config.mak.autogen
-include ../../config.mak

TARGETS = scalar$(X) scalar.o
GITLIBS = ../../common-main.o ../../libgit.a ../../xdiff/lib.a

all:: scalar$(X) ../../bin-wrappers/scalar

$(GITLIBS):
	$(QUIET_SUBDIR0)../.. $(QUIET_SUBDIR1) $(subst ../../,,$@)

$(TARGETS): $(GITLIBS) scalar.c
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

INSTALL = install
prefix = $(HOME)
bindir = $(prefix)/bin
mandir ?= $(prefix)/share/man
man1dir = $(mandir)/man1
htmldir ?= $(prefix)/share/doc/git-doc
DESTDIR_SQ = $(subst ','\'',$(DESTDIR))
bindir_SQ = $(subst ','\'',$(bindir))
man1dir_SQ = $(subst ','\'',$(man1dir))
htmldir_SQ = $(subst ','\'',$(htmldir))

install:
	$(INSTALL) -d -m 755 '$(DESTDIR_SQ)$(bindir_SQ)'
	$(INSTALL) scalar$(X) '$(DESTDIR_SQ)$(bindir_SQ)'

docs: scalar.html scalar.1

scalar.html: | scalar.1 # prevent them from trying to build `doc.dep` in parallel

scalar.html scalar.1: scalar.txt
	$(QUIET_SUBDIR0)../../Documentation$(QUIET_SUBDIR1) \
		MAN_TXT=../contrib/scalar/scalar.txt \
		../contrib/scalar/$@
	$(QUIET)test scalar.1 != "$@" || mv ../../Documentation/$@ .

install-doc: scalar.1
	$(INSTALL) -d -m 755 $(DESTDIR_SQ)$(man1dir_SQ)
	$(INSTALL) -m 644 $^ $(DESTDIR_SQ)$(man1dir_SQ)

install-html: scalar.html
	$(INSTALL) -d -m 755 $(DESTDIR_SQ)$(htmldir_SQ)
	$(INSTALL) -m 644 $^ $(DESTDIR_SQ)$(htmldir_SQ)

.PHONY: $(GITLIBS) all clean test docs install install-doc install-html FORCE
