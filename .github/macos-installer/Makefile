SHELL := /bin/bash
SUDO := sudo
C_INCLUDE_PATH := /usr/include
CPLUS_INCLUDE_PATH := /usr/include
LD_LIBRARY_PATH := /usr/lib

OSX_VERSION := $(shell sw_vers -productVersion)
TARGET_FLAGS := -mmacosx-version-min=$(OSX_VERSION) -DMACOSX_DEPLOYMENT_TARGET=$(OSX_VERSION)

ARCH := x86_64
ARCH_CODE := x86_64
ARCH_FLAGS_x86_64 := -arch x86_64

CFLAGS := $(TARGET_FLAGS) $(ARCH_FLAGS_${ARCH_CODE})
LDFLAGS := $(TARGET_FLAGS) $(ARCH_FLAGS_${ARCH_CODE})

PREFIX := /usr/local
GIT_PREFIX := $(PREFIX)/git

BUILD_CODE := intel-$(ARCH_CODE)
BUILD_DIR := $(GITHUB_WORKSPACE)/payload
DESTDIR := $(PWD)/stage/git-$(BUILD_CODE)-$(VERSION)
ARTIFACTDIR := build_artifacts
SUBMAKE := $(MAKE) C_INCLUDE_PATH="$(C_INCLUDE_PATH)" CPLUS_INCLUDE_PATH="$(CPLUS_INCLUDE_PATH)" LD_LIBRARY_PATH="$(LD_LIBRARY_PATH)" TARGET_FLAGS="$(TARGET_FLAGS)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" NO_GETTEXT=1 NO_DARWIN_PORTS=1 prefix=$(GIT_PREFIX) DESTDIR=$(DESTDIR)
CORES := $(shell bash -c "sysctl hw.ncpu | awk '{print \$$2}'")

.PHONY: image pkg payload

.SECONDARY:

$(DESTDIR)$(GIT_PREFIX)/VERSION-$(VERSION)-$(BUILD_CODE):
	rm -f $(BUILD_DIR)/git-$(VERSION)/osx-installed*
	mkdir -p $(DESTDIR)$(GIT_PREFIX)
	touch $@

$(BUILD_DIR)/git-$(VERSION)/osx-built-keychain:
	cd $(BUILD_DIR)/git-$(VERSION)/contrib/credential/osxkeychain; $(SUBMAKE) CFLAGS="$(CFLAGS) -g -O2 -Wall"
	touch $@

$(BUILD_DIR)/git-$(VERSION)/osx-built:
	[ -d $(DESTDIR)$(GIT_PREFIX) ] && $(SUDO) rm -rf $(DESTDIR) || echo ok
	cd $(BUILD_DIR)/git-$(VERSION); $(SUBMAKE) -j $(CORES) all strip
	touch $@

$(BUILD_DIR)/git-$(VERSION)/osx-installed-bin: $(BUILD_DIR)/git-$(VERSION)/osx-built $(BUILD_DIR)/git-$(VERSION)/osx-built-keychain
	cd $(BUILD_DIR)/git-$(VERSION); $(SUBMAKE) install
	cp $(BUILD_DIR)/git-$(VERSION)/contrib/credential/osxkeychain/git-credential-osxkeychain $(DESTDIR)$(GIT_PREFIX)/bin/git-credential-osxkeychain
	mkdir -p $(DESTDIR)$(GIT_PREFIX)/contrib/completion
	cp $(BUILD_DIR)/git-$(VERSION)/contrib/completion/git-completion.bash $(DESTDIR)$(GIT_PREFIX)/contrib/completion/
	cp $(BUILD_DIR)/git-$(VERSION)/contrib/completion/git-completion.zsh $(DESTDIR)$(GIT_PREFIX)/contrib/completion/
	cp $(BUILD_DIR)/git-$(VERSION)/contrib/completion/git-prompt.sh $(DESTDIR)$(GIT_PREFIX)/contrib/completion/
	# This is needed for Git-Gui, GitK
	mkdir -p $(DESTDIR)$(GIT_PREFIX)/lib/perl5/site_perl
	[ ! -f $(DESTDIR)$(GIT_PREFIX)/lib/perl5/site_perl/Error.pm ] && cp $(BUILD_DIR)/git-$(VERSION)/perl/private-Error.pm $(DESTDIR)$(GIT_PREFIX)/lib/perl5/site_perl/Error.pm || echo done
	touch $@

$(BUILD_DIR)/git-$(VERSION)/osx-installed-man: $(BUILD_DIR)/git-$(VERSION)/osx-installed-bin
	mkdir -p $(DESTDIR)$(GIT_PREFIX)/share/man
	cp -R $(GITHUB_WORKSPACE)/manpages/ $(DESTDIR)$(GIT_PREFIX)/share/man
	touch $@

$(BUILD_DIR)/git-$(VERSION)/osx-built-subtree:
	cd $(BUILD_DIR)/git-$(VERSION)/contrib/subtree; $(SUBMAKE) XML_CATALOG_FILES="$(XML_CATALOG_FILES)" all git-subtree.1
	touch $@

$(BUILD_DIR)/git-$(VERSION)/osx-installed-subtree: $(BUILD_DIR)/git-$(VERSION)/osx-built-subtree
	mkdir -p $(DESTDIR)
	cd $(BUILD_DIR)/git-$(VERSION)/contrib/subtree; $(SUBMAKE) XML_CATALOG_FILES="$(XML_CATALOG_FILES)" install install-man
	touch $@

$(BUILD_DIR)/git-$(VERSION)/osx-installed-assets: $(BUILD_DIR)/git-$(VERSION)/osx-installed-bin
	mkdir -p $(DESTDIR)$(GIT_PREFIX)/etc
	cat assets/etc/gitconfig.osxkeychain >> $(DESTDIR)$(GIT_PREFIX)/etc/gitconfig
	cp assets/uninstall.sh $(DESTDIR)$(GIT_PREFIX)/uninstall.sh
	sh -c "echo .DS_Store >> $(DESTDIR)$(GIT_PREFIX)/share/git-core/templates/info/exclude"

symlinks:
	mkdir -p $(ARTIFACTDIR)$(PREFIX)/bin
	cd $(ARTIFACTDIR)$(PREFIX)/bin; find ../git/bin -type f -exec ln -sf {} \;
	for man in man1 man3 man5 man7; do mkdir -p $(ARTIFACTDIR)$(PREFIX)/share/man/$$man; (cd $(ARTIFACTDIR)$(PREFIX)/share/man/$$man; ln -sf ../../../git/share/man/$$man/* ./); done
	ruby ../scripts/symlink-git-hardlinks.rb $(ARTIFACTDIR)
	touch $@

$(BUILD_DIR)/git-$(VERSION)/osx-installed: $(DESTDIR)$(GIT_PREFIX)/VERSION-$(VERSION)-$(BUILD_CODE) $(BUILD_DIR)/git-$(VERSION)/osx-installed-man $(BUILD_DIR)/git-$(VERSION)/osx-installed-assets $(BUILD_DIR)/git-$(VERSION)/osx-installed-subtree
	find $(DESTDIR)$(GIT_PREFIX) -type d -exec chmod ugo+rx {} \;
	find $(DESTDIR)$(GIT_PREFIX) -type f -exec chmod ugo+r {} \;
	touch $@

$(BUILD_DIR)/git-$(VERSION)/osx-built-assert-$(ARCH_CODE): $(BUILD_DIR)/git-$(VERSION)/osx-built
ifeq ("$(ARCH_CODE)", "universal")
	File $(BUILD_DIR)/git-$(VERSION)/git
	File $(BUILD_DIR)/git-$(VERSION)/contrib/credential/osxkeychain/git-credential-osxkeychain
else
	[ "$$(File $(BUILD_DIR)/git-$(VERSION)/git | cut -f 5 -d' ')" == "$(ARCH_CODE)" ]
	[ "$$(File $(BUILD_DIR)/git-$(VERSION)/contrib/credential/osxkeychain/git-credential-osxkeychain | cut -f 5 -d' ')" == "$(ARCH_CODE)" ]
endif
	touch $@

disk-image/VERSION-$(VERSION)-$(ARCH_CODE):
	rm -f disk-image/*.pkg disk-image/VERSION-* disk-image/.DS_Store
	mkdir disk-image
	touch "$@"

disk-image/git-$(VERSION)-$(BUILD_CODE).pkg: disk-image/VERSION-$(VERSION)-$(ARCH_CODE) symlinks
	pkgbuild --identifier com.git.pkg --version $(VERSION) --root $(ARTIFACTDIR)$(PREFIX) --scripts assets/scripts --install-location $(PREFIX) --component-plist ./assets/git-components.plist disk-image/git-$(VERSION)-$(BUILD_CODE).pkg

git-%-$(BUILD_CODE).dmg:
	hdiutil create git-$(VERSION)-$(BUILD_CODE).uncompressed.dmg -fs HFS+ -srcfolder disk-image -volname "Git $(VERSION) Intel $(ARCH)" -ov
	hdiutil convert -format UDZO -o $@ git-$(VERSION)-$(BUILD_CODE).uncompressed.dmg
	rm -f git-$(VERSION)-$(BUILD_CODE).uncompressed.dmg

payload: $(BUILD_DIR)/git-$(VERSION)/osx-installed $(BUILD_DIR)/git-$(VERSION)/osx-built-assert-$(ARCH_CODE)

pkg: disk-image/git-$(VERSION)-$(BUILD_CODE).pkg

image: git-$(VERSION)-$(BUILD_CODE).dmg
