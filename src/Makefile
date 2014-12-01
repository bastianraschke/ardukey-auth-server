
VERSION = 0.0.1
PACKAGE = ardukey-auth

all:
	@echo "Try 'make install' or 'make symlink'."
	@echo "Docs: https://github.com/Yubico/yubikey-val/wiki/Installation"
	@exit 1

# Installation rules.

etcprefix = /etc/yubico/val
sbinprefix = /usr/sbin
phpprefix = /usr/share/yubikey-val
docprefix = /usr/share/doc/yubikey-val
manprefix = /usr/share/man/man1
muninprefix = /usr/share/munin/plugins
wwwgroup = www-data

install:
	install -D --mode 644 ykval-verify.php $(DESTDIR)$(phpprefix)/ykval-verify.php
	install -D --mode 644 ykval-common.php $(DESTDIR)$(phpprefix)/ykval-common.php

wwwprefix = /var/www/wsapi

symlink:
	install -d $(DESTDIR)$(wwwprefix)/2.0
	ln -sf $(phpprefix)/ykval-verify.php $(DESTDIR)$(wwwprefix)/2.0/verify.php
	ln -sf $(phpprefix)/ykval-sync.php $(DESTDIR)$(wwwprefix)/2.0/sync.php
	ln -sf $(phpprefix)/ykval-resync.php $(DESTDIR)$(wwwprefix)/2.0/resync.php
	ln -sf 2.0/verify.php $(DESTDIR)$(wwwprefix)/verify.php

revoke:
	install -D --mode 644 ykval-revoke.php $(DESTDIR)$(phpprefix)/ykval-revoke.php
	ln -sf $(phpprefix)/ykval-revoke.php $(DESTDIR)$(wwwprefix)/revoke.php

# Maintainer rules.

PROJECT = $(PACKAGE)

$(PACKAGE)-$(VERSION).tgz: $(FILES)
	mkdir $(PACKAGE)-$(VERSION) $(PACKAGE)-$(VERSION)/doc
	cp $(CODE) $(MANS) $(MUNIN) $(PACKAGE)-$(VERSION)/
	cp $(DOCS) $(PACKAGE)-$(VERSION)/doc/
	git2cl > $(PACKAGE)-$(VERSION)/ChangeLog
	tar cfz $(PACKAGE)-$(VERSION).tgz $(PACKAGE)-$(VERSION)
	rm -rf $(PACKAGE)-$(VERSION)

dist: $(PACKAGE)-$(VERSION).tgz

clean:
	rm -f *~
	rm -rf $(PACKAGE)-$(VERSION)

release: dist
	@if test -z "$(KEYID)"; then \
		echo "Try this instead:"; \
		echo "  make release KEYID=[PGPKEYID]"; \
		echo "For example:"; \
		echo "  make release KEYID=2117364A"; \
		exit 1; \
	fi
	@head -1 NEWS | grep -q "Version $(VERSION) (released `date -I`)" || \
		(echo 'error: You need to update date/version in NEWS'; exit 1)
	@if test ! -d "$(YUBICO_GITHUB_REPO)"; then \
		echo "yubico.github.com repo not found!"; \
		echo "Make sure that YUBICO_GITHUB_REPO is set"; \
		exit 1; \
	fi
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tgz
	gpg --verify $(PACKAGE)-$(VERSION).tgz.sig
	git tag -u $(KEYID) -m $(VERSION) $(PACKAGE)-$(VERSION)
	@echo "Release created and tagged, remember to git push && git push --tags"
	$(YUBICO_GITHUB_REPO)/publish $(PROJECT) $(VERSION) $(PACKAGE)-$(VERSION).tgz*
