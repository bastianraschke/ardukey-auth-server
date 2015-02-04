# Written by Simon Josefsson <simon@josefsson.org>.
# Copyright (c) 2009-2012 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

VERSION = 1.2
PACKAGE = yubikey-gak
CODE = Makefile NEWS ykgak-config.php ykgak-index.php
DOCS = doc/Installation.wiki
MISC = misc/favicon.ico misc/style.css misc/yubicoLogo.png misc/yubikey.png

all:
	@echo "Try 'make install' or 'make symlink'."
	@echo "Docs: http://code.google.com/p/yubikey-getapikey/wiki/Installation"
	@exit 1

# Installation rules.

etcprefix = /etc/ykgak
phpprefix = /usr/share/ykgak
docprefix = /usr/share/doc/ykgak
wwwuser = www-data
wwwgroup = www-data

install:
	install -D ykgak-index.php $(phpprefix)/ykgak-index.php
	install -d $(phpprefix)/misc
	install -D $(MISC) $(phpprefix)/misc
	install -d --mode 700 --owner $(wwwuser) --group $(wwwgroup) $(etcprefix)
	install -D --backup --mode 640 --group $(wwwgroup) ykgak-config.php $(etcprefix)/ykgak-config.php-template
	install -D Makefile $(docprefix)/ykgak.mk
	install -D $(DOCS) $(docprefix)/

wwwprefix = /var/www/getapikey

symlink:
	install -d $(wwwprefix)
	ln -sf $(phpprefix)/ykgak-index.php $(wwwprefix)/index.php
	ln -sf $(phpprefix)/misc/favicon.ico $(wwwprefix)/../favicon.ico
	ln -sf $(phpprefix)/misc $(wwwprefix)/misc

# Maintainer rules.

PROJECT = yubikey-getapikey
USER = simon75j
KEYID = B9156397

$(PACKAGE)-$(VERSION).tgz: $(FILES)
	mkdir $(PACKAGE)-$(VERSION) $(PACKAGE)-$(VERSION)/doc $(PACKAGE)-$(VERSION)/misc
	cp $(CODE) $(PACKAGE)-$(VERSION)/
	cp $(DOCS) $(PACKAGE)-$(VERSION)/doc/
	cp $(MISC) $(PACKAGE)-$(VERSION)/misc/
	tar cfz $(PACKAGE)-$(VERSION).tgz $(PACKAGE)-$(VERSION)
	rm -rf $(PACKAGE)-$(VERSION)

dist: $(PACKAGE)-$(VERSION).tgz

clean:
	rm -f *~
	rm -rf $(PACKAGE)-$(VERSION)

release: dist
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tgz
	gpg --verify $(PACKAGE)-$(VERSION).tgz.sig
	svn copy https://$(PROJECT).googlecode.com/svn/trunk/ \
	 https://$(PROJECT).googlecode.com/svn/tags/$(PACKAGE)-$(VERSION) \
	 -m "Tagging the $(VERSION) release of the $(PACKAGE) project."
	googlecode_upload.py -s "OpenPGP signature for $(PACKAGE) $(VERSION)." \
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION).tgz.sig
	googlecode_upload.py -s "$(PACKAGE) $(VERSION)." \
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION).tgz 
