VERSION = 1.0
PACKAGE = ardukey-auth


all:
	@echo "Try 'make install' or 'make uninstall'."
	@exit 1

## Installation rules:

etcprefix = /etc
binprefix = /usr/bin
sbinprefix = /usr/sbin

libprefix = /usr/lib/ardukey-auth

docprefix = /usr/share/doc/ardukey-auth
manprefix = /usr/share/man/man1

varprefix = /var/ardukey-auth

install:
	install -D --mode 644 files/ardukey-auth.conf $(DESTDIR)$(etcprefix)/ardukey-auth.conf

	install -D --mode 644 files/libraries/__init__.py $(DESTDIR)$(libprefix)/__init__.py
	install -D --mode 644 files/libraries/AES.py$(DESTDIR)$(libprefix)/AES.py
	install -D --mode 644 files/libraries/SQLiteWrapper.py $(DESTDIR)$(libprefix)/SQLiteWrapper.py
	install -D --mode 644 files/libraries/ValidationRequest.py $(DESTDIR)$(libprefix)/ValidationRequest.py

	install -D --mode 755 files/ardukey-auth.py $(DESTDIR)$(sbinprefix)/ardukey-auth-daemon

	install -D --mode 644 files/ardukey-auth.sqlite $(DESTDIR)$(varprefix)/ardukey-auth.sqlite

#uninstall:
#	rm -rf $(LIBDIR)
#	rm -f $(DESTDIR)/usr/share/pam-configs/fingerprint
#	rm -f $(BINDIR)/pamfingerprint-check
#	rm -f $(BINDIR)/pamfingerprint-conf
#	rm -f $(DESTDIR)/lib/security/pam_fingerprint.py
#	rm -f $(DESTDIR)/etc/bash_completion.d/pamfingerprint
#	rm -f $(DESTDIR)/etc/pamfingerprint.conf

clean:
	find files/ -name "*.pyc" -exec rm -rf {} \;
	rm -rf files/libraries/__pycache__/
