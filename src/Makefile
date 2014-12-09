## ArduKey authserver
##
## Copyright 2014 Bastian Raschke
## All rights reserved.


## Installation rules

etcprefix = /etc
binprefix = /usr/bin
sbinprefix = /usr/sbin
libprefix = /usr/lib/ardukey-auth
docprefix = /usr/share/doc/ardukey-auth
manprefix = /usr/share/man/man1
varprefix = /var/ardukey-auth

all:
	@echo "Try 'make install' or 'make clean'."
	@exit 1

install:
	install -D --mode 644 files/ardukey-auth.conf $(DESTDIR)$(etcprefix)/ardukey-auth.conf

	install -D --mode 644 files/libraries/__init__.py $(DESTDIR)$(libprefix)/__init__.py
	install -D --mode 644 files/libraries/AES.py $(DESTDIR)$(libprefix)/AES.py
	install -D --mode 644 files/libraries/SQLiteWrapper.py $(DESTDIR)$(libprefix)/SQLiteWrapper.py
	install -D --mode 644 files/libraries/ValidationRequest.py $(DESTDIR)$(libprefix)/ValidationRequest.py

	install -D --mode 755 files/ardukey-auth.py $(DESTDIR)$(sbinprefix)/ardukey-auth

	install -D --mode 644 files/ardukey-auth.sqlite $(DESTDIR)$(varprefix)/ardukey-auth.sqlite

clean:
	find files/ -name "*.pyc" -exec rm -rf {} \;
	rm -rf files/libraries/__pycache__/
