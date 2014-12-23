## ArduKey authserver
##
## Copyright 2014 Bastian Raschke
## All rights reserved.

libprefix = /usr/lib/python3/dist-packages/ardukeyauth


all:
	@echo "Try 'make install' or 'make clean'."
	@exit 1

install:

	## TODO: Better cp -r files/ardukeyauth/* $(DESTDIR)$(libprefix)
	install -d $(DESTDIR)$(libprefix)
	install files/ardukeyauth/* -t $(DESTDIR)$(libprefix)

	install --mode 644 \
	  files/ardukey-auth.conf \
	  $(DESTDIR)/etc/ardukey-auth.conf

	install --mode 755 \
	  files/ardukey-auth.py \
	  $(DESTDIR)/usr/sbin/ardukey-auth.py

	install --mode 755 \
	  files/ardukey-auth \
	  $(DESTDIR)/etc/init.d/ardukey-auth

	install -D --mode 644 --owner www-data --group adm \
	  files/ardukey-auth.sqlite \
	  $(DESTDIR)/usr/share/ardukey-auth/ardukey-auth.sqlite

	install -D --mode 644 --owner www-data --group adm \
	  files/ardukey-auth.log \
	  $(DESTDIR)/var/log/ardukey-auth.log

clean:
	echo -n > files/ardukey-auth.sqlite

	## TODO: Better approach?
	rm -rf files/ardukeyauth/__pycache__/
