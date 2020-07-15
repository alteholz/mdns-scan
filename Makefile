VERSION=0.5
TARFILE=mdns-scan-$(VERSION).tar.gz
DISTDIR=mdns-scan-$(VERSION)/
DISTFILES=Makefile mdns-scan.1 dns.c dns.h mdns-scan.c query.c query.h util.h util.c README LICENSE
CFLAGS=-Wall -W -g -O0 -pipe
INSTALL=install

mdns-scan: mdns-scan.o dns.o query.o util.o
	$(CC) -o $@ $^

dist: $(TARFILE)

$(TARFILE): $(DISTFILES)
	rm -rf $(DISTDIR)
	mkdir $(DISTDIR)
	cp --parents $(DISTFILES) $(DISTDIR)
	rm -f $(TARFILE)
	tar czf $(TARFILE) $(DISTDIR)
	rm -rf $(DISTDIR)

install:
	$(INSTALL) mdns-scan $(DESTDIR)/usr/bin/mdns-scan

clean:
	rm -f mdns-scan *.o *.tar.gz
	rm -rf mdns-scan-$(VERSION)

deb:
	dpkg-buildpackage -uc -us -rfakeroot

.PHONY: clean dist deb install



