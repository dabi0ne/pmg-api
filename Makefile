PACKAGE=proxmox-mailgateway-api
PKGVER=1.0
PKGREL=1

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_all.deb

DESTDIR=

PERL5DIR=${DESTDIR}/usr/share/perl5
DOCDIR=${DESTDIR}/usr/share/doc/${PACKAGE}

all:

.PHONY: deb
deb ${DEB}:
	rm -rf build
	rsync -a * build
	cd build; dpkg-buildpackage -b -us -uc
	lintian ${DEB}

install: ${BTDATA}
	install -d -m 755 ${PERL5DIR}/PMG
	install -d -m 755 ${PERL5DIR}/PMG/API2
	install -m 0644 PMG/API2.pm ${PERL5DIR}/PMG
	install -m 0644 PMG/HTTPServer.pm ${PERL5DIR}/PMG
	install -m 0644 PMG/Ticket.pm ${PERL5DIR}/PMG
	install -m 0644 PMG/API2/Nodes.pm ${PERL5DIR}/PMG/API2


.PHONY: upload
upload: ${DEB}
	 ./repoid.pl .git/ check
	# fixme tar cf - ${DEB} | ssh repoman@repo.proxmox.com upload

distclean: clean

clean:
	rm -rf ./build *.deb *.changes *.buildinfo
	find . -name '*~' -exec rm {} ';'

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}
