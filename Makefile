PACKAGE=proxmox-mailgateway-api
PKGVER=1.0
PKGREL=1

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_all.deb

DESTDIR=

PERL5DIR=${DESTDIR}/usr/share/perl5
DOCDIR=${DESTDIR}/usr/share/doc/${PACKAGE}

REPOID=`./repoid.pl .git`

all: PMG/pmgcfg.pm

.PHONY: deb
deb ${DEB}:
	rm -rf build
	rsync -a * build
	cd build; dpkg-buildpackage -b -us -uc
	lintian ${DEB}


PMG/pmgcfg.pm: PMG/pmgcfg.pm.in
	sed -e s/@VERSION@/${PKGVER}/ -e s/@PACKAGERELEASE@/${PKGREL}/ -e s/@PACKAGE@/${PACKAGE}/ -e s/@REPOID@/${REPOID}/ $< >$@.tmp
	mv $@.tmp $@

install: ${BTDATA} PMG/pmgcfg.pm
	install -d -m 0755 ${PERL5DIR}/PMG
	install -d -m 0755 ${PERL5DIR}/PMG/API2
	install -d -m 0755 ${PERL5DIR}/PMG/Service
	install -m 0644 PMG/pmgcfg.pm ${PERL5DIR}/PMG
	install -m 0644 PMG/API2.pm ${PERL5DIR}/PMG
	install -m 0644 PMG/HTTPServer.pm ${PERL5DIR}/PMG
	install -m 0644 PMG/Ticket.pm ${PERL5DIR}/PMG
	install -m 0644 PMG/AccessControl.pm ${PERL5DIR}/PMG
	install -m 0644 PMG/API2/Nodes.pm ${PERL5DIR}/PMG/API2
	install -m 0644 PMG/API2/AccessControl.pm ${PERL5DIR}/PMG/API2
	install -m 0644 PMG/Service/pmgdaemon.pm ${PERL5DIR}/PMG/Service
	install -d -m 0755 ${DESTDIR}/usr/bin
	install -m 0755 bin/pmgdaemon ${DESTDIR}/usr/bin

.PHONY: upload
upload: ${DEB}
	 ./repoid.pl .git/ check
	# fixme tar cf - ${DEB} | ssh repoman@repo.proxmox.com upload

distclean: clean

clean:
	rm -rf ./build *.deb *.changes *.buildinfo PMG/pmgcfg.pm
	find . -name '*~' -exec rm {} ';'

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}
