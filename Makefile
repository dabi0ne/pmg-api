PACKAGE=proxmox-mailgateway-api
PKGVER=1.0
PKGREL=1

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_all.deb

DESTDIR=

PERL5DIR=${DESTDIR}/usr/share/perl5
DOCDIR=${DESTDIR}/usr/share/doc/${PACKAGE}
BASHCOMPLDIR=${DESTDIR}/usr/share/bash-completion/completions/

REPOID=`./repoid.pl .git`

SERVICES = pmgdaemon pmgproxy

LIBSOURCES =				\
	PMG/pmgcfg.pm			\
	PMG/NoVncIndex.pm		\
	PMG/Cluster.pm			\
	PMG/HTTPServer.pm		\
	PMG/Ticket.pm			\
	PMG/AccessControl.pm		\
	PMG/API2/Tasks.pm		\
	PMG/API2/Nodes.pm		\
	PMG/API2/AccessControl.pm	\
	PMG/API2.pm

all: ${LIBSOURCES}

.PHONY: deb
deb ${DEB}: ${LIBSOURCES}
	rm -rf build
	rsync -a * build
	cd build; dpkg-buildpackage -b -us -uc
	lintian ${DEB}


PMG/pmgcfg.pm: PMG/pmgcfg.pm.in
	sed -e s/@VERSION@/${PKGVER}/ -e s/@PACKAGERELEASE@/${PKGREL}/ -e s/@PACKAGE@/${PACKAGE}/ -e s/@REPOID@/${REPOID}/ $< >$@.tmp
	mv $@.tmp $@

%.service-bash-completion:
	perl -I.. -T -e "use PMG::Service::$*; PMG::Service::$*->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

install: ${BTDATA} $(addsuffix .pm, $(addprefix PMG/Service/, ${SERVICES})) $(addsuffix .service-bash-completion, ${SERVICES}) ${LIBSOURCES}
	for i in ${SERVICES}; do perl -I. -T -e "use PMG::Service::$$i; PMG::Service::$$i->verify_api();"; done
	install -d -m 0755 ${DESTDIR}/usr/bin
	install -d -m 0700 -o www-data -g www-data ${DESTDIR}/var/log/pmgproxy
	install -d -m 0755 ${DOCDIR}
	# TODO: is there a better location ?
	install -m 0644 favicon.ico ${DOCDIR}
	for i in ${LIBSOURCES}; do install -D -m 0644 $$i ${PERL5DIR}/$$i; done
	for i in ${SERVICES}; do install -D -m 0644 PMG/Service/$$i.pm ${PERL5DIR}/PMG/Service/$$i.pm; done
	for i in ${SERVICES}; do install -m 0755 bin/$$i ${DESTDIR}/usr/bin; done
	for i in ${SERVICES}; do install -m 0644 -D $$i.service-bash-completion ${BASHCOMPLDIR}/$$i; done


.PHONY: upload
upload: ${DEB}
	 ./repoid.pl .git/ check
	# fixme tar cf - ${DEB} | ssh repoman@repo.proxmox.com upload

distclean: clean

clean:
	rm -rf ./build *.deb *.changes *.buildinfo
	if test -d .git; then  rm -f PMG/pmgcfg.pm; fi
	find . -name '*~' -exec rm {} ';'

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}
