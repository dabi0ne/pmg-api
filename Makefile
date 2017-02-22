PACKAGE=proxmox-mailgateway-api
PKGVER=1.0
PKGREL=1

# this requires package pmg-doc-generator
export NOVIEW=1
include /usr/share/pmg-doc-generator/pmg-doc-generator.mk


DEB=${PACKAGE}_${PKGVER}-${PKGREL}_all.deb

DESTDIR=

PERL5DIR=${DESTDIR}/usr/share/perl5
DOCDIR=${DESTDIR}/usr/share/doc/${PACKAGE}
BASHCOMPLDIR=${DESTDIR}/usr/share/bash-completion/completions/

REPOID=`./repoid.pl .git`

SERVICES = pmgdaemon pmgproxy
CLITOOLS = pmgdb pmgconfig
CLISCRIPTS= pmg-smtp-filter pmgsh pmgpolicy

CLI_CLASSES = $(addprefix, 'PMG/API2/', $(addsuffix '.pm', ${CLITOOLS}))
CLI_BINARIES = $(addprefix, 'bin/', ${CLITOOLS} ${CLISCRIPTS})
CLI_MANS = $(addsuffix .1, ${CLITOOLS})

CONF_MANS=				\
	pmg.conf.5

TEMPLATES =				\
	main.cf.in			\
	main.cf.in.demo			\
	master.cf.in			\
	master.cf.in.demo		\
	init.pre.in			\
	local.cf.in			\
	v310.pre.in			\
	v320.pre.in			\
	razor-agent.conf.in		\
	freshclam.conf.in		\
	clamd.conf.in 			\
	postgresql.conf.in		\
	pg_hba.conf.in

TEMPLATES_FILES = $(addprefix, 'templates/', ${TEMPLATES})

LIBSOURCES =				\
	PMG/pmgcfg.pm			\
	PMG/Utils.pm			\
	PMG/ModGroup.pm			\
	PMG/SMTPPrinter.pm		\
	PMG/NoVncIndex.pm		\
	PMG/Config.pm			\
	PMG/Cluster.pm			\
	PMG/ClusterConfig.pm		\
	PMG/HTTPServer.pm		\
	PMG/Ticket.pm			\
	PMG/AccessControl.pm		\
	PMG/AtomicFile.pm		\
	PMG/MailQueue.pm		\
	PMG/SMTP.pm			\
	PMG/Unpack.pm			\
	PMG/RuleCache.pm		\
	PMG/Statistic.pm		\
	PMG/LDAPConfig.pm		\
	PMG/LDAPSet.pm			\
	PMG/LDAPCache.pm		\
	PMG/DBTools.pm			\
	PMG/RuleDB/Group.pm		\
	PMG/RuleDB/Rule.pm		\
	PMG/RuleDB/Object.pm		\
	PMG/RuleDB/Quarantine.pm	\
	PMG/RuleDB/WhoRegex.pm		\
	PMG/RuleDB/IPAddress.pm		\
	PMG/RuleDB/IPNet.pm		\
	PMG/RuleDB/ModField.pm		\
	PMG/RuleDB/MatchFilename.pm	\
	PMG/RuleDB/ReceiverRegex.pm	\
	PMG/RuleDB/EMail.pm		\
	PMG/RuleDB/Receiver.pm		\
	PMG/RuleDB/Domain.pm		\
	PMG/RuleDB/ReceiverDomain.pm	\
	PMG/RuleDB/TimeFrame.pm		\
	PMG/RuleDB/MatchField.pm	\
	PMG/RuleDB/ContentTypeFilter.pm	\
	PMG/RuleDB/ArchiveFilter.pm	\
	PMG/RuleDB/Spam.pm		\
	PMG/RuleDB/Virus.pm		\
	PMG/RuleDB/ReportSpam.pm	\
	PMG/RuleDB/Remove.pm		\
	PMG/RuleDB/Attach.pm		\
	PMG/RuleDB/BCC.pm		\
	PMG/RuleDB/Counter.pm		\
	PMG/RuleDB/Notify.pm		\
	PMG/RuleDB/Disclaimer.pm	\
	PMG/RuleDB/Accept.pm		\
	PMG/RuleDB/Block.pm		\
	PMG/RuleDB.pm			\
	PMG/CLI/pmgdb.pm		\
	${CLI_CLASSES} 			\
	PMG/API2/Network.pm             \
	PMG/API2/Services.pm		\
	PMG/API2/Tasks.pm		\
	PMG/API2/LDAP.pm		\
	PMG/API2/Domains.pm		\
	PMG/API2/Config.pm		\
	PMG/API2/ClusterConfig.pm	\
	PMG/API2/Nodes.pm		\
	PMG/API2/AccessControl.pm	\
	PMG/API2/RuleDB.pm		\
	PMG/API2.pm

all: ${LIBSOURCES} ${CLI_BINARIES} ${TEMPLATES_FILES} ${CONF_MANS} ${CLI_MANS}

.PHONY: deb
deb ${DEB}: ${LIBSOURCES} ${CLI_BINARIES} ${TEMPLATES_FILES} ${CONF_MANS} ${CLI_MANS}
	rm -rf build
	rsync -a * build
	cd build; dpkg-buildpackage -b -us -uc
	lintian ${DEB}


PMG/pmgcfg.pm: PMG/pmgcfg.pm.in
	sed -e s/@VERSION@/${PKGVER}/ -e s/@PACKAGERELEASE@/${PKGREL}/ -e s/@PACKAGE@/${PACKAGE}/ -e s/@REPOID@/${REPOID}/ $< >$@.tmp
	mv $@.tmp $@

%.bash-completion:
	perl -I. -T -e "use PMG::CLI::$*; PMG::CLI::$*->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

%.service-bash-completion:
	perl -I. -T -e "use PMG::Service::$*; PMG::Service::$*->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

install: ${BTDATA} $(addsuffix .pm, $(addprefix PMG/Service/, ${SERVICES})) $(addsuffix .service-bash-completion, ${SERVICES}) ${LIBSOURCES} ${CLI_BINARIES} $(addsuffix .bash-completion, ${CLITOOLS}) ${TEMPLATES_FILES} ${CONF_MANS} ${CLI_MANS}
	for i in ${SERVICES}; do perl -I. -T -e "use PMG::Service::$$i; PMG::Service::$$i->verify_api();"; done
	for i in ${CLITOOLS}; do perl -I. -T -e "use PMG::CLI::$$i; PMG::CLI::$$i->verify_api();"; done
	perl -I. bin/pmgsh verifyapi
	install -d -m 0755 ${DESTDIR}/usr/bin
	install -d -m 0700 -o www-data -g www-data ${DESTDIR}/var/log/pmgproxy
	install -d -m 0755 ${DOCDIR}
	# TODO: is there a better location ?
	install -m 0644 favicon.ico ${DOCDIR}
	for i in ${LIBSOURCES}; do install -D -m 0644 $$i ${PERL5DIR}/$$i; done
	for i in ${SERVICES}; do install -D -m 0644 PMG/Service/$$i.pm ${PERL5DIR}/PMG/Service/$$i.pm; done
	for i in ${SERVICES}; do install -m 0755 bin/$$i ${DESTDIR}/usr/bin; done
	for i in ${SERVICES}; do install -m 0644 -D $$i.service-bash-completion ${BASHCOMPLDIR}/$$i; done
	for i in ${CLITOOLS}; do install -D -m 0644 PMG/CLI/$$i.pm ${PERL5DIR}/PMG/CLI/$$i.pm; done
	for i in ${CLITOOLS}; do install -D -m 0755 bin/$$i ${DESTDIR}/usr/bin/$$i; done
	for i in ${CLITOOLS}; do install -D -m 0644 $$i.bash-completion ${BASHCOMPLDIR}/$$i; done
	for i in ${CLISCRIPTS}; do install -D -m 0755 bin/$$i ${DESTDIR}/usr/bin/$$i; done
	for i in ${TEMPLATES}; do install -D -m 0644 templates/$$i ${DESTDIR}/var/lib/pmg/templates/$$i; done
	for i in ${CLI_MANS}; do install -D -m 0644 $$i ${DESTDIR}/usr/share/man/man1/$$i; done
	for i in ${CONF_MANS}; do install -D -m 0644 $$i ${DESTDIR}/usr/share/man/man5/$$i; done


.PHONY: upload
upload: ${DEB}
	 ./repoid.pl .git/ check
	# fixme tar cf - ${DEB} | ssh repoman@repo.proxmox.com upload

.PHONY: check
check:
	make -C tests check

distclean: clean

clean:
	make cleanup-docgen
	make -C tests clean
	rm -rf ${CONF_MANS} ./build *.deb *.changes *.buildinfo *.bash-completion *.service-bash-completion
	if test -d .git; then  rm -f PMG/pmgcfg.pm; fi
	find . -name '*~' -exec rm {} ';'

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}
