package PMG::Config::Base;

use strict;
use warnings;
use Data::Dumper;

use PVE::Tools;
use PVE::JSONSchema qw(get_standard_option);
use PVE::SectionConfig;

use base qw(PVE::SectionConfig);

my $defaultData = {
    propertyList => {
	type => { description => "Section type." },
	section => {
	    description => "Secion ID.",
	    type => 'string', format => 'pve-configid',
	},
    },
};

sub private {
    return $defaultData;
}

sub format_section_header {
    my ($class, $type, $sectionId) = @_;

    if ($type eq 'ldap') {
	$sectionId =~ s/^ldap_//;
	return "$type: $sectionId\n";
    } else {
	return "section: $type\n";
    }
}


sub parse_section_header {
    my ($class, $line) = @_;

    if ($line =~ m/^(ldap|section):\s*(\S+)\s*$/) {
	my ($raw_type, $raw_id) = (lc($1), $2);
	my $type = $raw_type eq 'section' ? $raw_id : $raw_type;
	my $section_id =  "${raw_type}_${raw_id}";
	my $errmsg = undef; # set if you want to skip whole section
	eval { PVE::JSONSchema::pve_verify_configid($raw_id); };
	$errmsg = $@ if $@;
	my $config = {}; # to return additional attributes
	return ($type, $section_id, $errmsg, $config);
    }
    return undef;
}

package PMG::Config::Admin;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'admin';
}

sub properties {
    return {
	dailyreport => {
	    description => "Send daily reports.",
	    type => 'boolean',
	    default => 1,
	},
	demo => {
	    description => "Demo mode - do not start SMTP filter.",
	    type => 'boolean',
	    default => 0,
	},
	email => {
	    description => "Administrator E-Mail address.",
	    type => 'string', format => 'email',
	    default => 'admin@domain.tld',
	},
	proxyport => {
	    description => "HTTP proxy port.",
	    type => 'integer',
	    minimum => 1,
	    default => 8080,
	},
	proxyserver => {
	    description => "HTTP proxy server address.",
	    type => 'string',
	},
	proxyuser => {
	    description => "HTTP proxy user name.",
	    type => 'string',
	},
	proxypassword => {
	    description => "HTTP proxy password.",
	    type => 'string',
	},
    };
}

sub options {
    return {
	dailyreport => { optional => 1 },
	demo => { optional => 1 },
	proxyport => { optional => 1 },
	proxyserver => { optional => 1 },
	proxyuser => { optional => 1 },
	proxypassword => { optional => 1 },
    };
}

package PMG::Config::Spam;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'spam';
}

sub properties {
    return {
	languages => {
	    description => "This option is used to specify which languages are considered OK for incoming mail.",
	    type => 'string',
	    pattern => '(all|([a-z][a-z])+( ([a-z][a-z])+)*)',
	    default => 'all',
	},
	use_bayes => {
	    description => "Whether to use the naive-Bayesian-style classifier.",
	    type => 'boolean',
	    default => 1,
	},
	use_awl => {
	    description => "Use the Auto-Whitelist plugin.",
	    type => 'boolean',
	    default => 1,
	},
	use_razor => {
	    description => "Whether to use Razor2, if it is available.",
	    type => 'boolean',
	    default => 1,
	},
	use_ocr => {
	    description => "Enable OCR to scan pictures.",
	    type => 'boolean',
	    default => 0,
	},
	wl_bounce_relays => {
	    description => "Whitelist legitimate bounce relays.",
	    type => 'string',
	},
	bounce_score => {
	    description => "Additional score for bounce mails.",
	    type => 'integer',
	    minimum => 0,
	    maximum => 1000,
	    default => 0,
	},
	rbl_checks => {
	    description => "Enable real time blacklists (RBL) checks.",
	    type => 'boolean',
	    default => 1,
	},
	maxspamsize => {
	    description => "Maximum size of spam messages in bytes.",
	    type => 'integer',
	    minimim => 64,
	    default => 200*1024,
	},
    };
}

sub options {
    return {
	use_awl => { optional => 1 },
	use_razor => { optional => 1 },
	use_ocr => { optional => 1 },
	wl_bounce_relays => { optional => 1 },
	languages => { optional => 1 },
	use_bayes => { optional => 1 },
	bounce_score => { optional => 1 },
	rbl_checks => { optional => 1 },
	maxspamsize => { optional => 1 },
    };
}

package PMG::Config::ClamAV;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'clamav';
}

sub properties {
    return {
	dbmirror => {
	    description => "ClamAV database mirror server.",
	    type => 'string',
	    default => 'database.clamav.net',
	},
	archiveblockencrypted => {
	    description => "Wether to block encrypted archives. Mark encrypted archives as viruses.",
	    type => 'boolean',
	    default => 0,
	},
	archivemaxrec => {
	    description => "Nested archives are scanned recursively, e.g. if a ZIP archive contains a TAR  file,  all files within it will also be scanned. This options specifies how deeply the process should be continued. Warning: setting this limit too high may result in severe damage to the system.",
	    minimum => 1,
	    default => 5,
	},
	archivemaxfiles => {
	    description => "Number of files to be scanned within an archive, a document, or any other kind of container. Warning: disabling this limit or setting it too high may result in severe damage to the system.",
	    type => 'integer',
	    minimum => 0,
	    default => 1000,
	},
	archivemaxsize => {
	    description => "Files larger than this limit won't be scanned.",
	    type => 'integer',
	    minimum => 1000000,
	    default => 25000000,
	},
	maxscansize => {
	    description => "Sets the maximum amount of data to be scanned for each input file.",
	    type => 'integer',
	    minimum => 1000000,
	    default => 100000000,
	},
	maxcccount => {
	    description => "This option sets the lowest number of Credit Card or Social Security numbers found in a file to generate a detect.",
	    type => 'integer',
	    minimum => 0,
	    default => 0,
	},
    };
}

sub options {
    return {
	archiveblockencrypted => { optional => 1 },
	archivemaxrec => { optional => 1 },
	archivemaxfiles => { optional => 1 },
	archivemaxsize => { optional => 1 },
	maxscansize  => { optional => 1 },
	dbmirror => { optional => 1 },
	maxcccount => { optional => 1 },
    };
}

package PMG::Config::LDAP;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'ldap';
}

sub properties {
    return {
	mode => {
	    description => "LDAP protocol mode ('ldap' or 'ldaps').",
	    type => 'string',
	    enum => ['ldap', 'ldaps'],
	    default => 'ldap',
	},
    };
}

sub options {
    return {
	mode => { optional => 1 },
    };
}

package PMG::Config::Mail;

use strict;
use warnings;

use PVE::ProcFSTools;

use base qw(PMG::Config::Base);

sub type {
    return 'mail';
}

my $physicalmem = 0;
sub physical_memory {

    return $physicalmem if $physicalmem;

    my $info = PVE::ProcFSTools::read_meminfo();
    my $total = int($info->{memtotal} / (1024*1024));

    return $total;
}

sub get_max_filters {
    # estimate optimal number of filter servers

    my $max_servers = 5;
    my $servermem = 120;
    my $memory = physical_memory();
    my $add_servers = int(($memory - 512)/$servermem);
    $max_servers += $add_servers if $add_servers > 0;
    $max_servers = 40 if  $max_servers > 40;

    return $max_servers - 2;
}

sub get_max_smtpd {
    # estimate optimal number of smtpd daemons

    my $max_servers = 25;
    my $servermem = 20;
    my $memory = physical_memory();
    my $add_servers = int(($memory - 512)/$servermem);
    $max_servers += $add_servers if $add_servers > 0;
    $max_servers = 100 if  $max_servers > 100;
    return $max_servers;
}


sub properties {
    return {
	relay => {
	    description => "The default mail delivery transport (incoming mails).",
	    type => 'string',
	},
	relayport => {
	    description => "SMTP port number for relay host.",
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	    default => 25,
	},
	relaynomx => {
	    description => "Disable MX lookups for default relay.",
	    type => 'boolean',
	    default => 0,
	},
	smarthost => {
	    description => "When set, all outgoing mails are deliverd to the specified smarthost.",
	    type => 'string',
	},
	banner => {
	    description => "ESMTP banner.",
	    type => 'string',
	    maxLength => 1024,
	    default => 'ESMTP Proxmox',
	},
	max_filters => {
	    description => "Maximum number of filter processes.",
	    type => 'integer',
	    minimum => 3,
	    maximum => 40,
	    default => get_max_filters(),
	},
	max_smtpd_in => {
	    description => "Maximum number of SMTP daemon processes (in).",
	    type => 'integer',
	    minimum => 3,
	    maximum => 100,
	    default => get_max_smtpd(),
	},
	max_smtpd_out => {
	    description => "Maximum number of SMTP daemon processes (out).",
	    type => 'integer',
	    minimum => 3,
	    maximum => 100,
	    default => get_max_smtpd(),
	},
	conn_count_limit => {
	    description => "How many simultaneous connections any client is allowed to make to this service. To disable this feature, specify a limit of 0.",
	    type => 'integer',
	    minimum => 0,
	    default => 50,
	},
	conn_rate_limit => {
	    description => "The maximal number of connection attempts any client is allowed to make to this service per minute. To disable this feature, specify a limit of 0.",
	    type => 'integer',
	    minimum => 0,
	    default => 0,
	},
	message_rate_limit => {
	    description => "The maximal number of message delivery requests that any client is allowed to make to this service per minute.To disable this feature, specify a limit of 0.",
	    type => 'integer',
	    minimum => 0,
	    default => 0,
	},
	hide_received => {
	    description => "Hide received header in outgoing mails.",
	    type => 'boolean',
	    default => 0,
	},
	maxsize => {
	    description => "Maximum email size. Larger mails are rejected.",
	    type => 'integer',
	    minimum => 1024,
	    default => 1024*1024*10,
	},
	dwarning => {
	    description => "SMTP delay warning time (in hours).",
	    type => 'integer',
	    minimum => 0,
	    default => 4,
	},
	use_rbl => {
	    descriptions => "Use Realtime Blacklists.",
	    type => 'boolean',
	    default => 1,
	},
	tls => {
	    descriptions => "Use TLS.",
	    type => 'boolean',
	    default => 0,
	},
	spf => {
	    descriptions => "Use Sender Policy Framework.",
	    type => 'boolean',
	    default => 1,
	},
	greylist => {
	    descriptions => "Use Greylisting.",
	    type => 'boolean',
	    default => 1,
	},
	helotests => {
	    descriptions => "Use SMTP HELO tests.",
	    type => 'boolean',
	    default => 0,
	},
	rejectunknown => {
	    descriptions => "Reject unknown clients.",
	    type => 'boolean',
	    default => 0,
	},
	rejectunknownsender => {
	    descriptions => "Reject unknown senders.",
	    type => 'boolean',
	    default => 0,
	},
	verifyreceivers => {
	    description => "Enable receiver verification. The value (if greater than 0) spefifies the numerical reply code when the Postfix SMTP server rejects a recipient address (450 or 550).",
	    type => 'integer',
	    minimum => 0,
	    maximum => 599,
	    default => 0,
	},
	dnsbl_sites => {
	    description => "Optional list of DNS white/blacklist domains (see postscreen_dnsbl_sites parameter).",
	    type => 'string',
	},
    };
}

sub options {
    return {
	relay => { optional => 1 },
	relayport => { optional => 1 },
	relaynomx => { optional => 1 },
	dwarning => { optional => 1 },
	max_smtpd_in => { optional => 1 },
	max_smtpd_out => { optional => 1 },
	greylist => { optional => 1 },
	helotests => { optional => 1 },
	use_rbl => { optional => 1 },
	tls => { optional => 1 },
	spf => { optional => 1 },
	maxsize => { optional => 1 },
	banner => { optional => 1 },
	max_filters => { optional => 1 },
	hide_received => { optional => 1 },
	rejectunknown => { optional => 1 },
	rejectunknownsender => { optional => 1 },
	conn_count_limit => { optional => 1 },
	conn_rate_limit => { optional => 1 },
	message_rate_limit => { optional => 1 },
	verifyreceivers => { optional => 1 },
	dnsbl_sites => { optional => 1 },
    };
}
package PMG::Config;

use strict;
use warnings;
use IO::File;
use Data::Dumper;
use Template;

use PVE::SafeSyslog;
use PVE::Tools;
use PVE::INotify;

use PMG::AtomicFile;

PMG::Config::Admin->register();
PMG::Config::Mail->register();
PMG::Config::Spam->register();
PMG::Config::LDAP->register();
PMG::Config::ClamAV->register();

# initialize all plugins
PMG::Config::Base->init();


sub new {
    my ($type) = @_;

    my $class = ref($type) || $type;

    my $cfg = PVE::INotify::read_file("pmg.conf");

    return bless $cfg, $class;
}

# set section values
# this does not work for ldap entries
sub set {
    my ($self, $section, $key, $value) = @_;

    my $pdata = PMG::Config::Base->private();

    die "internal error" if $section eq 'ldap';

    my $plugin = $pdata->{plugins}->{$section};
    die "no such section '$section'" if !$plugin;

    my $configid = "section_$section";
    if (defined($value)) {
	my $tmp = PMG::Config::Base->check_value($section, $key, $value, $section, 0);
	print Dumper($self->{ids});
	$self->{ids}->{$configid} = { type => $section } if !defined($self->{ids}->{$configid});
	$self->{ids}->{$configid}->{$key} = PMG::Config::Base->decode_value($section, $key, $tmp);
    } else {
	if (defined($self->{ids}->{$configid})) {
	    delete $self->{ids}->{$configid}->{$key};
	}
    }

    return undef;
}

# get section value or default
# this does not work for ldap entries
sub get {
    my ($self, $section, $key) = @_;

    my $pdata = PMG::Config::Base->private();
    return undef if !defined($pdata->{options}->{$section});
    return undef if !defined($pdata->{options}->{$section}->{$key});
    my $pdesc = $pdata->{propertyList}->{$key};
    return undef if !defined($pdesc);

    my $configid = "section_$section";
    if (defined($self->{ids}->{$configid}) &&
	defined(my $value = $self->{ids}->{$configid}->{$key})) {
	return $value;
    }

    return $pdesc->{default};
}

# get a whole section with default value
# this does not work for ldap entries
sub get_section {
    my ($self, $section) = @_;

    my $pdata = PMG::Config::Base->private();
    return undef if !defined($pdata->{options}->{$section});

    my $res = {};

    foreach my $key (keys %{$pdata->{options}->{$section}}) {

	my $pdesc = $pdata->{propertyList}->{$key};

	my $configid = "section_$section";
	if (defined($self->{ids}->{$configid}) &&
	    defined(my $value = $self->{ids}->{$configid}->{$key})) {
	    $res->{$key} = $value;
	    next;
	}
	$res->{$key} = $pdesc->{default};
    }

    return $res;
}

# get a whole config with default values
# this does not work for ldap entries
sub get_config {
    my ($self) = @_;

    my $pdata = PMG::Config::Base->private();

    my $res = {};

    foreach my $type (keys %{$pdata->{plugins}}) {
	next if $type eq 'ldap';
	my $plugin = $pdata->{plugins}->{$type};
	$res->{$type} = $self->get_section($type);
    }

    return $res;
}

sub read_pmg_conf {
    my ($filename, $fh) = @_;

    local $/ = undef; # slurp mode

    my $raw = <$fh>;

    return  PMG::Config::Base->parse_config($filename, $raw);
}

sub write_pmg_conf {
    my ($filename, $fh, $cfg) = @_;

    my $raw = PMG::Config::Base->write_config($filename, $cfg);

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file('pmg.conf', "/etc/proxmox/pmg.conf",
			    \&read_pmg_conf,
			    \&write_pmg_conf);

# parsers/writers for other files

my $domainsfilename = "/etc/proxmox/domains";

sub read_pmg_domains {
    my ($filename, $fh) = @_;

    my $domains = [];

    if (defined($fh)) {
	while (defined(my $line = <$fh>)) {
	    if ($line =~ m/^\s*(\S+)\s*$/) {
		my $domain = $1;
		push @$domains, $domain;
	    }
	}
    }

    return $domains;
}

sub write_pmg_domains {
    my ($filename, $fh, $domain) = @_;

    foreach my $domain (sort @$domain) {
	PVE::Tools::safe_print($filename, $fh, "$domain\n");
    }
}

PVE::INotify::register_file('domains', $domainsfilename,
			    \&read_pmg_domains,
			    \&write_pmg_domains,
			    undef, always_call_parser => 1);

my $transport_map_filename = "/etc/postfix/transport";

sub read_transport_map {
    my ($filename, $fh) = @_;

    return [] if !defined($fh);

    my $res = {};

    while (defined(my $line = <$fh>)) {
	chomp $line;
	next if $line =~ m/^\s*$/;
	next if $line =~ m/^\s*\#/;

	if ($line =~ m/^(\S+)\s+smtp:([^\s:]+):(\d+)\s*$/) {
	    my $domain = $1;
	    my $host = $2;
	    my $port =$3;
	    my $nomx;

	    if ($host =~ m/^\[(.*)\]$/) {
		$host = $1;
		$nomx = 1;
	    }

	    my $key = "$host:$port";

	    $res->{$key}->{nomx} = $nomx;
	    $res->{$key}->{host} = $host;
	    $res->{$key}->{port} = $port;
	    $res->{$key}->{transport} = $key;

	    push @{$res->{$key}->{domains}}, $domain;
	}
    }

    my $ta = [];

    foreach my $t (sort keys %$res) {
	push @$ta, $res->{$t};
    }

    return $ta;
}

sub write_ransport_map {
    my ($filename, $fh, $tmap) = @_;

    return if !$tmap;

    foreach my $t (sort { $a->{transport} cmp $b->{transport} } @$tmap) {
	my $domains = $t->{domains};

	foreach my $d (sort @$domains) {
	    if ($t->{nomx}) {
		PVE::Tools::safe_print($filename, $fh, "$d smtp:[$t->{host}]:$t->{port}\n");
	    } else {
		PVE::Tools::safe_print($filename, $fh, "$d smtp:$t->{host}:$t->{port}\n");
	    }
	}
    }
}

PVE::INotify::register_file('transport', $transport_map_filename,
			    \&read_transport_map,
			    \&write_ransport_map,
			    undef, always_call_parser => 1);

# config file generation using templates

sub rewrite_config_file {
    my ($self, $tmplname, $dstfn) = @_;

    my $demo = $self->get('admin', 'demo');

    my $srcfn = ($tmplname =~ m|^.?/|) ?
	$tmplname : "/var/lib/pmg/templates/$tmplname";

    if ($demo) {
	my $demosrc = "$srcfn.demo";
	$srcfn = $demosrc if -f $demosrc;
    }

    my $srcfd = IO::File->new ($srcfn, "r")
	|| die "cant read template '$srcfn' - $!: ERROR";
    my $dstfd = PMG::AtomicFile->open ($dstfn, "w")
	|| die "cant open config file '$dstfn' - $!: ERROR";

    if ($dstfn eq '/etc/fetchmailrc') {
	my ($login, $pass, $uid, $gid) = getpwnam('fetchmail');
	if ($uid && $gid) {
	    chown($uid, $gid, ${*$dstfd}{'io_atomicfile_temp'});
	}
	chmod (0600, ${*$dstfd}{'io_atomicfile_temp'});
    } elsif ($dstfn eq '/etc/clamav/freshclam.conf') {
	# needed if file contains a HTTPProxyPasswort

	my $uid = getpwnam('clamav');
	my $gid = getgrnam('adm');

	if ($uid && $gid) {
	    chown ($uid, $gid, ${*$dstfd}{'io_atomicfile_temp'});
	}
	chmod (0600, ${*$dstfd}{'io_atomicfile_temp'});
    }

    my $template = Template->new({});

    my $vars = { pmg => $self->get_config() };

    my $nodename = PVE::INotify::nodename();
    my $int_ip = PMG::Cluster::remote_node_ip($nodename);
    my $int_net_cidr = PMG::Utils::find_local_network_for_ip($int_ip);

    $vars->{ipconfig}->{int_ip} = $int_ip;
    # $vars->{ipconfig}->{int_net_cidr} = $int_net_cidr;
    $vars->{ipconfig}->{int_port} = 26;
    $vars->{ipconfig}->{ext_port} = 25;

    my $transportnets = []; # fixme
    $vars->{postfix}->{transportnets} = join(' ', @$transportnets);

    my $mynetworks = [ '127.0.0.0/8', '[::1]/128' ];
    push @$mynetworks, @$transportnets;
    push @$mynetworks, $int_net_cidr;

    # add default relay to mynetworks
    if (my $relay = $self->get('mail', 'relay')) {
	if (Net::IP::ip_is_ipv4($relay)) {
	    push @$mynetworks, "$relay/32";
	} elsif (Net::IP::ip_is_ipv6($relay)) {
	    push @$mynetworks, "[$relay]/128";
	} else {
	    warn "unable to detect IP version of relay '$relay'";
	}
    }

    $vars->{postfix}->{mynetworks} = join(' ', @$mynetworks);

    my $usepolicy = 0;
    $usepolicy = 1 if $self->get('mail', 'greylist') ||
	$self->get('mail', 'spf') ||  $self->get('mail', 'use_rbl');
    $vars->{postfix}->{usepolicy} = $usepolicy;

    my $resolv = PVE::INotify::read_file('resolvconf');
    $vars->{dns}->{hostname} = $nodename;
    $vars->{dns}->{domain} = $resolv->{search};

    $template->process($srcfd, $vars, $dstfd) ||
	die $template->error();

    $srcfd->close();
    $dstfd->close (1);
}

sub rewrite_config_script {
    my ($self, $tmplname, $dstfn) = @_;

    $self->rewrite_config_file($tmplname, $dstfn);
    system("chmod +x $dstfn");
}

# rewrite spam configuration
sub rewrite_config_spam {
    my ($self) = @_;

    my $use_awl = $self->get('spam', 'use_awl');
    my $use_bayes = $self->get('spam', 'use_bayes');
    my $use_razor = $self->get('spam', 'use_razor');

    # delete AW and bayes databases if those features are disabled
    unlink '/root/.spamassassin/auto-whitelist' if !$use_awl;
    if (!$use_bayes) {
	unlink '/root/.spamassassin/bayes_journal';
	unlink '/root/.spamassassin/bayes_seen';
	unlink '/root/.spamassassin/bayes_toks';
    }

    # make sure we have a custom.cf file (else cluster sync fails)
    IO::File->new('/etc/mail/spamassassin/custom.cf', 'a', 0644);

    $self->rewrite_config_file('local.cf.in', '/etc/mail/spamassassin/local.cf');
    $self->rewrite_config_file('init.pre.in', '/etc/mail/spamassassin/init.pre');
    $self->rewrite_config_file('v310.pre.in', '/etc/mail/spamassassin/v310.pre');
    $self->rewrite_config_file('v320.pre.in', '/etc/mail/spamassassin/v320.pre');

    if ($use_razor) {
	mkdir "/root/.razor";
	$self->rewrite_config_file('razor-agent.conf.in', '/root/.razor/razor-agent.conf');
	if (! -e '/root/.razor/identity') {
	    eval {
		my $timeout = 30;
		PVE::Tools::run_command (['razor-admin', '-discover'], timeout => $timeout);
		PVE::Tools::run_command (['razor-admin', '-register'], timeout => $timeout);
	    };
	    my $err = $@;
	    syslog('info', msgquote ("registering razor failed: $err")) if $err;
	}
    }
}

# rewrite ClamAV configuration
sub rewrite_config_clam {
    my ($self) = @_;

    $self->rewrite_config_file('clamd.conf.in', '/etc/clamav/clamd.conf');
    $self->rewrite_config_file('freshclam.conf.in', '/etc/clamav/freshclam.conf');
}

sub rewrite_config_postgres {
    my ($self) = @_;

    my $pgconfdir = "/etc/postgresql/9.6/main";

    $self->rewrite_config_file('pg_hba.conf.in', "$pgconfdir/pg_hba.conf");
    $self->rewrite_config_file('postgresql.conf.in', "$pgconfdir/postgresql.conf");
}

# rewrite /root/.forward
sub rewrite_dot_forward {
    my ($self) = @_;

    my $fname = '/root/.forward';

    my $email = $self->get('administration', 'email');
    open(TMP, ">$fname");
    if ($email && $email =~ m/\s*(\S+)\s*/) {
	print (TMP "$1\n");
    } else {
	# empty .forward does not forward mails (see man local)
    }
    close (TMP);
}

# rewrite /etc/postfix/*
sub rewrite_config_postfix {
    my ($self) = @_;

    # make sure we have required files (else postfix start fails)
    IO::File->new($domainsfilename, 'a', 0644);
    IO::File->new($transport_map_filename, 'a', 0644);

    if ($self->get('mail', 'tls')) {
	eval {
	    my $resolv = PVE::INotify::read_file('resolvconf');
	    my $domain = $resolv->{search};

	    my $company = $domain; # what else ?
	    my $cn = "*.$domain";
	    PMG::Utils::gen_proxmox_tls_cert(0, $company, $cn);
	};
	syslog ('info', msgquote ("generating certificate failed: $@")) if $@;
    }

    $self->rewrite_config_file('main.cf.in', '/etc/postfix/main.cf');
    $self->rewrite_config_file('master.cf.in', '/etc/postfix/master.cf');
    #rewrite_config_transports ($class);
    #rewrite_config_whitelist ($class);
    #rewrite_config_tls_policy ($class);

    # make sure aliases.db is up to date
    system('/usr/bin/newaliases');
}

sub rewrite_config {
    my ($self) = @_;

    $self->rewrite_config_postfix(); 
    $self->rewrite_dot_forward();
    $self->rewrite_config_postgres();
    $self->rewrite_config_spam();
    $self->rewrite_config_clam();
    
}

1;
