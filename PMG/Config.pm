package PMG::Config::Base;

use strict;
use warnings;
use URI;
use Data::Dumper;

use PVE::Tools;
use PVE::JSONSchema qw(get_standard_option);
use PVE::SectionConfig;

use base qw(PVE::SectionConfig);

my $defaultData = {
    propertyList => {
	type => { description => "Section type." },
	section => {
	    description => "Section ID.",
	    type => 'string', format => 'pve-configid',
	},
    },
};

sub private {
    return $defaultData;
}

sub format_section_header {
    my ($class, $type, $sectionId) = @_;

    die "internal error ($type ne $sectionId)" if $type ne $sectionId;

    return "section: $type\n";
}


sub parse_section_header {
    my ($class, $line) = @_;

    if ($line =~ m/^section:\s*(\S+)\s*$/) {
	my $section = $1;
	my $errmsg = undef; # set if you want to skip whole section
	eval { PVE::JSONSchema::pve_verify_configid($section); };
	$errmsg = $@ if $@;
	my $config = {}; # to return additional attributes
	return ($section, $section, $errmsg, $config);
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
	advfilter => {
	    description => "Use advanced filters for statistic.",
	    type => 'boolean',
	    default => 1,
	},
	dailyreport => {
	    description => "Send daily reports.",
	    type => 'boolean',
	    default => 1,
	},
	statlifetime => {
	    description => "User Statistics Lifetime (days)",
	    type => 'integer',
	    default => 7,
	    minimum => 1,
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
	http_proxy => {
	    description => "Specify external http proxy which is used for downloads (example: 'http://username:password\@host:port/')",
	    type => 'string',
	    pattern => "http://.*",
	},
	avast => {
	    description => "Use Avast Virus Scanner (/bin/scan). You need to buy and install 'Avast Core Security' before you can enable this feature.",
	    type => 'boolean',
	    default => 0,
	},
	clamav => {
	    description => "Use ClamAV Virus Scanner. This is the default virus scanner and is enabled by default.",
	    type => 'boolean',
	    default => 1,
	},
	custom_check => {
	    description => "Use Custom Check Script. The script has to take the defined arguments and can return Virus findings or a Spamscore.",
	    type => 'boolean',
	    default => 0,
	},
	custom_check_path => {
	    description => "Absolute Path to the Custom Check Script",
	    type => 'string', pattern => '^/([^/\0]+\/)+[^/\0]+$',
	    default => '/usr/local/bin/pmg-custom-check',
	},
    };
}

sub options {
    return {
	advfilter => { optional => 1 },
	avast => { optional => 1 },
	clamav => { optional => 1 },
	statlifetime => { optional => 1 },
	dailyreport => { optional => 1 },
	demo => { optional => 1 },
	email => { optional => 1 },
	http_proxy => { optional => 1 },
	custom_check => { optional => 1 },
	custom_check_path => { optional => 1 },
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
	wl_bounce_relays => {
	    description => "Whitelist legitimate bounce relays.",
	    type => 'string',
	},
	clamav_heuristic_score => {
	    description => "Score for ClamAV heuristics (Google Safe Browsing database, PhishingScanURLs, ...).",
	    type => 'integer',
	    minimum => 0,
	    maximum => 1000,
	    default => 3,
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
	    minimum => 64,
	    default => 256*1024,
	},
    };
}

sub options {
    return {
	use_awl => { optional => 1 },
	use_razor => { optional => 1 },
	wl_bounce_relays => { optional => 1 },
	languages => { optional => 1 },
	use_bayes => { optional => 1 },
	clamav_heuristic_score => { optional => 1 },
	bounce_score => { optional => 1 },
	rbl_checks => { optional => 1 },
	maxspamsize => { optional => 1 },
    };
}

package PMG::Config::SpamQuarantine;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'spamquar';
}

sub properties {
    return {
	lifetime => {
	    description => "Quarantine life time (days)",
	    type => 'integer',
	    minimum => 1,
	    default => 7,
	},
	authmode => {
	    description => "Authentication mode to access the quarantine interface. Mode 'ticket' allows login using tickets sent with the daily spam report. Mode 'ldap' requires to login using an LDAP account. Finally, mode 'ldapticket' allows both ways.",
	    type => 'string',
	    enum => [qw(ticket ldap ldapticket)],
	    default => 'ticket',
	},
	reportstyle => {
	    description => "Spam report style.",
	    type => 'string',
	    enum => [qw(none short verbose custom)],
	    default => 'verbose',
	},
	viewimages => {
	    description => "Allow to view images.",
	    type => 'boolean',
	    default => 1,
	},
	allowhrefs => {
	    description => "Allow to view hyperlinks.",
	    type => 'boolean',
	    default => 1,
	},
	hostname => {
	    description => "Quarantine Host. Useful if you run a Cluster and want users to connect to a specific host.",
	    type => 'string', format => 'address',
	},
	port => {
	    description => "Quarantine Port. Useful if you have a reverse proxy or port forwarding for the webinterface. Only used for the generated Spam report.",
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	    default => 8006,
	},
	protocol => {
	    description => "Quarantine Webinterface Protocol. Useful if you have a reverse proxy for the webinterface. Only used for the generated Spam report.",
	    type => 'string',
	    enum => [qw(http https)],
	    default => 'https',
	},
	mailfrom => {
	    description => "Text for 'From' header in daily spam report mails.",
	    type => 'string',
	},
    };
}

sub options {
    return {
	mailfrom => { optional => 1 },
	hostname => { optional => 1 },
	lifetime => { optional => 1 },
	authmode => { optional => 1 },
	reportstyle => { optional => 1 },
	viewimages => { optional => 1 },
	allowhrefs => { optional => 1 },
	port => { optional => 1 },
	protocol => { optional => 1 },
    };
}

package PMG::Config::VirusQuarantine;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'virusquar';
}

sub properties {
    return {};
}

sub options {
    return {
	lifetime => { optional => 1 },
	viewimages => { optional => 1 },
	allowhrefs => { optional => 1 },
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
	    description => "Whether to block encrypted archives. Mark encrypted archives as viruses.",
	    type => 'boolean',
	    default => 0,
	},
	archivemaxrec => {
	    description => "Nested archives are scanned recursively, e.g. if a ZIP archive contains a TAR  file,  all files within it will also be scanned. This options specifies how deeply the process should be continued. Warning: setting this limit too high may result in severe damage to the system.",
	    type => 'integer',
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
	safebrowsing => {
	    description => "Enables support for Google Safe Browsing.",
	    type => 'boolean',
	    default => 1
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
	safebrowsing => { optional => 1 },
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

sub get_max_policy {
    # estimate optimal number of proxpolicy servers
    my $max_servers = 2;
    my $memory = physical_memory();
    $max_servers = 5 if  $memory >= 500;
    return $max_servers;
}

sub properties {
    return {
	int_port => {
	    description => "SMTP port number for outgoing mail (trusted).",
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	    default => 26,
	},
	ext_port => {
	    description => "SMTP port number for incoming mail (untrusted). This must be a different number than 'int_port'.",
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	    default => 25,
	},
	relay => {
	    description => "The default mail delivery transport (incoming mails).",
	    type => 'string', format => 'address',
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
	    type => 'string', format => 'address',
	},
	smarthostport => {
	    description => "SMTP port number for smarthost.",
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	    default => 25,
	},
	banner => {
	    description => "ESMTP banner.",
	    type => 'string',
	    maxLength => 1024,
	    default => 'ESMTP Proxmox',
	},
	max_filters => {
	    description => "Maximum number of pmg-smtp-filter processes.",
	    type => 'integer',
	    minimum => 3,
	    maximum => 40,
	    default => get_max_filters(),
	},
	max_policy => {
	    description => "Maximum number of pmgpolicy processes.",
	    type => 'integer',
	    minimum => 2,
	    maximum => 10,
	    default => get_max_policy(),
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
	tls => {
	    description => "Enable TLS.",
	    type => 'boolean',
	    default => 0,
	},
	tlslog => {
	    description => "Enable TLS Logging.",
	    type => 'boolean',
	    default => 0,
	},
	tlsheader => {
	    description => "Add TLS received header.",
	    type => 'boolean',
	    default => 0,
	},
	spf => {
	    description => "Use Sender Policy Framework.",
	    type => 'boolean',
	    default => 1,
	},
	greylist => {
	    description => "Use Greylisting.",
	    type => 'boolean',
	    default => 1,
	},
	helotests => {
	    description => "Use SMTP HELO tests.",
	    type => 'boolean',
	    default => 0,
	},
	rejectunknown => {
	    description => "Reject unknown clients.",
	    type => 'boolean',
	    default => 0,
	},
	rejectunknownsender => {
	    description => "Reject unknown senders.",
	    type => 'boolean',
	    default => 0,
	},
	verifyreceivers => {
	    description => "Enable receiver verification. The value spefifies the numerical reply code when the Postfix SMTP server rejects a recipient address.",
	    type => 'string',
	    enum => ['450', '550'],
	},
	dnsbl_sites => {
	    description => "Optional list of DNS white/blacklist domains (see postscreen_dnsbl_sites parameter).",
	    type => 'string', format => 'dnsbl-entry-list',
	},
	dnsbl_threshold => {
	    description => "The inclusive lower bound for blocking a remote SMTP client, based on its combined DNSBL score (see postscreen_dnsbl_threshold parameter).",
	    type => 'integer',
	    minimum => 0,
	    default => 1
	},
    };
}

sub options {
    return {
	int_port => { optional => 1 },
	ext_port => { optional => 1 },
	smarthost => { optional => 1 },
	smarthostport => { optional => 1 },
	relay => { optional => 1 },
	relayport => { optional => 1 },
	relaynomx => { optional => 1 },
	dwarning => { optional => 1 },
	max_smtpd_in => { optional => 1 },
	max_smtpd_out => { optional => 1 },
	greylist => { optional => 1 },
	helotests => { optional => 1 },
	tls => { optional => 1 },
	tlslog => { optional => 1 },
	tlsheader => { optional => 1 },
	spf => { optional => 1 },
	maxsize => { optional => 1 },
	banner => { optional => 1 },
	max_filters => { optional => 1 },
	max_policy => { optional => 1 },
	hide_received => { optional => 1 },
	rejectunknown => { optional => 1 },
	rejectunknownsender => { optional => 1 },
	conn_count_limit => { optional => 1 },
	conn_rate_limit => { optional => 1 },
	message_rate_limit => { optional => 1 },
	verifyreceivers => { optional => 1 },
	dnsbl_sites => { optional => 1 },
	dnsbl_threshold => { optional => 1 },
    };
}

package PMG::Config;

use strict;
use warnings;
use IO::File;
use Data::Dumper;
use Template;

use PVE::SafeSyslog;
use PVE::Tools qw($IPV4RE $IPV6RE);
use PVE::INotify;
use PVE::JSONSchema;

use PMG::Cluster;

PMG::Config::Admin->register();
PMG::Config::Mail->register();
PMG::Config::SpamQuarantine->register();
PMG::Config::VirusQuarantine->register();
PMG::Config::Spam->register();
PMG::Config::ClamAV->register();

# initialize all plugins
PMG::Config::Base->init();

PVE::JSONSchema::register_format(
    'transport-domain', \&pmg_verify_transport_domain);

sub pmg_verify_transport_domain {
    my ($name, $noerr) = @_;

    # like dns-name, but can contain leading dot
    my $namere = "([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)";

    if ($name !~ /^\.?(${namere}\.)*${namere}$/) {
	   return undef if $noerr;
	   die "value does not look like a valid transport domain\n";
    }
    return $name;
}

PVE::JSONSchema::register_format(
    'transport-domain-or-email', \&pmg_verify_transport_domain_or_email);

sub pmg_verify_transport_domain_or_email {
    my ($name, $noerr) = @_;

    my $namere = "([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)";

    # email address
    if ($name =~ m/^(?:[^\s\/\@]+\@)(${namere}\.)*${namere}$/) {
	return $name;
    }

    # like dns-name, but can contain leading dot
    if ($name !~ /^\.?(${namere}\.)*${namere}$/) {
	   return undef if $noerr;
	   die "value does not look like a valid transport domain or email address\n";
    }
    return $name;
}

PVE::JSONSchema::register_format(
    'dnsbl-entry', \&pmg_verify_dnsbl_entry);

sub pmg_verify_dnsbl_entry {
    my ($name, $noerr) = @_;

    # like dns-name, but can contain trailing weight: 'domain*<WEIGHT>'
    my $namere = "([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)";

    if ($name !~ /^(${namere}\.)*${namere}(\*\-?\d+)?$/) {
	   return undef if $noerr;
	   die "value '$name' does not look like a valid dnsbl entry\n";
    }
    return $name;
}

sub new {
    my ($type) = @_;

    my $class = ref($type) || $type;

    my $cfg = PVE::INotify::read_file("pmg.conf");

    return bless $cfg, $class;
}

sub write {
    my ($self) = @_;

    PVE::INotify::write_file("pmg.conf", $self);
}

my $lockfile = "/var/lock/pmgconfig.lck";

sub lock_config {
    my ($code, $errmsg) = @_;

    my $p = PVE::Tools::lock_file($lockfile, undef, $code);
    if (my $err = $@) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
}

# set section values
sub set {
    my ($self, $section, $key, $value) = @_;

    my $pdata = PMG::Config::Base->private();

    my $plugin = $pdata->{plugins}->{$section};
    die "no such section '$section'" if !$plugin;

    if (defined($value)) {
	my $tmp = PMG::Config::Base->check_value($section, $key, $value, $section, 0);
	$self->{ids}->{$section} = { type => $section } if !defined($self->{ids}->{$section});
	$self->{ids}->{$section}->{$key} = PMG::Config::Base->decode_value($section, $key, $tmp);
    } else {
	if (defined($self->{ids}->{$section})) {
	    delete $self->{ids}->{$section}->{$key};
	}
    }

    return undef;
}

# get section value or default
sub get {
    my ($self, $section, $key, $nodefault) = @_;

    my $pdata = PMG::Config::Base->private();
    my $pdesc = $pdata->{propertyList}->{$key};
    die "no such property '$section/$key'\n"
	if !(defined($pdesc) && defined($pdata->{options}->{$section}) &&
	     defined($pdata->{options}->{$section}->{$key}));

    if (defined($self->{ids}->{$section}) &&
	defined(my $value = $self->{ids}->{$section}->{$key})) {
	return $value;
    }

    return undef if $nodefault;

    return $pdesc->{default};
}

# get a whole section with default value
sub get_section {
    my ($self, $section) = @_;

    my $pdata = PMG::Config::Base->private();
    return undef if !defined($pdata->{options}->{$section});

    my $res = {};

    foreach my $key (keys %{$pdata->{options}->{$section}}) {

	my $pdesc = $pdata->{propertyList}->{$key};

	if (defined($self->{ids}->{$section}) &&
	    defined(my $value = $self->{ids}->{$section}->{$key})) {
	    $res->{$key} = $value;
	    next;
	}
	$res->{$key} = $pdesc->{default};
    }

    return $res;
}

# get a whole config with default values
sub get_config {
    my ($self) = @_;

    my $pdata = PMG::Config::Base->private();

    my $res = {};

    foreach my $type (keys %{$pdata->{plugins}}) {
	my $plugin = $pdata->{plugins}->{$type};
	$res->{$type} = $self->get_section($type);
    }

    return $res;
}

sub read_pmg_conf {
    my ($filename, $fh) = @_;

    local $/ = undef; # slurp mode

    my $raw = <$fh> if defined($fh);

    return  PMG::Config::Base->parse_config($filename, $raw);
}

sub write_pmg_conf {
    my ($filename, $fh, $cfg) = @_;

    my $raw = PMG::Config::Base->write_config($filename, $cfg);

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file('pmg.conf', "/etc/pmg/pmg.conf",
			    \&read_pmg_conf,
			    \&write_pmg_conf,
			    undef, always_call_parser => 1);

# parsers/writers for other files

my $domainsfilename = "/etc/pmg/domains";

sub postmap_pmg_domains {
    PMG::Utils::run_postmap($domainsfilename);
}

sub read_pmg_domains {
    my ($filename, $fh) = @_;

    my $domains = {};

    my $comment = '';
    if (defined($fh)) {
	while (defined(my $line = <$fh>)) {
	    chomp $line;
	    next if $line =~ m/^\s*$/;
	    if ($line =~ m/^#(.*)\s*$/) {
		$comment = $1;
		next;
	    }
	    if ($line =~ m/^(\S+)\s.*$/) {
		my $domain = $1;
		$domains->{$domain} = {
		    domain => $domain, comment => $comment };
		$comment = '';
	    } else {
		warn "parse error in '$filename': $line\n";
		$comment = '';
	    }
	}
    }

    return $domains;
}

sub write_pmg_domains {
    my ($filename, $fh, $domains) = @_;

    foreach my $domain (sort keys %$domains) {
	my $comment = $domains->{$domain}->{comment};
	PVE::Tools::safe_print($filename, $fh, "#$comment\n")
	    if defined($comment) && $comment !~ m/^\s*$/;

	PVE::Tools::safe_print($filename, $fh, "$domain 1\n");
    }
}

PVE::INotify::register_file('domains', $domainsfilename,
			    \&read_pmg_domains,
			    \&write_pmg_domains,
			    undef, always_call_parser => 1);

my $mynetworks_filename = "/etc/pmg/mynetworks";

sub read_pmg_mynetworks {
    my ($filename, $fh) = @_;

    my $mynetworks = {};

    my $comment = '';
    if (defined($fh)) {
	while (defined(my $line = <$fh>)) {
	    chomp $line;
	    next if $line =~ m/^\s*$/;
	    if ($line =~ m!^((?:$IPV4RE|$IPV6RE))/(\d+)\s*(?:#(.*)\s*)?$!) {
		my ($network, $prefix_size, $comment) = ($1, $2, $3);
		my $cidr = "$network/${prefix_size}";
		$mynetworks->{$cidr} = {
		    cidr => $cidr,
		    network_address => $network,
		    prefix_size => $prefix_size,
		    comment => $comment // '',
		};
	    } else {
		warn "parse error in '$filename': $line\n";
	    }
	}
    }

    return $mynetworks;
}

sub write_pmg_mynetworks {
    my ($filename, $fh, $mynetworks) = @_;

    foreach my $cidr (sort keys %$mynetworks) {
	my $data = $mynetworks->{$cidr};
	my $comment = $data->{comment} // '*';
	PVE::Tools::safe_print($filename, $fh, "$cidr #$comment\n");
    }
}

PVE::INotify::register_file('mynetworks', $mynetworks_filename,
			    \&read_pmg_mynetworks,
			    \&write_pmg_mynetworks,
			    undef, always_call_parser => 1);

PVE::JSONSchema::register_format(
    'tls-policy', \&pmg_verify_tls_policy);

# TODO: extend to parse attributes of the policy
my $VALID_TLS_POLICY_RE = qr/none|may|encrypt|dane|dane-only|fingerprint|verify|secure/;
sub pmg_verify_tls_policy {
    my ($policy, $noerr) = @_;

    if ($policy !~ /^$VALID_TLS_POLICY_RE\b/) {
	   return undef if $noerr;
	   die "value '$policy' does not look like a valid tls policy\n";
    }
    return $policy;
}

PVE::JSONSchema::register_format(
    'tls-policy-strict', \&pmg_verify_tls_policy_strict);

sub pmg_verify_tls_policy_strict {
    my ($policy, $noerr) = @_;

    if ($policy !~ /^$VALID_TLS_POLICY_RE$/) {
	return undef if $noerr;
	die "value '$policy' does not look like a valid tls policy\n";
    }
    return $policy;
}

sub read_tls_policy {
    my ($filename, $fh) = @_;

    return {} if !defined($fh);

    my $tls_policy = {};

    while (defined(my $line = <$fh>)) {
	chomp $line;
	next if $line =~ m/^\s*$/;
	next if $line =~ m/^#(.*)\s*$/;

	my $parse_error = sub {
	    my ($err) = @_;
	    die "parse error in '$filename': $line - $err";
	};

	if ($line =~ m/^(\S+)\s+(.+)\s*$/) {
	    my ($domain, $policy) = ($1, $2);

	    eval {
		pmg_verify_transport_domain($domain);
		pmg_verify_tls_policy($policy);
	    };
	    if (my $err = $@) {
		$parse_error->($err);
		next;
	    }

	    $tls_policy->{$domain} = {
		    domain => $domain,
		    policy => $policy,
	    };
	} else {
	    $parse_error->('wrong format');
	}
    }

    return $tls_policy;
}

sub write_tls_policy {
    my ($filename, $fh, $tls_policy) = @_;

    return if !$tls_policy;

    foreach my $domain (sort keys %$tls_policy) {
	my $entry = $tls_policy->{$domain};
	PVE::Tools::safe_print(
	    $filename, $fh, "$entry->{domain} $entry->{policy}\n");
    }
}

my $tls_policy_map_filename = "/etc/pmg/tls_policy";
PVE::INotify::register_file('tls_policy', $tls_policy_map_filename,
			    \&read_tls_policy,
			    \&write_tls_policy,
			    undef, always_call_parser => 1);

sub postmap_tls_policy {
    PMG::Utils::run_postmap($tls_policy_map_filename);
}

my $transport_map_filename = "/etc/pmg/transport";

sub postmap_pmg_transport {
    PMG::Utils::run_postmap($transport_map_filename);
}

sub read_transport_map {
    my ($filename, $fh) = @_;

    return [] if !defined($fh);

    my $res = {};

    my $comment = '';

    while (defined(my $line = <$fh>)) {
	chomp $line;
	next if $line =~ m/^\s*$/;
	if ($line =~ m/^#(.*)\s*$/) {
	    $comment = $1;
	    next;
	}

	my $parse_error = sub {
	    my ($err) = @_;
	    warn "parse error in '$filename': $line - $err";
	    $comment = '';
	};

	if ($line =~ m/^(\S+)\s+smtp:(\S+):(\d+)\s*$/) {
	    my ($domain, $host, $port) = ($1, $2, $3);

	    eval { pmg_verify_transport_domain_or_email($domain); };
	    if (my $err = $@) {
		$parse_error->($err);
		next;
	    }
	    my $use_mx = 1;
	    if ($host =~ m/^\[(.*)\]$/) {
		$host = $1;
		$use_mx = 0;
	    }

	    eval { PVE::JSONSchema::pve_verify_address($host); };
	    if (my $err = $@) {
		$parse_error->($err);
		next;
	    }

	    my $data = {
		domain => $domain,
		host => $host,
		port => $port,
		use_mx => $use_mx,
		comment => $comment,
	    };
	    $res->{$domain} = $data;
	    $comment = '';
	} else {
	    $parse_error->('wrong format');
	}
    }

    return $res;
}

sub write_transport_map {
    my ($filename, $fh, $tmap) = @_;

    return if !$tmap;

    foreach my $domain (sort keys %$tmap) {
	my $data = $tmap->{$domain};

	my $comment = $data->{comment};
	PVE::Tools::safe_print($filename, $fh, "#$comment\n")
	    if defined($comment) && $comment !~ m/^\s*$/;

	my $use_mx = $data->{use_mx};
	$use_mx = 0 if $data->{host} =~ m/^(?:$IPV4RE|$IPV6RE)$/;

	if ($use_mx) {
	    PVE::Tools::safe_print(
		$filename, $fh, "$data->{domain} smtp:$data->{host}:$data->{port}\n");
	} else {
	    PVE::Tools::safe_print(
		$filename, $fh, "$data->{domain} smtp:[$data->{host}]:$data->{port}\n");
	}
    }
}

PVE::INotify::register_file('transport', $transport_map_filename,
			    \&read_transport_map,
			    \&write_transport_map,
			    undef, always_call_parser => 1);

# config file generation using templates

sub get_template_vars {
    my ($self) = @_;

    my $vars = { pmg => $self->get_config() };

    my $nodename = PVE::INotify::nodename();
    my $int_ip = PMG::Cluster::remote_node_ip($nodename);
    $vars->{ipconfig}->{int_ip} = $int_ip;

    my $transportnets = [];

    if (my $tmap = PVE::INotify::read_file('transport')) {
	foreach my $domain (sort keys %$tmap) {
	    my $data = $tmap->{$domain};
	    my $host = $data->{host};
	    if ($host =~ m/^$IPV4RE$/) {
		push @$transportnets, "$host/32";
	    } elsif ($host =~ m/^$IPV6RE$/) {
		push @$transportnets, "[$host]/128";
	    }
	}
    }

    $vars->{postfix}->{transportnets} = join(' ', @$transportnets);

    my $mynetworks = [ '127.0.0.0/8', '[::1]/128' ];

    if (my $int_net_cidr = PMG::Utils::find_local_network_for_ip($int_ip, 1)) {
	if ($int_net_cidr =~ m/^($IPV6RE)\/(\d+)$/) {
	    push @$mynetworks, "[$1]/$2";
	} else {
	    push @$mynetworks, $int_net_cidr;
	}
    } else {
	if ($int_ip =~ m/^$IPV6RE$/) {
	    push @$mynetworks, "[$int_ip]/128";
	} else {
	    push @$mynetworks, "$int_ip/32";
	}
    }

    my $netlist = PVE::INotify::read_file('mynetworks');
    foreach my $cidr (keys %$netlist) {
	if ($cidr =~ m/^($IPV6RE)\/(\d+)$/) {
	    push @$mynetworks, "[$1]/$2";
	} else {
	    push @$mynetworks, $cidr;
	}
    }

    push @$mynetworks, @$transportnets;

    # add default relay to mynetworks
    if (my $relay = $self->get('mail', 'relay')) {
	if ($relay =~ m/^$IPV4RE$/) {
	    push @$mynetworks, "$relay/32";
	} elsif ($relay =~ m/^$IPV6RE$/) {
	    push @$mynetworks, "[$relay]/128";
	} else {
	    # DNS name - do nothing ?
	}
    }

    $vars->{postfix}->{mynetworks} = join(' ', @$mynetworks);

    # normalize dnsbl_sites
    my @dnsbl_sites = PVE::Tools::split_list($vars->{pmg}->{mail}->{dnsbl_sites});
    if (scalar(@dnsbl_sites)) {
	$vars->{postfix}->{dnsbl_sites} = join(',', @dnsbl_sites);
    }

    $vars->{postfix}->{dnsbl_threshold} = $self->get('mail', 'dnsbl_threshold');

    my $usepolicy = 0;
    $usepolicy = 1 if $self->get('mail', 'greylist') ||
	$self->get('mail', 'spf');
    $vars->{postfix}->{usepolicy} = $usepolicy;

    if ($int_ip =~ m/^$IPV6RE$/) {
        $vars->{postfix}->{int_ip} = "[$int_ip]";
    } else {
        $vars->{postfix}->{int_ip} = $int_ip;
    }

    my $resolv = PVE::INotify::read_file('resolvconf');
    $vars->{dns}->{hostname} = $nodename;

    my $domain = $resolv->{search} // 'localdomain';
    $vars->{dns}->{domain} = $domain;

    my $wlbr = "$nodename.$domain";
    foreach my $r (PVE::Tools::split_list($vars->{pmg}->{spam}->{wl_bounce_relays})) {
	$wlbr .= " $r"
    }
    $vars->{composed}->{wl_bounce_relays} = $wlbr;

    if (my $proxy = $vars->{pmg}->{admin}->{http_proxy}) {
	eval {
	    my $uri = URI->new($proxy);
	    my $host = $uri->host;
	    my $port = $uri->port // 8080;
	    if ($host) {
		my $data = { host => $host, port => $port };
		if (my $ui = $uri->userinfo) {
		    my ($username, $pw) = split(/:/, $ui, 2);
		    $data->{username} = $username;
		    $data->{password} = $pw if defined($pw);
		}
		$vars->{proxy} = $data;
	    }
	};
	warn "parse http_proxy failed - $@" if $@;
    }

    return $vars;
}

# use one global TT cache
our $tt_include_path = ['/etc/pmg/templates' ,'/var/lib/pmg/templates' ];

my $template_toolkit;

sub get_template_toolkit {

    return $template_toolkit if $template_toolkit;

    $template_toolkit = Template->new({ INCLUDE_PATH => $tt_include_path });

    return $template_toolkit;
}

# rewrite file from template
# return true if file has changed
sub rewrite_config_file {
    my ($self, $tmplname, $dstfn) = @_;

    my $demo = $self->get('admin', 'demo');

    if ($demo) {
	my $demosrc = "$tmplname.demo";
	$tmplname = $demosrc if -f "/var/lib/pmg/templates/$demosrc";
    }

    my ($perm, $uid, $gid);

    if ($dstfn eq '/etc/clamav/freshclam.conf') {
	# needed if file contains a HTTPProxyPasswort

	$uid = getpwnam('clamav');
	$gid = getgrnam('adm');
	$perm = 0600;
    }

    my $tt = get_template_toolkit();

    my $vars = $self->get_template_vars();

    my $output = '';

    $tt->process($tmplname, $vars, \$output) ||
	die $tt->error() . "\n";

    my $old = PVE::Tools::file_get_contents($dstfn, 128*1024) if -f $dstfn;

    return 0 if defined($old) && ($old eq $output); # no change

    PVE::Tools::file_set_contents($dstfn, $output, $perm);

    if (defined($uid) && defined($gid)) {
	chown($uid, $gid, $dstfn);
    }

    return 1;
}

# rewrite spam configuration
sub rewrite_config_spam {
    my ($self) = @_;

    my $use_awl = $self->get('spam', 'use_awl');
    my $use_bayes = $self->get('spam', 'use_bayes');
    my $use_razor = $self->get('spam', 'use_razor');

    my $changes = 0;

    # delete AW and bayes databases if those features are disabled
    if (!$use_awl) {
	$changes = 1 if unlink '/root/.spamassassin/auto-whitelist';
    }

    if (!$use_bayes) {
	$changes = 1 if unlink '/root/.spamassassin/bayes_journal';
	$changes = 1 if unlink '/root/.spamassassin/bayes_seen';
	$changes = 1 if unlink '/root/.spamassassin/bayes_toks';
    }

    # make sure we have a custom.cf file (else cluster sync fails)
    IO::File->new('/etc/mail/spamassassin/custom.cf', 'a', 0644);

    $changes = 1 if $self->rewrite_config_file(
	'local.cf.in', '/etc/mail/spamassassin/local.cf');

    $changes = 1 if $self->rewrite_config_file(
	'init.pre.in', '/etc/mail/spamassassin/init.pre');

    $changes = 1 if $self->rewrite_config_file(
	'v310.pre.in', '/etc/mail/spamassassin/v310.pre');

    $changes = 1 if $self->rewrite_config_file(
	'v320.pre.in', '/etc/mail/spamassassin/v320.pre');

    if ($use_razor) {
	mkdir "/root/.razor";

	$changes = 1 if $self->rewrite_config_file(
	    'razor-agent.conf.in', '/root/.razor/razor-agent.conf');

	if (! -e '/root/.razor/identity') {
	    eval {
		my $timeout = 30;
		PVE::Tools::run_command(['razor-admin', '-discover'], timeout => $timeout);
		PVE::Tools::run_command(['razor-admin', '-register'], timeout => $timeout);
	    };
	    my $err = $@;
	    syslog('info', "registering razor failed: $err") if $err;
	}
    }

    return $changes;
}

# rewrite ClamAV configuration
sub rewrite_config_clam {
    my ($self) = @_;

    return $self->rewrite_config_file(
	'clamd.conf.in', '/etc/clamav/clamd.conf');
}

sub rewrite_config_freshclam {
    my ($self) = @_;

    return $self->rewrite_config_file(
	'freshclam.conf.in', '/etc/clamav/freshclam.conf');
}

sub rewrite_config_postgres {
    my ($self) = @_;

    my $pgconfdir = "/etc/postgresql/9.6/main";

    my $changes = 0;

    $changes = 1 if $self->rewrite_config_file(
	'pg_hba.conf.in', "$pgconfdir/pg_hba.conf");

    $changes = 1 if $self->rewrite_config_file(
	'postgresql.conf.in', "$pgconfdir/postgresql.conf");

    return $changes;
}

# rewrite /root/.forward
sub rewrite_dot_forward {
    my ($self) = @_;

    my $dstfn = '/root/.forward';

    my $email = $self->get('admin', 'email');

    my $output = '';
    if ($email && $email =~ m/\s*(\S+)\s*/) {
	$output = "$1\n";
    } else {
	# empty .forward does not forward mails (see man local)
    }

    my $old = PVE::Tools::file_get_contents($dstfn, 128*1024) if -f $dstfn;

    return 0 if defined($old) && ($old eq $output); # no change

    PVE::Tools::file_set_contents($dstfn, $output);

    return 1;
}

my $write_smtp_whitelist = sub {
    my ($filename, $data, $action) = @_;

    $action = 'OK' if !$action;

    my $old = PVE::Tools::file_get_contents($filename, 1024*1024)
	if -f $filename;

    my $new = '';
    foreach my $k (sort keys %$data) {
	$new .= "$k $action\n";
    }

    return 0 if defined($old) && ($old eq $new); # no change

    PVE::Tools::file_set_contents($filename, $new);

    PMG::Utils::run_postmap($filename);

    return 1;
};

sub rewrite_postfix_whitelist {
    my ($rulecache) = @_;

    # see man page for regexp_table for postfix regex table format

    # we use a hash to avoid duplicate entries in regex tables
    my $tolist = {};
    my $fromlist = {};
    my $clientlist = {};

    foreach my $obj (@{$rulecache->{"greylist:receiver"}}) {
	my $oclass = ref($obj);
	if ($oclass eq 'PMG::RuleDB::Receiver') {
	    my $addr = PMG::Utils::quote_regex($obj->{address});
	    $tolist->{"/^$addr\$/"} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::ReceiverDomain') {
	    my $addr = PMG::Utils::quote_regex($obj->{address});
	    $tolist->{"/^.+\@$addr\$/"} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::ReceiverRegex') {
	    my $addr = $obj->{address};
	    $addr =~ s|/|\\/|g;
	    $tolist->{"/^$addr\$/"} = 1;
	}
    }

    foreach my $obj (@{$rulecache->{"greylist:sender"}}) {
	my $oclass = ref($obj);
	my $addr = PMG::Utils::quote_regex($obj->{address});
	if ($oclass eq 'PMG::RuleDB::EMail') {
	    my $addr = PMG::Utils::quote_regex($obj->{address});
	    $fromlist->{"/^$addr\$/"} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::Domain') {
	    my $addr = PMG::Utils::quote_regex($obj->{address});
	    $fromlist->{"/^.+\@$addr\$/"} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::WhoRegex') {
	    my $addr = $obj->{address};
	    $addr =~ s|/|\\/|g;
	    $fromlist->{"/^$addr\$/"} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::IPAddress') {
	    $clientlist->{$obj->{address}} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::IPNet') {
	    $clientlist->{$obj->{address}} = 1;
	}
    }

    $write_smtp_whitelist->("/etc/postfix/senderaccess", $fromlist);
    $write_smtp_whitelist->("/etc/postfix/rcptaccess", $tolist);
    $write_smtp_whitelist->("/etc/postfix/clientaccess", $clientlist);
    $write_smtp_whitelist->("/etc/postfix/postscreen_access", $clientlist, 'permit');
};

# rewrite /etc/postfix/*
sub rewrite_config_postfix {
    my ($self, $rulecache) = @_;

    # make sure we have required files (else postfix start fails)
    IO::File->new($transport_map_filename, 'a', 0644);

    my $changes = 0;

    if ($self->get('mail', 'tls')) {
	eval {
	    PMG::Utils::gen_proxmox_tls_cert();
	};
	syslog ('info', "generating certificate failed: $@") if $@;
    }

    $changes = 1 if $self->rewrite_config_file(
	'main.cf.in', '/etc/postfix/main.cf');

    $changes = 1 if $self->rewrite_config_file(
	'master.cf.in', '/etc/postfix/master.cf');

    # make sure we have required files (else postfix start fails)
    # Note: postmap need a valid /etc/postfix/main.cf configuration
    postmap_pmg_domains();
    postmap_pmg_transport();
    postmap_tls_policy();

    rewrite_postfix_whitelist($rulecache) if $rulecache;

    # make sure aliases.db is up to date
    system('/usr/bin/newaliases');

    return $changes;
}

sub rewrite_config {
    my ($self, $rulecache, $restart_services, $force_restart) = @_;

    $force_restart = {} if ! $force_restart;

    if (($self->rewrite_config_postfix($rulecache) && $restart_services) ||
	$force_restart->{postfix}) {
	PMG::Utils::service_cmd('postfix', 'restart');
    }

    if ($self->rewrite_dot_forward() && $restart_services) {
	# no need to restart anything
    }

    if ($self->rewrite_config_postgres() && $restart_services) {
	# do nothing (too many side effects)?
	# does not happen anyways, because config does not change.
    }

    if (($self->rewrite_config_spam() && $restart_services) ||
	$force_restart->{spam}) {
	PMG::Utils::service_cmd('pmg-smtp-filter', 'restart');
    }

    if (($self->rewrite_config_clam() && $restart_services) ||
	$force_restart->{clam}) {
	PMG::Utils::service_cmd('clamav-daemon', 'restart');
    }

    if (($self->rewrite_config_freshclam() && $restart_services) ||
	$force_restart->{freshclam}) {
	PMG::Utils::service_cmd('clamav-freshclam', 'restart');
    }
}

1;
