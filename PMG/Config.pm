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
	section_id => {
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

sub properties {
    return {
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
	hide_received => {
	    description => "Hide received header in outgoing mails.",
	    type => 'boolean',
	    default => 0,
	},
	max_size => {
	    description => "Maximum email size. Larger mails are rejected.",
	    type => 'integer',
	    minimum => 1024,
	    default => 1024*1024*10,
	},
    };
}

sub options {
    return {
	max_size => { optional => 1 },
	banner => { optional => 1 },
	max_filters => { optional => 1 },
	hide_received => { optional => 1 },
    };
}
package PMG::Config;

use strict;
use warnings;
use IO::File;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools;
use PVE::INotify;

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

    my $res = {};

    foreach my $key (keys %{$self->{ids}}) {
	if ($key =~ m/^section_(\S+)$/) {
	    my $section = $1;
	    $res->{$section} = $self->get_section($section);
	}
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

    PMG::Utils::rewrite_config_file($self, 'local.cf.in', '/etc/mail/spamassassin/local.cf');
    PMG::Utils::rewrite_config_file($self, 'init.pre.in', '/etc/mail/spamassassin/init.pre');
    PMG::Utils::rewrite_config_file($self, 'v310.pre.in', '/etc/mail/spamassassin/v310.pre');
    PMG::Utils::rewrite_config_file($self, 'v320.pre.in', '/etc/mail/spamassassin/v320.pre');

    if ($use_razor) {
	mkdir "/root/.razor";
	PMG::Utils::rewrite_config_file(
	    $self, 'razor-agent.conf.in', '/root/.razor/razor-agent.conf');
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

    PMG::Utils::rewrite_config_file($self, 'clamd.conf.in', '/etc/clamav/clamd.conf');
    PMG::Utils::rewrite_config_file($self, 'freshclam.conf.in', '/etc/clamav/freshclam.conf');
}

1;
