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

package PMG::Config::Administration;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'administration';
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
	}
    };
}

sub options {
    return {
	dailyreport => { optional => 1 },
	demo => { optional => 1 },
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
	archivemaxfiles => {
	    description => "Number of files to be scanned within an archive.",
	    type => 'integer',
	    minimum => 0,
	    default => 1000,
	},
    };
}

sub options {
    return {
	archivemaxfiles => { optional => 1 },
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
	    degault => 0,
	},
    };
}

sub options {
    return {
	banner => { optional => 1 },
	max_filters => { optional => 1 },
	hide_received => { optional => 1 },
    };
}
package PMG::Config;

use strict;
use warnings;

use Data::Dumper;

use PVE::Tools;
use PVE::INotify;

PMG::Config::Administration->register();
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


1;
