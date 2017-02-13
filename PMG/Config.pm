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
    };
}

sub options {
    return {
	dailyreport => { optional => 1 },
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
	bounce_score => {
	    description => "Additional score for bounce mails.",
	    type => 'integer',
	    minimum => 0,
	    maximum => 1000,
	    default => 0,
	},
    };
}

sub options {
    return {
	bounce_score => { optional => 1 },
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
	
package PMG::Config;

use strict;
use warnings;

use Data::Dumper;

use PVE::Tools;
use PVE::INotify;

PMG::Config::Administration->register();
PMG::Config::Spam->register();
PMG::Config::LDAP->register();

# initialize all plugins
PMG::Config::Base->init();

#print Dumper(PMG::Config::Base->private());
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
