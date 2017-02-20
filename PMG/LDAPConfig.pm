package PMG::LDAPConfig;

use strict;
use warnings;
use Data::Dumper;

use PVE::Tools;
use PVE::JSONSchema qw(get_standard_option);
use PVE::INotify;
use PVE::SectionConfig;

use base qw(PVE::SectionConfig);

my $defaultData = {
    propertyList => {
	type => { description => "Section type." },
	section => {
	    description => "Secion ID.",
	    type => 'string', format => 'pve-configid',
	},
	mode => {
	    description => "LDAP protocol mode ('ldap' or 'ldaps').",
	    type => 'string',
	    enum => ['ldap', 'ldaps'],
	    default => 'ldap',
	},
    },
};

sub options {
    return {
	mode => { optional => 1 },
    };
}

sub type {
    return 'ldap';
}

sub private {
    return $defaultData;
}

sub format_section_header {
    my ($class, $type, $sectionId) = @_;

    return "$type: $sectionId\n";
}


sub parse_section_header {
    my ($class, $line) = @_;

    if ($line =~ m/^(ldaps?):\s*(\S+)\s*$/) {
	my $mode = $1,
	my $section_id = $2;
	my $errmsg = undef; # set if you want to skip whole section
	eval { PVE::JSONSchema::pve_verify_configid($section_id); };
	$errmsg = $@ if $@;
	my $config = { mode => $mode}; # to return additional attributes
	return ('ldap', $section_id, $errmsg, $config);
    }
    return undef;
}

__PACKAGE__->register();
__PACKAGE__->init();

sub read_pmg_ldap_conf {
    my ($filename, $fh) = @_;

    local $/ = undef; # slurp mode

    my $raw = <$fh>;

    return __PACKAGE__->parse_config($filename, $raw);
}

sub write_pmg_ldap_conf {
    my ($filename, $fh, $cfg) = @_;

    my $raw = __PACKAGE__->write_config($filename, $cfg);

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file('pmg-ldap.conf', "/etc/proxmox/ldap.conf",
			    \&read_pmg_ldap_conf,
			    \&write_pmg_ldap_conf);


1;
