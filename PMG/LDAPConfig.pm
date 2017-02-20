package PMG::LDAPConfig;

use strict;
use warnings;
use MIME::Base64;
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
	server1 => {
	    description => "Server address.",
	    type => 'string', format => 'address',
	},
	server2 => {
	    description => "Fallback server address. Userd when the first server is not available.",
	    type => 'string', format => 'address',
	},
	port => {
	    description => "Specify the port to connect to.",
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	},
	binddn => {
	    description => "Bind domain name.",
	    type => 'string',
	},
	bindpw => {
	    description => "Bind password.",
	    type => 'string',
	},
	basedn => {
	    description => "Base domain name.",
	    type => 'string',
	},
	groupbasedn => {
	    description => "Base domain name for groups.",
	    type => 'string',
	},
	filter => {
	    description => "LDAP filter.",
	    type => 'string',
	},
	accountattr => {
	    description => "Account attribute name name.",
	    type => 'string',
	    pattern => '[a-zA-Z0-9]+',
	    default => 'sAMAccountName',
	},
	mailattr => {
	    description => "List of mail attribute names.",
	    type => 'string-list',
	    pattern => '[a-zA-Z0-9]+',
	    default => "mail, userPrincipalName, proxyAddresses, othermailbox",
	},
    },
};

sub options {
    return {
	server1 => {  optional => 0 },
	server2 => {  optional => 1 },
	port => { optional => 1 },
	mode => { optional => 1 },
	binddn => { optional => 1 },
	bindpw => { optional => 1 },
	basedn => { optional => 1 },
	groupbasedn => { optional => 1 },
	filter => { optional => 1 },
	accountattr => { optional => 1 },
	mailattr => { optional => 1 },
    };
}

sub type {
    return 'ldap';
}

sub private {
    return $defaultData;
}

sub decode_value {
    my ($class, $type, $key, $value) = @_;

    $value = decode_base64($value) if $key eq 'bindpw';

    return $value;
}

sub encode_value {
    my ($class, $type, $key, $value) = @_;

    $value = encode_base64($value, '') if $key eq 'bindpw';

    return $value;
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

    chmod(0600, $fh);

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file('pmg-ldap.conf', "/etc/proxmox/ldap.conf",
			    \&read_pmg_ldap_conf,
			    \&write_pmg_ldap_conf);


1;
