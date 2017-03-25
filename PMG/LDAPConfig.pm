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

my $inotify_file_id = 'pmg-ldap.conf';
my $config_filename = '/etc/pmg/ldap.conf';

my $defaultData = {
    propertyList => {
	type => { description => "Section type." },
	profile => {
	    description => "Profile ID.",
	    type => 'string', format => 'pve-configid',
	},
    },
};

sub properties {
    return {
	disable => {
	    description => "Flag to disable/deactivate the entry.",
	    type => 'boolean',
	    optional => 1,
	},
	comment => {
	    description => "Description.",
	    type => 'string',
	    optional => 1,
	    maxLength => 4096,
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
	    maxLength => 256,
	},
	server2 => {
	    description => "Fallback server address. Userd when the first server is not available.",
	    type => 'string', format => 'address',
	    maxLength => 256,
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
	    type => 'string', format => 'string-list',
	    pattern => '[a-zA-Z0-9]+',
	    default => "mail, userPrincipalName, proxyAddresses, othermailbox",
	},
    };
}

sub options {
    return {
	disable => { optional => 1 },
	comment => { optional => 1 },
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

sub parse_section_header {
    my ($class, $line) = @_;

    if ($line =~ m/^(\S+):\s*(\S+)\s*$/) {
	my ($type, $profileId) = ($1, $2);
	my $errmsg = undef; # set if you want to skip whole section
	eval { PVE::JSONSchema::pve_verify_configid($profileId); };
	$errmsg = $@ if $@;
	my $config = {}; # to return additional attributes
	return ($type, $profileId, $errmsg, $config);
    }
    return undef;
}

sub parse_config {
    my ($class, $filename, $raw) = @_;

    my $cfg = $class->SUPER::parse_config($filename, $raw);

    foreach my $profile (keys %{$cfg->{ids}}) {
	my $data = $cfg->{ids}->{$profile};

	$data->{comment} = PVE::Tools::decode_text($data->{comment})
	    if defined($data->{comment});

	$data->{bindpw} = decode_base64($data->{bindpw})
	    if defined($data->{bindpw});
    }

    return $cfg;
}

sub write_config {
    my ($class, $filename, $cfg) = @_;

    foreach my $profile (keys %{$cfg->{ids}}) {
	my $data = $cfg->{ids}->{$profile};

	$data->{comment} = PVE::Tools::encode_text($data->{comment})
	    if defined($data->{comment});

	$data->{bindpw} = encode_base64($data->{bindpw}, '')
	    if defined($data->{bindpw});
    }

    $class->SUPER::write_config($filename, $cfg);
}

sub new {
    my ($type) = @_;

    my $class = ref($type) || $type;

    my $cfg = PVE::INotify::read_file($inotify_file_id);

    return bless $cfg, $class;
}

sub write {
    my ($self) = @_;

    PVE::INotify::write_file($inotify_file_id, $self);
}

my $lockfile = "/var/lock/pmgldapconfig.lck";

sub lock_config {
    my ($code, $errmsg) = @_;

    my $p = PVE::Tools::lock_file($lockfile, undef, $code);
    if (my $err = $@) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
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

PVE::INotify::register_file($inotify_file_id, $config_filename,
			    \&read_pmg_ldap_conf,
			    \&write_pmg_ldap_conf);


1;
