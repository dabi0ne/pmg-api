package PMG::API2::LDAP;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use HTTP::Status qw(:constants);
use Storable qw(dclone);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::LDAPConfig;
use PMG::LDAPCache;
use PMG::LDAPSet;

use base qw(PVE::RESTHandler);

my $ldapconfigfile = "pmg-ldap.conf";

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "List configured LDAP profiles.",
    proxyto => 'master',
    protected => 1,
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		profile => { type => 'string'},
		disable => { type => 'boolean' },
		server1 => { type => 'string'},
		server2 => { type => 'string', optional => 1},
		comment => { type => 'string', optional => 1},
		gcount => { type => 'integer', optional => 1},
		mcount => { type => 'integer', optional => 1},
		ucount => { type => 'integer', optional => 1},
		mode => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{profile}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $ldap_cfg = PVE::INotify::read_file($ldapconfigfile);

	my $ldap_set = PMG::LDAPSet->new_from_ldap_cfg($ldap_cfg, 1);

	my $res = [];

	if (defined($ldap_cfg)) {
	    foreach my $profile (keys %{$ldap_cfg->{ids}}) {
		my $d = $ldap_cfg->{ids}->{$profile};
		my $entry = {
		    profile => $profile,
		    disable => $d->{disable} ? 1 : 0,
		    server1 => $d->{server1},
		    mode => $d->{mode} // 'ldap',
		};
		$entry->{server2} = $d->{server2} if defined($d->{server2});
		$entry->{comment} = $d->{comment} if defined($d->{comment});

		if (my $d = $ldap_set->{$profile}) {
		    foreach my $k (qw(gcount mcount ucount)) {
			my $v = $d->{$k};
			$entry->{$k} = $v if defined($v);
		    }
		}

		push @$res, $entry;
	    }
	}

	return $res;
    }});

my $forced_ldap_sync = sub {
    my ($profile, $config) = @_;

    my $ldapcache = PMG::LDAPCache->new(
	id => $profile, syncmode => 2, %$config);

    die $ldapcache->{errors} if $ldapcache->{errors};

    die "unable to find valid email addresses\n"
	if !$ldapcache->{mcount};
};

__PACKAGE__->register_method ({
    name => 'create',
    path => '',
    method => 'POST',
    proxyto => 'master',
    protected => 1,
    description => "Add LDAP profile.",
    parameters => PMG::LDAPConfig->createSchema(1),
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PVE::INotify::read_file($ldapconfigfile);

	    $cfg->{ids} //= {};

	    my $ids = $cfg->{ids};

	    my $profile = extract_param($param, 'profile');
	    my $type = $param->{type};

	    die "LDAP profile '$profile' already exists\n"
		if $ids->{$profile};

	    my $config = PMG::LDAPConfig->check_config($profile, $param, 1, 1);

	    $ids->{$profile} = $config;

	    $forced_ldap_sync->($profile, $config)
		if !$config->{disable};

	    PVE::INotify::write_file($ldapconfigfile, $cfg);
	};

	PMG::LDAPConfig::lock_config($code, "add LDAP profile failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'profile_index',
    path => '{profile}',
    method => 'GET',
    description => "Directory index",
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	return [
	    { subdir => 'config' },
	    { subdir => 'sync' },
	];
    }});

__PACKAGE__->register_method ({
    name => 'read_config',
    path => '{profile}/config',
    method => 'GET',
    description => "Get LDAP profile configuration.",
    proxyto => 'master',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => {},
    code => sub {
	my ($param) = @_;

	my $cfg = PVE::INotify::read_file($ldapconfigfile);

	my $profile = $param->{profile};

	my $data = $cfg->{ids}->{$profile};
	die "LDAP profile '$profile' does not exist\n" if !$data;

	$data->{digest} = $cfg->{digest};

	return $data;
    }});

__PACKAGE__->register_method ({
    name => 'update_config',
    path => '{profile}/config',
    method => 'PUT',
    description => "Update LDAP profile settings.",
    protected => 1,
    proxyto => 'master',
    parameters => PMG::LDAPConfig->updateSchema(),
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PVE::INotify::read_file($ldapconfigfile);
	    my $ids = $cfg->{ids};

	    my $digest = extract_param($param, 'digest');
	    PVE::SectionConfig::assert_if_modified($cfg, $digest);

	    my $profile = extract_param($param, 'profile');

	    die "LDAP profile '$profile' does not exist\n"
		if !$ids->{$profile};

	    my $delete_str = extract_param($param, 'delete');
	    die "no options specified\n"
		if !$delete_str && !scalar(keys %$param);

	    foreach my $opt (PVE::Tools::split_list($delete_str)) {
		delete $ids->{$profile}->{$opt};
	    }

	    my $config = PMG::LDAPConfig->check_config($profile, $param, 0, 1);

	    foreach my $p (keys %$config) {
		$ids->{$profile}->{$p} = $config->{$p};
	    }

	    $forced_ldap_sync->($profile, $config)
		if !$config->{disable};

	    PVE::INotify::write_file($ldapconfigfile, $cfg);
	};

	PMG::LDAPConfig::lock_config($code, "update LDAP profile failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'sync_profile',
    path => '{profile}/sync',
    method => 'POST',
    description => "Synchronice LDAP users to local database.",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $cfg = PVE::INotify::read_file($ldapconfigfile);
	my $ids = $cfg->{ids};

	my $profile = extract_param($param, 'profile');

	die "LDAP profile '$profile' does not exist\n"
	    if !$ids->{$profile};

	my $config = $ids->{$profile};

	if ($config->{disable}) {
	    die "LDAP profile '$profile' is disabled\n";
	} else {
	    $forced_ldap_sync->($profile, $config)
	}

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{profile}',
    method => 'DELETE',
    description => "Delete an LDAP profile",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PVE::INotify::read_file($ldapconfigfile);
	    my $ids = $cfg->{ids};

	    my $profile = $param->{profile};

	    die "LDAP profile '$profile' does not exist\n"
		if !$ids->{$profile};

	    delete $ids->{$profile};

	    PMG::LDAPCache->delete($profile);

	    PVE::INotify::write_file($ldapconfigfile, $cfg);
	};

	PMG::LDAPConfig::lock_config($code, "delete LDAP profile failed");

	return undef;
    }});

1;
