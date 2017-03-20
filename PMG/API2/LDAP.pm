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

use base qw(PVE::RESTHandler);

my $ldapconfigfile = "pmg-ldap.conf";

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "LDAP server list.",
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
		section => { type => 'string'},
		disable => { type => 'boolean' },
		server1 => { type => 'string'},
		server2 => { type => 'string', optional => 1},
		comment => { type => 'string', optional => 1},
		mode => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{section}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $ldap_cfg = PVE::INotify::read_file($ldapconfigfile);

	my $res = [];

	if (defined($ldap_cfg)) {
	    foreach my $section (keys %{$ldap_cfg->{ids}}) {
		my $d = $ldap_cfg->{ids}->{$section};
		my $entry = {
		    section => $section,
		    disable => $d->{disable} ? 1 : 0,
		    server1 => $d->{server1},
		    mode => $d->{mode} // 'ldap',
		};
		$entry->{server2} = $d->{server2} if defined($d->{server2});
		$entry->{comment} = $d->{comment} if defined($d->{comment});
		push @$res, $entry;
	    }
	}

	return $res;
    }});


__PACKAGE__->register_method ({
    name => 'create',
    path => '',
    method => 'POST',
    proxyto => 'master',
    protected => 1,
    description => "Add LDAP server.",
    parameters => PMG::LDAPConfig->createSchema(1),
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PVE::INotify::read_file($ldapconfigfile);

	    $cfg->{ids} //= {};

	    my $ids = $cfg->{ids};

	    my $section = extract_param($param, 'section');
	    my $type = $param->{type};

	    die "LDAP entry '$section' already exists\n"
		if $ids->{$section};

	    my $config = PMG::LDAPConfig->check_config($section, $param, 1, 1);

	    $ids->{$section} = $config;

	    if (!$config->{disable}) {

		# test ldap bind

		my $ldapcache = PMG::LDAPCache->new(
		    id => $section, syncmode => 1, %$config);

		$ldapcache->ldap_connect_and_bind();
	    }

	    PVE::INotify::write_file($ldapconfigfile, $cfg);
	};

	PMG::LDAPConfig::lock_config($code, "add LDAP entry failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'read',
    path => '{section}',
    method => 'GET',
    description => "Get LDAP server configuration.",
    proxyto => 'master',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    section => {
		description => "Secion ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => {},
    code => sub {
	my ($param) = @_;

	my $cfg = PVE::INotify::read_file($ldapconfigfile);

	my $section = $param->{section};

	my $data = $cfg->{ids}->{$section};
	die "LDAP entry '$section' does not exist\n" if !$data;

	$data->{digest} = $cfg->{digest};

	return $data;
    }});

__PACKAGE__->register_method ({
    name => 'update',
    path => '{section}',
    method => 'PUT',
    description => "Update LDAP server settings.",
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

	    my $section = extract_param($param, 'section');

	    die "LDAP entry '$section' does not exist\n"
		if !$ids->{$section};

	    my $delete_str = extract_param($param, 'delete');
	    die "no options specified\n"
		if !$delete_str && !scalar(keys %$param);

	    foreach my $opt (PVE::Tools::split_list($delete_str)) {
		delete $ids->{$section}->{$opt};
	    }

	    my $config = PMG::LDAPConfig->check_config($section, $param, 0, 1);

	    foreach my $p (keys %$config) {
		$ids->{$section}->{$p} = $config->{$p};
	    }

	    if (!$config->{disable}) {

		# test ldap bind

		my $ldapcache = PMG::LDAPCache->new(
		    id => $section, syncmode => 1, %$config);

		$ldapcache->ldap_connect_and_bind();
	    }

	    PVE::INotify::write_file($ldapconfigfile, $cfg);
	};

	PMG::LDAPConfig::lock_config($code, "update LDAP entry failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{section}',
    method => 'DELETE',
    description => "Delete an LDAP server entry.",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    section => {
		description => "Secion ID.",
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

	    my $section = $param->{section};

	    die "LDAP entry '$section' does not exist\n"
		if !$ids->{$section};

	    delete $ids->{$section};

	    PVE::INotify::write_file($ldapconfigfile, $cfg);
	};

	PMG::LDAPConfig::lock_config($code, "delete LDAP entry failed");

	return undef;
    }});

1;
