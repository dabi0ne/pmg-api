package PMG::API2::Cluster;

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

use PMG::ClusterConfig;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => { user => 'all' },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $result = [
	    { name => 'nodes' },
	    { name => 'create' },
	    { name => 'join' },
        ];

	return $result;
    }});

__PACKAGE__->register_method({
    name => 'nodes',
    path => 'nodes',
    method => 'GET',
    description => "Cluster node index.",
    # alway read local file
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    permissions => { check => [ 'admin' ] },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		cid => { type => 'integer' },
	    },
	},
	links => [ { rel => 'child', href => "{cid}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $cfg = PVE::INotify::read_file('cluster.conf');

	if (scalar(keys %{$cfg->{ids}})) {
	    my $role = $cfg->{local}->{type} // '-';
	    if ($role eq '-') {
		die "local node '$cfg->{local}->{name}' not part of cluster\n";
	    }
	}

	return PVE::RESTHandler::hash_to_array($cfg->{ids}, 'cid');
    }});

__PACKAGE__->register_method({
    name => 'create',
    path => 'create',
    method => 'POST',
    description => "Create initial cluster config with current node as master.",
    # alway read local file
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {
	    my $cfg = PMG::ClusterConfig->new();

	    die "cluster alreayd defined\n" if scalar(keys %{$cfg->{ids}});

	    my $info = PMG::Cluster::read_local_cluster_info();

	    $info->{type} = 'master';
	    $info->{maxcid} = 1,

	    $cfg->{ids}->{$info->{maxcid}} = $info;

	    $cfg->write();
	};

	PMG::ClusterConfig::lock_config($code, "create cluster failed");

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'join',
    path => 'join',
    method => 'POST',
    description => "Join local node to an existing cluster.",
    # alway read local file
    parameters => {
	additionalProperties => 0,
	properties => {
	    master_ip => {
		description => "IP address.",
		type => 'string', format => 'ip',
	    },
	    fingerprint => {
		description => "SSL certificate fingerprint.",
		type => 'string',
		pattern => '^(:?[A-Z0-9][A-Z0-9]:){31}[A-Z0-9][A-Z0-9]$',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {
	    my $cfg = PMG::ClusterConfig->new();

	    die "cluster alreayd defined\n" if scalar(keys %{$cfg->{ids}});

	    die "implement me";
	};

	PMG::ClusterConfig::lock_config($code, "cluster join failed");

	return undef;
    }});


1;
