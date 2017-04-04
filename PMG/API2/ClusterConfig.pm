package PMG::API2::ClusterConfig;

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

	return PVE::RESTHandler::hash_to_array($cfg->{ids}, 'cid');
    }});

__PACKAGE__->register_method({
    name => 'create_master',
    path => '',
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


1;
