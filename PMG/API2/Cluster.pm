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
use PVE::APIClient::LWP;

use PMG::ClusterConfig;
use PMG::Cluster;

use base qw(PVE::RESTHandler);

sub cluster_join {
    my ($cfg, $conn_setup) = @_;

    my $conn = PVE::APIClient::LWP->new(%$conn_setup);

    my $info = PMG::Cluster::read_local_cluster_info();

    my $res = $conn->post("/config/cluster/nodes", $info);

    foreach my $node (@$res) {
	$cfg->{ids}->{$node->{cid}} = $node;
    }

    $cfg->write();
}

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

my $add_node_schema = PMG::ClusterConfig::Node->createSchema(1);
delete  $add_node_schema->{properties}->{cid};

__PACKAGE__->register_method({
    name => 'add_node',
    path => 'nodes',
    method => 'POST',
    description => "Add an node to the cluster config.",
    proxyto => 'master',
    protected => 1,
    parameters => $add_node_schema,
    returns => {
	description => "Returns the resulting node list.",
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		cid => { type => 'integer' },
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $code = sub {
	    my $cfg = PMG::ClusterConfig->new();

	    die "no cluster defined\n" if !scalar(keys %{$cfg->{ids}});

	    my $master = $cfg->{master} || die "unable to lookup master node\n";

	    my $next_cid;
	    foreach my $cid (keys %{$cfg->{ids}}) {
		my $d = $cfg->{ids}->{$cid};

		if ($d->{type} eq 'node' && $d->{ip} eq $param->{ip} && $d->{name} eq $param->{name}) {
		    $next_cid = $cid; # allow overwrite existing node data
		    last;
		}

		if ($d->{ip} eq $param->{ip}) {
		    die "ip address '$param->{ip}' is already used by existing node $d->{name}\n";
		}

		if ($d->{name} eq $param->{name}) {
		    die "node with name '$param->{name}' already exists\n";
		}
	    }

	    if (!defined($next_cid)) {
		$next_cid = ++$master->{maxcid};
	    }

	    my $node = {
		type => 'node',
		cid => $master->{maxcid},
	    };

	    foreach my $k (qw(ip name hostrsapubkey rootrsapubkey fingerprint)) {
		$node->{$k} = $param->{$k};
	    }

	    $cfg->{ids}->{$node->{cid}} = $node;

	    $cfg->write();

	    return PVE::RESTHandler::hash_to_array($cfg->{ids}, 'cid');
	};

	return PMG::ClusterConfig::lock_config($code, "add node failed");
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
	    password => {
		description => "Superuser password.",
		type => 'string',
		maxLength => 128,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {
	    my $cfg = PMG::ClusterConfig->new();

	    die "cluster alreayd defined\n" if scalar(keys %{$cfg->{ids}});

	    my $setup = {
		username => 'root@pam',
		password => $param->{password},
		cookie_name => 'PMGAuthCookie',
		host => $param->{master_ip},
		cached_fingerprints => {
		    $param->{fingerprint} => 1,
		}
	    };

	    cluster_join($cfg, $setup);
	};

	PMG::ClusterConfig::lock_config($code, "cluster join failed");

	return undef;
    }});


1;
