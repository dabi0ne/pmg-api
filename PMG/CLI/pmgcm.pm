package PMG::CLI::pmgcm;

use strict;
use warnings;
use Data::Dumper;
use Term::ReadLine;
use JSON;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::CLIHandler;

use PMG::DBTools;
use PMG::Cluster;
use PMG::ClusterConfig;
use PMG::API2::Cluster;

use base qw(PVE::CLIHandler);

my $format_nodelist = sub {
    my $res = shift;

    if (!scalar(@$res)) {
	print "no cluster defined\n";
	return;
    }

    print "NAME(CID)--------------IPADDRESS----ROLE-STATE---------UPTIME---LOAD----MEM---DISK\n";
    foreach my $ni (@$res) {
	my $state = '?';

	printf "%-20s %-15s %-6s %1s %15s %6s %5s%% %5s%%\n",
	"$ni->{name}($ni->{cid})", $ni->{ip}, $ni->{type},
	$state, '-', '-', '-', '-';
    }
};

__PACKAGE__->register_method({
    name => 'join_cmd',
    path => 'join_cmd',
    method => 'GET',
    description => "Prints the command for joining an new node to the cluster. You need to execute the command on the new node.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $cfg = PVE::INotify::read_file('cluster.conf');

	if (scalar(keys %{$cfg->{ids}})) {

	    my $master = $cfg->{master} ||
		die "no master found\n";

	    print "pmgcm join $master->{ip} --fingerprint $master->{fingerprint}\n";

	} else {
	    die "no cluster defined\n";
	}

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'join',
    path => 'join',
    method => 'GET',
    description => "Join a new node to an existing cluster.",
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
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {
	    my $cfg = PVE::INotify::read_file('cluster.conf');

	    die "cluster alreayd defined\n" if scalar(keys %{$cfg->{ids}});

	    my $term = new Term::ReadLine ('pmgcm');
	    my $attribs = $term->Attribs;
	    $attribs->{redisplay_function} = $attribs->{shadow_redisplay};
	    my $password = $term->readline('Enter password: ');

	    my $setup = {
		username => 'root@pam',
		password => $password,
		cookie_name => 'PMGAuthCookie',
		host => $param->{master_ip},
	    };
	    if ($param->{fingerprint}) {
		$setup->{cached_fingerprints} = {
		    $param->{fingerprint} => 1,
		};
	    } else {
		# allow manual fingerprint verification
		$setup->{manual_verification} = 1;
	    }

	    PMG::API2::Cluster::cluster_join($setup);
	};

	PMG::ClusterConfig::lock_config($code, "cluster join failed");

	return undef;
    }});

our $cmddef = {
    nodes => [ 'PMG::API2::Cluster', 'nodes', [], {}, $format_nodelist],
    create => [ 'PMG::API2::Cluster', 'create', []],
    join => [ __PACKAGE__, 'join', ['master_ip']],
    join_cmd => [ __PACKAGE__, 'join_cmd', []],
};

1;
