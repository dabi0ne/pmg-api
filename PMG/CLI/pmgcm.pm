package PMG::CLI::pmgcm;

use strict;
use warnings;
use Data::Dumper;
use Term::ReadLine;
use POSIX qw(strftime);
use JSON;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::CLIHandler;

use PMG::Ticket;
use PMG::RESTEnvironment;
use PMG::DBTools;
use PMG::Cluster;
use PMG::ClusterConfig;
use PMG::API2::Cluster;

use base qw(PVE::CLIHandler);

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();

    my $rpcenv = PMG::RESTEnvironment->get();
    # API /config/cluster/nodes need a ticket to connect to other nodes
    my $ticket = PMG::Ticket::assemble_ticket('root@pam');
    $rpcenv->set_ticket($ticket);
}

my $upid_exit = sub {
    my $upid = shift;
    my $status = PVE::Tools::upid_read_status($upid);
    exit($status eq 'OK' ? 0 : -1);
};

my $format_nodelist = sub {
    my $res = shift;

    if (!scalar(@$res)) {
	print "no cluster defined\n";
	return;
    }

    print "NAME(CID)--------------IPADDRESS----ROLE-STATE---------UPTIME---LOAD----MEM---DISK\n";
    foreach my $ni (@$res) {
	my $state = 'A';
	$state = 'S' if !$ni->{insync};

	if (my $err = $ni->{conn_error}) {
	    $err =~ s/\n/ /g;
	    $state = "ERROR: $err";
	}

	my $uptime = '-';
	if (my $ut = $ni->{uptime}) {
	    my $days = int($ut/86400);
	    $ut -= $days*86400;
	    my $hours = int($ut/3600);
	    $ut -= $hours*3600;
	    my $mins = $ut/60;
	    if ($days) {
		my $ds = $days > 1 ? 'days' : 'day';
		$uptime = sprintf "%d $ds %02d:%02d", $days, $hours, $mins;
	    } else {
		$uptime = sprintf "%02d:%02d", $hours, $mins;
	    }
	}

	my $loadavg1 = '-';
	if (my $d = $ni->{loadavg}) {
	    $loadavg1 = $d->[0];
	}

	my $mem = '-';
	if (my $d = $ni->{memory}) {
	    $mem = int(0.5 + ($d->{used}*100/$d->{total}));
	}
	my $disk = '-';
	if (my $d = $ni->{rootfs}) {
	    $disk = int(0.5 + ($d->{used}*100/$d->{total}));
	}

	printf "%-20s %-15s %-6s %1s %15s %6s %5s%% %5s%%\n",
	"$ni->{name}($ni->{cid})", $ni->{ip}, $ni->{type},
	$state, $uptime, $loadavg1, $mem, $disk;
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
	    my $cfg = PMG::ClusterConfig->new();

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

	    PMG::API2::Cluster::cluster_join($cfg, $setup);
	};

	PMG::ClusterConfig::lock_config($code, "cluster join failed");

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'sync',
    path => 'sync',
    method => 'GET',
    description => "Synchronize cluster configuration.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    master_ip => {
		description => 'Optional IP address for master node.',
		type => 'string', format => 'ip',
		optional => 1,
	    }
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $cfg = PVE::INotify::read_file('cluster.conf');

        my $master_name = undef;
	my $master_ip = $param->{master_ip};

	if (!$master_ip && $cfg->{master}) {
	    $master_ip = $cfg->{master}->{ip};
	    $master_name = $cfg->{master}->{name};
	}

	die "no master IP specified (use option --master_ip)\n" if !$master_ip;

	print STDERR "syncing master configuration from '${master_ip}'\n";

	PMG::Cluster::sync_config_from_master($cfg, $master_name, $master_ip);
    }});

our $cmddef = {
    nodes => [ 'PMG::API2::Cluster', 'nodes', [], {}, $format_nodelist],
    create => [ 'PMG::API2::Cluster', 'create', [], {}, $upid_exit],
    join => [ __PACKAGE__, 'join', ['master_ip']],
    join_cmd => [ __PACKAGE__, 'join_cmd', []],
    sync => [ __PACKAGE__, 'sync', []],
};

1;
