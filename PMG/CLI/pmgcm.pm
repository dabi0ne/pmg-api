package PMG::CLI::pmgcm;

use strict;
use warnings;
use Data::Dumper;

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

	    print "pmgcm join --master_ip $master->{ip} --fingerprint $master->{fingerprint}\n";

	} else {
	    die "no cluster defined\n";
	}

	return undef;
    }});

our $cmddef = {
    nodes => [ 'PMG::API2::Cluster', 'nodes', [], {}, $format_nodelist],
    create => [ 'PMG::API2::Cluster', 'create', []],
    join => [ 'PMG::API2::Cluster', 'join', ['master_ip', 'fingerprint']],
    join_cmd => [ __PACKAGE__, 'join_cmd', []],
};

1;
