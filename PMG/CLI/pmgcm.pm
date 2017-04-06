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

    print "NAME(CID)--------------IPADDRESS----ROLE-STATE---------UPTIME---LOAD----MEM---DISK\n";
    foreach my $ni (@$res) {
	my $state = '?';
	
	printf "%-20s %-15s %-6s %1s %15s %6s %5s%% %5s%%\n", 
	"$ni->{name}($ni->{cid})", $ni->{ip}, $ni->{type}, 
	$state, '-', '-', '-', '-';
    }
};

our $cmddef = {
    nodes => [ 'PMG::API2::Cluster', 'nodes', [], {}, $format_nodelist],
    create => [ 'PMG::API2::Cluster', 'create', []],
    join => [ 'PMG::API2::Cluster', 'join', ['master_ip', 'fingerprint']],
};

1;
