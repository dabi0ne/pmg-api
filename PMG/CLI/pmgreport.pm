package PMG::CLI::pmgreport;

use strict;
use Data::Dumper;
use Template;
use POSIX qw(strftime);

use PVE::INotify;
use PVE::CLIHandler;

use PMG::Utils;
use PMG::Config;
use PMG::RESTEnvironment;

use PMG::API2::Nodes;
use PMG::ClusterConfig;
use PMG::Cluster;
use PMG::API2::Cluster;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();

    my $rpcenv = PMG::RESTEnvironment->get();
    # API /config/cluster/nodes need a ticket to connect to other nodes
    my $ticket = PMG::Ticket::assemble_ticket('root@pam');
    $rpcenv->set_ticket($ticket);
}

my $get_system_table_data = sub {

    my $ni = PMG::API2::NodeInfo->status({ node => $nodename });

    my $data = [];

    push @$data, { text => 'Hostname', value => $nodename };

    my $uptime = $ni->{uptime} ? PMG::Utils::format_uptime($ni->{uptime}) : '-';

    push @$data, { text => 'Uptime', value => $uptime };

    push @$data, { text => 'Version', value => $ni->{pmgversion} };

    my $loadavg15 = '-';
    if (my $d = $ni->{loadavg}) {
	$loadavg15 = sprintf("%.2f", $d->[2]);
    }
    push @$data, { text => 'Load', value => $loadavg15 };

    my $mem = '-';
    if (my $d = $ni->{memory}) {
	$mem = sprintf("%.2f%%", $d->{used}*100/$d->{total});
    }
    push @$data, { text => 'Memory', value => $mem };

    my $disk = '-';
    if (my $d = $ni->{rootfs}) {
	$disk = sprintf("%.2f%%", $d->{used}*100/$d->{total});
    }
    push @$data, { text => 'Disk', value => $disk };

    return $data
};

my $get_cluster_table_data = sub {

    my $res = PMG::API2::Cluster->status({});
    return undef if !scalar(@$res);

    my $data = [];

    foreach my $ni (@$res) {
	my $state = 'A';
	$state = 'S' if !$ni->{insync};

	my $loadavg1  = '-';
	if (my $d = $ni->{loadavg}) {
	    $loadavg1 = sprintf("%.2f", $d->[0]);
	}

	my $memory = '-';
	if (my $d = $ni->{memory}) {
	    $memory = sprintf("%.2f%%", $d->{used}*100/$d->{total});
	}

	my $disk = '-';
	if (my $d = $ni->{rootfs}) {
	    $disk = sprintf("%.2f%%", $d->{used}*100/$d->{total});
	}

	push @$data, {
	    hostname => $ni->{name},
	    ip => $ni->{ip},
	    type => $ni->{type},
	    state => $state,
	    loadavg1 => $loadavg1,
	    memory => $memory,
	    disk => $disk,
	};
    };

    return $data;
};

__PACKAGE__->register_method ({
    name => 'pmgreport',
    path => 'pmgreport',
    method => 'POST',
    description => "Generate and send daily system report email.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    debug => {
		description => "Debug mode. Print raw email to stdout instead of sending them.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	    auto => {
		description => "Auto mode. Use setting from system configuration (set when invoked fron cron).",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	    receiver => {
		description => "Send report to this email address. Default is the administratior email address.",
		type => 'string', format => 'email',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $fqdn = PVE::Tools::get_fqdn($nodename);

	my $end = time(); # fixme

	my $vars = {
	    hostname => $nodename,
	    fqdn => $fqdn,
	    date => strftime("%F", localtime($end - 1)),
	};

	my $cinfo = PMG::ClusterConfig->new();
	my $role = $cinfo->{local}->{type} // '-';

	if ($role eq '-') {
	    $vars->{system} = $get_system_table_data->();
	} else {
	    $vars->{cluster} = $get_cluster_table_data->();
	    if ($role eq 'master') {
		# OK
	    } else {
		return undef if $param->{auto}; # silent exit - do not send report
	    }
	}

	my $tt = PMG::Config::get_template_toolkit();

	my $cfg = PMG::Config->new();
	my $email = $param->{receiver} // $cfg->get ('admin', 'email');

	if (!defined($email)) {
	    return undef if $param->{auto}; # silent exit - do not send report
	    die "no receiver configured\n";
	}

	my $mailfrom = "Proxmox Mail Gateway <postmaster>";
	PMG::Utils::finalize_report($tt, 'pmgreport.tt', $vars, $mailfrom, $email, $param->{debug});

	return undef;
    }});

our $cmddef = [ __PACKAGE__, 'pmgreport', [], undef ];

1;
