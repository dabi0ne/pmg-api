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
use PMG::RuleDB;
use PMG::Statistic;

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

my $get_incoming_table_data = sub {
    my ($totals) = @_;

    my $data = [];

    push @$data, {
	text => 'Incoming Mails',
	value => $totals->{count_in},
	percentage => $totals->{count_in_per},
    };

    push @$data, {
	text => 'Spam Mails',
	value => $totals->{spamcount_in},
	percentage => $totals->{spamcount_in_per},
    };

    push @$data, {
	text => 'Virus Mails',
	value => $totals->{viruscount_in},
	percentage => $totals->{viruscount_in_per},
    };

    push @$data, {
	text => 'SPF rejects',
	value => $totals->{spfcount},
	percentage => $totals->{spfcount_per},
    };

    push @$data, {
	text => 'Mail Traffic',
	value => sprintf ("%.3f MByte", $totals->{traffic_in}),
    };

    return $data;
};

my $get_outgoing_table_data = sub {
    my ($totals) = @_;

    my $data = [];

    push @$data, {
	text => 'Outgoing Mails',
	value => $totals->{count_out},
	percentage => $totals->{count_out_per},
    };

    push @$data, {
	text => 'Bounces',
	value => $totals->{bounces_out},
	percentage => $totals->{bounces_out_per},
    };

    push @$data, {
	text => 'Mail Traffic',
	value => sprintf ("%.3f MByte", $totals->{traffic_out}),
    };

    return $data;
};

my $get_virus_table_data = sub {
    my ($virusinfo) = @_;

    my $data = [];

    foreach my $entry (@$virusinfo) {
	next if !$entry->{count};
	last if scalar(@$data) >= 10;
	push @$data, { name => $entry->{name}, count => $entry->{count} };
    }

    return undef if !scalar(@$data);

    return $data;
};

my $get_quarantine_table_data = sub {
    my ($dbh, $qtype) = @_;

    # Note;: We try to estimate used disk space - each mail
    # is stored in an extra file ...

    my $bs = 4096;

    my $sth = $dbh->prepare(
	"SELECT count(ID) as count,  sum (ceil((Bytes+$bs-1)/$bs)*$bs) / (1024*1024) as mbytes, " .
	"avg(Bytes) as avgbytes, avg(Spamlevel) as avgspam " .
	"FROM CMailStore WHERE QType = ?");

    $sth->execute($qtype);

    my $ref = $sth->fetchrow_hashref();

    $sth->finish;

    return undef if !($ref && $ref->{count});

    my $data = [];

    push @$data, {
	text => "Quarantine Size (MBytes)",
	value => int($ref->{mbytes}),
    };

    push @$data, {
	text => "Number of Mails",
	value => $ref->{count},
    };

    push @$data, {
	text => "Average Size (Bytes)",
	value => int($ref->{avgbytes}),
    };

    if ($qtype eq 'S') {
	push @$data, {
	    text => "Average Spam Level",
	    value => int($ref->{avgspam}),
	};
    }

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
	    timespan => {
		description => "Select time span for included email statistics.\n\nNOTE: System and cluster performance data is always from current time (when script is run).",
		type => 'string',
		enum => ['today', 'yesterday'],
		default => 'today',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $timespan = $param->{timespan} // 'today';
	my ($start, $end) = PMG::Utils::lookup_timespan($timespan);

	my $fqdn = PVE::Tools::get_fqdn($nodename);

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


	my $stat = PMG::Statistic->new ($start, $end);
	my $rdb = PMG::RuleDB->new();

	# update statistics
	PMG::Statistic::update_stats($rdb->{dbh}, $cinfo);

	my $totals = $stat->total_mail_stat($rdb);

	$vars->{incoming} = $get_incoming_table_data->($totals);

	$vars->{outgoing} = $get_outgoing_table_data->($totals);

	my $virusinfo = $stat->total_virus_stat ($rdb);
	if (my $data = $get_virus_table_data->($virusinfo)) {
	    $vars->{virusstat} = $data;
	}

	if (my $data = $get_quarantine_table_data->($rdb->{dbh}, 'V')) {
	    $vars->{virusquar} = $data;
	}

	if (my $data = $get_quarantine_table_data->($rdb->{dbh}, 'S')) {
	    $vars->{spamquar} = $data;
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
