package PMG::Service::pmgmirror;

use strict;
use warnings;
use Data::Dumper;
use Time::HiRes qw (gettimeofday);

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::Daemon;
use PVE::ProcFSTools;

use PMG::RESTEnvironment;
use PMG::DBTools;
use PMG::RuleDB;
use PMG::Cluster;
use PMG::ClusterConfig;
use PMG::Statistic;

use base qw(PVE::Daemon);

my $cmdline = [$0, @ARGV];

my %daemon_options = (restart_on_error => 5, stop_wait_time => 5);

my $daemon = __PACKAGE__->new('pmgmirror', $cmdline, %daemon_options);

my $restart_request = 0;
my $next_update = 0;

my $cycle = 0;
my $updatetime = 10;

my $initial_memory_usage;

sub init {
    # syslog('INIT');
}

sub hup {
    my ($self) = @_;

    $restart_request = 1;
}

sub run {
    my ($self) = @_;

    for (;;) { # forever

	$next_update = time() + $updatetime;

	eval {
	    my $cinfo = PMG::ClusterConfig->new(); # reload
	    
	    syslog('info' , "do something");
	};

	if (my $err = $@) {
	    syslog('err', PMG::Utils::msgquote ("sync error: $err"));
	}

	$cycle++;

	last if $self->{terminate};

	my $mem = PVE::ProcFSTools::read_memory_usage();

	if (!defined($initial_memory_usage) || ($cycle < 10)) {
	    $initial_memory_usage = $mem->{resident};
	} else {
	    my $diff = $mem->{resident} - $initial_memory_usage;
	    if ($diff > 5*1024*1024) {
		syslog ('info', "restarting server after $cycle cycles to " .
			"reduce memory usage (free $mem->{resident} ($diff) bytes)");
		$self->restart_daemon();
	    }
	}

	my $wcount = 0;
	while ((time() < $next_update) &&
	       ($wcount < $updatetime) && # protect against time wrap
	       !$restart_request && !$self->{terminate}) {

	    $wcount++; sleep (1);
	};

	last if $self->{terminate};

	$self->restart_daemon() if $restart_request;
    }
}

$daemon->register_start_command("Start the Database Mirror Daemon");
$daemon->register_stop_command("Stop the Database Mirror Daemon");
$daemon->register_restart_command(1, "Restart the Database Mirror Daemon");

our $cmddef = {
    start => [ __PACKAGE__, 'start', []],
    restart => [ __PACKAGE__, 'restart', []],
    stop => [ __PACKAGE__, 'stop', []],
};

1;
