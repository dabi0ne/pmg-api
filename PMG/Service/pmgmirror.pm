package PMG::Service::pmgmirror;

use strict;
use warnings;
use Data::Dumper;
use Time::HiRes qw (gettimeofday);

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::Daemon;

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


sub init {
    syslog('INIT');
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
