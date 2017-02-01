package PMG::DBTools;

use strict;
use warnings;

use POSIX ":sys_wait_h";
use POSIX ':signal_h';
use DBI;

use PVE::Tools;

sub open_ruledb {
    my ($database, $host, $port) = @_;

    $port = 5432 if !$port;

    $database = "Proxmox_ruledb" if !$database;

    if ($host) {

	my $dsn = "dbi:Pg:dbname=$database;host=$host;port=$port;";

	my $timeout = 5;
	# only low level alarm interface works for DBI->connect
	my $mask = POSIX::SigSet->new(SIGALRM);
	my $action = POSIX::SigAction->new(sub { die "connect timeout\n" }, $mask);
	my $oldaction = POSIX::SigAction->new();
	sigaction(SIGALRM, $action, $oldaction);

	my $rdb;

	eval {
	    alarm($timeout);
	    $rdb = DBI->connect($dsn, "postgres", undef,
				{ PrintError => 0, RaiseError => 1 });
	    alarm(0);
	};
	alarm(0);
	sigaction(SIGALRM, $oldaction);  # restore original handler
	    
	die $@ if $@;

	return $rdb;
    } else {
	my $dsn = "DBI:Pg:dbname=$database";

	my $dbh = DBI->connect($dsn, "postgres", undef, 
			       { PrintError => 0, RaiseError => 1 });

	return $dbh;
    }
}

sub delete_ruledb {
    my ($dbname) = @_;

    PVE::Tools::run_command(['dropdb', '-U', 'postgres', $dbname]);
}

1;
