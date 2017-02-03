package PMG::CLI::pmgdb;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;

use PMG::DBTools;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

__PACKAGE__->register_method ({
    name => 'dump',
    path => 'dump',
    method => 'GET',
    description => "Print the PMG rule database.",
    parameters => {
	additionalProperties => 0,
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	print "DUMP\n";

	return undef;
    }});


__PACKAGE__->register_method ({
    name => 'delete',
    path => 'delete',
    method => 'DELETE',
    description => "Delete PMG rule database.",
    parameters => {
	additionalProperties => 0,
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $list = PMG::DBTools::database_list();

	my $dbname = "Proxmox_ruledb";

	die "Database '$dbname' does not exist\n" if !$list->{$dbname};

	syslog('info', "delete rule database");

	PMG::DBTools::delete_ruledb($dbname);

	return undef;
    }});


__PACKAGE__->register_method ({
    name => 'update',
    path => 'update',
    method => 'POST',
    description => "Update or initialize PMG rule database.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    force => {
		type => 'boolean',
		description => "Delete existing database.",
		optional => 1,
		default => 0,
	    },
	    statistics => {
		type => 'boolean',
		description => "Update/initialize statistic database (this is done by default).",
		optional => 1,
		default => 1,
	    },
	}
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $list = PMG::DBTools::database_list();

	my $dbname = "Proxmox_ruledb";

	if (!$list->{$dbname} || $param->{force}) {

	    if ($list->{$dbname}) {
		print "Destroy existing rule database\n";
		PMG::DBTools::delete_ruledb($dbname);
	    }

	    print "Initialize rule database\n";

	    my $dbh = PMG::DBTools::create_ruledb ($dbname);
	    my $ruledb = PMG::RuleDB->new($dbh);
	    PMG::DBTools::init_ruledb($ruledb);

	    $dbh->disconnect();

	} else {

	    my $dbh = PMG::DBTools::open_ruledb("Proxmox_ruledb");
	    my $ruledb = PMG::RuleDB->new($dbh);

	    print "Analyzing/Upgrading existing Databases...";
	    PMG::DBTools::upgradedb ($ruledb);
	    print "done\n";

	    # reset and update statistic databases
	    if ($param->{statistics}) {
		print "Generating Proxmox Statistic Databases... ";
		#Proxmox::Statistic::clear_stats($dbh);
		#Proxmox::Statistic::update_stats($dbh, $cinfo);
		print "done\n";
	    }

	    $dbh->disconnect();
	}

	return undef;
    }});


our $cmddef = {
    'dump' => [ __PACKAGE__, 'dump', []],
    delete => [ __PACKAGE__, 'delete', []],
    update => [ __PACKAGE__, 'update', []],
};

1;
