package PMG::CLI::proxdb;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;

use PMG::DBTools;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

my $upid_exit = sub {
    my $upid = shift;
    my $status = PVE::Tools::upid_read_status($upid);
    exit($status eq 'OK' ? 0 : -1);
};

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

	my $dbh = PMG::DBTools::open_ruledb("Proxmox_ruledb"); # raises error if db not exists
	$dbh->disconnect();

	syslog('info', "delete rule database");

	PMG::DBTools::delete_ruledb("Proxmox_ruledb");

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
	    init => {
		type => 'boolean',
		description => "Initialize the database.",
		optional => 1,
		default => 0,
	    },
	    fail => {
		type => 'boolean',
		description => "Fail if databse already exists. We normally try to update and reinitialize the existing database.",
		requires => 'init',
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

	syslog('info', "init rule database");
	
	print "INIT\n";
	print Dumper($param);

	my $dbh = PMG::DBTools::open_ruledb("Proxmox_ruledb");

	return undef;
    }});


our $cmddef = {
    'dump' => [ __PACKAGE__, 'dump', []],
    delete => [ __PACKAGE__, 'delete', []],
    update => [ __PACKAGE__, 'update', []],
};

1;
