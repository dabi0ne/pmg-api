package PMG::API2::Backup;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::RESTEnvironment;
use PMG::Config;
use PMG::Backup;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'list',
    path => '',
    method => 'GET',
    description => "List all stored backups (files named proxmox-backup_{DATE}.tgz).",
    permissions => { check => [ 'admin', 'audit' ] },
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
   returns => {
	type => "array",
	items => {
	    type => "object",
	    properties => {
		filename => { type => 'string'},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	die "implement me";

	my $res = [];

	return $res;
    }});

my $include_statistic_property = {
    description => "Backup/Restore statistic databases.",
    type => 'boolean',
    optional => 1,
    default => 0,
};

__PACKAGE__->register_method ({
    name => 'backup',
    path => '',
    method => 'POST',
    description => "Backup the system configuration.",
    permissions => { check => [ 'admin' ] },
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    statistic => $include_statistic_property,
	},
    },
   returns => { type => "string" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $bkdir = "/var/lib/pmg/tmp";

	my (undef, undef, undef, $mday, $mon, $year) = localtime(time);
	my $bkfile = sprintf("pmg-backup_%04d_%02d_%02d.tgz", $year + 1900, $mon + 1, $mday);
	my $filename = "$bkdir/$bkfile";

	my $worker = sub {
	    my $upid = shift;

	    print "starting backup\n";
	    print "target file: $filename\n";

	    PMG::Backup::pmg_backup($filename, $param->{statistic});
	    print "backup finished\n";

	    return;
	};

	return $rpcenv->fork_worker('backup', undef, $authuser, $worker);
    }});


__PACKAGE__->register_method ({
    name => 'restore',
    path => '{filename}',
    method => 'POST',
    description => "Restore the system configuration.",
    permissions => { check => [ 'admin' ] },
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    filename => {
		description => "The backup file you want to retore.",
		type => "string",
		minLength => 4,
		maxLength => 256,
	    },
	    statistic => $include_statistic_property,
	    config => {
		description => "Restore system configuration.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	    database => {
		description => "Restore the rule database.",
		type => 'boolean',
		optional => 1,
		default => 1,
	    },
	},
    },
    returns => { type => "string" },
    code => sub {
	my ($param) = @_;

	die "implement me";

	my $res = "test";

	return $res;
    }});

1;
