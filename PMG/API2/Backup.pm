package PMG::API2::Backup;

use strict;
use warnings;
use Time::Local;
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

my $backup_dir = "/var/lib/pmg/backup";
my $backup_filename_pattern = 'pmg-backup_(\d{4})_(\d\d)_(\d\d)_([0-9A-F]+)\.tgz';

my $backup_filename_property = {
    description => "The backup file name.",
    type => "string",
    pattern => $backup_filename_pattern,
    minLength => 4,
    maxLength => 256,
};

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
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => "array",
	items => {
	    type => "object",
	    properties => {
		filename => $backup_filename_property,
		size => {
		    description => "Size of backup file in bytes.",
		    type => 'integer',
		},
		timestamp => {
		    description => "Backup timestamp (Unix epoch).",
		    type => 'integer',
		},
	    },
	},
	links => [ { rel => 'child', href => "{filename}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	PVE::Tools::dir_glob_foreach(
	    $backup_dir,
	    $backup_filename_pattern,
	    sub {
		my ($filename, $year, $mon, $mday, $timestamp_hex) = @_;
		push @$res, {
		    filename => $filename,
		    size => -s "$backup_dir/$filename",
		    year => int($year),
		    mon => int($mon),
		    mday => int($mday),
		    timestamp => hex($timestamp_hex),
		};
	    });

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

	my (undef, undef, undef, $mday, $mon, $year) = localtime(time);
	my $bkfile = sprintf("pmg-backup_%04d_%02d_%02d_%08X.tgz", $year + 1900, $mon + 1, $mday, time());
	my $filename = "${backup_dir}/$bkfile";

	my $worker = sub {
	    my $upid = shift;

	    print "starting backup to: $filename\n";

	    PMG::Backup::pmg_backup($filename, $param->{statistic});

	    print "backup finished\n";

	    return;
	};

	return $rpcenv->fork_worker('backup', undef, $authuser, $worker);
    }});

__PACKAGE__->register_method ({
    name => 'download',
    path => '{filename}',
    method => 'GET',
    description => "Download a backup file.",
    permissions => { check => [ 'admin' ] },
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    filename => $backup_filename_property,
	},
    },
    download => 1,
    returns => { type => "string" },
    code => sub {
	my ($param) = @_;

	my $filename = "${backup_dir}/$param->{filename}";

	return $filename;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{filename}',
    method => 'DELETE',
    description => "Delete a backup file.",
    permissions => { check => [ 'admin' ] },
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    filename => $backup_filename_property,
	},
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $filename = "${backup_dir}/$param->{filename}";
	unlink($filename) || die "delete backup file '$filename' failed - $!\n";

	return undef;
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
	    filename => $backup_filename_property,
	    statistic => $include_statistic_property,
	    config => {
		description => "Restore system configuration.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	    database => {
		description => "Restore the rule database. This is the default.",
		type => 'boolean',
		optional => 1,
		default => 1,
	    },
	},
    },
    returns => { type => "string" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $filename = "${backup_dir}/$param->{filename}";
	-f $filename || die "backup file '$filename' does not exist - $!\n";

	$param->{database} //= 1;

	die "nothing selected - please select what you want to restore (config or database?)\n"
	    if !($param->{database} || $param->{config});

	my $worker = sub {
	    my $upid = shift;

	    print "starting restore: $filename\n";

	    PMG::Backup::pmg_restore($filename, $param->{database},
				     $param->{config}, $param->{statistic});
	    print "restore finished\n";

	    return;
	};

	return $rpcenv->fork_worker('restore', undef, $authuser, $worker);
    }});

1;
