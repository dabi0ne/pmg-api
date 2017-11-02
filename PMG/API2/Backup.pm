package PMG::API2::Backup;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::Config;

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
	    statistic => $include_statistic_property,
	},
    },
   returns => { type => "string" },
    code => sub {
	my ($param) = @_;

	die "implement me";

	my $res = "test";

	return $res;
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
