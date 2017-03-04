package PMG::API2::ClamAV;

use strict;
use warnings;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Exception qw(raise_param_exc);
use PVE::RESTHandler;
use PVE::RESTEnvironment;
use PVE::JSONSchema qw(get_standard_option);

use PMG::Utils;

use base qw(PVE::RESTHandler);


__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	push @$res, { subdir => "dbstat" };

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'dbstat',
    path => 'dbstat',
    method => 'GET',
    description => "ClamAV virus database status.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		type => { type => 'string' },
		build_time => { type => 'string' },
		version => { type => 'string', optional => 1 },
		nsigs => { type => 'integer' },
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	return PMG::Utils::clamav_dbstat();
    }});

1;
