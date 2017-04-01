package PMG::API2::Postfix;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::Postfix;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Directory index.",
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
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $result = [
	    { name => 'qshape' },
	];

	return $result;
    }});

__PACKAGE__->register_method ({
    name => 'qshape',
    path => 'qshape',
    method => 'GET',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    proxyto => 'node',
    description => "Print Postfix queue domain and age distribution.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    queue => {
		description => "Postfix queue name.",
		type => 'string',
		enum => ['deferred', 'active', 'incoming', 'bounce'],
		default => 'deferred',
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
    },
    code => sub {
	my ($param) = @_;

	my $queue = $param->{queue} || 'deferred';

	my $res = PMG::Postfix::qshape($queue);

	return $res;
    }});


1;
