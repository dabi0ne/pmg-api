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
	    { name => 'mailq' },
	    { name => 'qshape' },
	    { name => 'flush_queues' },
	    { name => 'delete_deferred_queue' },
	    { name => 'discard_verify_cache' },
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

__PACKAGE__->register_method ({
    name => 'mailq',
    path => 'mailq',
    method => 'GET',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    proxyto => 'node',
    description => "List the mail queue for a specific domain.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    start => {
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    limit => {
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    filter => {
		description => "Filter string.",
		type => 'string',
		maxLength => 64,
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

	my $restenv = PVE::RESTEnvironment::get();

	my ($count, $res) = PMG::Postfix::mailq(
	    $param->{filter}, $param->{start}, $param->{limit});

	$restenv->set_result_attrib('total', $count);

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'flush_queues',
    path => 'flush_queues',
    method => 'POST',
    description => "Flush the queue: attempt to deliver all queued mail.",
    proxyto => 'node',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PMG::Postfix::flush_queues();

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete_deferred_queue',
    path => 'delete_deferred_queue',
    method => 'POST',
    description => "Delete all mails in the deffered queue.",
    proxyto => 'node',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PMG::Postfix::delete_deferred_queue();

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'discard_verify_cache',
    path => 'discard_verify_cache',
    method => 'POST',
    description => "Discards the address verification cache.",
    proxyto => 'node',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PMG::Postfix::discard_verify_cache();

	return undef;
    }});

1;
