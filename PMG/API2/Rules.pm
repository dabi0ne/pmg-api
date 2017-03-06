package PMG::API2::Rules;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use HTTP::Status qw(:constants);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::Config;

use PMG::RuleDB;
use PMG::API2::ObjectGroupHelpers;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => {
		description => "Rule ID.",
		type => 'integer',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	$rdb->load_rule($param->{id}); # test if rule exist

	return [
	    { subdir => 'config' },
	    { subdir => 'from' },
	    { subdir => 'to' },
	    { subdir => 'when' },
	    { subdir => 'what' },
	    { subdir => 'actions' },
	];

    }});


__PACKAGE__->register_method ({
    name => 'config',
    path => 'config',
    method => 'GET',
    description => "Get common rule properties.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => {
		description => "Rule ID.",
		type => 'integer',
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    id => { type => 'integer'},
	    name => { type => 'string' },
	    active => { type => 'boolean' },
	    direction => { type => 'integer' },
	    priority => { type => 'integer' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $rule = $rdb->load_rule($param->{id});

	my ($from, $to, $when, $what, $action) =
	    $rdb->load_groups($rule);

	my $data = PMG::API2::ObjectGroupHelpers::format_rule(
	    $rule, $from, $to, $when, $what, $action);

	return $data;
   }});

1;
