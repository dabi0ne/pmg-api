package PMG::API2::Who;

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

use PMG::RuleDB::WhoRegex;
use PMG::RuleDB::EMail;
use PMG::RuleDB::IPAddress;
use PMG::RuleDB::IPNet;
use PMG::RuleDB::Domain;
use PMG::RuleDB;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    ogroup => {
		description => "Object Group ID.",
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

	return [
	    { subdir => 'objects' },
	    { subdir => 'email' },
	    { subdir => 'domain' },
	    { subdir => 'regex' },
	    { subdir => 'ip' },
	    { subdir => 'network' },
	    # fixme: ldap
	];

    }});

__PACKAGE__->register_method({
    name => 'delete_who_group',
    path => '',
    method => 'DELETE',
    description => "Delete a 'who' group.",
    proxyto => 'master',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    ogroup => {
		description => "Object Group ID.",
		type => 'integer',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	$rdb->delete_group($param->{ogroup});

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'objects',
    path => 'objects',
    method => 'GET',
    description => "List group objects.",
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    ogroup => {
		description => "Object Group ID.",
		type => 'integer',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		id => { type => 'integer'},
	    },
	},
	links => [ { rel => 'child', href => "{id}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $og = $rdb->load_group_objects($param->{ogroup});

	my $res = [];

	foreach my $obj (@$og) {
	    push @$res, $obj->get_data();
	}

	return $res;
    }});


# fixme:
# $conn->reload_ruledb ();

__PACKAGE__->register_method ({
    name => 'delete_object',
    path => 'objects/{id}',
    method => 'DELETE',
    description => "Remove an object from the group.",
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    ogroup => {
		description => "Object Group ID.",
		type => 'integer',
	    },
	    id => {
		description => "Object ID.",
		type => 'integer',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $obj = $rdb->load_object($param->{id});

	die "object '$param->{id}' does not exists\n" if !defined($obj);

	$rdb->delete_object($obj);

	return undef;
    }});

PMG::RuleDB::EMail->register_api(__PACKAGE__, 'email');
PMG::RuleDB::Domain->register_api(__PACKAGE__, 'domain');
PMG::RuleDB::WhoRegex->register_api(__PACKAGE__, 'regex');
PMG::RuleDB::IPAddress->register_api(__PACKAGE__, 'ip');
PMG::RuleDB::IPNet->register_api(__PACKAGE__, 'network');

1;
