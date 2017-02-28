package PMG::API2::RuleDB;

use strict;
use warnings;

use PVE::INotify;
use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTEnvironment;
use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);

use PMG::DBTools;
use PMG::RuleDB;

use PMG::API2::Who;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    parameters => {
    	additionalProperties => 0,
	properties => {},
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
	    { name => 'action' },
	    { name => 'rules' },
	    { name => 'what' },
	    { name => 'when' },
	    { name => 'who' },
	];

	return $result;
    }});

my $format_object_group = sub {
    my ($ogroups) = @_;

    my $res = [];
    foreach my $og (@$ogroups) {
	push @$res, {
	    id => $og->{id}, name => $og->{name}, info => $og->{info}
	};
    }
    return $res;
};

__PACKAGE__->register_method({
    name => 'list_rules',
    path => 'rules',
    method => 'GET',
    description => "Get list of rules.",
    proxyto => 'master',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		id => { type => 'integer' },
	    },
	},
	links => [ { rel => 'child', href => "{id}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $rules = $rdb->load_rules();

	my $res = [];

	my $cond_create_group = sub {
	    my ($res, $name, $groupdata) = @_;

	    return if !$groupdata;

	    $res->{$name} = $format_object_group->($groupdata);
	};

	foreach my $rule (@$rules) {
	    my ($from, $to, $when, $what, $action) =
		$rdb->load_groups($rule);

	    my $data = {
		id =>  $rule->{id},
		name => $rule->{name},
		priority => $rule->{priority},
		active => $rule->{active},
	    };

	    $cond_create_group->($data, 'from', $from);
	    $cond_create_group->($data, 'to', $to);
	    $cond_create_group->($data, 'when', $when);
	    $cond_create_group->($data, 'what', $what);
	    $cond_create_group->($data, 'action', $action);

	    push @$res, $data;
	}

	$rdb->close();

	return $res;
    }});



sub register_object_group_api {
    my ($oclass) = @_;

    __PACKAGE__->register_method({
	name => "list_${oclass}_groups",
	path => $oclass,
	method => 'GET',
	description => "Get list of '$oclass' groups.",
	proxyto => 'master',
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => {},
	},
	returns => {
	    type => 'array',
	    items => {
		type => "object",
		properties => {
		    id => { type => 'integer' },
		},
	    },
	},
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $ogroups = $rdb->load_objectgroups($oclass);

	    return $format_object_group->($ogroups);
	}});

    __PACKAGE__->register_method({
	name => "create_${oclass}_group",
	path => $oclass,
	method => 'POST',
	description => "Create a new '$oclass' group.",
	proxyto => 'master',
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => {
		name => {
		    description => "Group name.",
		    type => 'string',
		    maxLength => 255,
		},
		info => {
		    description => "Informational comment.",
		    type => 'string',
		    maxLength => 255,
		    optional => 1,
		},
	    },
	},
	returns => { type => 'integer' },
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $og = PMG::RuleDB::Group->new(
		$param->{name}, $param->{info} // '', $oclass);

	    return $rdb->save_group($og);
	}});
}

register_object_group_api('action');
register_object_group_api('what');
register_object_group_api('when');
register_object_group_api('who');

__PACKAGE__->register_method ({
    subclass => 'PMG::API2::Who',
    path => 'who/{ogroup}',
});


1;
