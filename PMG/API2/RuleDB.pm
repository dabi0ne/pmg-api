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

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
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
	    { name => 'rules' },
	];

	return $result;
    }});

__PACKAGE__->register_method({
    name => 'list_rules',
    path => 'rules',
    method => 'GET',
    description => "Get list of rules.",
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
	    properties => {
	    }
	}
    },
    code => sub {
	my ($param) = @_;

	# fixme: use RuleCache ?

	my $dbh = PMG::DBTools::open_ruledb();
	my $ruledb = PMG::RuleDB->new($dbh);

	my $rules = $ruledb->load_rules();

	my $res = [];

	my $cond_create_group = sub {
	    my ($res, $name, $groupdata) = @_;

	    return if !$groupdata;

	    my $group = [];
	    foreach my $og (@$groupdata) {
		push @$group, { id => $og->{id}, name => $og->{name} };
	    }
	    $res->{$name} = $group;
	};

	foreach my $rule (@$rules) {
	    my ($from, $to, $when, $what, $action) =
		$ruledb->load_groups($rule);

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

	$ruledb->close();

	return $res;
    }});

1;
