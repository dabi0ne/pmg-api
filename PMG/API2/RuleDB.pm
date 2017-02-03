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
	    { name => 'actions' },
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

	my $dbh = PMG::DBTools::open_ruledb();
	my $ruledb = PMG::RuleDB->new($dbh);

	my $rules = $ruledb->load_rules();

	my $res = [];

	my $cond_create_group = sub {
	    my ($res, $name, $groupdata) = @_;

	    return if !$groupdata;

	    $res->{$name} = $format_object_group->($groupdata);
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

__PACKAGE__->register_method({
    name => 'list_actions',
    path => 'actions',
    method => 'GET',
    description => "Get list of 'action' objects.",
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

	my $dbh = PMG::DBTools::open_ruledb();
	my $ruledb = PMG::RuleDB->new($dbh);

	my $ogroups = $ruledb->load_objectgroups('action');

	return $format_object_group->($ogroups);
    }});

__PACKAGE__->register_method({
    name => 'list_what_object',
    path => 'what',
    method => 'GET',
    description => "Get list of 'what' objects.",
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

	my $dbh = PMG::DBTools::open_ruledb();
	my $ruledb = PMG::RuleDB->new($dbh);

	my $ogroups = $ruledb->load_objectgroups('what');

	return $format_object_group->($ogroups);
    }});

__PACKAGE__->register_method({
    name => 'list_when_object',
    path => 'when',
    method => 'GET',
    description => "Get list of 'when' objects.",
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

	my $dbh = PMG::DBTools::open_ruledb();
	my $ruledb = PMG::RuleDB->new($dbh);

	my $ogroups = $ruledb->load_objectgroups('when');

	return $format_object_group->($ogroups);
    }});

__PACKAGE__->register_method({
    name => 'list_who_object',
    path => 'who',
    method => 'GET',
    description => "Get list of 'who' objects.",
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

	my $dbh = PMG::DBTools::open_ruledb();
	my $ruledb = PMG::RuleDB->new($dbh);

	my $ogroups = $ruledb->load_objectgroups('who');

	return $format_object_group->($ogroups);
    }});

1;
