package PMG::API2::Action;

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

use PMG::RuleDB::BCC;
use PMG::RuleDB;

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
	    { subdir => 'bcc' },
	];

    }});

my $id_property = {
    description => "Action Object ID.",
    type => 'string',
    pattern => '\d+_\d+',
};

my $format_action_object = sub {
    my ($action) = @_;

    my $data = $action->get_data();
    $data->{id} = "$data->{ogroup}_$data->{id}";
    delete $data->{ogroup};

    return $data;
};

__PACKAGE__->register_method ({
    name => 'list_actions',
    path => 'objects',
    method => 'GET',
    description => "List 'actions' objects.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		id => $id_property,
	    },
	},
	links => [ { rel => 'child', href => "{id}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $ogroups = $rdb->load_objectgroups('action');
	my $res = [];
	foreach my $og (@$ogroups) {
	    my $action = $og->{action};
	    next if !$action;
	    push @$res, $format_action_object->($action);
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'delete_action',
    path => 'objects/{id}',
    method => 'DELETE',
    description => "Delete 'actions' object.",
    parameters => {
	additionalProperties => 0,
	properties => { id => $id_property }
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	die "internal error" if $param->{id} !~ m/^(\d+)_(\d+)$/;
	my ($ogroup, $objid) = ($1, $2);

	# test if object exists
	$rdb->load_object_full($objid, $ogroup);

	$rdb->delete_group($ogroup);

	return undef;
    }});

my $register_action_api = sub {
    my ($class, $name) = @_;

    my $otype = $class->otype();
    my $otype_text = $class->otype_text();
    my $properties = $class->properties();

    my $create_properties = {};
    my $update_properties = { id => $id_property };
    my $read_properties = { id => $id_property };

    foreach my $key (keys %$properties) {
	$create_properties->{$key} = $properties->{$key};
	$update_properties->{$key} = $properties->{$key};
    }

    __PACKAGE__->register_method ({
	name => $name,
	path => $name,
	method => 'POST',
	description => "Create '$otype_text' object.",
	proxyto => 'master',
	parameters => {
	    additionalProperties => 0,
	    properties => $create_properties,
	},
	returns => {
	    description => "The object ID.",
	    type => 'string',
	},
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $obj = $rdb->get_object($otype);
	    $obj->update($param);

	    my $og = $rdb->new_action($obj);

	    return "$og->{id}_$obj->{id}";
	}});

    __PACKAGE__->register_method ({
	name => "read_$name",
	path => "$name/{id}",
	method => 'GET',
	description => "Read '$otype_text' object settings.",
	proxyto => 'master',
	parameters => {
	    additionalProperties => 0,
	    properties => $read_properties,
	},
	returns => {
	    type => "object",
	    properties => {
		id => { type => 'string'},
	    },
	},
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    die "internal error" if $param->{id} !~ m/^(\d+)_(\d+)$/;
	    my ($ogroup, $objid) = ($1, $2);

	    my $action = $rdb->load_object_full($objid, $ogroup, $otype);

	    return $format_action_object->($action);
	}});

    __PACKAGE__->register_method ({
	name => "update_$name",
	path => "$name/{id}",
	method => 'PUT',
	description => "Update '$otype_text' object.",
	proxyto => 'master',
	parameters => {
	    additionalProperties => 0,
	    properties => $update_properties,
	},
	returns => { type => 'null' },
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    die "internal error" if $param->{id} !~ m/^(\d+)_(\d+)$/;
	    my ($ogroup, $objid) = ($1, $2);

	    my $action = $rdb->load_object_full($objid, $ogroup, $otype);

	    $action->update($param);

	    $action->save($rdb);

	    return undef;
	}});

};

$register_action_api->('PMG::RuleDB::BCC', 'bcc');


1;
