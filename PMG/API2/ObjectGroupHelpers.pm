package PMG::API2::ObjectGroupHelpers;

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

sub format_object_group {
    my ($ogroups) = @_;

    my $res = [];
    foreach my $og (@$ogroups) {
	push @$res, {
	    id => $og->{id}, name => $og->{name}, info => $og->{info}
	};
    }
    return $res;
}

sub register_group_list_api {
    my ($apiclass, $oclass) = @_;

    $apiclass->register_method({
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

	    return format_object_group($ogroups);
	}});

    $apiclass->register_method({
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

1;
