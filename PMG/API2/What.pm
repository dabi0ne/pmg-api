package PMG::API2::What;

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

use PMG::RuleDB::TimeFrame;
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
	    { subdir => 'config' },
	    { subdir => 'objects' },
	    { subdir => 'contenttype' },
	    { subdir => 'matchfield' },
	];

    }});

PMG::API2::ObjectGroupHelpers::register_delete_object_group_api(__PACKAGE__, 'what', '');
PMG::API2::ObjectGroupHelpers::register_object_group_config_api(__PACKAGE__, 'what', 'config');
PMG::API2::ObjectGroupHelpers::register_objects_api(__PACKAGE__, 'what', 'objects');

PMG::RuleDB::ContentTypeFilter->register_api(__PACKAGE__, 'contenttype');
PMG::RuleDB::MatchField->register_api(__PACKAGE__, 'matchfield');

1;
