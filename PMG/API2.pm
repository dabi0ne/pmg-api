package PMG::API2;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::JSONSchema;

use PMG::API2::AccessControl;
use PMG::API2::Nodes;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Nodes",  
    path => 'nodes',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::AccessControl",  
    path => 'access',
});

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
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
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($resp, $param) = @_;

	my $res = [ { subdir => 'nodes' } ];

	return $res;
    }});


1;
