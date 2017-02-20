package PMG::API2::Domains;

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

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "List relay domains.",
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		domain => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{section}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $domains = PVE::INotify::read_file('domains');

	my $res = [];

	foreach my $domain (@$domains) {
	    push @$res, { domain => $domain };
	}

	return $res;
    }});

1;
