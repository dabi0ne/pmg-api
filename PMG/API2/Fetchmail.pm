package PMG::API2::Fetchmail;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::Config;
use PMG::Fetchmail;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "List fetchmail users.",
    permissions => { check => [ 'admin', 'audit' ] },
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
		id => { type => 'string'},
		target => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{id}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $fmcfg = PVE::INotify::read_file('fetchmailrc');

	my $res = [];

	foreach my $id (sort keys %$fmcfg) {
	    push @$res, $fmcfg->{$id};
	}

	return $res;
    }});

1;
