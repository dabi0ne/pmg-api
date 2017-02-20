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

__PACKAGE__->register_method ({
    name => 'create',
    path => '',
    method => 'POST',
    proxyto => 'master',
    protected => 1,
    description => "Add relay domain.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "Domain name.",
		type => 'string', format => 'dns-name',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $domains = PVE::INotify::read_file('domains');

	    die "Domain '$param->{domain}' already exists\n"
		if grep { $_ eq $param->{domain} } @$domains;

	    push @$domains, $param->{domain};

	    PVE::INotify::write_file('domains', $domains);
	};

	PMG::Config::lock_config($code, "add relay domain failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{domain}',
    method => 'DELETE',
    description => "Delete a relay domain",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "Domain name.",
		type => 'string', format => 'dns-name',
	    },
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $domains = PVE::INotify::read_file('domains');

	    die "Domain '$param->{domain}' does not exist\n"
		if !grep { $_ eq $param->{domain} } @$domains;

	    my $res = [ grep { $_ ne $param->{domain} } @$domains ];

	    PVE::INotify::write_file('domains', $res);
	};

	PMG::Config::lock_config($code, "delete relay domain failed");

	return undef;
    }});

1;
