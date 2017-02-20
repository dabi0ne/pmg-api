package PMG::API2::LDAP;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use HTTP::Status qw(:constants);
use Storable qw(dclone);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;

use PMG::LDAPConfig;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "LDAP server list.",
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
		section => { type => 'string'},
		server1 => { type => 'string'},
		mode => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{section}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $ldap_cfg = PVE::INotify::read_file("pmg-ldap.conf");
	
	my $res = [];

	if (defined($ldap_cfg)) {
	    foreach my $section (keys %{$ldap_cfg->{ids}}) {	    
		my $d = $ldap_cfg->{ids}->{$section};
		push @$res, {
		    section => $section,
		    server1 => $d->{server1},
		    mode => $d->{mode} // 'ldap',
		};
	    }
	}
	
	return $res;
    }});

1;
