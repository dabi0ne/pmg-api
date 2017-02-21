package PMG::CLI::pmgconfig;

use strict;
use warnings;
use IO::File;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::CLIHandler;

use PMG::Cluster;
use PMG::LDAPConfig;
use PMG::LDAPSet;
use PMG::Config;

use base qw(PVE::CLIHandler);

__PACKAGE__->register_method ({
    name => 'dump',
    path => 'dump',
    method => 'POST',
    description => "Print configuration setting which can be used in templates.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();
	my $vars = $cfg->get_template_vars();

	foreach my $realm (sort keys %$vars) {
	    foreach my $section (sort keys %{$vars->{$realm}}) {
		my $secvalue = $vars->{$realm}->{$section} // '';
		if (ref($secvalue)) {
		    foreach my $key (sort keys %{$vars->{$realm}->{$section}}) {
			my $value = $vars->{$realm}->{$section}->{$key} // '';
			print "$realm.$section.$key = $value\n";
		    }
		} else {
		    print "$realm.$section = $secvalue\n";
		}
	    }
	}

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'sync',
    path => 'sync',
    method => 'POST',
    description => "Syncronize Proxmox Mail Gateway configurations with system configuration.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    restart => {
		description => "Restart services if necessary.",
		type => 'boolean',
		default => 0,
		optional => 1,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();
	$cfg->rewrite_config($param->{restart});

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'ldapsync',
    path => 'ldapsync',
    method => 'POST',
    description => "Syncronize the LDAP database.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $ldap_cfg = PVE::INotify::read_file("pmg-ldap.conf");
	PMG::LDAPSet::ldap_resync($ldap_cfg, 1);

	return undef;
    }});

our $cmddef = {
    'dump' => [ __PACKAGE__, 'dump', []],
    sync => [ __PACKAGE__, 'sync', []],
    ldapsync => [ __PACKAGE__, 'ldapsync', []],
};


1;
