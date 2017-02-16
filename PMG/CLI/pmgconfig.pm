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
use PMG::LDAPSet;
use PMG::Config;

use base qw(PVE::CLIHandler);

__PACKAGE__->register_method ({
    name => 'pmgconfig',
    path => 'pmgconfig',
    method => 'POST',
    description => "Syncronize Proxmox Mail Gateway configurations with system configuration. Prints the configuration when no options specified.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    syncronize => {
		description => "Re-generate all configuration files.",
		type => 'boolean',
		default => 0,
		optional => 1,
	    },
	    ldapsync => {
		description => "Re-generate ldap database.",
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

	if (!scalar(keys %$param)) {
	    my $raw = PMG::Config::Base->write_config('pmg.conf', $cfg);
	    print $raw;
	    return undef;
	}

	if ($param->{syncronize}) {
	    $cfg->rewrite_config();
	    return undef;
	}

	if ($param->{ldapsync}) {
	    PMG::LDAPSet::ldap_resync($cfg, 1);
	}

	return undef;
    }});

our $cmddef = [ __PACKAGE__, 'pmgconfig', []];


1;
