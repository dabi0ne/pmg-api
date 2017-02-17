package PMG::API2::Config;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use HTTP::Status qw(:constants);
use Storable qw(dclone);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;

use PMG::Config;

use base qw(PVE::RESTHandler);

my $section_type_enum = PMG::Config::Base->lookup_types();

__PACKAGE__->register_method ({
    name => 'index', 
    path => '',
    method => 'GET',
    description => "Directory index.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => { section => { type => 'string'} },
	},
	links => [ { rel => 'child', href => "{section}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];
	foreach my $section (@$section_type_enum) {
	    push @$res, { section => $section };
	}   
	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'read_section',
    path => '{section}',
    method => 'GET',
    description => "Read configuration properties.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    section => {
		description => "Section name.",
		type => 'string',
		enum => $section_type_enum,
	    },
	},
    },
    returns => { type => 'object' },
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();
	my $section = $param->{section};

	my $data = dclone($cfg->{ids}->{"section_$section"});
	$data->{digest} = $cfg->{digest};
	delete $data->{type};

	return $data;
    }});
