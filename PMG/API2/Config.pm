package PMG::API2::Config;

use strict;
use warnings;
use Data::Dumper;

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
	properties => {},
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

my $api_read_config_section = sub {
    my ($section) = @_;

    my $cfg = PMG::Config->new();

    my $data = dclone($cfg->{ids}->{"section_$section"});
    $data->{digest} = $cfg->{digest};
    delete $data->{type};

    return $data;
};

my $api_update_config_section = sub {
   my ($section, $param) = @_;

   my $code = sub {
       my $cfg = PMG::Config->new();
       my $ids = $cfg->{ids};

       my $digest = extract_param($param, 'digest');
       PVE::SectionConfig::assert_if_modified($cfg, $digest);

       my $delete_str = extract_param($param, 'delete');
       die "no options specified\n"
	   if !$delete_str && !scalar(keys %$param);

       foreach my $opt (PVE::Tools::split_list($delete_str)) {
	   delete $ids->{"section_$section"}->{$opt};
       }

       my $plugin = PMG::Config::Base->lookup($section);
       my $config = $plugin->check_config($section, $param, 0, 1);

       foreach my $p (keys %$config) {
	   $ids->{"section_$section"}->{$p} = $config->{$p};
       }

       $cfg->write();
   };

   PMG::Config::lock_config($code, "update config section '$section' failed");
};

foreach my $section (@$section_type_enum) {

    next if $section eq 'ldap'; # fixme

    my $plugin = PMG::Config::Base->lookup($section);

    __PACKAGE__->register_method ({
	name => "read_${section}_section",
	path => $section,
	method => 'GET',
	description => "Read $section configuration properties.",
	parameters => {
	    additionalProperties => 0,
	    properties => {},
	},
	returns => { type => 'object' },
	code => sub {
	    my ($param) = @_;

	    return $api_read_config_section->($section);
	}});

    __PACKAGE__->register_method ({
	name => "update_${section}_section",
	path => $section,
	method => 'PUT',
	description => "Update $section configuration properties.",
	parameters => $plugin->updateSchema(1),
	returns => { type => 'null' },
	code => sub {
	    my ($param) = @_;

	    $api_update_config_section->($section, $param);

	    return undef;
	}});
}

1;
