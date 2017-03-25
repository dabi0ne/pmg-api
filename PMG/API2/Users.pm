package PMG::API2::Users;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::UserConfig;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "List users.",
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
		userid => { type => 'string'},
		enable => { type => 'boolean'},
		role => { type => 'string'},
		comment => { type => 'string', optional => 1},
	    },
	},
	links => [ { rel => 'child', href => "{userid}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::UserConfig->new();

	my $res = [];

	foreach my $userid (sort keys %$cfg) {
	    push @$res, $cfg->{$userid};
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create',
    path => '',
    method => 'POST',
    proxyto => 'master',
    protected => 1,
    description => "Creat new user",
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('username'),
	    password => {
		description => "Initial password.",
		type => 'string',
		optional => 1,
		minLength => 5,
		maxLength => 64
	    },
	    comment => {
		description => "Comment.",
		type => 'string',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PMG::UserConfig->new();

	    die "User '$param->{userid}' already exists\n"
		if $cfg->{$param->{userid}};

	    die "fixme";

	    $cfg->write();
	};

	PMG::UserConfig::lock_config($code, "create user failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'read',
    path => '{userid}',
    method => 'GET',
    description => "Read User data.",
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('username'),
	},
    },
    returns => {
	type => "object",
	properties => {},
    },
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::UserConfig->new();

	return $cfg->lookup_user_data($param->{userid});
    }});

__PACKAGE__->register_method ({
    name => 'write',
    path => '{userid}',
    method => 'PUT',
    description => "Update user data.",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('username'),
	    comment => {
		description => "Comment.",
		type => 'string',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PMG::UserConfig->new();

	    my $data = $cfg->lookup_user_data($param->{userid});

	    die "fixme";
	    #$data->{comment} = $param->{comment};

	    $cfg->write();
	};

	PMG::UserConfig::lock_config($code, "update user failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{userid}',
    method => 'DELETE',
    description => "Delete a user.",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('username'),
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PMG::UserConfig->new();

	    $cfg->lookup_user_data($param->{userid}); # user exists?

	    delete $cfg->{$param->{userid}};

	    $cfg->write();
	};

	PMG::UserConfig::lock_config($code, "delete user failed");

	return undef;
    }});

1;
