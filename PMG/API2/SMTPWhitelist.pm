package PMG::API2::SMTPWhitelist;

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
use PMG::RuleDB;

use base qw(PVE::RESTHandler);

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
	    properties => {
		subdir => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	return [
	    { subdir => 'objects' },
	    { subdir => 'sender_domain' },
	    { subdir => 'receiver_domain' },
	];

    }});

__PACKAGE__->register_method ({
    name => 'objects',
    path => 'objects',
    method => 'GET',
    description => "Get list of all SMTP whitelist entries.",
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
		id => { type => 'integer'},
	    },
	},
	links => [ { rel => 'child', href => "{domain}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $gid = $rdb->greylistexclusion_groupid();

	my $og = $rdb->load_group_objects($gid);

	my $res = [];

	foreach my $obj (@$og) {
	    push @$res, {
		id => $obj->{id},
		otype => $obj->{otype},
		receivertest => $obj->receivertest(),
		descr => $obj->short_desc(),
	    };
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'sender_domain',
    path => 'sender_domain',
    method => 'POST',
    description => "Add a sender domain to the SMTP whitelist.",
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "DNS domain name.",
		type => 'string', format => 'dns-name',
	    },
	},
    },
    returns => {
	description => "The object ID.",
	type => 'integer',
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $gid = $rdb->greylistexclusion_groupid();

	my $og = $rdb->load_group_objects($gid);

	my $obj = PMG::RuleDB::Domain->new($param->{domain});
	$obj->{ogroup} = $gid;

	my $id = $obj->save($rdb);

	return $id;
    }});

__PACKAGE__->register_method ({
    name => 'receiver_domain',
    path => 'receiver_domain',
    method => 'POST',
    description => "Add a receiver domain to the SMTP whitelist.",
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "DNS domain name.",
		type => 'string', format => 'dns-name',
	    },
	},
    },
    returns => {
	description => "The object ID.",
	type => 'integer',
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $gid = $rdb->greylistexclusion_groupid();

	my $og = $rdb->load_group_objects($gid);

	my $obj = PMG::RuleDB::ReceiverDomain->new($param->{domain});
	$obj->{ogroup} = $gid;

	my $id = $obj->save($rdb);

	return $id;
    }});


__PACKAGE__->register_method ({
    name => 'delete_object',
    path => 'objects/{id}',
    method => 'DELETE',
    description => "Remove an object from the SMTP whitelist.",
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => {
		description => "Object ID.",
		type => 'integer',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $gid = $rdb->greylistexclusion_groupid();

	my $obj = $rdb->load_object($param->{id});

	die "object '$param->{id}' does not exists\n" if !defined($obj);

	$rdb->delete_object($obj);

	return undef;
    }});

1;
