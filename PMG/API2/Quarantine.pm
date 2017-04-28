package PMG::API2::Quarantine;

use strict;
use warnings;
use Time::Local;
use Time::Zone;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Exception qw(raise_param_exc);
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::AccessControl;
use PMG::DBTools;

use base qw(PVE::RESTHandler);


__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Directory index.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $result = [
	    { name => 'deliver' },
	    { name => 'spam' },
	    { name => 'virus' },
	];

	return $result;
    }});

__PACKAGE__->register_method ({
    name => 'spam',
    path => 'spam',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Show spam mails distribution (per day).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => {
		description => "Only consider entries newer than 'startime' (unix epoch).",
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    endtime => {
		description => "Only consider entries older than 'endtime' (unix epoch).",
		type => 'integer',
		minimum => 1,
		optional => 1,
	    },
	    pmail => {
		description => "List entries for the user with this primary email address.",
		type => 'string', format => 'email',
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		day => {
		    description => "Day (as unix epoch).",
		    type => 'integer',
		},
		count => { 
		    description => "Number of quarantine entries.",
		    type => 'integer',
		},
		spamavg => {
		    description => "Average spam level.",
		    type => 'number',
		},		    
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();
	my $role = $rpcenv->get_role();

	my $pmail = $param->{pmail};

	if ($role eq 'quser') {
	    raise_param_exc({ pmail => "paramater not allwed with role '$role'"})
		if defined($pmail);
	    $pmail = $authuser;
	}

	my $res = [];
	
	my $dbh = PMG::DBTools::open_ruledb();

	my $start = $param->{starttime} // 0;
	my $end = $param->{endtime};

	my $timezone = tz_local_offset();

	my $sth = $dbh->prepare(
	    "SELECT " .
	    "((time + $timezone) / 86400) * 86400 - $timezone as day, " .
	    "count (ID) as count, avg (Spamlevel) as spamavg " .
	    "FROM CMailStore, CMSReceivers WHERE " .
	    ($start ? "time >= $start AND " : '') .
	    ($end ? "time < $end AND " : '') .
	    (defined($pmail) ? "pmail = ? AND " : '') .
	    "QType = 'S' AND CID = CMailStore_CID AND RID = CMailStore_RID " .
	    "AND Status = 'N' " .
	    "GROUP BY day " .
	    "ORDER BY day DESC");

	if (defined($pmail)) {
	    $sth->execute($pmail);
	} else {
	    $sth->execute();
	}

	while (my $ref = $sth->fetchrow_hashref()) {
	    push @$res, $ref;
	}

	return $res;
    }});

1;
