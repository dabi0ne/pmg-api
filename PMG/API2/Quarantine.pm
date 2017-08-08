package PMG::API2::Quarantine;

use strict;
use warnings;
use Time::Local;
use Time::Zone;
use Data::Dumper;

use  Mail::Header;

use PVE::SafeSyslog;
use PVE::Exception qw(raise_param_exc);
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::Utils;
use PMG::AccessControl;
use PMG::DBTools;

use base qw(PVE::RESTHandler);


my $parse_header_info = sub {
    my ($ref) = @_;

    my $res = { subject => '', from => '' };

    my @lines = split('\n', $ref->{header});
    my $head = Mail::Header->new(\@lines);

    $res->{subject} = PMG::Utils::decode_rfc1522(PVE::Tools::trim($head->get('subject'))) // '';

    my @fromarray = split('\s*,\s*', $head->get('from') || $ref->{sender});

    $res->{from} = PMG::Utils::decode_rfc1522(PVE::Tools::trim ($fromarray[0])) // '';

    my $sender = PMG::Utils::decode_rfc1522(PVE::Tools::trim($head->get('sender')));
    $res->{sender} = $sender if $sender;

    $res->{envelope_sender} = $ref->{sender};
    $res->{receiver} = $ref->{receiver};
    $res->{id} = $ref->{cid} . '_' . $ref->{rid};
    $res->{time} = $ref->{time};
    $res->{bytes} = $ref->{bytes};

    return $res;
};

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
		description => "List entries for the user with this primary email address. Quarantine users cannot speficy this parameter, but it is required for all other roles.",
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
	links => [ { rel => 'child', href => "{day}" } ],
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
	} else {
	    raise_param_exc({ pmail => "paramater required with role '$role'"})
		if !defined($pmail);
	}

	my $res = [];

	my $dbh = PMG::DBTools::open_ruledb();

	my $start = $param->{starttime};
	my $end = $param->{endtime};

	my $timezone = tz_local_offset();

	my $sth = $dbh->prepare(
	    "SELECT " .
	    "((time + $timezone) / 86400) * 86400 - $timezone as day, " .
	    "count (ID) as count, avg (Spamlevel) as spamavg " .
	    "FROM CMailStore, CMSReceivers WHERE " .
	    (defined($start) ? "time >= $start AND " : '') .
	    (defined($end) ? "time < $end AND " : '') .
	    "pmail = ? AND " .
	    "QType = 'S' AND CID = CMailStore_CID AND RID = CMailStore_RID " .
	    "AND Status = 'N' " .
	    "GROUP BY day " .
	    "ORDER BY day DESC");

	$sth->execute($pmail);

	while (my $ref = $sth->fetchrow_hashref()) {
	    push @$res, $ref;
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'spamlist',
    path => 'spam/{starttime}',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Show spam mails distribution (per day).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => {
		description => "Only consider entries newer than 'starttime' (unix epoch).",
		type => 'integer',
		minimum => 0,
	    },
	    endtime => {
		description => "Only consider entries older than 'endtime' (unix epoch). This is set to '<start> + 1day' by default.",
		type => 'integer',
		minimum => 1,
		optional => 1,
	    },
	    pmail => {
		description => "List entries for the user with this primary email address. Quarantine users cannot speficy this parameter, but it is required for all other roles.",
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
		id => {
		    description => 'Unique ID',
		    type => 'string',
		},
		bytes => {
		    description => "Size of raw email.",
		    type => 'integer' ,
		},
		envelope_sender => {
		    description => "SMTP envelope sender.",
		    type => 'string',
		},
		from => {
		    description => "Header 'From' field.",
		    type => 'string',
		},
		sender => {
		    description => "Header 'Sender' field.",
		    type => 'string',
		    optional => 1,
		},
		receiver => {
		    description => "Receiver email address",
		    type => 'string',
		},
		subject => {
		    description => "Header 'Subject' field.",
		    type => 'string',
		},
		time => {
		    description => "Receive time stamp",
		    type => 'integer',
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
	} else {
	    raise_param_exc({ pmail => "paramater required with role '$role'"})
		if !defined($pmail);
	}

	my $res = [];

	my $dbh = PMG::DBTools::open_ruledb();

	my $start = $param->{starttime};
	my $end = $param->{endtime} // ($start + 86400);

	my $sth = $dbh->prepare(
	    "SELECT * " .
	    "FROM CMailStore, CMSReceivers WHERE " .
	    "pmail = ? AND time >= $start AND time < $end AND " .
	    "QType = 'S' AND CID = CMailStore_CID AND RID = CMailStore_RID " .
	    "AND Status = 'N' ORDER BY pmail, time, receiver");

	$sth->execute($pmail);

	while (my $ref = $sth->fetchrow_hashref()) {
	    my $data = $parse_header_info->($ref);
	    push @$res, $data;
	}

	return $res;
    }});

1;
