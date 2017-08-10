package PMG::API2::Quarantine;

use strict;
use warnings;
use Time::Local;
use Time::Zone;
use Data::Dumper;
use Encode;

use Mail::Header;

use PVE::SafeSyslog;
use PVE::Exception qw(raise_param_exc raise_perm_exc);
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;
use PVE::APIServer::Formatter;

use PMG::Utils;
use PMG::AccessControl;
use PMG::Config;
use PMG::DBTools;
use PMG::HTMLMail;

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
    $res->{id} = 'C' . $ref->{cid} . 'R' . $ref->{rid};
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
	    { name => 'content' },
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

__PACKAGE__->register_method ({
    name => 'content',
    path => 'content',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Get email data. There is a special formatter called 'htmlmail' to get sanitized html view of the mail content (use the '/api2/htmlmail/quarantine/content' url).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => {
		description => 'Unique ID',
		type => 'string',
		pattern => 'C\d+R\d+',
		maxLength => 40,
	    },
	    raw => {
		description => "Display 'raw' eml data. This is only used with the 'htmlmail' formatter.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();
	my $role = $rpcenv->get_role();
	my $format = $rpcenv->get_format();

	my ($cid, $rid) = $param->{id} =~ m/^C(\d+)R(\d+)$/;
	$cid = int($cid);
	$rid = int($rid);

	my $dbh = PMG::DBTools::open_ruledb();

	my $ref = PMG::DBTools::load_mail_data($dbh, $cid, $rid);

	if ($role eq 'quser') {
	    raise_perm_exc("mail does not belong to user '$authuser'")
		if $authuser ne $ref->{pmail};
	}

	my $res = $parse_header_info->($ref);

	foreach my $k (qw(info file spamlevel)) {
	    $res->{$k} = $ref->{$k} if defined($ref->{$k});
	}

	my $filename = $ref->{file};
	my $spooldir = $PMG::MailQueue::spooldir;

	my $path = "$spooldir/$filename";

	if ($format eq 'htmlmail') {

	    my $cfg = PMG::Config->new();
	    my $viewimages = $cfg->get('spamquar', 'viewimages');
	    my $allowhref = $cfg->get('spamquar', 'allowhrefs');

	    $res->{header} = ''; # not required
	    $res->{content} = PMG::HTMLMail::email_to_html($path, $param->{raw}, $viewimages, $allowhref);

	} else {
	    my ($header, $content) = PMG::HTMLMail::read_raw_email($path, 4096);

	    $res->{header} = $header;
	    $res->{content} = $content;
	}


	return $res;

    }});

PVE::APIServer::Formatter::register_page_formatter(
    'format' => 'htmlmail',
    method => 'GET',
    path => '/quarantine/content',
    code => sub {
        my ($res, $data, $param, $path, $auth, $config) = @_;

	if(!HTTP::Status::is_success($res->{status})) {
	    return ("Error $res->{status}: $res->{message}", "text/plain");
	}

	my $ct = "text/html;charset=UTF-8";

	my $raw = $data->{content};

	return (encode('UTF-8', $raw), $ct, 1);
});

1;
