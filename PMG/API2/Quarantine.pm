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
use PMG::Quarantine;

use base qw(PVE::RESTHandler);

my $spamdesc;

my $verify_optional_pmail = sub {
    my ($authuser, $role, $pmail) = @_;

    if ($role eq 'quser') {
	raise_param_exc({ pmail => "paramater not allwed with role '$role'"})
	    if defined($pmail);
	$pmail = $authuser;
    } else {
	raise_param_exc({ pmail => "paramater required with role '$role'"})
	    if !defined($pmail);
    }
    return $pmail;
};

sub decode_spaminfo {
    my ($info) = @_;

    $spamdesc = PMG::Utils::load_sa_descriptions() if !$spamdesc;

    my $res = [];

    foreach my $test (split (',', $info)) {
	my ($name, $score) = split (':', $test);

	my $info = { name => $name, score => $score, desc => '-' };
	if (my $si = $spamdesc->{$name}) {
	    $info->{desc} = $si->{desc};
	    $info->{url} = $si->{url} if defined($si->{url});
	}
	push @$res, $info;
    }

    return $res;
}

my $extract_email = sub {
    my $data = shift;

    return $data if !$data;

    if ($data =~ m/^.*\s(\S+)\s*$/) {
	$data = $1;
    }

    if ($data =~ m/^<([^<>\s]+)>$/) {
	$data = $1;
    }

    if ($data !~ m/[\s><]/ && $data =~ m/^(.+\@[^\.]+\..*[^\.]+)$/) {
	$data = $1;
    } else {
	$data = undef;
    }

    return $data;
};

my $get_real_sender = sub {
    my ($ref) = @_;

    my @lines = split('\n', $ref->{header});
    my $head = Mail::Header->new(\@lines);

    my @fromarray = split ('\s*,\s*', $head->get ('from') || $ref->{sender});
    my $from =  $extract_email->($fromarray[0]) || $ref->{sender};;
    my $sender = $extract_email->($head->get ('sender'));

    return $sender if $sender;

    return $from;
};

my $parse_header_info = sub {
    my ($ref) = @_;

    my $res = { subject => '', from => '' };

    my @lines = split('\n', $ref->{header});
    my $head = Mail::Header->new(\@lines);

    $res->{subject} = PMG::Utils::decode_rfc1522(PVE::Tools::trim($head->get('subject'))) // '';

    my @fromarray = split('\s*,\s*', $head->get('from') || $ref->{sender});

    $res->{from} = PMG::Utils::decode_rfc1522(PVE::Tools::trim ($fromarray[0])) // '';

    my $sender = PMG::Utils::decode_rfc1522(PVE::Tools::trim($head->get('sender')));
    $res->{sender} = $sender if $sender && ($sender ne $res->{from});

    $res->{envelope_sender} = $ref->{sender};
    $res->{receiver} = $ref->{receiver} // $ref->{pmail};
    $res->{id} = 'C' . $ref->{cid} . 'R' . $ref->{rid};
    $res->{time} = $ref->{time};
    $res->{bytes} = $ref->{bytes};

    my $qtype = $ref->{qtype};

    if ($qtype eq 'V') {
	$res->{virusname} = $ref->{info};
    } elsif ($qtype eq 'S') {
	$res->{spamlevel} = $ref->{spamlevel} // 0;
    }

    return $res;
};

my $pmail_param_type = {
    description => "List entries for the user with this primary email address. Quarantine users cannot speficy this parameter, but it is required for all other roles.",
    type => 'string', format => 'email',
    optional => 1,
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
	    { name => 'whitelist' },
	    { name => 'blacklist' },
	    { name => 'content' },
	    { name => 'spam' },
	    { name => 'virus' },
	];

	return $result;
    }});


my $read_or_modify_user_bw_list = sub {
    my ($listname, $param, $addrs, $delete) = @_;

    my $rpcenv = PMG::RESTEnvironment->get();
    my $authuser = $rpcenv->get_user();
    my $role = $rpcenv->get_role();

    my $pmail = $verify_optional_pmail->($authuser, $role, $param->{pmail});

    my $dbh = PMG::DBTools::open_ruledb();

    my $list = PMG::Quarantine::add_to_blackwhite(
	$dbh, $pmail, $listname, $addrs, $delete);

    my $res = [];
    foreach my $a (@$list) { push @$res, { address => $a }; }
    return $res;
};

my $address_pattern = '[a-zA-Z0-9\+\-\_\*\.\@]+';

__PACKAGE__->register_method ({
    name => 'whitelist',
    path => 'whitelist',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Show user whitelist.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		address => {
		    type => "string",
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	return $read_or_modify_user_bw_list->('WL', $param);
    }});

__PACKAGE__->register_method ({
    name => 'whitelist_add',
    path => 'whitelist',
    method => 'POST',
    description => "Add user whitelist entries.",
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	    address => {
		description => "The address you want to add.",
		type => "string",
		pattern => $address_pattern,
		maxLength => 512,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	$read_or_modify_user_bw_list->('WL', $param, [ $param->{address} ]);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'whitelist_delete',
    path => 'whitelist/{address}',
    method => 'DELETE',
    description => "Delete user whitelist entries.",
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	    address => {
		description => "The address you want to remove.",
		type => "string",
		pattern => $address_pattern,
		maxLength => 512,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	$read_or_modify_user_bw_list->('WL', $param, [ $param->{address} ], 1);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'blacklist',
    path => 'blacklist',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Show user blacklist.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		address => {
		    type => "string",
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	return $read_or_modify_user_bw_list->('BL', $param);
    }});

__PACKAGE__->register_method ({
    name => 'blacklist_add',
    path => 'blacklist',
    method => 'POST',
    description => "Add user blacklist entries.",
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	    address => {
		description => "The address you want to add.",
		type => "string",
		pattern => $address_pattern,
		maxLength => 512,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	$read_or_modify_user_bw_list->('BL', $param, [ $param->{address} ]);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'blacklist_delete',
    path => 'blacklist/{address}',
    method => 'DELETE',
    description => "Delete user blacklist entries.",
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	    address => {
		description => "The address you want to remove.",
		type => "string",
		pattern => $address_pattern,
		maxLength => 512,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	$read_or_modify_user_bw_list->('BL', $param, [ $param->{address} ], 1);

	return undef;
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
	    pmail => $pmail_param_type,
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

	my $pmail = $verify_optional_pmail->($authuser, $role, $param->{pmail});

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
	    pmail => $pmail_param_type,
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
		spamlevel => {
		    description => "Spam score.",
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

	my $pmail = $verify_optional_pmail->($authuser, $role, $param->{pmail});

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
		spamlevel => {
		    description => "Spam score.",
		    type => 'number',
		},
		spaminfo => {
		    description => "Information about matched spam tests (name, score, desc, url).",
		    type => 'array',
		},
		header => {
		    description => "Raw email header data.",
		    type => 'string',
		},
		content => {
		    description => "Raw email data (first 4096 bytes). Useful for preview. NOTE: The  'htmlmail' formatter displays the whole email.",
		    type => 'string',
		}
	},
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


	my $filename = $ref->{file};
	my $spooldir = $PMG::MailQueue::spooldir;

	my $path = "$spooldir/$filename";

	if ($format eq 'htmlmail') {

	    my $cfg = PMG::Config->new();
	    my $viewimages = $cfg->get('spamquar', 'viewimages');
	    my $allowhref = $cfg->get('spamquar', 'allowhrefs');

	    $res->{content} = PMG::HTMLMail::email_to_html($path, $param->{raw}, $viewimages, $allowhref);

	    # to make result verification happy
	    $res->{file} = '';
	    $res->{header} = '';
	    $res->{spaminfo} = [];
	} else {
	    # include additional details

	    my ($header, $content) = PMG::HTMLMail::read_raw_email($path, 4096);

	    $res->{file} = $ref->{file};
	    $res->{spaminfo} = decode_spaminfo($ref->{info});
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

__PACKAGE__->register_method ({
    name =>'action',
    path => 'content',
    method => 'POST',
    description => "Execute quarantine actions.",
    permissions => { check => [ 'admin', 'qmanager', 'quser'] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => {
		description => 'Unique ID',
		type => 'string',
		pattern => 'C\d+R\d+',
		maxLength => 40,
	    },
	    action => {
		description => 'Action - specify what you want to do with the mail.',
		type => 'string',
		enum => ['whitelist', 'blacklist', 'deliver', 'delete'],
	    },
	},
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();
	my $role = $rpcenv->get_role();
	my $action = $param->{action};

	my ($cid, $rid) = $param->{id} =~ m/^C(\d+)R(\d+)$/;
	$cid = int($cid);
	$rid = int($rid);

	my $dbh = PMG::DBTools::open_ruledb();

	my $ref = PMG::DBTools::load_mail_data($dbh, $cid, $rid);

	if ($role eq 'quser') {
	    raise_perm_exc("mail does not belong to user '$authuser'")
		if $authuser ne $ref->{pmail};
	}

	my $sender = $get_real_sender->($ref);
	my $username = $ref->{pmail};

	if ($action eq 'whitelist') {
	    PMG::Quarantine::add_to_blackwhite($dbh, $username, 'WL', [ $sender ]);
	} elsif ($action eq 'blacklist') {
	    PMG::Quarantine::add_to_blackwhite($dbh, $username, 'BL', [ $sender ]);
	} elsif ($action eq 'deliver') {
	    my $targets = [ $ref->{pmail} ];
	    PMG::Quarantine::deliver_quarantined_mail($dbh, $ref, $targets);
	} elsif ($action eq 'delete') {
	    PMG::Quarantine::delete_quarantined_mail($dbh, $ref);
	} else {
	    die "internal error"; # should not be reached
	}

	return undef;
    }});

1;
