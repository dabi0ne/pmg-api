package PMG::API2::Quarantine;

use strict;
use warnings;
use Time::Local;
use Time::Zone;
use Data::Dumper;
use Encode;

use Mail::Header;
use Mail::SpamAssassin;

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

my $extract_pmail = sub {
    my ($authuser, $role) = @_;

    if ($authuser =~ m/^(.+)\@quarantine$/) {
	return $1;
    }
    raise_param_exc({ pmail => "got unexpected authuser '$authuser' with role '$role'"});
};

my $verify_optional_pmail = sub {
    my ($authuser, $role, $pmail_param) = @_;

    my $pmail;
    if ($role eq 'quser') {
	$pmail = $extract_pmail->($authuser, $role);
	raise_param_exc({ pmail => "parameter not allwed with role '$role'"})
	    if defined($pmail_param) && ($pmail ne $pmail_param);
    } else {
	raise_param_exc({ pmail => "parameter required with role '$role'"})
	    if !defined($pmail_param);
	$pmail = $pmail_param;
    }
    return $pmail;
};

sub decode_spaminfo {
    my ($info) = @_;

    my $saversion = Mail::SpamAssassin->VERSION;

    my $salocaldir = "/var/lib/spamassassin/$saversion/updates_spamassassin_org";

    $spamdesc = PMG::Utils::load_sa_descriptions([$salocaldir]) if !$spamdesc;

    my $res = [];

    foreach my $test (split (',', $info)) {
	my ($name, $score) = split (':', $test);

	my $info = { name => $name, score => $score + 0, desc => '-' };
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
    $res->{id} = 'C' . $ref->{cid} . 'R' . $ref->{rid} . 'T' . $ref->{ticketid};
    $res->{time} = $ref->{time};
    $res->{bytes} = $ref->{bytes};

    my $qtype = $ref->{qtype};

    if ($qtype eq 'V') {
	$res->{virusname} = $ref->{info};
	$res->{spamlevel} = 0;
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
	    { name => 'spamusers' },
	    { name => 'spamstatus' },
	    { name => 'virus' },
	    { name => 'virusstatus' },
	    { name => 'quarusers' },
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
	    address => get_standard_option('pmg-email-address', {
		description => "The address you want to add.",
	    }),
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
	    address => get_standard_option('pmg-email-address', {
		description => "The address you want to remove.",
	    }),
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
	    address => get_standard_option('pmg-email-address', {
		description => "The address you want to add.",
	    }),
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
	    address => get_standard_option('pmg-email-address', {
		description => "The address you want to remove.",
	    }),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	$read_or_modify_user_bw_list->('BL', $param, [ $param->{address} ], 1);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'spamusers',
    path => 'spamusers',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    description => "Get a list of receivers of spam in the given timespan (Default the last 24 hours).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		mail => {
		    description => 'the receiving email',
		    type => 'string',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $res = [];

	my $dbh = PMG::DBTools::open_ruledb();

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $sth = $dbh->prepare(
	    "SELECT DISTINCT pmail " .
	    "FROM CMailStore, CMSReceivers WHERE " .
	    "time >= $start AND time < $end AND " .
	    "QType = 'S' AND CID = CMailStore_CID AND RID = CMailStore_RID " .
	    "AND Status = 'N' ORDER BY pmail");

	$sth->execute();

	while (my $ref = $sth->fetchrow_hashref()) {
	    push @$res, { mail => $ref->{pmail} };
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'spamstatus',
    path => 'spamstatus',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    description => "Get Spam Quarantine Status",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => "object",
	properties => {
	    count => {
		description => 'Number of stored mails.',
		type => 'integer',
	    },
	    mbytes => {
		description => "Estimated disk space usage in MByte.",
		type => 'number',
	    },
	    avgbytes => {
		description => "Average size of stored mails in bytes.",
		type => 'number',
	    },
	    avgspam => {
		description => "Average spam level.",
		type => 'number',
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $dbh = PMG::DBTools::open_ruledb();
	my $ref =  PMG::DBTools::get_quarantine_count($dbh, 'S');

	return $ref;
    }});

__PACKAGE__->register_method ({
    name => 'quarusers',
    path => 'quarusers',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    description => "Get a list of users with whitelist/blacklist setttings.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		mail => {
		    description => 'the receiving email',
		    type => 'string',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $res = [];

	my $dbh = PMG::DBTools::open_ruledb();

	my $sth = $dbh->prepare(
	    "SELECT DISTINCT pmail FROM UserPrefs ORDER BY pmail");

	$sth->execute();

	while (my $ref = $sth->fetchrow_hashref()) {
	    push @$res, { mail => $ref->{pmail} };
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'spam',
    path => 'spam',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Get a list of quarantined spam mails in the given timeframe (default the last 24 hours) for the given user.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
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

	my $start = $param->{starttime} // (time - 86400);
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
    name => 'virus',
    path => 'virus',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit' ] },
    description => "Get a list of quarantined virus mails in the given timeframe (default the last 24 hours).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
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
		virusname => {
		    description => "Virus name.",
		    type => 'string',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $res = [];

	my $dbh = PMG::DBTools::open_ruledb();

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $sth = $dbh->prepare(
	    "SELECT * " .
	    "FROM CMailStore, CMSReceivers WHERE " .
	    "time >= $start AND time < $end AND " .
	    "QType = 'V' AND CID = CMailStore_CID AND RID = CMailStore_RID " .
	    "AND Status = 'N' ORDER BY time, receiver");

	$sth->execute();

	while (my $ref = $sth->fetchrow_hashref()) {
	    my $data = $parse_header_info->($ref);
	    push @$res, $data;
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'virusstatus',
    path => 'virusstatus',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    description => "Get Virus Quarantine Status",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => "object",
	properties => {
	    count => {
		description => 'Number of stored mails.',
		type => 'integer',
	    },
	    mbytes => {
		description => "Estimated disk space usage in MByte.",
		type => 'number',
	    },
	    avgbytes => {
		description => "Average size of stored mails in bytes.",
		type => 'number',
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $dbh = PMG::DBTools::open_ruledb();
	my $ref = PMG::DBTools::get_quarantine_count($dbh, 'V');

	delete $ref->{avgspam};
	
	return $ref;
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
		pattern => 'C\d+R\d+T\d+',
		maxLength => 60,
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
		},
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();
	my $role = $rpcenv->get_role();
	my $format = $rpcenv->get_format();

	my ($cid, $rid, $tid) = $param->{id} =~ m/^C(\d+)R(\d+)T(\d+)$/;
	$cid = int($cid);
	$rid = int($rid);
	$tid = int($tid);

	my $dbh = PMG::DBTools::open_ruledb();

	my $ref = PMG::DBTools::load_mail_data($dbh, $cid, $rid, $tid);

	if ($role eq 'quser') {
	    my $quar_username = $ref->{pmail} . '@quarantine';
	    raise_perm_exc("mail does not belong to user '$authuser' ($ref->{pmail})")
		if $authuser ne $quar_username;
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
	    $res->{spamlevel} = 0;
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
		description => 'Unique IDs, seperate with ;',
		type => 'string',
		pattern => 'C\d+R\d+T\d+(;C\d+R\d+T\d+)*',
		maxLength => 600,
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
	my @idlist = split(';', $param->{id});

	my $dbh = PMG::DBTools::open_ruledb();

	for my $id (@idlist) {
	    my ($cid, $rid, $tid) = $id =~ m/^C(\d+)R(\d+)T(\d+)$/;
	    $cid = int($cid);
	    $rid = int($rid);
	    $tid = int($tid);

	    my $ref = PMG::DBTools::load_mail_data($dbh, $cid, $rid, $tid);

	    if ($role eq 'quser') {
		my $quar_username = $ref->{pmail} . '@quarantine';
		raise_perm_exc("mail does not belong to user '$authuser' ($ref->{pmail})")
		if $authuser ne $quar_username;
	    }

	    my $sender = $get_real_sender->($ref);

	    if ($action eq 'whitelist') {
		PMG::Quarantine::add_to_blackwhite($dbh, $ref->{pmail}, 'WL', [ $sender ]);
	    } elsif ($action eq 'blacklist') {
		PMG::Quarantine::add_to_blackwhite($dbh, $ref->{pmail}, 'BL', [ $sender ]);
	    } elsif ($action eq 'deliver') {
		PMG::Quarantine::deliver_quarantined_mail($dbh, $ref, $ref->{receiver} // $ref->{pmail});
	    } elsif ($action eq 'delete') {
		PMG::Quarantine::delete_quarantined_mail($dbh, $ref);
	    } else {
		die "internal error"; # should not be reached
	    }
	}

	return undef;
    }});

1;
