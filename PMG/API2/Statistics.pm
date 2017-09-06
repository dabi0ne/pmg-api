package PMG::API2::Statistics;

use strict;
use warnings;
use Data::Dumper;
use JSON;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Exception qw(raise_param_exc);
use PVE::RESTHandler;
use PMG::RESTEnvironment;
use PVE::JSONSchema qw(get_standard_option);

use PMG::Utils;
use PMG::RuleDB;
use PMG::Statistic;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
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

	return [
	    { name => "contact" },
	    { name => "domains" },
	    { name => "mail" },
	    { name => "mailcount" },
	    { name => "maildistribution" },
	    { name => "spamscores" },
	    { name => "sender" },
	    { name => "receiver" },
	    { name => "virus" },
	];
    }});

my $decode_orderby = sub {
    my ($orderby, $allowed_props) = @_;

    my $sorters;

    eval { $sorters = decode_json($orderby); };
    if (my $err = $@) {
	raise_param_exc({ orderby => 'invalid JSON'});
    }

    my $schema = {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		property => {
		    type => 'string',
		    enum => $allowed_props,
		},
		direction => {
		    type => 'string',
		    enum => ['ASC', 'DESC'],
		},
	    },
	},
    };

    PVE::JSONSchema::validate($sorters, $schema, "Parameter 'orderby' verification failed\n");

    return $sorters;
};

my $orderby_param_desc = {
    description => "Remote sorting (ExtJS compatible).",
    type => 'string',
    optional => 1,
    maxLength => 4096,
};

my $userstat_limit = 2000; # hardcoded limit


__PACKAGE__->register_method ({
    name => 'contact',
    path => 'contact',
    method => 'GET',
    description => "Contact Address Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    filter => {
		description => "Contact address filter.",
		type => 'string',
		maxLength => 512,
		optional => 1,
	    },
	    orderby => $orderby_param_desc,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		contact => {
		    description => "Contact email.",
		    type => 'string',
		},
		count => {
		    description => "Mail count.",
		    type => 'number',
		    optional => 1,
		},
		bytes => {
		    description => "Mail traffic (Bytes).",
		    type => 'number',
		},
		viruscount => {
		    description => "Number of sent virus mails.",
		    type => 'number',
		    optional => 1,
		},
	    },
	},
	links => [ { rel => 'child', href => "{contact}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $sorters = [];
	if ($param->{orderby}) {
	    my $props = ['contact', 'count', 'bytes', 'viruscount'];
	    $sorters = $decode_orderby->($param->{orderby}, $props);
	}

	my $res = $stat->user_stat_contact($rdb, $userstat_limit, $sorters, $param->{filter});

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'contactdetails',
    path => 'contact/{contact}',
    method => 'GET',
    description => "Detailed Contact Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    contact => get_standard_option('pmg-email-address', {
		description => "Contact email address.",
	    }),
	    filter => {
		description => "Sender address filter.",
		type => 'string',
		maxLength => 512,
		optional => 1,
	    },
	    orderby => $orderby_param_desc,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		time => {
		    description => "Receive time stamp",
		    type => 'integer',
		},
		sender => {
		    description => "Sender email.",
		    type => 'string',
		},
		bytes => {
		    description => "Mail traffic (Bytes).",
		    type => 'number',
		},
		blocked => {
		    description => "Mail was blocked.",
		    type => 'boolean',
		},
		spamlevel => {
		    description => "Spam score.",
		    type => 'number',
		},
		virusinfo => {
		    description => "Virus name.",
		    type => 'string',
		    optional => 1,
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $sorters = [];
	if ($param->{orderby}) {
	    my $props = ['time', 'sender', 'bytes', 'blocked', 'spamlevel', 'virusinfo'];
	    $sorters = $decode_orderby->($param->{orderby}, $props);
	}

	return $stat->user_stat_contact_details(
	    $rdb, $param->{contact}, $userstat_limit, $sorters, $param->{filter});
    }});

__PACKAGE__->register_method ({
    name => 'sender',
    path => 'sender',
    method => 'GET',
    description => "Sender Address Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    filter => {
		description => "Sender address filter.",
		type => 'string',
		maxLength => 512,
		optional => 1,
	    },
	    orderby => $orderby_param_desc,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		sender => {
		    description => "Sender email.",
		    type => 'string',
		},
		count => {
		    description => "Mail count.",
		    type => 'number',
		    optional => 1,
		},
		bytes => {
		    description => "Mail traffic (Bytes).",
		    type => 'number',
		},
		viruscount => {
		    description => "Number of sent virus mails.",
		    type => 'number',
		    optional => 1,
		},
	    },
	},
	links => [ { rel => 'child', href => "{sender}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $sorters = [];
	if ($param->{orderby}) {
	    my $props = ['sender', 'count', 'bytes', 'viruscount'];
	    $sorters = $decode_orderby->($param->{orderby}, $props);
	}

	my $res = $stat->user_stat_sender($rdb, $userstat_limit, $sorters, $param->{filter});

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'senderdetails',
    path => 'sender/{sender}',
    method => 'GET',
    description => "Detailed Sender Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    sender => get_standard_option('pmg-email-address', {
		description => "Sender email address.",
	    }),
	    filter => {
		description => "Receiver address filter.",
		type => 'string',
		maxLength => 512,
		optional => 1,
	    },
	    orderby => $orderby_param_desc,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		time => {
		    description => "Receive time stamp",
		    type => 'integer',
		},
		receiver => {
		    description => "Receiver email.",
		    type => 'string',
		},
		bytes => {
		    description => "Mail traffic (Bytes).",
		    type => 'number',
		},
		blocked => {
		    description => "Mail was blocked.",
		    type => 'boolean',
		},
		spamlevel => {
		    description => "Spam score.",
		    type => 'number',
		},
		virusinfo => {
		    description => "Virus name.",
		    type => 'string',
		    optional => 1,
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $sorters = [];
	if ($param->{orderby}) {
	    my $props = ['time', 'receiver', 'bytes', 'blocked', 'spamlevel', 'virusinfo'];
	    $sorters = $decode_orderby->($param->{orderby}, $props);
	}

	return $stat->user_stat_sender_details(
	    $rdb, $param->{sender}, $userstat_limit, $sorters, $param->{filter});
    }});

__PACKAGE__->register_method ({
    name => 'receiver',
    path => 'receiver',
    method => 'GET',
    description => "Receiver Address Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    filter => {
		description => "Receiver address filter.",
		type => 'string',
		maxLength => 512,
		optional => 1,
	    },
	    orderby => $orderby_param_desc,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		receiver => {
		    description => "Sender email.",
		    type => 'string',
		},
		count => {
		    description => "Mail count.",
		    type => 'number',
		    optional => 1,
		},
		bytes => {
		    description => "Mail traffic (Bytes).",
		    type => 'number',
		},
		spamcount => {
		    description => "Number of sent spam mails.",
		    type => 'number',
		    optional => 1,
		},
		viruscount => {
		    description => "Number of sent virus mails.",
		    type => 'number',
		    optional => 1,
		},
	    },
	},
	links => [ { rel => 'child', href => "{receiver}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	# fixme: advanced stat setting
	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $sorters = [];
	if ($param->{orderby}) {
	    my $props = ['receiver', 'count', 'bytes', 'spamcount', 'viruscount'];
	    $sorters = $decode_orderby->($param->{orderby}, $props);
	}

	my $res = $stat->user_stat_receiver($rdb, $userstat_limit, $sorters, $param->{filter});

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'receiverdetails',
    path => 'receiver/{receiver}',
    method => 'GET',
    description => "Detailed Receiver Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    receiver => get_standard_option('pmg-email-address', {
		description => "Receiver email address.",
	    }),
	    filter => {
		description => "Sender address filter.",
		type => 'string',
		maxLength => 512,
		optional => 1,
	    },
	    orderby => $orderby_param_desc,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		time => {
		    description => "Receive time stamp",
		    type => 'integer',
		},
		sender => {
		    description => "Sender email.",
		    type => 'string',
		},
		bytes => {
		    description => "Mail traffic (Bytes).",
		    type => 'number',
		},
		blocked => {
		    description => "Mail was blocked.",
		    type => 'boolean',
		},
		spamlevel => {
		    description => "Spam score.",
		    type => 'number',
		},
		virusinfo => {
		    description => "Virus name.",
		    type => 'string',
		    optional => 1,
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $sorters = [];
	if ($param->{orderby}) {
	    my $props = ['time', 'sender', 'bytes', 'blocked', 'spamlevel', 'virusinfo'];
	    $sorters = $decode_orderby->($param->{orderby}, $props);
	}

	return $stat->user_stat_receiver_details(
	    $rdb, $param->{receiver}, $userstat_limit, $sorters, $param->{filter});
    }});

__PACKAGE__->register_method ({
    name => 'domains',
    path => 'domains',
    method => 'GET',
    description => "Mail Domains Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
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
		domain => {
		    description => "Domain name.",
		    type => 'string',
		},
		count_in => {
		    description => "Incoming mail count.",
		    type => 'number',
		},
		count_out => {
		    description => "Outgoing mail count.",
		    type => 'number',
		},
		spamcount_in => {
		    description => "Incoming spam mails.",
		    type => 'number',
		},
		spamcount_out => {
		    description => "Outgoing spam mails.",
		    type => 'number',
		},
		mbytes_in => {
		    description => "Incoming mail traffic (Mebibytes).",
		    type => 'number',
		},
		mbytes_out => {
		    description => "Outgoing mail traffic (Mebibytes).",
		    type => 'number',
		},
		viruscount_in => {
		    description => "Number of incoming virus mails.",
		    type => 'number',
		},
		viruscount_out => {
		    description => "Number of outgoing virus mails.",
		    type => 'number',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	#PMG::Statistic::update_stats_domainstat_in($rdb->{dbh}, $cinfo);
	#PMG::Statistic::update_stats_domainstat_out($rdb->{dbh}, $cinfo);

	my $res = $stat->total_domain_stat($rdb);


	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'mail',
    path => 'mail',
    method => 'GET',
    description => "General Mail Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	},
    },
    returns => {
	type => "object",
	properties => {
	    avptime => {
		description => "Average mail processing time in seconds.",
		type => 'number',
	    },
	    bounces_in => {
		description => "Incoming bounce mail count (sender = <>).",
		type => 'number',
	    },
	    bounces_out => {
		description => "Outgoing bounce mail count (sender = <>).",
		type => 'number',
	    },
	    count => {
		description => "Overall mail count (in and out).",
		type => 'number',
	    },
	    count_in => {
		description => "Incoming mail count.",
		type => 'number',
	    },
	    count_out => {
		description => "Outgoing mail count.",
		type => 'number',
	    },
	    glcount => {
		description => "Number of greylisted mails.",
		type => 'number',
	    },
	    junk_in => {
		description => "Incoming junk mail count (viruscount_in + spamcount_in + glcount + spfcount).",
		type => 'number',
	    },
	    junk_out => {
		description => "Outgoing junk mail count (viruscount_out + spamcount_out).",
		type => 'number',
	    },
	    spamcount_in => {
		description => "Incoming spam mails.",
		type => 'number',
	    },
	    spamcount_out => {
		description => "Outgoing spam mails.",
		type => 'number',
	    },
	    spfcount => {
		description => "Mails rejected by SPF.",
		type => 'number',
	    },
	    bytes_in => {
		description => "Incoming mail traffic (bytes).",
		type => 'number',
	    },
	    bytes_out => {
		description => "Outgoing mail traffic (bytes).",
		type => 'number',
	    },
	    viruscount_in => {
		description => "Number of incoming virus mails.",
		type => 'number',
	    },
	    viruscount_out => {
		description => "Number of outgoing virus mails.",
		type => 'number',
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $res = $stat->total_mail_stat($rdb);

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'mailcount',
    path => 'mailcount',
    method => 'GET',
    description => "Mail Count Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    timespan => {
		description => "Return Mails/<timespan>, when <timespan> is specified in seconds.",
		type => 'integer',
		minimum => 3600,
		maximum => 366*86400,
		optional => 1,
		default => 3600,
	    }
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		index => {
		    description => "Time index.",
		    type => 'integer',
		},
		time => {
		    description => "Time (Unix epoch).",
		    type => 'integer',
		},
		count => {
		    description => "Overall mail count (in and out).",
		    type => 'number',
		},
		count_in => {
		    description => "Incoming mail count.",
		    type => 'number',
		},
		count_out => {
		    description => "Outgoing mail count.",
		    type => 'number',
		},
		spamcount_in => {
		    description => "Incoming spam mails (spamcount_in + glcount + spfcount).",
		    type => 'number',
		},
		spamcount_out => {
		    description => "Outgoing spam mails.",
		    type => 'number',
		},
		viruscount_in => {
		    description => "Number of incoming virus mails.",
		    type => 'number',
		},
		viruscount_out => {
		    description => "Number of outgoing virus mails.",
		    type => 'number',
		},
		bounces_in => {
		    description => "Incoming bounce mail count (sender = <>).",
		    type => 'number',
		},
		bounces_out => {
		    description => "Outgoing bounce mail count (sender = <>).",
		    type => 'number',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $span = $param->{timespan} // 3600;

	my $count = ($end - $start)/$span;

	die "too many entries - try to increase parameter 'span'\n" if $count > 5000;

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	#PMG::Statistic::update_stats_dailystat($rdb->{dbh}, $cinfo);

	my $res = $stat->traffic_stat_graph ($rdb, $span);

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'virus',
    path => 'virus',
    method => 'GET',
    description => "Get Statistics about detected Viruses.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
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
		name => {
		    description => 'Virus name.',
		    type => 'string',
		},
		count => {
		    description => 'Detection count.',
		    type => 'integer',
		},
	    },
	}
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $res = $stat->total_virus_stat($rdb);

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'spamscores',
    path => 'spamscores',
    method => 'GET',
    description => "Get the count of spam mails grouped by spam score. " .
	"Count for score 10 includes mails with spam score > 10.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
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
		level => {
		    description => 'Spam level.',
		    type => 'string',
		},
		count => {
		    description => 'Detection count.',
		    type => 'integer',
		},
		ratio => {
		    description => 'Portion of overall mail count.',
		    type => 'number',
		},
	    },
	}
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $totalstat = $stat->total_mail_stat ($rdb);
	my $spamstat = $stat->total_spam_stat($rdb);

	my $res = [];

	my $count_in = $totalstat->{count_in};
	my $rest = $totalstat->{spamcount_in};

	my $levelcount = {};
	foreach my $ref (@$spamstat) {
	    my $level = $ref->{spamlevel} // 0;
	    next if $level >= 10 || $level < 1;
	    $rest -= $ref->{count} if $level >= 3;
	    $levelcount->{$level} = $ref->{count};
	}

	$levelcount->{0} = $totalstat->{count_in} - $totalstat->{spamcount_in};
	$levelcount->{10} = $rest if $rest;

	for (my $i = 0; $i <= 10; $i++) {
	    my $count = $levelcount->{$i} // 0;
	    my $ratio = $count_in ? $count/$count_in : 0;
	    push @$res, { level => $i, count => $count, ratio => $ratio };
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'maildistribution',
    path => 'maildistribution',
    method => 'GET',
    description => "Get the count of spam mails grouped by spam score. " .
	"Count for score 10 includes mails with spam score > 10.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
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
		index => {
		    description => "Hour (0-23).",
		    type => 'integer',
		},
		count => {
		    description => "Overall mail count (in and out).",
		    type => 'number',
		},
		count_in => {
		    description => "Incoming mail count.",
		    type => 'number',
		},
		count_out => {
		    description => "Outgoing mail count.",
		    type => 'number',
		},
		spamcount_in => {
		    description => "Incoming spam mails (spamcount_in + glcount + spfcount).",
		    type => 'number',
		},
		spamcount_out => {
		    description => "Outgoing spam mails.",
		    type => 'number',
		},
		viruscount_in => {
		    description => "Number of incoming virus mails.",
		    type => 'number',
		},
		viruscount_out => {
		    description => "Number of outgoing virus mails.",
		    type => 'number',
		},
		bounces_in => {
		    description => "Incoming bounce mail count (sender = <>).",
		    type => 'number',
		},
		bounces_out => {
		    description => "Outgoing bounce mail count (sender = <>).",
		    type => 'number',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	#PMG::Statistic::update_stats_dailystat($rdb->{dbh}, $cinfo);

	my $res = $stat->traffic_stat_day_dist ($rdb);

	return $res;
    }});

1;
