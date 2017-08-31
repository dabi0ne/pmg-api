package PMG::API2::Statistics;

use strict;
use warnings;
use Data::Dumper;

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
	    { name => "mail" },
	    { name => "mailcount" },
	    { name => "spamscores" },
	    { name => "virus" },
	];
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
	    traffic_in => {
		description => "Incoming mail traffic (bytes).",
		type => 'number',
	    },
	    traffic_out => {
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

1;
