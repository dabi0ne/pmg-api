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
	    { name => "spam" },
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
	properties => {},
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
    name => 'spam',
    path => 'spam',
    method => 'GET',
    description => "Get the count of spam mails grouped by spam level. " .
	"Count for level 10 includes mails with spam level > 10.",
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
	    push @$res, { level => $i, count => $levelcount->{$i} // 0 };
	}

	return $res;
    }});

1;
