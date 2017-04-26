package PMG::CLI::pmgspamreport;

use strict;
use Data::Dumper;
use Template;
use MIME::Entity;
use HTML::Entities;
use Time::Local;
use Clone 'clone';
use Mail::Header;
use POSIX qw(strftime);

use PVE::SafeSyslog;
use PVE::Tools;
use PVE::INotify;
use PVE::CLIHandler;

use PMG::RESTEnvironment;
use PMG::Utils;
use PMG::DBTools;
use PMG::RuleDB;
use PMG::Config;
use PMG::ClusterConfig;

use base qw(PVE::CLIHandler);

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

sub domain_regex {
    my ($domains) = @_;

    my @ra;
    foreach my $d (@$domains) {
	# skip domains with non-DNS name characters
	next if $d =~ m/[^A-Za-z0-9\-\.]/;
	if ($d =~ m/^\.(.*)$/) {
	    my $dom = $1;
	    $dom =~ s/\./\\\./g;
	    push @ra, $dom;
	    push @ra, "\.\*\\.$dom";
	} else {
	    $d =~ s/\./\\\./g;
	    push @ra, $d;
	}
    }

    my $re = join ('|', @ra);

    my $regex = qr/\@($re)$/i;

    return $regex;
}

sub get_item_data {
    my ($ref) = @_;

    my @lines = split ('\n', $ref->{header});
    my $head = new Mail::Header(\@lines);

    my $data = {};
    
    $data->{subject} = PMG::Utils::rfc1522_to_html(
	PVE::Tools::trim($head->get('subject')) || 'No Subject');

    my @fromarray = split('\s*,\s*', $head->get('from') || $ref->{sender});
    my $from = PMG::Utils::rfc1522_to_html(PVE::Tools::trim($fromarray[0]));
    my $sender = PMG::Utils::rfc1522_to_html(PVE::Tools::trim($head->get('sender')));

    if ($sender) {
	$data->{sender} = $sender;
	$data->{from} = sprintf ("%s on behalf of %s", $sender, $from);
    } else {
	$data->{from} = $from;
    }

    $data->{pmail} = $ref->{pmail};
    $data->{receiver} = $ref->{receiver} || $ref->{pmail};

    $data->{date} = strftime("%F", localtime($ref->{time}));
    $data->{time} = strftime("%H:%M:%S", localtime($ref->{time}));
 
    # fixme: $data->{ticket} = Proxmox::Utils::create_ticket ($ref);
    $data->{bytes} = $ref->{bytes};
    $data->{spamlevel} = $ref->{spamlevel};
    $data->{spaminfo} = $ref->{info};
      
    my $title = "Received: $data->{date} $data->{time}\n";
    $title .= "From: $ref->{sender}\n";
    $title .= "To: $ref->{receiver}\n" if $ref->{receiver};
    $title .= sprintf("Size: %d KB\n", int (($ref->{bytes} + 1023) / 1024 ));
    $title .= sprintf("Spam level: %d\n", $ref->{spamlevel}) if $ref->{qtype} eq 'S';
    $title .= sprintf("Virus info: %s\n", encode_entities ($ref->{info})) if $ref->{qtype} eq 'V';
    $title .= sprintf("File: %s", encode_entities($ref->{file}));

    # fixme: urlencode?
    $data->{title} = $title;

    return $data;
}

sub finalize_report {
    my ($tmpl_data, $data, $mailfrom, $receiver, $debug) = @_;

    my $html = '';

    my $template = Template->new({});

    $template->process(\$tmpl_data, $data, \$html) ||
	die $template->error();

    my $title;
    if ($html =~ m|^\s*<title>(.*)</title>|m) {
	$title = $1;
    } else {
	die "unable to extract template title\n";
    }

    my $top = MIME::Entity->build(
	Type    => "multipart/related",
	To      => $data->{pmail},
	From    => $mailfrom,
	Subject => PMG::Utils::bencode_header(decode_entities($title)));

    $top->attach(
	Data     => $html,
	Type     => "text/html",
	Encoding => $debug ? 'binary' : 'quoted-printable');

    if ($debug) {
	$top->print();
	return;
    }
    # we use an empty envelope sender (we dont want to receive NDRs)
    PMG::Utils::reinject_mail ($top, '', [$receiver], undef, $data->{fqdn});
}

__PACKAGE__->register_method ({
    name => 'send',
    path => 'send',
    method => 'POST',
    description => "Generate and send spam report emails.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    receiver => {
		description => "Generate report for a single email address. If not specified, generate reports for all users.",
		type => 'string', format => 'email',
		optional => 1,		
	    },
	    timespan => {
		description => "Select time span.",
		type => 'string',
		enum => ['today', 'yesterday', 'week'],
		default => 'today',
		optional => 1,
	    },
	    style => {
		description => "Spam report style. Value 'none' just prints the spam counts and does not send any emails. Default value is read from spam quarantine configuration.",
		type => 'string',
		enum => ['none', 'short', 'verbose', 'outlook', 'custom'],
		optional => 1,
	    },
	    redirect => {
		description => "Redirect spam report email to this address.",
		type => 'string', format => 'email',
		optional => 1,
	    },
	    debug => {
		description => "Debug mode. Print raw email to stdout instead of sending them.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    }
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cinfo = PMG::ClusterConfig->new();
	my $role = $cinfo->{local}->{type} // '-';

	if (!(($role eq '-') || ($role eq 'master'))) {
	   die "local node is not master - not sending spam report\n";
	} 

	my $cfg = PMG::Config->new();

	my $reportstyle = $param->{style} // $cfg->get('spamquar', 'reportstyle');

	my $timespan = $param->{timespan} // 'today';

	my (undef, undef, undef, $mday, $mon, $year) = localtime(time());	
	my $daystart = timelocal(0, 0, 0, $mday, $mon, $year);
	
	my $start;
	my $end;
	
	if ($timespan eq 'today') {
	    $start = $daystart;
	    $end = $start + 86400;
	} elsif ($timespan eq 'yesterday') {
	    $end = $daystart;
	    $start = $end - 86400;
	} elsif ($timespan eq 'week') {
	    $end = $daystart;
	    $start = $end - 7*86400;
	} else {
	    die "internal error";
	}

	my $hostname = PVE::INotify::nodename();
	
	my $fqdn = $cfg->get('spamquar', 'hostname') // 
	    PVE::Tools::get_fqdn($hostname);
	
	my $port = 8006;
	
	my $global_data = {
	    protocol => 'https',
	    port => $port,
	    fqdn => $fqdn,
	    hostname => $hostname,
	    actionhref => "https://$fqdn:$port/userquar/",
	    date => strftime("%F", localtime($end - 1)),
	    timespan => $timespan,
	    items => [],
	};

	my $mailfrom = $cfg->get ('spamquar', 'mailfrom') // 
	    "Proxmox Mail Gateway <postmaster>";
	
	my $dbh = PMG::DBTools::open_ruledb();

	my $target = $param->{receiver};
	my $redirect = $param->{redirect};
	
	if (defined($redirect)) {
	    die "can't redirect mails for all users\n";
	}
	
	my $domains = PVE::INotify::read_file('domains');
	my $domainregex = domain_regex([keys %$domains]);

	my $tmpl_data;
	
	if ($reportstyle ne 'none') {

	    my $template_filename;

	    my $customtmpl =  "/etc/pmg/spamreport.tmpl";
	    if ($reportstyle eq 'verbose') {
		$template_filename = "/var/lib/pmg/templates/spamreport-verbose.tmpl";
	    } elsif ($reportstyle eq 'outlook') {
		$template_filename = "/var/lib/pmg/templates/spamreport-verbose-noform.tmpl";
	    } elsif (($reportstyle eq 'custom') && (-f $customtmpl)) {
		$template_filename = $customtmpl;
	    } else {
		$template_filename = "/var/lib/pmg/templates/spamreport-short.tmpl";
	    }

	    $tmpl_data = PVE::Tools::file_get_contents($template_filename);
	}
	
	    
	my $sth = $dbh->prepare(
	    "SELECT * FROM CMailStore, CMSReceivers " . 
	    "WHERE time >= $start AND time < $end AND " . 
	    ($target ? "pmail = ? AND " : '') .
	    "QType = 'S' AND CID = CMailStore_CID AND RID = CMailStore_RID " .
	    "AND Status = 'N' " .
	    "ORDER BY pmail, time, receiver");
	    
	if ($target) {
	    $sth->execute($target);
	} else {
	    $sth->execute();
	}

	my $lastref;
	my $mailcount = 0;
	my $creceiver = '';
	my $data;
	
	my $finalize = sub {
	    
	    my $extern = ($domainregex && $creceiver !~ $domainregex);
		
	    if ($tmpl_data) {
		if (!$extern) {
		    # fixme: my $ticket = Proxmox::Utils::create_ticket ($lastref);
		    my $ticket = "TEST";
		    $data->{ticket} = $ticket;
		    $data->{managehref} = "https://$fqdn:$port?ticket=$ticket";
		    $data->{mailcount} = $mailcount;

		    my $sendto = $redirect ? $redirect : $creceiver;
		    finalize_report($tmpl_data, $data, $mailfrom, $sendto, $param->{debug});
		}
	    } else {
		my $hint = $extern ? " (external address)" : "";
		printf ("%-5d %s$hint\n", $mailcount, $creceiver);
	    }
	};
	
	while (my $ref = $sth->fetchrow_hashref()) {
	    if ($creceiver ne $ref->{pmail}) {

		$finalize->() if $data;

		$data = clone($global_data);
		
		$creceiver = $ref->{pmail};
		$mailcount = 0;

		$data->{pmail} = $creceiver;
	    }

	    if ($tmpl_data) {
		push @{$data->{items}}, get_item_data($ref);
	    }
	    
	    $mailcount++;
	    $lastref = $ref;
	}

	$sth->finish();

	$finalize->() if $data;

	if (defined($target) && !$mailcount) {
	    print STDERR "no mails for '$target'\n";
	}

	return undef;
    }});

sub find_stale_files {
    my ($path, $lifetime, $purge) = @_;

    my $cmd = ['find', $path, '-daystart', '-mtime', '+$lifetime',
	       '-type', 'f'];

    if ($purge) {
	push @$cmd, '-exec', 'rm', '-vf', '{}', ';';
    } else {
	push @$cmd, '-print';
    }
    
    PVE::Tools::run_command($cmd);
}

sub test_quarantine_files {
    my ($spamlifetime, $viruslifetime, $purge) = @_;
    
    print STDERR "searching for stale files\n" if !$purge; 

    find_stale_files ("/var/spool/proxmox/spam", $spamlifetime, $purge);
    find_stale_files ("/var/spool/proxmox/cluster/*/spam", $spamlifetime, $purge);

    find_stale_files ("/var/spool/proxmox/virus", $viruslifetime, $purge);
    find_stale_files ("/var/spool/proxmox/cluster/*/virus", $viruslifetime, $purge);
}

__PACKAGE__->register_method ({
    name => 'purge',
    path => 'purge',
    method => 'POST',
    description => "Cleanup Quarantine database. Remove entries older than configured quarantine lifetime.",
    parameters => {
	additionalProperties => 0,
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();

	my $spamlifetime = $cfg->get('spamquar', 'lifetime');
	my $viruslifetime = $cfg->get ('virusquar', 'lifetime');

	print STDERR "purging database\n"; 

	my $dbh = PMG::DBTools::open_ruledb();

	if (my $count = PMG::DBTools::purge_quarantine_database($dbh, 'S', $spamlifetime)) {
	    print STDERR "removed $count spam quarantine files\n"; 
	}

	if (my $count = PMG::DBTools::purge_quarantine_database($dbh, 'V', $viruslifetime)) {
	    print STDERR "removed $count virus quarantine files\n"; 
	}

	test_quarantine_files($spamlifetime, $viruslifetime, 1);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'check',
    path => 'check',
    method => 'GET',
    description => "Search Quarantine database for entries older than configured quarantine lifetime.",
    parameters => {
	additionalProperties => 0,
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();

	my $spamlifetime = $cfg->get('spamquar', 'lifetime');
	my $viruslifetime = $cfg->get ('virusquar', 'lifetime');

	test_quarantine_files($spamlifetime, $viruslifetime, 0);

	return undef;
    }});



our $cmddef = {
    'check' => [ __PACKAGE__, 'check', []],
    'purge' => [ __PACKAGE__, 'purge', []],
    'send' => [ __PACKAGE__, 'send', []],
};

1;
