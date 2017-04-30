package PMG::CLI::pmgqm;

use strict;
use Data::Dumper;
use Template;
use MIME::Entity;
use HTML::Entities;
use Time::Local;
use Clone 'clone';
use Mail::Header;
use POSIX qw(strftime);
use File::Find;
use File::stat;
use URI::Escape;

use PVE::SafeSyslog;
use PVE::Tools;
use PVE::INotify;
use PVE::CLIHandler;

use PMG::RESTEnvironment;
use PMG::Utils;
use PMG::Ticket;
use PMG::DBTools;
use PMG::RuleDB;
use PMG::Config;
use PMG::ClusterConfig;
use PMG::API2::Quarantine;

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
    my ($data, $ref) = @_;

    my @lines = split ('\n', $ref->{header});
    my $head = new Mail::Header(\@lines);

    my $item = {};

    $item->{id} = sprintf("C%dR%d", $ref->{cid}, $ref->{rid});
    
    $item->{subject} = PMG::Utils::rfc1522_to_html(
	PVE::Tools::trim($head->get('subject')) || 'No Subject');

    my @fromarray = split('\s*,\s*', $head->get('from') || $ref->{sender});
    my $from = PMG::Utils::rfc1522_to_html(PVE::Tools::trim($fromarray[0]));
    my $sender = PMG::Utils::rfc1522_to_html(PVE::Tools::trim($head->get('sender')));

    if ($sender) {
	$item->{sender} = $sender;
	$item->{from} = sprintf ("%s on behalf of %s", $sender, $from);
    } else {
	$item->{from} = $from;
    }

    $item->{pmail} = $ref->{pmail};
    $item->{receiver} = $ref->{receiver} || $ref->{pmail};

    $item->{date} = strftime("%F", localtime($ref->{time}));
    $item->{time} = strftime("%H:%M:%S", localtime($ref->{time}));
 
    $item->{bytes} = $ref->{bytes};
    $item->{spamlevel} = $ref->{spamlevel};
    $item->{spaminfo} = $ref->{info};
      
    my $title = "Received: $item->{date} $item->{time}\n";
    $title .= "From: $ref->{sender}\n";
    $title .= "To: $ref->{receiver}\n" if $ref->{receiver};
    $title .= sprintf("Size: %d KB\n", int (($ref->{bytes} + 1023) / 1024 ));
    $title .= sprintf("Spam level: %d\n", $ref->{spamlevel}) if $ref->{qtype} eq 'S';
    $title .= sprintf("Virus info: %s\n", encode_entities ($ref->{info})) if $ref->{qtype} eq 'V';
    $title .= sprintf("File: %s", encode_entities($ref->{file}));

    $item->{title} = $title;

    my $basehref = "https://$data->{fqdn}:$data->{port}/quarantine";
    my $ticket = uri_escape($data->{ticket});
    $item->{wlhref} = "$basehref?ticket=$ticket&cselect=$item->{id}&action=whitelist";
    $item->{blhref} = "$basehref?ticket=$ticket&cselect=$item->{id}&action=blacklist";
    $item->{deliverhref} = "$basehref?ticket=$ticket&cselect=$item->{id}&action=deliver";
    $item->{deletehref} = "$basehref?ticket=$ticket&cselect=$item->{id}&action=delete";

    return $item;
}

sub finalize_report {
    my ($tt, $template, $data, $mailfrom, $receiver, $debug) = @_;

    my $html = '';

    $tt->process($template, $data, \$html) ||
	die $tt->error() . "\n";

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
		enum => ['none', 'short', 'verbose', 'custom'],
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
	    date => strftime("%F", localtime($end - 1)),
	    timespan => $timespan,
	    items => [],
	};

	my $mailfrom = $cfg->get ('spamquar', 'mailfrom') // 
	    "Proxmox Mail Gateway <postmaster>";
	
	my $dbh = PMG::DBTools::open_ruledb();

	my $target = $param->{receiver};
	my $redirect = $param->{redirect};
	
	if (defined($redirect) && !defined($target)) {
	    die "can't redirect mails for all users\n";
	}
	
	my $domains = PVE::INotify::read_file('domains');
	my $domainregex = domain_regex([keys %$domains]);

	my $template;

	if ($reportstyle ne 'none') {

	    $template = "spamreport-${reportstyle}.tt";
	    my $found = 0;
	    foreach my $path (@$PMG::Config::tt_include_path) {
		if (-f "$path/$template") { $found = 1; last; }
	    }
	    if (!$found) {
		warn "unable to find template '$template' - using default\n";
		$template = "spamreport-verbose.tt";
	    }
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

	my $tt = PMG::Config::get_template_toolkit();

	my $finalize = sub {
	    
	    my $extern = ($domainregex && $creceiver !~ $domainregex);
		
	    if ($template) {
		if (!$extern) {
		    $data->{mailcount} = $mailcount;
		    my $sendto = $redirect ? $redirect : $creceiver;
		    finalize_report($tt, $template, $data, $mailfrom, $sendto, $param->{debug});
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
		$data->{ticket} = PMG::Ticket::assemble_quarantine_ticket($data->{pmail});
		my $esc_ticket = uri_escape($data->{ticket});
		$data->{managehref} = "https://$fqdn:$port/quarantine?ticket=${esc_ticket}";
	    }

	    if ($template) {
		push @{$data->{items}}, get_item_data($data, $ref);
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

    return if ! -d $path;

    my (undef, undef, undef, $mday, $mon, $year) = localtime(time());
    my $daystart = timelocal(0, 0, 0, $mday, $mon, $year);
    my $expire = $daystart - $lifetime*86400;

    my $wanted = sub {
	my $name = $File::Find::name;
	return if $name !~ m|^($path/.*)$|;
	$name = $1; # untaint
	my $stat = stat($name);
	return if ! -f _;
	return if $stat->mtime >= $expire;
	if ($purge) {
	    if (unlink($name)) {
		print "removed: $name\n";
	    }
	} else {
	    print "$name\n";
	}
    };

    find({ wanted => $wanted, no_chdir => 1 }, $path);
}

sub test_quarantine_files {
    my ($spamlifetime, $viruslifetime, $purge) = @_;
    
    print STDERR "searching for stale files\n" if !$purge; 

    my $spooldir = $PMG::MailQueue::spooldir;

    find_stale_files ("$spooldir/spam", $spamlifetime, $purge);
    foreach my $dir (<"/var/spool/pmg/cluster/*/spam">) {
	next if $dir !~ m|^(/var/spool/pmg/cluster/\d+/spam)$|;
	$dir = $1; # untaint
	find_stale_files ($dir, $spamlifetime, $purge);
    }

    find_stale_files ("$spooldir/virus", $viruslifetime, $purge);
    foreach my $dir (<"/var/spool/pmg/cluster/*/virus">) {
	next if $dir !~ m|^(/var/spool/pmg/cluster/\d+/virus)$|;
	$dir = $1; # untaint
	find_stale_files ($dir, $viruslifetime, $purge);
    }
}

__PACKAGE__->register_method ({
    name => 'purge',
    path => 'purge',
    method => 'POST',
    description => "Cleanup Quarantine database. Remove entries older than configured quarantine lifetime.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    check => {
		description => "Only search for quarantine files older than configured quarantine lifetime. Just print found files, but do not remove them.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    }
	}
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();

	my $spamlifetime = $cfg->get('spamquar', 'lifetime');
	my $viruslifetime = $cfg->get ('virusquar', 'lifetime');

	my $purge = !$param->{check};

	if ($purge) {
	    print STDERR "purging database\n"; 

	    my $dbh = PMG::DBTools::open_ruledb();

	    if (my $count = PMG::DBTools::purge_quarantine_database($dbh, 'S', $spamlifetime)) {
		print STDERR "removed $count spam quarantine files\n"; 
	    }

	    if (my $count = PMG::DBTools::purge_quarantine_database($dbh, 'V', $viruslifetime)) {
		print STDERR "removed $count virus quarantine files\n"; 
	    }
	}

	test_quarantine_files($spamlifetime, $viruslifetime, $purge);

	return undef;
    }});


our $cmddef = {
    'purge' => [ __PACKAGE__, 'purge', []],
    'send' => [ __PACKAGE__, 'send', []],
    'spam' => [ 'PMG::API2::Quarantine', 'spam', [], undef, sub {
	my $res = shift;
	print "Day          Count  AVG(Spam)\n";
	foreach my $ref (@$res) {
	    print sprintf("%-12s %5d %10.2f\n",
			  strftime("%F", localtime($ref->{day})),
			  $ref->{count}, $ref->{spamavg});
	}
     }],
};

1;
