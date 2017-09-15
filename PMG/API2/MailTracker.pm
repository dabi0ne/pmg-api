package PMG::API2::MailTracker;

use strict;
use warnings;
use POSIX;
use Digest::MD5;
use Data::Dumper;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);

use PMG::RESTEnvironment;

use base qw(PVE::RESTHandler);

my $statmap = {
    2 => 'delivered',
    4 => 'deferred',
    5 => 'bounced',
    N => 'rejected',
    G => 'greylisted',
    A => 'accepted',
    B => 'blocked',
    Q => 'quarantine',
};

my $run_pmg_log_tracker = sub {
    my ($args, $includelog) = @_;

    my $logids = {};

    if (defined(my $id = $includelog)) {
	if ($id =~ m/^Q([a-f0-9]+)R([a-f0-9]+)$/i) {
	    $logids->{$1} = 1;
	    $logids->{$2} = 1;
	} else {
	    $logids->{$id} = 1;
	}
    }

    my $lookup_hash = {};
    my $list = [];
    my $state = 'start';
    my $status;
    my $entry;
    my $logs = [];

    my $parser = sub {
	my ($line) = @_;

	if ($state eq 'start') {

	    return if $line =~ m/^\#/;
	    return if $line =~ m/^\s*$/;

	    if ($line =~ m/^STATUS: (.*)$/) {
		$state = 'end';
		$status = $1;
		return;
	    }

	    if ($line =~ m/^SMTPD:/) {
		$state = 'smtp';
		$entry = { logs => [] };
		return;
	    }

	    if ($line =~ m/^QENTRY:\s+([0-9A-F]+)$/) {
		$state = 'qentry';
		$entry = { qid => $1, logs => [] };
		return;
	    }

	    die "got unexpected data: $line";
	} elsif ($state eq 'end') {
	    die "got unexpected data after status: $line";
	} elsif ($state eq 'skiplogs') {
	    if ($line =~  m/^\s*$/) {
		$entry = undef;
		$state = 'start';
	    } else {
		# skip
	    }
	} elsif ($state eq 'logs') {
	    if ($line =~  m/^\s*$/) {
		$entry = undef;
		$state = 'start';
	    } elsif ($line =~ m/^(SMTP|FILTER|QMGR):/) {
		# skip
	    } elsif ($line =~ m/^(L[A-F0-9]+)\s(.*)$/) {
		push @$logs, { linenr => $1, text => $2 };
	    } else {
		die "got unexpected data: $line";
	    }
	} elsif ($state eq 'qentry') {
	    if ($line =~  m/^\s*$/) {
		$entry = undef;
		$state = 'start';
	    } elsif ($line =~ m/^SIZE:\s+(\d+)$/) {
		$entry->{size} = $1;
	    } elsif ($line =~ m/^CLIENT:\s+(\S+)$/) {
		$entry->{client} = $1;
	    } elsif ($line =~ m/^MSGID:\s+(\S+)$/) {
		$entry->{msgid} = $1;
	    } elsif ($line =~ m/^CTIME:\s+([0-9A-F]+)$/) {
		# ignore ?
	    } elsif ($line =~ m/^TO:([0-9A-F]+):([0-9A-F]+):([0-9A-Z]):\s+from <(\S*)>\s+to\s+<(\S+)>\s+\((\S+)\)$/) {
		my $new = {};
		$new->{size} = $entry->{size} // 0,
		$new->{client} = $entry->{client} if defined($entry->{client});
		$new->{msgid} = $entry->{msgid} if defined($entry->{msgid});
		$new->{time} = hex $1;
		$new->{qid} = $2;
		$new->{dstatus} = $3;
		$new->{from} = $4;
		$new->{to} = $5;
		$new->{relay} = $6;

		push @$list, $new;
		$lookup_hash->{$2}->{$5} = $new;
	    } elsif ($line =~ m/^(SMTP|FILTER|QMGR):/) {
		if ($logids->{$entry->{qid}}) {
		    $state = 'logs';
		} else {
		    $state = 'skiplogs';
		}
	    } else {
		die "got unexpected data: $line";
	    }
	} elsif ($state eq 'smtp') {

	    if ($line =~  m/^\s*$/) {
		$entry = undef;
		$state = 'start';
	    } elsif  ($line =~ m/^CONNECT:\s+(\S+)$/) {
		# ignore
	    } elsif ($line =~ m/^CTIME:\s+([0-9A-F]+)$/) {
		# ignore ?
	    } elsif ($line =~ m/^TO:([0-9A-F]+):00000000000:([0-9A-Z]):\s+from <(\S*)>\s+to\s+<(\S+)>$/) {
		my $e = {};
		$e->{time} = hex $1;
		$e->{dstatus} = $2;
		$e->{from} = $3;
		$e->{to} = $4;

		my $logid = 'T' . sprintf("%08x", $e->{time}) . 'D' .
		    Digest::MD5::md5_hex("<$e->{from}><$e->{to}>");

		if ($logids->{$logid}) {
		    $entry->{wantlog} = 1;
		}
		push @$list, $e;
	    } elsif ($line =~ m/^LOGS:$/) {
		if ($entry->{wantlog}) {
		    $state = 'logs';
		} else {
		    $state = 'skiplogs';
		}
	    } else {
		die "got unexpected data: $line";
	    }
	} else {
	    die "unknown state '$state'\n";
	}
    };

    my $cmd = ['/usr/bin/pmg-log-tracker', '-v', '-l', 200]; # fixme: 200?

    PVE::Tools::run_command([@$cmd, @$args], outfunc => $parser);

    my $sorted_logs = [];
    foreach my $le (sort {$a->{linenr} cmp $b->{linenr}} @$logs) {
	push @$sorted_logs, $le->{text};
    }

    foreach my $e (@$list) {
	if (my $id = $e->{qid}) {
	    if (my $relay = $e->{relay}) {
		if (my $ref = $lookup_hash->{$relay}->{$e->{to}}) {
		    $ref->{is_relay} = 1;
		    $id = 'Q' . $e->{qid} . 'R' . $e->{relay};
		    if ($e->{dstatus} eq 'A') {
			$e->{rstatus} = $ref->{dstatus};
		    }
		}
	    }
	    $e->{id} = $id;
	} else {
	    $e->{id} = 'T' . sprintf("%08x", $e->{time}) . 'D' .
		Digest::MD5::md5_hex("<$e->{from}><$e->{to}>");
	}
	if ($includelog && ($e->{id} eq $includelog)) {
	    $e->{logs} = $sorted_logs;
	}
    }

    return $list;
};

__PACKAGE__->register_method({
    name => 'list_mails',
    path => '',
    method => 'GET',
    description => "Read mail list.",
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    from => {
		description => "Sender email address filter.",
		type => 'string',
		optional => 1,
		minLength => 3,
		maxLength => 256,
	    },
	    target => {
		description => "Receiver email address filter.",
		type => 'string',
		optional => 1,
		minLength => 3,
		maxLength => 256,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
	    },
	},
	links => [ { rel => 'child', href => "{id}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();

	my $args = [];

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	push @$args, '-s', $start;
	push @$args, '-e', $end;

	if (defined($param->{from})) {
	    push @$args, '-f', $param->{from};
	}
	if (defined($param->{target})) {
	    push @$args, '-t', $param->{target};
	}

	my $list = $run_pmg_log_tracker->($args);

	my $res = [];
	foreach my $e (@$list) {
	    push @$res, $e if !$e->{is_relay};
	}

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'maillog',
    path => '{id}',
    method => 'GET',
    description => "Get the detailed syslog entries for a specific mail ID.",
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    id => {
		description => "Mail ID (as returend by the list API).",
		type => 'string',
		minLength => 3,
		maxLength => 64,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	},
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();

	my $args = [];

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	push @$args, '-s', $start;
	push @$args, '-e', $end;

	my $list = $run_pmg_log_tracker->($args, $param->{id});

	my $res;
	foreach my $e (@$list) {
	    $res = $e if $e->{id} eq $param->{id};
	}

	die "entry '$param->{id}' not found\n" if !defined($res);

	return $res;
    }});

1;
