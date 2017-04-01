package PMG::Postfix;

use strict;
use warnings;
use Data::Dumper;
use File::Find;

my $spooldir = "/var/spool/postfix";

my $postfix_rec_get = sub {
    my ($fh) = @_;

    my $r = getc($fh);
    return if !defined($r);

    my $l = 0;
    my $shift = 0;

    while (defined(my $lb = getc($fh))) {
	my $o = ord($lb);
	$l |= ($o & 0x7f) << $shift ;
	last if (($o & 0x80) == 0);
	$shift += 7;
	return if ($shift > 7);	# XXX: max rec len of 4096
    }

    my $d = "";
    return unless ($l == 0 || read($fh, $d, $l) == $l);
    return ($r, $l, $d);
};

my $postfix_qenv = sub {
    my ($filename) = @_;

    my $fh = new IO::File($filename, "r");
    return undef if !defined($fh);

    my $dlen;
    my $res = { receivers => [] };
    while (my ($r, $l, $d) = $postfix_rec_get->($fh)) {
	#print "test:$r:$l:$d\n";
	if ($r eq "C") { $dlen = $1 if $d =~ /^\s*(\d+)\s+\d+\s+\d+/; }
	elsif ($r eq 'T') { $res->{time} = $1 if $d =~ /^\s*(\d+)\s\d+/; }
	elsif ($r eq 'S') { $res->{sender} = $d; }
	elsif ($r eq 'R') { push @{$res->{receivers}}, $d; }
	elsif ($r eq 'N') {
	    if ($d =~ m/^Subject:\s+(.*)$/i) {
		$res->{subject} = $1;
	    } elsif (!$res->{messageid} && $d =~ m/^Message-Id:\s+<(.*)>$/i) {
		$res->{messageid} = $1;
	    }
	}
	#elsif ($r eq "M") { last unless defined $dlen; seek($fh, $dlen, 1); }
	elsif ($r eq "E") { last; }
    }

    close($fh);

    return $res;
};

sub show_deferred_queue {

    my $res;

    my $queue = 'deferred';

    my $callback = sub {
	my $path = $File::Find::name;
	my $filename = $_;

	my ($dev, $ino, $mode) = lstat($path);

	return if !defined($mode);
	return if !(-f _ && (($mode & 07777) == 0700));

	if (my $rec = $postfix_qenv->($path)) {
	    $rec->{queue} = $queue;
	    $rec->{qid} = $filename;
	    push @$res, $rec;
	}
    };

    find($callback, "$spooldir/deferred");

    return $res;
}

1;
