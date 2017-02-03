package PMG::Utils;

use strict;
use warnings;
use Carp;
use DBI;
use Net::Cmd;
use Net::SMTP;

use MIME::Words;
use MIME::Parser;

use PVE::SafeSyslog;

sub msgquote {
    my $msg = shift || '';
    $msg =~ s/%/%%/g;
    return $msg;
}

sub lastid {
    my ($dbh, $seq) = @_;

    return $dbh->last_insert_id(
	undef, undef, undef, undef, { sequence => $seq});
}

sub extract_filename {
    my ($head) = @_;

    if (my $value = $head->recommended_filename()) {
	chomp $value;	    
	if (my $decvalue = MIME::Words::decode_mimewords($value)) {
	    $decvalue =~ s/\0/ /g;
	    $decvalue = trim ($decvalue);
	    return $decvalue;
	}
    }

    return undef;
}

sub remove_marks {
    my ($entity, $add_id, $id) = @_;

    $id //= 1;

    foreach my $tag (grep {/^x-proxmox-tmp/i} $entity->head->tags) {
	$entity->head->delete ($tag);
    }

    $entity->head->replace('X-Proxmox-tmp-AID', $id) if $add_id;

    foreach my $part ($entity->parts)  {
	$id = remove_marks($part, $add_id, $id + 1);
    }

    return $id;
}

sub subst_values {
    my ($body, $dh) = @_;

    return if !$body;

    foreach my $k (keys %$dh) {
	my $v = $dh->{$k};
	if (defined ($v)) {
	    $body =~ s/__${k}__/$v/gs;
	}
    }

    return $body;
}

sub reinject_mail {
    my ($entity, $sender, $targets, $xforward, $me, $nodsn) = @_;

    my $smtp;
    my $resid;
    my $rescode;
    my $resmess;

    eval {
	my $smtp = Net::SMTP->new('127.0.0.1', Port => 10025, Hello => $me) ||
	    die "unable to connect to localhost at port 10025";

	if (defined($xforward)) {
	    my $xfwd;
   
	    foreach my $attr (keys %{$xforward}) {
		$xfwd .= " $attr=$xforward->{$attr}";
	    }

	    if ($xfwd && $smtp->command("XFORWARD", $xfwd)->response() != CMD_OK) {
		syslog('err', "xforward error - got: %s %s", $smtp->code, scalar($smtp->message));
	    }
	}

	if (!$smtp->mail($sender)) {
	    syslog('err', "smtp error - got: %s %s", $smtp->code, scalar ($smtp->message));
	    die "smtp from: ERROR";
	}

	my $dsnopts = $nodsn ? {Notify => ['NEVER']} : {};

	if (!$smtp->to (@$targets, $dsnopts)) {
	    syslog ('err', "smtp error - got: %s %s", $smtp->code, scalar($smtp->message));
	    die "smtp to: ERROR";
	}

	# Output the head:
	#$entity->sync_headers ();
	$smtp->data();

	my $out = PMG::SMTPPrinter->new($smtp);
	$entity->print($out);
	
	# make sure we always have a newline at the end of the mail 
	# else dataend() fails
	$smtp->datasend("\n");

	if ($smtp->dataend()) {
	    my @msgs = $smtp->message;
	    $resmess = $msgs[$#msgs]; 
	    ($resid) = $resmess =~ m/Ok: queued as ([0-9A-Z]+)/; 
	    $rescode = $smtp->code;
	    if (!$resid) {
		die sprintf("unexpected SMTP result - got: %s %s : WARNING", $smtp->code, $resmess);
	    } 
	} else {
	    my @msgs = $smtp->message;
	    $resmess = $msgs[$#msgs]; 
	    $rescode = $smtp->code;
	    die sprintf("sending data failed - got: %s %s : ERROR", $smtp->code, $resmess);
	}
    };
    my $err = $@;
    
    $smtp->quit if $smtp;
    
    if ($err) {
	syslog ('err', $err);
    }

    return wantarray ? ($resid, $rescode, $resmess) : $resid;
}


1;
