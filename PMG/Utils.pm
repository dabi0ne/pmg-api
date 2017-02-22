package PMG::Utils;

use strict;
use warnings;
use Carp;
use DBI;
use Net::Cmd;
use Net::SMTP;
use IO::File;
use File::stat;
use File::Basename;
use MIME::Words;
use MIME::Parser;
use Time::HiRes qw (gettimeofday);
use Xdgmime;
use Data::Dumper;
use Net::IP;
use Socket;

use PVE::Network;
use PVE::Tools;
use PVE::SafeSyslog;
use PVE::ProcFSTools;
use PMG::AtomicFile;
use PMG::MailQueue;
use PMG::SMTPPrinter;

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

sub file_older_than {
    my ($filename, $lasttime) = @_;

    my $st = stat($filename);

    return 0 if !defined($st);

    return ($lasttime >= $st->ctime);
}

sub extract_filename {
    my ($head) = @_;

    if (my $value = $head->recommended_filename()) {
	chomp $value;
	if (my $decvalue = MIME::Words::decode_mimewords($value)) {
	    $decvalue =~ s/\0/ /g;
	    $decvalue = PVE::Tools::trim($decvalue);
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
	if (defined($v)) {
	    $body =~ s/__\Q${k}\E__/$v/gs;
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

sub analyze_virus_clam {
    my ($queue, $dname, $pmg_cfg) = @_;

    my $timeout = 60*5;
    my $vinfo;

    my $clamdscan_opts = "--stdout";

    my ($csec, $usec) = gettimeofday();

    my $previous_alarm;

    eval {

	$previous_alarm = alarm($timeout);

	$SIG{ALRM} = sub {
	    die "$queue->{logid}: Maximum time ($timeout sec) exceeded. " .
		"virus analyze (clamav) failed: ERROR";
	};

	open(CMD, "/usr/bin/clamdscan $clamdscan_opts '$dname'|") ||
	    die "$queue->{logid}: can't exec clamdscan: $! : ERROR";

	my $ifiles;

	my $response = '';
	while (defined(my $line = <CMD>)) {
	    if ($line =~ m/^$dname.*:\s+([^ :]*)\s+FOUND$/) {
		# we just use the first detected virus name
		$vinfo = $1 if !$vinfo;
	    } elsif ($line =~ m/^Infected files:\s(\d*)$/i) {
		$ifiles = $1;
	    }

	    $response .= $line;
	}

	close(CMD);

	alarm(0); # avoid race conditions

	if (!defined($ifiles)) {
	    die "$queue->{logid}: got undefined output from " .
		"virus detector: $response : ERROR";
	}

	if ($vinfo) {
	    syslog('info', "$queue->{logid}: virus detected: $vinfo (clamav)");
	}
    };
    my $err = $@;

    alarm($previous_alarm);

    my ($csec_end, $usec_end) = gettimeofday();
    $queue->{ptime_clam} =
	int (($csec_end-$csec)*1000 + ($usec_end - $usec)/1000);

    if ($err) {
	syslog ('err', $err);
	$vinfo = undef;
	$queue->{errors} = 1;
    }

    $queue->{vinfo_clam} = $vinfo;

    return $vinfo ? "$vinfo (clamav)" : undef;
}

sub analyze_virus {
    my ($queue, $filename, $pmg_cfg, $testmode) = @_;

    # TODO: support other virus scanners?

    # always scan with clamav
    return analyze_virus_clam($queue, $filename, $pmg_cfg);
}

sub magic_mime_type_for_file {
    my ($filename) = @_;
    
    # we do not use get_mime_type_for_file, because that considers
    # filename extensions - we only want magic type detection

    my $bufsize = Xdgmime::xdg_mime_get_max_buffer_extents();
    die "got strange value for max_buffer_extents" if $bufsize > 4096*10;

    my $ct = "application/octet-stream";

    my $fh = IO::File->new("<$filename") || 
	die "unable to open file '$filename' - $!";

    my ($buf, $len);
    if (($len = $fh->read($buf, $bufsize)) > 0) {
	$ct = xdg_mime_get_mime_type_for_data($buf, $len);
    }
    $fh->close();
    
    die "unable to read file '$filename' - $!" if ($len < 0);
    
    return $ct;
}

sub add_ct_marks {
    my ($entity) = @_;

    if (my $path = $entity->{PMX_decoded_path}) {

	# set a reasonable default if magic does not give a result
	$entity->{PMX_magic_ct} = $entity->head->mime_attr('content-type');

	if (my $ct = magic_mime_type_for_file($path)) {
	    if ($ct ne 'application/octet-stream' || !$entity->{PMX_magic_ct}) {
		$entity->{PMX_magic_ct} = $ct;
	    }
	}

	my $filename = $entity->head->recommended_filename;
	$filename = basename($path) if !defined($filename) || $filename eq '';

	if (my $ct = xdg_mime_get_mime_type_from_file_name($filename)) {
	    $entity->{PMX_glob_ct} = $ct;
	}
    }

    foreach my $part ($entity->parts)  {
	add_ct_marks ($part);
    }
}

# x509 certificate utils

my $proxmox_tls_cert_fn = "/etc/pmg/pmg-tls.pem";

sub gen_proxmox_tls_cert {
    my ($force, $company, $cn) = @_;

    return if !$force && -f $proxmox_tls_cert_fn;

    my $sslconf = <<__EOD__;
RANDFILE = /root/.rnd
extensions = v3_req

[ req ]
default_bits = 4096
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
string_mask = nombstr

[ req_distinguished_name ]
organizationalUnitName = Proxmox Mail Gateway
organizationName = $company
commonName = $cn

[ v3_req ]
basicConstraints = CA:FALSE
nsCertType = server
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
__EOD__

    my $cfgfn = "/tmp/pmgtlsconf-$$.tmp";
    my $fh = IO::File->new ($cfgfn, "w");
    print $fh $sslconf;
    close ($fh);

    eval {
	PVE::Tools::run_command(['openssl', 'req', '-batch', '-x509', '-new', '-sha256',
				 '-config', $cfgfn, '-days', 3650, '-nodes',
				 '-out', $proxmox_tls_cert_fn,
				 '-keyout', $proxmox_tls_cert_fn]);
    };

    if (my $err = $@) {
	unlink $proxmox_tls_cert_fn;
	unlink $cfgfn;
	die "unable to generate proxmox certificate request:\n$err";
    }

    unlink $cfgfn;
}

sub find_local_network_for_ip {
    my ($ip) = @_;

    my $testip = Net::IP->new($ip);

    my $isv6 = $testip->version == 6;
    my $routes = $isv6 ?
	PVE::ProcFSTools::read_proc_net_ipv6_route() :
	PVE::ProcFSTools::read_proc_net_route();

    foreach my $entry (@$routes) {
	my $mask;
	if ($isv6) {
	    $mask = $entry->{prefix};
	    next if !$mask; # skip the default route...
	} else {
	    $mask = $PVE::Network::ipv4_mask_hash_localnet->{$entry->{mask}};
	    next if !defined($mask);
	}
	my $cidr = "$entry->{dest}/$mask";
	my $testnet = Net::IP->new($cidr);
	my $overlap = $testnet->overlaps($testip);
	if ($overlap == $Net::IP::IP_B_IN_A_OVERLAP ||
	    $overlap == $Net::IP::IP_IDENTICAL)
	{
	    return $cidr;
	}
    }

    die "unable to detect local network for ip '$ip'\n";
}

sub service_cmd {
    my ($service, $cmd) = @_;

    die "unknown service command '$cmd'\n"
	if $cmd !~ m/^(start|stop|restart|reload)$/;

    if ($service eq 'pmgdaemon' || $service eq 'pmgproxy') {
	if ($cmd eq 'restart') {
	    # OK
	} else {
	    die "invalid service cmd '$service $cmd': ERROR";
	}
    }

    $service = 'postfix@-' if $service eq 'postfix';
    PVE::Tools::run_command(['systemctl', $cmd, $service]);
};

# this is also used to get the IP of the local node
sub lookup_node_ip {
    my ($nodename, $noerr) = @_;

    my ($family, $packed_ip);

    eval {
	my @res = PVE::Tools::getaddrinfo_all($nodename);
	$family = $res[0]->{family};
	$packed_ip = (PVE::Tools::unpack_sockaddr_in46($res[0]->{addr}))[2];
    };

    if ($@) {
	die "hostname lookup failed:\n$@" if !$noerr;
	return undef;
    }

    my $ip = Socket::inet_ntop($family, $packed_ip);
    if ($ip =~ m/^127\.|^::1$/) {
	die "hostname lookup failed - got local IP address ($nodename = $ip)\n" if !$noerr;
	return undef;
    }

    return wantarray ? ($ip, $family) : $ip;
}

1;
