package PMG::Utils;

use strict;
use warnings;
use DBI;
use Net::Cmd;
use Net::SMTP;
use IO::File;
use File::stat;
use POSIX qw(strftime);
use File::stat;
use File::Basename;
use MIME::Words;
use MIME::Parser;
use Time::HiRes qw (gettimeofday);
use Time::Local;
use Xdgmime;
use Data::Dumper;
use Digest::SHA;
use Digest::MD5;
use Net::IP;
use Socket;
use RRDs;
use Filesys::Df;
use Encode;
use HTML::Entities;

use PVE::ProcFSTools;
use PVE::Network;
use PVE::Tools;
use PVE::SafeSyslog;
use PVE::ProcFSTools;
use PMG::AtomicFile;
use PMG::MailQueue;
use PMG::SMTPPrinter;

my $valid_pmg_realms = ['pam', 'pmg', 'quarantine'];

PVE::JSONSchema::register_standard_option('realm', {
    description => "Authentication domain ID",
    type => 'string',
    enum => $valid_pmg_realms,
    maxLength => 32,
});

PVE::JSONSchema::register_standard_option('pmg-starttime', {
    description => "Only consider entries newer than 'starttime' (unix epoch). Default is 'now - 1day'.",
    type => 'integer',
    minimum => 0,
    optional => 1,
});

PVE::JSONSchema::register_standard_option('pmg-endtime', {
    description => "Only consider entries older than 'endtime' (unix epoch). This is set to '<start> + 1day' by default.",
    type => 'integer',
    minimum => 1,
    optional => 1,
});

PVE::JSONSchema::register_format('pmg-userid', \&verify_username);
sub verify_username {
    my ($username, $noerr) = @_;

    $username = '' if !$username;
    my $len = length($username);
    if ($len < 3) {
	die "user name '$username' is too short\n" if !$noerr;
	return undef;
    }
    if ($len > 64) {
	die "user name '$username' is too long ($len > 64)\n" if !$noerr;
	return undef;
    }

    # we only allow a limited set of characters
    # colon is not allowed, because we store usernames in
    # colon separated lists)!
    # slash is not allowed because it is used as pve API delimiter
    # also see "man useradd"
    my $realm_list = join('|', @$valid_pmg_realms);
    if ($username =~ m!^([^\s:/]+)\@(${realm_list})$!) {
	return wantarray ? ($username, $1, $2) : $username;
    }

    die "value '$username' does not look like a valid user name\n" if !$noerr;

    return undef;
}

PVE::JSONSchema::register_standard_option('userid', {
    description => "User ID",
    type => 'string', format => 'pmg-userid',
    minLength => 4,
    maxLength => 64,
});

PVE::JSONSchema::register_standard_option('username', {
    description => "Username (without realm)",
    type => 'string',
    pattern => '[^\s:\/\@]{3,60}',
    minLength => 4,
    maxLength => 64,
});

PVE::JSONSchema::register_standard_option('pmg-email-address', {
    description => "Email Address (allow most characters).",
    type => 'string',
    pattern => '(?:|[^\s\/\@]+\@[^\s\/\@]+)',
    maxLength => 512,
    minLength => 3,
});

sub lastid {
    my ($dbh, $seq) = @_;

    return $dbh->last_insert_id(
	undef, undef, undef, undef, { sequence => $seq});
}

# quote all regex operators
sub quote_regex {
    my $val = shift;

    $val =~ s/([\(\)\[\]\/\}\+\*\?\.\|\^\$\\])/\\$1/g;

    return $val;
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

# only write output if something fails
sub run_silent_cmd {
    my ($cmd) = @_;

    my $outbuf = '';

    my $record_output = sub {
	$outbuf .= shift;
	$outbuf .= "\n";
    };

    eval {
	PVE::Tools::run_command($cmd, outfunc => $record_output,
				errfunc => $record_output);
    };
    my $err = $@;

    if ($err) {
	print STDERR $outbuf;
	die $err;
    }
}

my $proxmox_tls_cert_fn = "/etc/pmg/pmg-tls.pem";

sub gen_proxmox_tls_cert {
    my ($force) = @_;

    my $resolv = PVE::INotify::read_file('resolvconf');
    my $domain = $resolv->{search};

    my $company = $domain; # what else ?
    my $cn = "*.$domain";

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
	my $cmd = ['openssl', 'req', '-batch', '-x509', '-new', '-sha256',
		   '-config', $cfgfn, '-days', 3650, '-nodes',
		   '-out', $proxmox_tls_cert_fn,
		   '-keyout', $proxmox_tls_cert_fn];
	run_silent_cmd($cmd);
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

my $service_aliases = {
    'postfix' =>  'postfix@-',
    'postgres' => 'postgresql@9.6-main',
};

sub lookup_real_service_name {
    my $alias = shift;

    return $service_aliases->{$alias} // $alias;
}

sub get_full_service_state {
    my ($service) = @_;

    my $res;

    my $parser = sub {
	my $line = shift;
	if ($line =~ m/^([^=\s]+)=(.*)$/) {
	    $res->{$1} = $2;
	}
    };

    $service = $service_aliases->{$service} // $service;
    PVE::Tools::run_command(['systemctl', 'show', $service], outfunc => $parser);

    return $res;
}

our $db_service_list = [
    'pmgpolicy', 'pmgmirror', 'pmgtunnel', 'pmg-smtp-filter' ];

sub service_wait_stopped {
    my ($timeout, $service_list) = @_;

    my $starttime = time();

    foreach my $service (@$service_list) {
	PVE::Tools::run_command(['systemctl', 'stop', $service]);
    }

    while (1) {
	my $wait = 0;

	foreach my $service (@$service_list) {
	    my $ss = get_full_service_state($service);
	    my $state = $ss->{ActiveState} // 'unknown';

	    if ($state ne 'inactive') {
		if ((time() - $starttime) > $timeout) {
		    syslog('err', "unable to stop services (got timeout)");
		    $wait = 0;
		    last;
		}
		$wait = 1;
	    }
	}

	last if !$wait;

	sleep(1);
    }
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

    $service = $service_aliases->{$service} // $service;
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

sub run_postmap {
    my ($filename) = @_;

    # make sure the file exists (else postmap fails)
    IO::File->new($filename, 'a', 0644);

    my $age_src = -M $filename // 0;
    my $age_dst = -M "$filename.db" // 10000000000;

    # if not changed, do nothing
    return if $age_src > $age_dst;

    eval {
	PVE::Tools::run_command(
	    ['/usr/sbin/postmap', $filename],
	    errmsg => "unable to update postfix table $filename");
    };
    my $err = $@;

    warn $err if $err;
}

sub clamav_dbstat {

    my $res = [];

    my $read_cvd_info = sub {
	my ($dbname, $dbfile) = @_;

        my $header;
	my $fh = IO::File->new("<$dbfile");
	if (!$fh) {
	    warn "cant open ClamAV Database $dbname ($dbfile) - $!\n";
	    return;
	}
	$fh->read($header, 512);
	$fh->close();

	## ClamAV-VDB:16 Mar 2016 23-17 +0000:57:4218790:60:06386f34a16ebeea2733ab037f0536be:
	if ($header =~ m/^(ClamAV-VDB):([^:]+):(\d+):(\d+):/) {
	    my ($ftype, $btime, $version, $nsigs) = ($1, $2, $3, $4);
	    push @$res, {
		name => $dbname,
		type => $ftype,
		build_time => $btime,
		version => $version,
		nsigs => $nsigs,
	    };
	} else {
	    warn "unable to parse ClamAV Database $dbname ($dbfile)\n";
	}
    };

    # main database
    my $filename = "/var/lib/clamav/main.inc/main.info";
    $filename = "/var/lib/clamav/main.cvd" if ! -f $filename;

    $read_cvd_info->('main', $filename) if -f $filename;

    # daily database
    $filename = "/var/lib/clamav/daily.inc/daily.info";
    $filename = "/var/lib/clamav/daily.cvd" if ! -f $filename;
    $filename = "/var/lib/clamav/daily.cld" if ! -f $filename;

    $read_cvd_info->('daily', $filename) if -f $filename;

    $filename = "/var/lib/clamav/bytecode.cvd";
    $read_cvd_info->('bytecode', $filename) if -f $filename;

    $filename = "/var/lib/clamav/safebrowsing.cvd";
    $read_cvd_info->('safebrowsing', $filename) if -f $filename;

    my $ss_dbs_fn = "/var/lib/clamav-unofficial-sigs/configs/ss-include-dbs.txt";
    my $ss_dbs_files = {};
    if (my $ssfh = IO::File->new("<${ss_dbs_fn}")) {
	while (defined(my $line = <$ssfh>)) {
	    chomp $line;
	    $ss_dbs_files->{$line} = 1;
	}
    }
    my $last = 0;
    my $nsigs = 0;
    foreach $filename (</var/lib/clamav/*>) {
	my $fn = basename($filename);
	next if !$ss_dbs_files->{$fn};

	my $fh = IO::File->new("<$filename");
	next if !defined($fh);
	my $st = stat($fh);
	next if !$st;
	my $mtime = $st->mtime();
	$last = $mtime if $mtime > $last;
	while (defined(my $line = <$fh>)) { $nsigs++; }
    }

    if ($nsigs > 0) {
	push @$res, {
	    name => 'sanesecurity',
	    type => 'unofficial',
	    build_time => strftime("%d %b %Y %H-%M %z", localtime($last)),
	    nsigs => $nsigs,
	};
    }

    return $res;
}

# RRD related code
my $rrd_dir = "/var/lib/rrdcached/db";
my $rrdcached_socket = "/var/run/rrdcached.sock";

my $rrd_def_node = [
    "DS:loadavg:GAUGE:120:0:U",
    "DS:maxcpu:GAUGE:120:0:U",
    "DS:cpu:GAUGE:120:0:U",
    "DS:iowait:GAUGE:120:0:U",
    "DS:memtotal:GAUGE:120:0:U",
    "DS:memused:GAUGE:120:0:U",
    "DS:swaptotal:GAUGE:120:0:U",
    "DS:swapused:GAUGE:120:0:U",
    "DS:roottotal:GAUGE:120:0:U",
    "DS:rootused:GAUGE:120:0:U",
    "DS:netin:DERIVE:120:0:U",
    "DS:netout:DERIVE:120:0:U",

    "RRA:AVERAGE:0.5:1:70", # 1 min avg - one hour
    "RRA:AVERAGE:0.5:30:70", # 30 min avg - one day
    "RRA:AVERAGE:0.5:180:70", # 3 hour avg - one week
    "RRA:AVERAGE:0.5:720:70", # 12 hour avg - one month
    "RRA:AVERAGE:0.5:10080:70", # 7 day avg - ony year

    "RRA:MAX:0.5:1:70", # 1 min max - one hour
    "RRA:MAX:0.5:30:70", # 30 min max - one day
    "RRA:MAX:0.5:180:70", # 3 hour max - one week
    "RRA:MAX:0.5:720:70", # 12 hour max - one month
    "RRA:MAX:0.5:10080:70", # 7 day max - ony year
];

sub cond_create_rrd_file {
    my ($filename, $rrddef) = @_;

    return if -f $filename;

    my @args = ($filename);

    push @args, "--daemon" => "unix:${rrdcached_socket}"
	if -S $rrdcached_socket;

    push @args, '--step', 60;

    push @args, @$rrddef;

    # print "TEST: " . join(' ', @args) . "\n";

    RRDs::create(@args);
    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;
}

sub update_node_status_rrd {

    my $filename = "$rrd_dir/pmg-node-v1.rrd";
    cond_create_rrd_file($filename, $rrd_def_node);

    my ($avg1, $avg5, $avg15) = PVE::ProcFSTools::read_loadavg();

    my $stat = PVE::ProcFSTools::read_proc_stat();

    my $netdev = PVE::ProcFSTools::read_proc_net_dev();

    my ($uptime) = PVE::ProcFSTools::read_proc_uptime();

    my $cpuinfo = PVE::ProcFSTools::read_cpuinfo();

    my $maxcpu = $cpuinfo->{cpus};

    # traffic from/to physical interface cards
    my $netin = 0;
    my $netout = 0;
    foreach my $dev (keys %$netdev) {
	next if $dev !~ m/^$PVE::Network::PHYSICAL_NIC_RE$/;
	$netin += $netdev->{$dev}->{receive};
	$netout += $netdev->{$dev}->{transmit};
    }

    my $meminfo = PVE::ProcFSTools::read_meminfo();

    my $dinfo = df('/', 1); # output is bytes

    my $ctime = time();

    # everything not free is considered to be used
    my $dused = $dinfo->{blocks} - $dinfo->{bfree};

    my $data = "$ctime:$avg1:$maxcpu:$stat->{cpu}:$stat->{wait}:" .
	"$meminfo->{memtotal}:$meminfo->{memused}:" .
	"$meminfo->{swaptotal}:$meminfo->{swapused}:" .
	"$dinfo->{blocks}:$dused:$netin:$netout";


    my @args = ($filename);

    push @args, "--daemon" => "unix:${rrdcached_socket}"
	if -S $rrdcached_socket;

    push @args, $data;

    # print "TEST: " . join(' ', @args) . "\n";

    RRDs::update(@args);
    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;
}

sub create_rrd_data {
    my ($rrdname, $timeframe, $cf) = @_;

    my $rrd = "${rrd_dir}/$rrdname";

    my $setup = {
	hour =>  [ 60, 70 ],
	day  =>  [ 60*30, 70 ],
	week =>  [ 60*180, 70 ],
	month => [ 60*720, 70 ],
	year =>  [ 60*10080, 70 ],
    };

    my ($reso, $count) = @{$setup->{$timeframe}};
    my $ctime  = $reso*int(time()/$reso);
    my $req_start = $ctime - $reso*$count;

    $cf = "AVERAGE" if !$cf;

    my @args = (
	"-s" => $req_start,
	"-e" => $ctime - 1,
	"-r" => $reso,
	);

    push @args, "--daemon" => "unix:${rrdcached_socket}"
	if -S $rrdcached_socket;

    my ($start, $step, $names, $data) = RRDs::fetch($rrd, $cf, @args);

    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;

    die "got wrong time resolution ($step != $reso)\n"
	if $step != $reso;

    my $res = [];
    my $fields = scalar(@$names);
    for my $line (@$data) {
	my $entry = { 'time' => $start };
	$start += $step;
	for (my $i = 0; $i < $fields; $i++) {
	    my $name = $names->[$i];
	    if (defined(my $val = $line->[$i])) {
		$entry->{$name} = $val;
	    } else {
		# leave empty fields undefined
		# maybe make this configurable?
	    }
	}
	push @$res, $entry;
    }

    return $res;
}

sub decode_to_html {
    my ($charset, $data) = @_;

    my $res = $data;

    eval { $res = encode_entities(decode($charset, $data)); };

    return $res;
}

sub decode_rfc1522 {
    my ($enc) = @_;

    my $res = '';

    return '' if !$enc;

    eval {
	foreach my $r (MIME::Words::decode_mimewords($enc)) {
	    my ($d, $cs) = @$r;
	    if ($d) {
		if ($cs) {
		    $res .= decode($cs, $d);
		} else {
		    $res .= $d;
		}
	    }
	}
    };

    $res = $enc if $@;

    return $res;
}

sub rfc1522_to_html {
    my ($enc) = @_;

    my $res = '';

    return '' if !$enc;

    eval {
	foreach my $r (MIME::Words::decode_mimewords($enc)) {
	    my ($d, $cs) = @$r;
	    if ($d) {
		if ($cs) {
		    $res .= encode_entities(decode($cs, $d));
		} else {
		    $res .= encode_entities($d);
		}
	    }
	}
    };

    $res = $enc if $@;

    return $res;
}

# RFC 2047 B-ENCODING http://rfc.net/rfc2047.html
# (Q-Encoding is complex and error prone)
sub bencode_header {
    my $txt = shift;

    my $CRLF = "\015\012";

    # Nonprintables (controls + x7F + 8bit):
    my $NONPRINT = "\\x00-\\x1F\\x7F-\\xFF";

    # always use utf-8 (work with japanese character sets)
    $txt = encode("UTF-8", $txt);

    return $txt if $txt !~ /[$NONPRINT]/o;

    my $res = '';

    while ($txt =~ s/^(.{1,42})//sm) {
	my $t = MIME::Words::encode_mimeword ($1, 'B', 'UTF-8');
	$res .= $res ? "\015\012\t$t" : $t;
    }

    return $res;
}

sub load_sa_descriptions {
    my ($additional_dirs) = @_;

    my @dirs = ('/usr/share/spamassassin',
		'/usr/share/spamassassin-extra');

    push @dirs, @$additional_dirs if @$additional_dirs;

    my $res = {};

    my $parse_sa_file = sub {
	my ($file) = @_;

	open(my $fh,'<', $file);
	return if !defined($fh);

	while (defined(my $line = <$fh>)) {
	    if ($line =~ m/^describe\s+(\S+)\s+(.*)\s*$/) {
		my ($name, $desc) = ($1, $2);
		next if $res->{$name};
		$res->{$name}->{desc} = $desc;
		if ($desc =~ m|[\(\s](http:\/\/\S+\.[^\s\.\)]+\.[^\s\.\)]+)|i) {
		    $res->{$name}->{url} = $1;
		}
	    }
	}
	close($fh);
    };

    foreach my $dir (@dirs) {
	foreach my $file (<$dir/*.cf>) {
	    $parse_sa_file->($file);
	}
    }

    $res->{'ClamAVHeuristics'}->{desc} = "ClamAV heuristic tests";

    return $res;
}

sub format_uptime {
    my ($uptime) = @_;

    my $days = int($uptime/86400);
    $uptime -= $days*86400;

    my $hours = int($uptime/3600);
    $uptime -= $hours*3600;

    my $mins = $uptime/60;

    if ($days) {
	my $ds = $days > 1 ? 'days' : 'day';
	return sprintf "%d $ds %02d:%02d", $days, $hours, $mins;
    } else {
	return sprintf "%02d:%02d", $hours, $mins;
    }
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
	Subject => bencode_header(decode_entities($title)));

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

sub lookup_timespan {
    my ($timespan) = @_;

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

    return ($start, $end);
}

my $rbl_scan_last_cursor;
my $rbl_scan_start_time = time();

sub scan_journal_for_rbl_rejects {

    # example postscreen log entry for RBL rejects
    # Aug 29 08:00:36 proxmox postfix/postscreen[11266]: NOQUEUE: reject: RCPT from [x.x.x.x]:1234: 550 5.7.1 Service unavailable; client [x.x.x.x] blocked using zen.spamhaus.org; from=<xxxx>, to=<yyyy>, proto=ESMTP, helo=<zzz>

    # example for PREGREET reject
    # Dec  7 06:57:11 proxmox postfix/postscreen[32084]: PREGREET 14 after 0.23 from [x.x.x.x]:63492: EHLO yyyyy\r\n

    my $identifier = 'postfix/postscreen';

    my $rbl_count = 0;
    my $pregreet_count = 0;

    my $parser = sub {
	my $line = shift;

	if ($line =~ m/^--\scursor:\s(\S+)$/) {
	    $rbl_scan_last_cursor = $1;
	    return;
	}

	if ($line =~ m/\s$identifier\[\d+\]:\sNOQUEUE:\sreject:.*550 5.7.1 Service unavailable;/) {
	    $rbl_count++;
	} elsif ($line =~ m/\s$identifier\[\d+\]:\sPREGREET\s\d+\safter\s/) {
	    $pregreet_count++;
	}
    };

    # limit to last 5000 lines to avoid long delays
    my $cmd = ['journalctl', '--show-cursor', '-o', 'short-unix', '--no-pager',
	       '--identifier', $identifier, '-n', 5000];

    if (defined($rbl_scan_last_cursor)) {
	push @$cmd, "--after-cursor=${rbl_scan_last_cursor}";
    } else {
	push @$cmd, "--since=@" . $rbl_scan_start_time;
    }

    PVE::Tools::run_command($cmd, outfunc => $parser);

    return ($rbl_count, $pregreet_count);
}

my $hwaddress;

sub get_hwaddress {

    return $hwaddress if defined ($hwaddress);

    my $fn = '/etc/ssh/ssh_host_rsa_key.pub';
    my $sshkey = PVE::Tools::file_get_contents($fn);
    $hwaddress = uc(Digest::MD5::md5_hex($sshkey));

    return $hwaddress;
}

my $default_locale = "en_US.UTF-8 UTF-8";

sub cond_add_default_locale {

    my $filename = "/etc/locale.gen";

    open(my $infh, "<", $filename) || return;

    while (defined(my $line = <$infh>)) {
	if ($line =~ m/^\Q${default_locale}\E/) {
	    # already configured
	    return;
	}
    }

    seek($infh, 0, 0) // return; # seek failed

    open(my $outfh, ">", "$filename.tmp") || return;

    my $done;
    while (defined(my $line = <$infh>)) {
	if ($line =~ m/^#\s*\Q${default_locale}\E.*/) {
	    print $outfh "${default_locale}\n" if !$done;
	    $done = 1;
	} else {
	    print $outfh $line;
	}
    }

    print STDERR "generation pmg default locale\n";

    rename("$filename.tmp", $filename) || return; # rename failed

    system("dpkg-reconfigure locales -f noninteractive");
}

1;
