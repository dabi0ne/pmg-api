package PMG::Cluster;

use strict;
use warnings;
use Data::Dumper;
use Socket;
use File::Path;

use PVE::SafeSyslog;
use PVE::Tools;
use PVE::INotify;

use PMG::Utils;
use PMG::Config;
use PMG::ClusterConfig;
use PMG::RuleDB;
use PMG::RuleCache;
use PVE::APIClient::LWP;

our $spooldir = "/var/spool/proxmox";

sub create_needed_dirs {
    my ($lcid, $cleanup) = @_;

    # if requested, remove any stale date
    File::Path::remove_tree("$spooldir/cluster", "$spooldir/virus", "$spooldir/spam") if $cleanup;

    mkdir "$spooldir/spam";
    mkdir "$spooldir/virus";

    if ($lcid) {
	mkpath "$spooldir/cluster/$lcid/virus";
	mkpath "$spooldir/cluster/$lcid/spam";
    }
}

sub remote_node_ip {
    my ($nodename, $noerr) = @_;

    my $cinfo = PMG::ClusterConfig->new();

    foreach my $entry (values %{$cinfo->{ids}}) {
	if ($entry->{name} eq $nodename) {
	    my $ip = $entry->{ip};
	    return $ip if !wantarray;
	    my $family = PVE::Tools::get_host_address_family($ip);
	    return ($ip, $family);
	}
    }

    # fallback: try to get IP by other means
    return PMG::Utils::lookup_node_ip($nodename, $noerr);
}

sub get_master_node {
    my ($cinfo) = @_;

    $cinfo = PMG::ClusterConfig->new() if !$cinfo;

    return $cinfo->{master}->{name} if defined($cinfo->{master});

    return 'localhost';
}

sub read_local_ssl_cert_fingerprint {
    my $cert_path = "/etc/pmg/pmg-api.pem";

    my $cert;
    eval {
	my $bio = Net::SSLeay::BIO_new_file($cert_path, 'r');
	$cert = Net::SSLeay::PEM_read_bio_X509($bio);
	Net::SSLeay::BIO_free($bio);
    };
    if (my $err = $@) {
	die "unable to read certificate '$cert_path' - $err\n";
    }

    if (!defined($cert)) {
	die "unable to read certificate '$cert_path' - got empty value\n";
    }

    my $fp;
    eval {
	$fp = Net::SSLeay::X509_get_fingerprint($cert, 'sha256');
    };
    if (my $err = $@) {
	die "unable to get fingerprint for '$cert_path' - $err\n";
    }

    if (!defined($fp) || $fp eq '') {
	die "unable to get fingerprint for '$cert_path' - got empty value\n";
    }

    return $fp;
}

my $hostrsapubkey_fn = '/etc/ssh/ssh_host_rsa_key.pub';
my $rootrsakey_fn = '/root/.ssh/id_rsa';
my $rootrsapubkey_fn = '/root/.ssh/id_rsa.pub';

sub read_local_cluster_info {

    my $res = {};

    my $hostrsapubkey = PVE::Tools::file_read_firstline($hostrsapubkey_fn);
    $hostrsapubkey =~ s/^.*ssh-rsa\s+//i;
    $hostrsapubkey =~ s/\s+root\@\S+\s*$//i;

    die "unable to parse ${hostrsapubkey_fn}\n"
	if $hostrsapubkey !~ m/^[A-Za-z0-9\.\/\+]{200,}$/;

    my $nodename = PVE::INotify::nodename();

    $res->{name} = $nodename;

    $res->{ip} = PMG::Utils::lookup_node_ip($nodename);

    $res->{hostrsapubkey} = $hostrsapubkey;

    if (! -f $rootrsapubkey_fn) {
	unlink $rootrsakey_fn;
	my $cmd = ['ssh-keygen', '-t', 'rsa', '-N', '', '-b', '2048',
		   '-f', $rootrsakey_fn];
	PMG::Utils::run_silent_cmd($cmd);
    }

    my $rootrsapubkey = PVE::Tools::file_read_firstline($rootrsapubkey_fn);
    $rootrsapubkey =~ s/^.*ssh-rsa\s+//i;
    $rootrsapubkey =~ s/\s+root\@\S+\s*$//i;

    die "unable to parse ${rootrsapubkey_fn}\n"
	if $rootrsapubkey !~ m/^[A-Za-z0-9\.\/\+]{200,}$/;

    $res->{rootrsapubkey} = $rootrsapubkey;

    $res->{fingerprint} = read_local_ssl_cert_fingerprint();

    return $res;
}

# X509 Certificate cache helper

my $cert_cache_nodes = {};
my $cert_cache_timestamp = time();
my $cert_cache_fingerprints = {};

sub update_cert_cache {

    $cert_cache_timestamp = time();

    $cert_cache_fingerprints = {};
    $cert_cache_nodes = {};

    my $cinfo = PMG::ClusterConfig->new();

    foreach my $entry (values %{$cinfo->{ids}}) {
	my $node = $entry->{name};
	my $fp = $entry->{fingerprint};
	if ($node && $fp) {
	    $cert_cache_fingerprints->{$fp} = 1;
	    $cert_cache_nodes->{$node} = $fp;
	}
    }
}

# load and cache cert fingerprint once
sub initialize_cert_cache {
    my ($node) = @_;

    update_cert_cache()
	if defined($node) && !defined($cert_cache_nodes->{$node});
}

sub check_cert_fingerprint {
    my ($cert) = @_;

    # clear cache every 30 minutes at least
    update_cert_cache() if time() - $cert_cache_timestamp >= 60*30;

    # get fingerprint of server certificate
    my $fp;
    eval {
	$fp = Net::SSLeay::X509_get_fingerprint($cert, 'sha256');
    };
    return 0 if $@ || !defined($fp) || $fp eq ''; # error

    my $check = sub {
	for my $expected (keys %$cert_cache_fingerprints) {
	    return 1 if $fp eq $expected;
	}
	return 0;
    };

    return 1 if $check->();

    # clear cache and retry at most once every minute
    if (time() - $cert_cache_timestamp >= 60) {
	syslog ('info', "Could not verify remote node certificate '$fp' with list of pinned certificates, refreshing cache");
	update_cert_cache();
	return $check->();
    }

    return 0;
}

my $sshglobalknownhosts = "/etc/ssh/ssh_known_hosts2";
my $rootsshauthkeys = "/root/.ssh/authorized_keys";
my $ssh_rsa_id = "/root/.ssh/id_rsa.pub";

sub update_ssh_keys {
    my ($cinfo) = @_;

    my $data = '';
    foreach my $node (values %{$cinfo->{ids}}) {
	$data .= "$node->{ip} ssh-rsa $node->{hostrsapubkey}\n";
	$data .= "$node->{name} ssh-rsa $node->{hostrsapubkey}\n";
    }

    PVE::Tools::file_set_contents($sshglobalknownhosts, $data);

    $data = '';

    # always add ourself
    if (-f $ssh_rsa_id) {
	my $pub = PVE::Tools::file_get_contents($ssh_rsa_id);
	chomp($pub);
	$data .= "$pub\n";
    }

    foreach my $node (values %{$cinfo->{ids}}) {
	$data .= "ssh-rsa $node->{rootrsapubkey} root\@$node->{name}\n";
    }

    if (-f $rootsshauthkeys) {
	my $mykey = PVE::Tools::file_get_contents($rootsshauthkeys, 128*1024);
	chomp($mykey);
	$data .= "$mykey\n";
    }

    my $newdata = "";
    my $vhash = {};
    my @lines = split(/\n/, $data);
    foreach my $line (@lines) {
	if ($line !~ /^#/ && $line =~ m/(^|\s)ssh-(rsa|dsa)\s+(\S+)\s+\S+$/) {
            next if $vhash->{$3}++;
	}
	$newdata .= "$line\n";
    }

    PVE::Tools::file_set_contents($rootsshauthkeys, $newdata, 0600);
}

my $cfgdir = '/etc/pmg';
my $syncdir = "$cfgdir/master";

my $cond_commit_synced_file = sub {
    my ($filename, $dstfn) = @_;

    $dstfn = "$cfgdir/$filename" if !defined($dstfn);
    my $srcfn = "$syncdir/$filename";

    if (! -f $srcfn) {
	unlink $dstfn;
	return;
    }

    my $new = PVE::Tools::file_get_contents($srcfn, 1024*1024);

    if (-f $dstfn) {
	my $old = PVE::Tools::file_get_contents($dstfn, 1024*1024);
	return 0 if $new eq $old;
    }

    rename($srcfn, $dstfn) ||
	die "cond_rename_file '$filename' failed - $!\n";

    print STDERR "updated $dstfn\n";

    return 1;
};

my $rsync_command = sub {
    my ($host_key_alias, @args) = @_;

    my $ssh_cmd = '--rsh=ssh -l root -o BatchMode=yes';
    $ssh_cmd .=  " -o HostKeyAlias=${host_key_alias}" if $host_key_alias;

    my $cmd = ['rsync', $ssh_cmd,  '-q', @args];

    return $cmd;
};

sub sync_quarantine_files {
    my ($host_ip, $host_name, $flistname) = @_;

    my $cmd = $rsync_command->(
	$host_name, '--timeout', '10', "${host_ip}:$spooldir", $spooldir,
	'--files-from', $flistname);

    Proxmox::Utils::run_command($cmd);
}

sub sync_spooldir {
    my ($host_ip, $host_name, $rcid) = @_;

    mkdir "$spooldir/cluster/";
    my $syncdir = "$spooldir/cluster/$rcid";
    mkdir $syncdir;

    my $cmd = $rsync_command->(
	$host_name, '-aq', '--timeout', '10', "${host_ip}:$syncdir/", $syncdir);

    foreach my $incl (('spam/', 'spam/*', 'spam/*/*', 'virus/', 'virus/*', 'virus/*/*')) {
	push @$cmd, '--include', $incl;
    }

    push @$cmd, '--exclude', '*';

    PVE::Tools::run_command($cmd);
}

sub sync_master_quar {
    my ($host_ip, $host_name) = @_;

    my $syncdir = "$spooldir/cluster/";
    mkdir $syncdir;

    my $cmd = $rsync_command->(
	$host_name, '-aq', '--timeout', '10', "${host_ip}:$syncdir", $syncdir);

    PVE::Tools::run_command($cmd);
}

sub sync_config_from_master {
    my ($cinfo, $master_name, $master_ip, $noreload) = @_;

    my $local_ip = $cinfo->{local}->{ip};
    my $local_name = $cinfo->{local}->{name};

    if ($local_ip eq $master_ip) {
	print STDERR "local node is master - nothing to do\n";
	return;
    }

    mkdir $syncdir;
    File::Path::remove_tree($syncdir, {keep_root => 1});

    my $sa_conf_dir = "/etc/mail/spamassassin";
    my $sa_custom_cf = "custom.cf";

    my $cmd = $rsync_command->(
	$master_name, '-lpgoq',
	"${master_ip}:$cfgdir/* ${sa_conf_dir}/${sa_custom_cf}",
	"$syncdir/",
	'--exclude', '*~',
	'--exclude', '*.db',
	'--exclude', 'pmg-api.pem',
	'--exclude', 'pmg-tls.pem',
	);

    my $errmsg = "syncing master configuration from '${master_ip}' failed";
    PVE::Tools::run_command($cmd, errmsg => $errmsg);

    # verify that the remote host is cluster master
    open (my $fh, '<', "$syncdir/cluster.conf") ||
	die "unable to open synced cluster.conf - $!\n";
    my $newcinfo = PMG::ClusterConfig::read_cluster_conf('cluster.conf', $fh);

    if (!$newcinfo->{master} || ($newcinfo->{master}->{ip} ne $master_ip)) {
	die "host '$master_ip' is not cluster master\n";
    }

    my $role = $newcinfo->{'local'}->{type} // '-';
    die "local node '$newcinfo->{local}->{name}' not part of cluster\n"
	if $role eq '-';

    die "local node '$newcinfo->{local}->{name}' is new cluster master\n"
	if $role eq 'master';


    $cond_commit_synced_file->('cluster.conf');
    $cinfo = $newcinfo;

    my $files = [
	'pmg-authkey.key',
	'pmg-authkey.pub',
	'pmg-csrf.key',
	'ldap.conf',
	'user.conf',
	];

    foreach my $filename (@$files) {
	$cond_commit_synced_file->($filename);
    }

    my $force_restart = {};

    if ($cond_commit_synced_file->($sa_custom_cf, "${sa_conf_dir}/${sa_custom_cf}")) {
	$force_restart->{spam} = 1;
    }

    $cond_commit_synced_file->('pmg.conf');

    my $cfg = PMG::Config->new();

    $cfg->rewrite_config(1, $force_restart);
}

sub sync_ruledb_from_master {
    my ($ldb, $rdb, $ni, $ticket) = @_;

    my $ruledb = PMG::RuleDB->new($ldb);
    my $rulecache = PMG::RuleCache->new($ruledb);

    my $conn = PVE::APIClient::LWP->new(
	ticket => $ticket,
	cookie_name => 'PMGAuthCookie',
	host => $ni->{ip},
	cached_fingerprints => {
	    $ni->{fingerprint} => 1,
	});

    my $digest = $conn->get("/config/ruledb/digest", {});

    return if $digest eq $rulecache->{digest}; # no changes

    syslog('info', "detected rule database changes - starting sync from '$ni->{ip}'");

    eval {
	$ldb->begin_work;

	$ldb->do("DELETE FROM Rule");
	$ldb->do("DELETE FROM RuleGroup");
	$ldb->do("DELETE FROM ObjectGroup");
	$ldb->do("DELETE FROM Object");
	$ldb->do("DELETE FROM Attribut");

	eval {
	    $rdb->begin_work;

	    # read a consistent snapshot
	    $rdb->do("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");

	    PMG::DBTools::copy_table($ldb, $rdb, "Rule");
	    PMG::DBTools::copy_table($ldb, $rdb, "RuleGroup");
	    PMG::DBTools::copy_table($ldb, $rdb, "ObjectGroup");
	    PMG::DBTools::copy_table($ldb, $rdb, "Object", 'value');
	    PMG::DBTools::copy_table($ldb, $rdb, "Attribut", 'value');
	};

	$rdb->rollback; # end transaction

	die $@ if $@;

	# update sequences

	$ldb->do("SELECT setval('rule_id_seq', max(id)+1) FROM Rule");
	$ldb->do("SELECT setval('object_id_seq', max(id)+1) FROM Object");
	$ldb->do("SELECT setval('objectgroup_id_seq', max(id)+1) FROM ObjectGroup");

	$ldb->commit;
    };
    if (my $err = $@) {
	$ldb->rollback;
	die $err;
    }

    syslog('info', "finished rule database sync from host '$ni->{ip}'");
}

1;
