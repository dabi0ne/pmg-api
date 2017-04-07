package PMG::Cluster;

use strict;
use warnings;
use Data::Dumper;
use Socket;
use File::Path;

use PVE::Tools;
use PVE::INotify;

use PMG::ClusterConfig;

our $spooldir = "/var/spool/proxmox";

sub create_needed_dirs {
    my ($lcid, $cleanup) = @_;

    # if requested, remove any stale date
    rmtree("$spooldir/cluster", "$spooldir/virus" "$spooldir/spam") if $cleanup;

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
	PVE::Tools::run_command($cmd);
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

1;
