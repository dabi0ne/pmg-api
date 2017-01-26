package PMG::Cluster;

use strict;
use warnings;

use Socket;
use PVE::Tools;
use PVE::INotify;

# this is also used to get the IP of the local node
sub remote_node_ip {
    my ($nodename, $noerr) = @_;

    # todo: implement cluster node list

    # fallback: try to get IP by other means
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

# X509 Certificate cache helper

my $cert_cache_nodes = {};
my $cert_cache_timestamp = time();
my $cert_cache_fingerprints = {};

sub update_cert_cache {
    my ($update_node, $clear) = @_;

    syslog('info', "Clearing outdated entries from certificate cache")
	if $clear;

    $cert_cache_timestamp = time() if !defined($update_node);

    my $node_list = defined($update_node) ?
	[ $update_node ] : [ keys %$cert_cache_nodes ];

    my $clear_node = sub {
	my ($node) = @_;
	if (my $old_fp = $cert_cache_nodes->{$node}) {
	    # distrust old fingerprint
	    delete $cert_cache_fingerprints->{$old_fp};
	    # ensure reload on next proxied request
	    delete $cert_cache_nodes->{$node};
	}
    };

    my $nodename = PVE::INotify::nodename();

    foreach my $node (@$node_list) {

	if ($node ne $nodename) {
	    &$clear_node($node) if $clear;
	    next;
	}

	my $cert_path = "/etc/proxmox/pmg-api.pem";

	my $cert;
	eval {
	    my $bio = Net::SSLeay::BIO_new_file($cert_path, 'r');
	    $cert = Net::SSLeay::PEM_read_bio_X509($bio);
	    Net::SSLeay::BIO_free($bio);
	};
	my $err = $@;
	if ($err || !defined($cert)) {
	    &$clear_node($node) if $clear;
	    next;
	}

	my $fp;
	eval {
	    $fp = Net::SSLeay::X509_get_fingerprint($cert, 'sha256');
	};
	$err = $@;
	if ($err || !defined($fp) || $fp eq '') {
	    &$clear_node($node) if $clear;
	    next;
	}

	my $old_fp = $cert_cache_nodes->{$node};
	$cert_cache_fingerprints->{$fp} = 1;
	$cert_cache_nodes->{$node} = $fp;

	if (defined($old_fp) && $fp ne $old_fp) {
	    delete $cert_cache_fingerprints->{$old_fp};
	}
    }
}

# load and cache cert fingerprint once
sub initialize_cert_cache {
    my ($node) = @_;

    update_cert_cache($node)
	if defined($node) && !defined($cert_cache_nodes->{$node});
}

sub check_cert_fingerprint {
    my ($cert) = @_;

    # clear cache every 30 minutes at least
    update_cert_cache(undef, 1) if time() - $cert_cache_timestamp >= 60*30;

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

    return 1 if &$check();

    # clear cache and retry at most once every minute
    if (time() - $cert_cache_timestamp >= 60) {
	syslog ('info', "Could not verify remote node certificate '$fp' with list of pinned certificates, refreshing cache");
	update_cert_cache();
	return &$check();
    }

    return 0;
}

1;
