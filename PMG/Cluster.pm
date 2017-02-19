package PMG::Cluster;

use strict;
use warnings;

use Socket;
use PVE::Tools;
use PVE::INotify;

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

sub remote_node_ip {
    my ($nodename, $noerr) = @_;

    my $cinfo = PVE::INotify::read_file("cluster.conf");

    foreach my $entry (@{$cinfo->{nodes}}) {
	if ($entry->{name} eq $nodename) {
	    my $ip = $entry->{ip};
	    return $ip if !wantarray;
	    my $family = PVE::Tools::get_host_address_family($ip);
	    return ($ip, $family);
	}
    }

    # fallback: try to get IP by other means
    return lookup_node_ip($nodename, $noerr);
}

sub get_master_node {
    my ($cinfo) = @_;

    $cinfo //= PVE::INotify::read_file("cluster.conf");

    return $cinfo->{master}->{name} if defined($cinfo->{master});

    return 'localhost';
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

sub read_cluster_conf {
    my ($filename, $fh) = @_;

    my $localname = PVE::INotify::nodename();
    my $localip = lookup_node_ip($localname);

    my $level = 0;
    my $maxcid = 0;

    my $cinfo;

    $cinfo->{nodes} = [];
    $cinfo->{remnodes} = [];

    $cinfo->{local} = {
	role => '-',
	cid => 0,
	ip => $localip,
	name => $localname,
	configport => 83,
	dbport => 5432,
    };

    # fixme: add test is local node is part of node list
    if (defined($fh)) {

	$cinfo->{exists} = 1; # cluster configuratin file exists and is readable

	while (defined(my $line = <$fh>)) {
	    chomp $line;

	    next if $line =~ m/^\s*$/; # skip empty lines

	    if ($line =~ m/^maxcid\s+(\d+)\s*$/i) {
		$maxcid = $1 > $maxcid ? $1 : $maxcid;
		next;
	    }

	    if ($line =~ m/^(master|node)\s+(\d+)\s+\{\s*$/i) {
		$level++;
		my ($t, $cid) = (lc($1), $2);

		$maxcid = $cid > $maxcid ? $cid : $maxcid;

		my $res = {
		    role => $t eq 'master' ? 'M' : 'N',
		    cid => $cid
		};

		while (defined($line = <$fh>)) {
		    chomp $line;
		    next if $line =~ m/^\s*$/; # skip empty lines
		    if ($line =~ m/^\}\s*$/) {
			$level--;
			last;
		    }

		    if ($line =~ m/^\s*(\S+)\s*:\s*(\S+)\s*$/) {
			my ($n, $v) = (lc $1, $2);

			# fixme: do syntax checks
			if ($n eq 'ip') {
			    $res->{$n} = $v;
			} elsif ($n eq 'name') {
			    $res->{$n} = $v;
			} elsif ($n eq 'hostrsapubkey') {
			    $res->{$n} = $v;
			} elsif ($n eq 'rootrsapubkey') {
			    $res->{$n} = $v;
			} else {
			    die "syntax error in configuration file\n";
			}
		    } else {
			die "syntax error in configuration file\n";
		    }
		}

		die "missing ip address for node '$cid'\n" if !$res->{ip};
		die "missing name for node '$cid'\n" if !$res->{name};
		#die "missing host RSA key for node '$cid'\n" if !$res->{hostrsapubkey};
		#die "missing user RSA key for node '$cid'\n" if !$res->{rootrsapubkey};

		push @{$cinfo->{nodes}}, $res;

		if ($res->{role} eq 'M') {
		    $cinfo->{master} = $res;
		}

		if ($res->{ip} eq $localname) {
		    $cinfo->{local} = $res;
		}
	    } else {
		die "syntax error in configuration file\n";
	    }
	}
    }

    die "syntax error in configuration file\n" if $level;

    $cinfo->{maxcid} = $maxcid;

    my @cidlist = ();
    foreach my $ni (@{$cinfo->{nodes}}) {
	next if $cinfo->{local}->{cid} == $ni->{cid}; # skip local CID
	push @cidlist, $ni->{cid};
    }

    my $ind = 0;
    my $portid = {};
    foreach my $cid (sort @cidlist) {
	$portid->{$cid} = $ind;
	$ind++;
    }

    foreach my $ni (@{$cinfo->{nodes}}) {
	# fixme: do we still need those ports?
	$ni->{configport} = $ni->{cid} == $cinfo->{local}->{cid} ? 83 : 50000 + $portid->{$ni->{cid}};
	$ni->{dbport} = $ni->{cid} == $cinfo->{local}->{cid} ? 5432 : 50100 + $portid->{$ni->{cid}};
    }

    foreach my $ni (@{$cinfo->{nodes}}) {
	next if $ni->{cid} == $cinfo->{local}->{cid};
	push @{$cinfo->{remnodes}}, $ni->{cid};
    }

    return $cinfo;
}

sub write_cluster_conf {
    my ($filename, $fh, $cinfo) = @_;

    my $raw = "maxcid $cinfo->{maxcid}\n\n";

    foreach my $ni (@{$cinfo->{nodes}}) {

	if ($ni->{role} eq 'M') {
	    $raw .= "master $ni->{cid} {\n";
	    $raw .= " IP: $ni->{ip}\n";
	    $raw .= " NAME: $ni->{name}\n";
	    $raw .= " HOSTRSAPUBKEY: $ni->{hostrsapubkey}\n";
	    $raw .= " ROOTRSAPUBKEY: $ni->{rootrsapubkey}\n";
	    $raw .= "}\n\n";
	} elsif ($ni->{role} eq 'N') {
	    $raw .= "node $ni->{cid} {\n";
	    $raw .= " IP: $ni->{ip}\n";
	    $raw .= " NAME: $ni->{name}\n";
	    $raw .= " HOSTRSAPUBKEY: $ni->{hostrsapubkey}\n";
	    $raw .= " ROOTRSAPUBKEY: $ni->{rootrsapubkey}\n";
	    $raw .= "}\n\n";
	}
    }

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file('cluster.conf', "/etc/proxmox/cluster.conf",
			    \&read_cluster_conf,
			    \&write_cluster_conf,
			    undef,
			    always_call_parser => 1);

1;
