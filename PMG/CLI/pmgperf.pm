package PMG::CLI::pmgperf;

use strict;
use warnings;
use Data::Dumper;
use File::Sync;
use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );
use Net::DNS::Resolver;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::CLIHandler;

use PMG::RESTEnvironment;

use base qw(PVE::CLIHandler);

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

sub drop_cache {

    # free pagecache,dentries,inode cache
    if (-f '/proc/sys/vm/drop_caches') {
	system ("echo 3 > /proc/sys/vm/drop_caches");
    }
}

sub test_bogomips {
    my $bogomips = 0;

    open (TMP, "/proc/cpuinfo");

    while (my $line = <TMP>) {
	if ($line =~ m/^bogomips\s*:\s*(\d+\.\d+)\s*$/) {
	    $bogomips += $1;
	}
    }

    close (TMP);

    printf "CPU BOGOMIPS:      %.2f\n", $bogomips;
}

sub test_regex {

    my $starttime = [gettimeofday];

    my $count = 0;
    my $elapsed = 0;

    for (;; $count++) {

	my $str = int(rand(1000000)) . time();
	if ($str =~ m/(.+)123.?123/) {
	}
	$elapsed = tv_interval ($starttime);

	last if $elapsed > 3;
    }

    printf "REGEX/SECOND:      %d\n", $count;
}

sub test_fsync {
    my $basedir = shift;

    drop_cache ();

    my $dir = "$basedir/ptest.$$";

    eval {

	mkdir $dir;

	my $data = ('A' x 4000) . "\n";

	my $starttime = [gettimeofday];

	my $count;
	my $elapsed = 0;

	for ($count=1;;$count++) {
	    my $m = $count % 300;

	    my $filename = "$dir/tf_$m.dat";

	    open (TMP, ">$filename") || die "open failed";

	    print TMP $data;

	    File::Sync::fsync (\*TMP);

	    close (TMP);

	    $elapsed = tv_interval ($starttime);

	    last if $elapsed > 3;
	}
	my $sps = $count /$elapsed; # fsync per second

	printf "FSYNCS/SECOND:     %.2f\n", $sps;
    };

    my $err = $@;

    system ("rm -rf $dir");

    die $err if $err;
}

sub test_seektime {
    my ($rootdev, $hdsize) = @_;

    drop_cache ();

    open (ROOTHD, "<$rootdev") || die "unable to open HD";

    my $starttime = [gettimeofday];
    my $count;
    my $elapsed = 0;
    my $readbuf;

    for ($count=1;;$count++) {

	my $pos = int (rand (int($hdsize/512))) * 512;

	sysseek (ROOTHD, $pos, 0);

	(sysread (ROOTHD, $readbuf, 512) == 512) || die "read failed";

	$elapsed = tv_interval ($starttime);

	last if $elapsed > 3;
    }

    close (ROOTHD);

    my $rps = $count /$elapsed; # blocks per second
    my $ast = (1000/$rps);
    printf "AVERAGE SEEK TIME: %.2f ms\n", $ast;
}

sub test_read {
    my $rootdev = shift;

    drop_cache ();

    my $starttime = [gettimeofday];
    my $bytes = 0;
    my $elapsed = 0;
    my $readbuf;


    open (ROOTHD, "<$rootdev") || die "unable to open HD";


    for (;;) {

	my $c = sysread (ROOTHD, $readbuf, 2 * 1024 *1024);
	die "read failed" if $c < 0;

	$bytes += $c;

	$elapsed = tv_interval ($starttime);

	last if $elapsed > 3;
    }

    close (ROOTHD);

    my $bps = $bytes /($elapsed * 1024 * 1024); # MB per second
    printf "BUFFERED READS:    %.2f MB/sec\n", $bps;
}

sub get_address {
    my ($resolv, $dns) = @_;

    if (my $a = $resolv->send ($dns, 'A')) {
	foreach my $rra ($a->answer) {
	    if ($rra->type eq 'A') {
		return $rra->address;
	    }
	}
    }

    return undef;
}

sub test_dns {

    my %dnsargs = (
		   tcp_timeout => 10,
		   udp_timeout => 10,
		   retry => 1,
		   retrans => 0,
		   dnsrch => 0,
		   defnames => 0,
		   debug => 0,
		   );

    #$dnsargs{nameservers} = [ qw (208.67.222.222) ];
    #$dnsargs{nameservers} = [ qw (127.0.0.1) ];

    my $resolv = Net::DNS::Resolver->new (%dnsargs);

    my $starttime = [gettimeofday];

    my $count;
    my $elapsed = 0;

    my $uid = time() . int(rand(1000000));
    my $domain = "nonexistent$uid.com";

    for ($count=1;;$count++) {

	my $hid = int(rand(1000000));
	my $hname = "test${hid}.$domain";
	get_address ($resolv, $hname);
	$elapsed = tv_interval ($starttime);

	last if ($count > 100) || ($elapsed > 3);
    }

    printf "DNS EXT:           %0.2f ms\n", ($elapsed * 1000)/$count;

    my $resolv_conf = `cat /etc/resolv.conf`;
    ($domain) = $resolv_conf =~ m/^search\s+(\S+)\s*$/mg;

    if ($domain) {
	$starttime = [gettimeofday];
	$elapsed = 0;

	for ($count=1;;$count++) {

	    my $hid = int(rand(1000000));
	    my $hname = "test${hid}.$domain";
	    get_address ($resolv, $hname);
	    $elapsed = tv_interval ($starttime);

	    last if ($count > 100) || ($elapsed > 3);
	}

	printf "DNS INT:           %0.2f ms (%s)\n",
	($elapsed * 1000)/ $count, $domain;
    }
}



use base qw(PVE::CLIHandler);
__PACKAGE__->register_method ({
    name => 'pmgperf',
    path => 'pmgperf',
    method => 'POST',
    description => "Proxmox benchmark.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    path => {
		description => "File system location to test.",
		type => 'string',
		optional => 1,
		default => '/',
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $path = $param->{path} // '/';

	test_bogomips ();
	test_regex ();

	my $hd = `df -P '$path'`;

	my ($rootdev, $hdo_total, $hdo_used, $hdo_avail) = $hd =~
	    m/^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+\s+.*$/mg;

	if ($rootdev) {
	    my $hdsize = $hdo_total*1024;
	    printf "HD SIZE:           %.2f GB ($rootdev)\n", ($hdsize / (1024*1024*1024));

	    if ($rootdev =~ m|^/dev/|) {
		test_read ($rootdev);

		test_seektime ($rootdev, $hdsize);
	    }
	}

	test_fsync ($path) if $hdo_avail;

	test_dns ();

	return undef;
    }});

our $cmddef = [ __PACKAGE__, 'pmgperf', ['path']];

1;
