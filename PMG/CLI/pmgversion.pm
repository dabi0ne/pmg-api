#!/usr/bin/perl

use strict;
use warnings;
use POSIX;
use Getopt::Long;
use PMG::pmgcfg;
use PMG::API2::APT;

my $pkgarray = PMG::API2::APT->versions({ node => 'localhost'});
my $pkglist = {};
foreach my $pkg (@$pkgarray) {
    $pkglist->{$pkg->{Package}} = $pkg;
}

sub print_status {
    my ($pkg) = @_;

    my $pkginfo =  $pkglist->{$pkg};

    if (!$pkginfo) {
	print "$pkg: unknown package - internal error\n";
	return;
    }
    my $version = "not correctly installed";
    if ($pkginfo->{OldVersion} && $pkginfo->{CurrentState} eq 'Installed') {
	$version = $pkginfo->{OldVersion};
    }

    if ($pkginfo->{RunningKernel}) {
	print "$pkg: $version (running kernel: $pkginfo->{RunningKernel})\n";
    } elsif ($pkginfo->{ManagerVersion}) {
	print "$pkg: $version (running version: $pkginfo->{ManagerVersion})\n";
    } else {
	print "$pkg: $version\n";
    }
}

sub print_usage {
    my $msg = shift;

    print STDERR "ERROR: $msg\n" if $msg;
    print STDERR "USAGE: pmgversion [--verbose]\n";

}

my $opt_verbose;

if (!GetOptions ('verbose' => \$opt_verbose)) {
    print_usage ();
    exit (-1);
} 

if (scalar (@ARGV) != 0) {
    print_usage ();
    exit (-1);
}

my $ver =  PMG::pmgcfg::package() . '/' . PMG::pmgcfg::version_text();
my (undef, undef, $kver) = POSIX::uname();


if (!$opt_verbose) {
    print "$ver (running kernel: $kver)\n";
    exit (0);
}

foreach my $pkg (@$pkgarray) {
    print_status($pkg->{Package});
}

exit 0;

__END__

=head1 NAME

pmgversion - Proxmox Mail Gateway version info

=head1 SYNOPSIS

pmgversion [--verbose]

=head1 DESCRIPTION

Print version information for Proxmox Mail Gateway packages.
