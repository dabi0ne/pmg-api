package PMG::RuleDB::IPNet;

use strict;
use warnings;
use Carp;
use DBI;
use Net::CIDR::Lite;

use PMG::Utils;
use PMG::RuleDB::WhoRegex;

use base qw(PMG::RuleDB::WhoRegex);

sub otype {
    return 1004;
}

sub otype_text {
    return 'IP Network';
}

sub oicon {
    return 'ip.gif';
}

sub new {
    my ($type, $address, $ogroup) = @_;
    
    my $class = ref($type) || $type;
 
    $address //= '127.0.0.1/32';

    my $self = $class->SUPER::new($address, $ogroup);

    return $self;
}

sub who_match {
    my ($self, $addr, $ip) = @_;

    # fixme: implement me
    # use queue->{xforward}->{addr} for from match
    # dont know what to do in To match

    return 0 if !$ip;

    my $cidr = Net::CIDR::Lite->new;
    $cidr->add($self->{address});

    return $cidr->find($ip);
}


my @subnets = map { join(".", unpack("C*", pack("B*", substr("1" x $_ . "0" x 32, 0, 32))))} 0..32;

sub short_desc {
    my $self 	= shift;

    my ($address, $mask) = split('/', $self->{address});

    my $desc = $address . "/" . $subnets[$mask];
    
    return $desc;
}

1;

__END__

=head1 PMG::RuleDB::IPNet

A WHO object to check sender IP addresses.

=head2 Attribues

=head3 address

An IP address/network (CIDR representation).

=head2 Examples

    $obj = PMG::RuleDB::IPNet->new ('192.168.2.0/20');

