package PMG::RuleDB::IPAddress;

use strict;
use warnings;
use Carp;
use DBI;

use PMG::Utils;
use PMG::RuleDB::WhoRegex;

use base qw(PMG::RuleDB::WhoRegex);

sub otype {
    return 1003;
}

sub otype_text {
    return 'IP Address';
}

sub oicon {
    return 'ip.gif';
}

sub new {
    my ($type, $address, $ogroup) = @_;
    
    my $class = ref($type) || $type;
 
    $address //= '127.0.0.1';

    my $self = $class->SUPER::new($address, $ogroup);

    return $self;
}

sub who_match {
    my ($self, $addr, $ip) = @_;

    # fixme: implement me
    # use queue->{xforward}->{addr} for from match
    # dont know what to do in To match

    return 0 if !$ip;

    return $self->{address} eq $ip;
}

sub short_desc {
    my $self = shift;
    
    my $desc = $self->{address};
    
    return $desc;
}

1;

__END__

=head1 PMG::RuleDB::IPAddress

A WHO object to check sender IP addresses.

=head2 Attribues

=head3 address

An IP address.

=head2 Examples

    $obj = PMG::RuleDB::IPAddress->new('192.168.2.1');

