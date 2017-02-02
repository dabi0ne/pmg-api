package PMG::RuleDB::Domain;

use strict;
use warnings;
use Carp;
use DBI;

use PMG::RuleDB::WhoRegex;

use base qw(PMG::RuleDB::WhoRegex);

sub otype {
    return 1002;
}

sub otype_text {
    return 'Domain';
}

sub oicon {
    return 'domain.gif';
}

sub oconfigsite {
    # fixme: ???
    return 'item_domain.epl';
}

sub new {
    my ($type, $address, $ogroup) = @_;
    
    my $class = ref($type) || $type;
 
    $address //= 'domain.tld';

    my $self = $class->SUPER::new($address, $ogroup);

    return $self;
}

sub who_match {
    my ($self, $addr) = @_;

    $addr =~ m/^.+@(.+)$/; 

    return (lc ($1) eq lc ($self->address));
}

sub short_desc {
    my $self = shift;
    
    my $desc = $self->{address};
    
    return $desc;
}



1;
__END__

=head1 PMG::RuleDB::Domain

A WHO object to check email domains.

=head2 Attribues

=head3 address

An Email domain. We use case insensitive compares.

=head2 Examples

    $obj = PMG::RuleDB::Domain->new ('yourdomain.com');
