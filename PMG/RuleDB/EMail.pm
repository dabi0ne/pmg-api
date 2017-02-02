package PMG::RuleDB::EMail;

use strict;
use warnings;
use Carp;
use DBI;

use PMG::RuleDB::WhoRegex;

use base qw(PMG::RuleDB::WhoRegex);

sub otype {
    return 1001;
}

sub otype_text {
    return 'Mail address';
}

sub oicon {
    return 'mail.gif';
}

sub new {
    my ($type, $address, $ogroup) = @_;
    my $class = ref($type) || $type;
 
    $address //= 'unknown@domain.tld';

    my $self = $class->SUPER::new($address, $ogroup);

    return $self;
}

sub who_match {
    my ($self, $addr) = @_;

    return (lc ($addr) eq lc ($self->address));
}


sub short_desc {
    my $self = shift;
    
    my $desc = $self->{address};
    
    return $desc;
}

1;

__END__

=head1 PMG::RuleDB::EMail

A WHO object to check email addresses.

=head2 Attribues

=head3 address

An Email address. We use case insensitive compares.

=head2 Examples

    $obj = PMG::RuleDB::Email->new ('you@yourdomain.com');

