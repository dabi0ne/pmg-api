package PMG::RuleDB::WhoRegex;

use strict;
use warnings;
use Carp;
use DBI;
use Digest::SHA;

use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 1000;
}

sub oclass {
    return 'who';
}

sub otype_text {
    return 'Regular Expression';
}

sub oicon {
    return 'regexp.gif';
}

sub new {
    my ($type, $address, $ogroup) = @_;
    
    my $class = ref($type) || $type;
 
    my $self = $class->SUPER::new(otype(), $ogroup);

    $address //= '.*@domain\.tld';
  
    $self->{address} = $address;
    
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    defined($value) || croak "undefined value: ERROR";

    my $obj = $class->new ($value, $ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $value, $ogroup);
    
    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || croak "undefined ogroup: ERROR";
    defined($self->{address}) || croak "undefined address: ERROR";

    my $adr = $self->{address};
    $adr =~ s/\\/\\\\/g;

    if (defined ($self->{id})) {
	# update
	
	$ruledb->{dbh}->do (
	    "UPDATE Object SET Value = ? WHERE ID = ?", 
	    undef, $adr, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare (
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->{ogroup}, $self->otype, $adr);

	$self->{id} = PMG::RuleDB::lastid($ruledb->{dbh}, 'object_id_seq');
    }
       
    return $self->{id};
}

sub who_match {
    my ($self, $addr) = @_;

    my $t = $self->address;

    return $addr =~ m/^$t$/i;
}

sub address { 
    my ($self, $addr) = @_; 

    if (defined ($addr)) {
	$self->{address} = $addr;
    }

    $self->{address}; 
}

sub short_desc {
    my $self = shift;

    my $desc = $self->{address};
    
    return $desc;
}

1;

__END__

=head1 PMG::RuleDB::WhoRegex

A WHO object to check email addresses with regular expresssions.

=head2 Attribues

=head3 address

A Perl regular expression used to compare email addresses (ignore case).

=head2 Examples

    $obj = PMG::RuleDB::WhoRegex->new ('.*@yourdomain.com');

