package PMG::RuleDB::Object;

use strict;
use warnings;
use Carp;
use DBI;

sub new {
    my ($type, $otype, $ogroup) = @_;

    $otype //= 0;
    
    my $self = { 
	otype => $otype,
	ogroup => $ogroup,
    }; 
 
    bless $self, $type;

    return $self;
}

sub save { 
    croak "never call this method: ERROR"; 
}

sub load_attr { 
    croak "never call this method: ERROR"; 
}

sub load {
    my ($ruledb, $objid) = @_;

    return $ruledb->load_object($objid);
}

sub who_match {
    croak "never call this method: ERROR";
}

sub when_match {
    croak "never call this method: ERROR";
}

sub what_match {
    croak "never call this method: ERROR";
}

sub execute {
    croak "never call this method: ERROR";
}

sub final {
    return undef;
}

sub priority {
    return 0;
}

sub oisedit {
    return 1;   
}

sub ogroup { 
    my ($self, $v) = @_; 

    if (defined ($v)) {
	$self->{ogroup} = $v;
    }

    $self->{ogroup}; 
}

sub otype { 
    my $self = shift;  
    
    $self->{otype}; 
}

sub otype_text { 
    my $self = shift;  

    return "object"; 
}

sub oicon { 
    my $self = shift;  

    return "def_icon.gif"; 
}

sub oconfigsite { 
    return undef; 
}

sub oinfo { 
    return 'object'; 
}

# some who object only matches 'receivers'
sub receivertest {
    return 0;
}

sub oclass { 
    croak "never call this method: ERROR"; 
}

sub id { 
    my $self = shift; 

    $self->{id}; 
}

sub short_desc {
    return "basic object";
}

1;

__END__

=head1 PMG::RuleDB::Object

The Proxmox Rules consists of Objects. There are several classes of Objects. Ech such class has a method to check if the object 'matches'.

=head2 WHO Objects ($obj->oclass() eq 'who')

Who sent the mail, who is the receiver?

=head3  $obj->who_match ($addr)

Returns true if $addr belongs to this objects. $addr is a text string representing the email address you want to check.

=over

=item * 

EMail: the only attribute is a regex to test email addresses

=back

=head2 WHEN Objects ($obj->oclass() eq 'when')

Used to test for a certain daytime 

=head3  $obj->when_match ($time)

Return true if $time matches the when object constraints. $time is an integer like returned by the time() system call (or generated with POSIX::mktime()).

=over

=item *

TimeFrame: specifies a start and a end time

=back

=head2 WHAT Objects ($obj->oclass() eq 'what')

mail content tests

=head2 ACTION Objects ($obj->oclass() eq 'action')

actions which can be executed

=head3 $obj->execute ($mod_group, $queue, $ruledb, $mod_group, $targets, $msginfo, $vars, $marks)

Execute the action code. $target is a array reference containing all
matching targets.

=head2 Common Methods

=head3 $obj->oclass()

Returns 'who', 'when' 'what' or 'action';

=head3 $obj->short_desc()

Returns a short text describing the contents of the object. This is used 
for debugging purposes.

=head3 $obj->otype

Returns an integer representing the Type of the objects. This integer 
is used in the database to uniquely identify object types.

=head3 $obj->id

Returns the unique database ID of the object. undef means the object is not jet stored in the databse.

=head3 $obj->final()

Return true if the object is an action and the action is final, i.e. the action stops further rule processing for all matching targets.

=head3 $obj->priority()

Return a priority between 0 and 100. This is currently used to sort action objects by priority.

