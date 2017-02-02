package PMG::RuleDB::MatchField;

use strict;
use warnings;
use Carp;
use DBI;
use Digest::SHA;
use MIME::Words;

use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 3002;
}

sub oclass {
    return 'what';
}

sub otype_text {
    return 'Match Field';
}

sub oicon {
    # fixme:
    return 'matchfield.gif';
}

sub new {
    my ($type, $field, $field_value, $ogroup) = @_;
   
    my $class = ref($type) || $type;

    my $self = $class->SUPER::new(otype(), $ogroup);

    $self->{field} = $field;
    $self->{field_value} = $field_value;
    
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    defined($value) || croak "undefined value: ERROR";;

    my ($field, $field_value) = $value =~ m/^([^:]*)\:(.*)$/;

    defined($field) || croak "undefined object attribute: ERROR";
    defined($field_value) || croak "undefined object attribute: ERROR";

    my $obj = $class->new($field, $field_value, $ogroup);
    $obj->{id} = $id;
    
    $obj->{digest} = Digest::SHA::sha1_hex($id, $field, $field_value, $ogroup);
    
    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || croak "undefined ogroup: ERROR";

    my $new_value = "$self->{field}:$self->{field_value}";
    $new_value =~ s/\\/\\\\/g;

    if (defined ($self->{id})) {
	# update
	
	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?", 
	    undef, $new_value, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->ogroup, $self->otype, $new_value);
    
	$self->{id} = PMG::RuleDB::lastid($ruledb->{dbh}, 'object_id_seq'); 
    }
	
    return $self->{id};
}

sub parse_entity {
    my ($self, $entity) = @_;

    return undef if !$self->{field};

    my $res;

    if (my $id = $entity->head->mime_attr ('x-proxmox-tmp-aid')) {
	chomp $id;

	if (my $value = $entity->head->get ($self->{field})) {
	    chomp $value;

	    my $decvalue = MIME::Words::decode_mimewords($value);

	    if ($decvalue =~ m|$self->{field_value}|i) {
		push @$res, $id;
	    }
	}
    }

    foreach my $part ($entity->parts)  {
	if (my $match = $self->parse_entity($part)) {
	    push @$res, @$match;
	}
    }

    return $res;
}

sub what_match {
    my ($self, $queue, $entity, $msginfo) = @_;

    return $self->parse_entity ($entity);
}

sub short_desc {
    my $self = shift;
    
    return "$self->{field}=$self->{field_value}";
 }

1;

__END__

=head1 PMG::RuleDB::MatchField

Match Header Fields
