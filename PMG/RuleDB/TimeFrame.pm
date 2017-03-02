package PMG::RuleDB::TimeFrame;

use strict;
use warnings;
use DBI;
use Digest::SHA;

use PMG::Utils;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 2000;
}

sub oclass {
    return 'when';
}

sub otype_text {
    return 'TimeFrame';
}

sub new {
    my ($type, $start, $end, $ogroup) = @_;

    my $class = ref($type) || $type;

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $start //= "00:00";
    $end //= "24:00";

    if ($start =~ m/:/) {
        my @tmp = split(/:/, $start);
        $start = $tmp[0]*60+$tmp[1];
    }

    if ($end =~ m/:/) {
        my @tmp = split(/:/, $end);
        $end = $tmp[0]*60+$tmp[1];
    }

    $self->{start} = $start;
    $self->{end} = $end;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;

    my $class = ref($type) || $type;

    defined($value) || return undef;

    my ($sh, $sm, $eh, $em) = $value =~ m/(\d+):(\d+)-(\d+):(\d+)/;

    my $start = $sh*60+$sm;
    my $end = $eh*60+$em;

    my $obj = $class->new($start, $end, $ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex ($id, $start, $end, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || return undef;
    defined($self->{start}) || return undef;
    defined($self->{end}) || return undef;

    my $v = sprintf ("%d:%d-%d:%d", int ($self->{start} / 60), int ($self->{start} % 60),
		     int ($self->{end} / 60), int ($self->{end} % 60));

    if (defined ($self->{id})) {
	# update

	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?", undef, $v, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object " .
	    "(Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->ogroup, $self->otype, $v);

	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq');
    }

    return $self->{id};
}

sub when_match {
    my ($self, $t) = @_;

    my ($sec,$min,$hour) = localtime($t);

    my $amin = $hour*60 + $min;

    return $amin >= $self->{start} && $amin <= $self->{end}
}

sub start {
    my ($self, $v) = @_;

    if (defined ($v)) {
	$self->{start} = $v;
    }

    $self->{start};
}

sub end {
    my ($self, $v) = @_;

    if (defined ($v)) {
	$self->{end} = $v;
    }

    $self->{end};
}

sub short_desc {
    my $self = shift;

    my $v = sprintf ("%d:%02d-%d:%02d",
    int ($self->{start} / 60),
    int ($self->{start} % 60 ),
    int ($self->{end} / 60),
    int ($self->{end} % 60));
    return "$v";
}


1;

__END__

=head1 PMG::RuleDB::TimeFrame

A WHEN object to check for a specific daytime.

=head2 Attribues

=head3 start

Start time im minutes since 00:00.

=head3 end

End time im minutes since 00:00.

=head2 Examples

    $obj = PMG::RuleDB::TimeFrame->new(8*60+15, 16*60+30);

Represent: 8:15 to 16:30
