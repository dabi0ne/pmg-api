package PMG::RuleDB::Block;

use strict;
use warnings;
use Carp;
use DBI;
use Digest::SHA;

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::ModGroup;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4001;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'Block';
}

sub oicon {
    return 'block.gif';
}

sub oisedit {
    return 0;   
}

sub final {
    return 1;
}

sub priority {
    return 98;
}

sub new {
    my ($type, $ogroup) = @_;
    
    my $class = ref($type) || $type;
 
    my $self = $class->SUPER::new($class->otype(), $ogroup);
   
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    my $obj = $class->new ($ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $ogroup);
    
    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || return undef;

    if (defined ($self->{id})) {
	# update
	
	# nothing to update

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType) VALUES (?, ?);");

	$sth->execute($self->ogroup, $self->otype);
    
	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq'); 
    }
	
    return $self->{id};
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets, 
	$msginfo, $vars, $marks) = @_;

    if ($msginfo->{testmode}) {
	my $fh = $msginfo->{test_fh};
	print $fh "block from: $msginfo->{sender}\n";
	printf  $fh "block   to: %s\n", join (',', @$targets);
    }

    foreach my $to (@$targets) {
	syslog('info', "%s: block mail to <%s>", $queue->{logid}, $to);
    }

    $queue->set_status($targets, 'blocked');
}

sub short_desc {
    my $self = shift;

    return "block message";
}

1;

__END__

=head1 PMG::RuleDB::Block

Block a message.
