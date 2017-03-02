package PMG::RuleDB::BCC;

use strict;
use warnings;
use DBI;

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::ModGroup;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4005;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'BCC';
}

sub oicon {
    return 'bcc.gif';
}

sub oisedit {
    return 1;
}

sub final {
    return 0;
}

sub priority {
    return 80;
}

sub new {
    my ($type, $target, $original, $ogroup) = @_;

    my $class = ref($type) || $type;

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $self->{target} = $target || 'receiver@domain.tld';

    defined ($original) || ($original = 1);

    $self->{original} = $original;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;

    my $class = ref($type) || $type;

    defined($value) || return undef;

    $value =~ m/^([01]):(.*)/ || return undef;

    my ($target, $original) = ($2, $1);

    my $obj = $class->new($target, $original, $ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $target, $original, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined object attribute: ERROR";
    defined($self->{target}) || die "undefined object attribute: ERROR";
    defined($self->{original}) || die "undefined object attribute: ERROR";

    if ($self->{original}) {
	$self->{original} = 1;
    } else {
	$self->{original} = 0;
    }

    my $value = "$self->{original}:$self->{target}";

    if (defined($self->{id})) {
	# update

	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?",
	    undef, $value, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->{ogroup}, $self->otype, $value);

	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq');
    }

    return $self->{id};
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets,
	$msginfo, $vars, $marks) = @_;

    my $subgroups = $mod_group->subgroups($targets, 1);

    my $bcc_to = PMG::Utils::subst_values($self->{target}, $vars);

    if ($bcc_to =~ m/^\s*$/) {
	# this happens if a notification is triggered by bounce mails
	# which notifies the sender <> - we just log and then ignore it
	syslog('info', "%s: bcc to <> (ignored)", $queue->{logid});
	return;
    }

    my @bcc_targets = split (/\s*,\s*/, $bcc_to);

    if ($self->{original}) {
	$subgroups = [[\@bcc_targets, $mod_group->{entity}]];
    }

    foreach my $ta (@$subgroups) {
	my ($tg, $entity) = (@$ta[0], @$ta[1]);

	$entity = $entity->dup();
	PMG::Utils::remove_marks($entity);

	if ($msginfo->{testmode}) {
	    my $fh = $msginfo->{test_fh};
	    print $fh "bcc from: $msginfo->{sender}\n";
	    printf $fh "bcc   to: %s\n", join (',', @$tg);
	    print $fh "bcc content:\n";
	    $entity->print ($fh);
	    print $fh "bcc end\n";
	} else {
	    my $qid = PMG::Utils::reinject_mail(
		$entity, $msginfo->{sender}, \@bcc_targets,
		$msginfo->{xforward}, $msginfo->{fqdn}, 1);
	    foreach (@bcc_targets) {
		if ($qid) {
		    syslog('info', "%s: bcc to <%s> (%s)", $queue->{logid}, $_, $qid);
		} else {
		    syslog('err', "%s: bcc to <%s> failed", $queue->{logid}, $_);
		}
	    }
	}
    }

    # warn if no subgroups
}

sub short_desc {
    my $self = shift;

    return "send bcc to: $self->{target}";
}

1;

__END__

=head1 PMG::RuleDB::BCC

Send BCC.
