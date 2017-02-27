package PMG::RuleDB::Notify;

use strict;
use warnings;
use Carp;
use DBI;
use MIME::Body;
use MIME::Head;
use MIME::Entity;

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::ModGroup;
use PMG::RuleDB::Object;
use PMG::MailQueue;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4002;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'Notification';
}

sub oicon {
    return 'notify.gif';
}

sub oinfo {
    return 'Send a notification Mail';
}

sub final {
    return 0;
}

sub priority {
    return 89;
}

sub new {
    my ($type, $to, $subject, $body, $attach, $ogroup) = @_;
    
    my $class = ref($type) || $type;
 
    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $to //= '__ADMIN__';
    $attach //= 'N';
    $subject //= 'Notification: __SUBJECT__';
    
    if (!defined($body)) {
	$body = <<EOB;
Proxmox Notification:

Sender:   __SENDER__
Receiver: __RECEIVERS__
Targets:  __TARGETS__

Subject: __SUBJECT__

Matching Rule: __RULE__

__RULE_INFO__

__VIRUS_INFO__
__SPAM_INFO__
EOB
    }
    $self->{to} = $to;
    $self->{subject} = $subject;
    $self->{body} = $body;
    $self->{attach} = $attach;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
   
    my $class = ref($type) || $type;

    defined($value) || croak "undefined object attribute: ERROR";
    
    my ($subject, $body, $attach);

    my $sth = $ruledb->{dbh}->prepare(
	"SELECT * FROM Attribut WHERE Object_ID = ?");

    $sth->execute($id);

    while (my $ref = $sth->fetchrow_hashref()) {
	$subject =  $ref->{value} if $ref->{name} eq 'subject';
	$body = $ref->{value} if $ref->{name} eq 'body';
	$attach = $ref->{value} if $ref->{name} eq 'attach';
    }
	
    $sth->finish();
   
    my $obj = $class->new($value, $subject, $body, $attach, $ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex(
	$id, $value, $subject, $body, $attach, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb, $no_trans) = @_;

    defined($self->{ogroup}) || croak "undefined object attribute: ERROR";
    defined($self->{to}) || croak "undefined object attribute: ERROR";
    defined($self->{subject}) || croak "undefined object attribute: ERROR";
    defined($self->{body}) || croak "undefined object attribute: ERROR";

    if (defined ($self->{id})) {
	# update
	
	eval {
	    $ruledb->{dbh}->begin_work if !$no_trans;

	    $ruledb->{dbh}->do(
		"UPDATE Object SET Value = ? WHERE ID = ?", 
		undef, $self->{to}, $self->{id});

	    $ruledb->{dbh}->do(
		"UPDATE Attribut SET Value = ? " .
		"WHERE Name = ? and Object_ID = ?", 
		undef, $self->{subject}, 'subject',  $self->{id});

	    $ruledb->{dbh}->do(
		"UPDATE Attribut SET Value = ? " .
		"WHERE Name = ? and Object_ID = ?", 
		undef, $self->{body}, 'body',  $self->{id});

	    $ruledb->{dbh}->do(
		"UPDATE Attribut SET Value = ? " .
		"WHERE Name = ? and Object_ID = ?", 
		undef, $self->{attach}, 'attach',  $self->{id});
	    
	    $ruledb->{dbh}->commit if !$no_trans;
	};
	if (my $err = $@) {
	    die $err if !$no_trans;
	    $ruledb->{dbh}->rollback;
	    syslog('err', $err);
	    return undef;
	}

    } else {
	# insert

	$ruledb->{dbh}->begin_work if !$no_trans;

	eval {

	    my $sth = $ruledb->{dbh}->prepare(
		"INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
		"VALUES (?, ?, ?);");

	    $sth->execute($self->ogroup, $self->otype, $self->{to});

	    $self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq'); 
    	
	    $sth->finish();

	    $ruledb->{dbh}->do("INSERT INTO Attribut " . 
			       "(Object_ID, Name, Value) " .
			       "VALUES (?, ?, ?)", undef,
			       $self->{id}, 'subject', $self->{subject});
	    $ruledb->{dbh}->do("INSERT INTO Attribut " . 
			       "(Object_ID, Name, Value) " .
			       "VALUES (?, ?, ?)", undef,
			       $self->{id}, 'body', $self->{body});
	    $ruledb->{dbh}->do("INSERT INTO Attribut " . 
			       "(Object_ID, Name, Value) " .
			       "VALUES (?, ?, ?)", undef,
			       $self->{id}, 'attach', $self->{attach});

	    $ruledb->{dbh}->commit if !$no_trans;
	};
	if (my $err = $@) {
	    die $err if !$no_trans;
	    $ruledb->{dbh}->rollback;
	    syslog('err', $err);
	    return undef;
	}
    }
	
    return $self->{id};
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets, 
	$msginfo, $vars, $marks) = @_;

    my $original;

    my $from = 'postmaster';

    my $body = PMG::Utils::subst_values($self->{body}, $vars);
    my $subject = PMG::Utils::subst_values($self->{subject}, $vars);
    my $to = PMG::Utils::subst_values($self->{to}, $vars);

    if ($to =~ m/^\s*$/) {
	# this happens if a notification is triggered by bounce mails
	# which notifies the sender <> - we just log and then ignore it
	syslog('info', "%s: notify <> (ignored)", $queue->{logid});
	return;
    }

    $to =~ s/[;,]/ /g;
    $to =~ s/\s+/,/g;

    my $top = MIME::Entity->build(
	From    => $from,
	To      => $to,
	Subject => $subject,
	Data => $body);

    if ($self->{attach} eq 'O') {
	# attach original mail
	my $spooldir = $PMG::MailQueue::spooldir;
	my $path = "$spooldir/active/$queue->{uid}";
	$original = $top->attach(
	    Path => $path,
	    Filename => "original_message.eml",
	    Type => "message/rfc822",);
    }

    if ($msginfo->{testmode}) {
	my $fh = $msginfo->{test_fh};
	print $fh "notify: $self->{to}\n";
	print $fh "notify content:\n";
	
	if ($self->{attach} eq 'O') {
	    # make result reproducable for regression testing
	    $top->head->replace('content-type', 
				'multipart/mixed; boundary="---=_1234567"');
	}
	$top->print ($fh);
	print $fh "notify end\n";
    } else {
	my @targets = split(/\s*,\s*/, $to);
	my $qid = PMG::Utils::reinject_mail(
	    $top, $from, \@targets, undef, $msginfo->{fqdn});
	foreach (@targets) {
	    if ($qid) {
		syslog('info', "%s: notify <%s> (%s)", $queue->{logid}, $_, $qid);
	    } else {
		syslog ('err', "%s: notify <%s> failed", $queue->{logid}, $_);
	    }
	}
    }
}

sub to { 
    my ($self, $v) = @_; 

    if (defined ($v)) {
	$self->{to} = $v;
    }

    $self->{to}; 
}

sub subject { 
    my ($self, $v) = @_; 

    if (defined ($v)) {
	$self->{subject} = $v;
    }

    $self->{subject}; 
}

sub body { 
    my ($self, $v) = @_; 

    if (defined ($v)) {
	$self->{body} = $v;
    }

    $self->{body}; 
}

sub attach { 
    my ($self, $v) = @_; 

    if (defined ($v)) {
	$self->{attach} = $v;
    }

    $self->{attach}; 
}

sub short_desc {
    my $self = shift;

    return "notify $self->{to}";
}

1;

__END__

=head1 PMG::RuleDB::Notify

Notifications.
