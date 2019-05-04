package PMG::RuleDB::Quota;

use strict;
use warnings;

use PVE::SafeSyslog;
use Digest::SHA;

use PMG::Utils;
use PMG::RuleDB::Object;


use base qw(PMG::RuleDB::Object);

my $quotatypes = ['user', 'anyuser', 'domain', 'anydomain'];

sub otype {
    return 3006;
}

sub oclass {
    return 'what';
}

sub otype_text {
    return 'Quota Filter';
}

sub oisedit {
    return 0;   
}

sub new {
    my ($type, $quotatype, $quotalimit, $quotaframe, $quotatarget, $ogroup) = @_;
    
    my $class = ref($type) || $type;

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $self->{quotatype} = $quotatype;
    $self->{quotalimit} = $quotalimit;
    $self->{quotaframe} = $quotaframe;
    $self->{quotatarget} = $quotatarget;
    
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    defined($value) || die "undefined value: ERROR";;

    my ($quotatype, $quotalimit, $quotaframe, $quotatarget) = $value =~ m/^([^\:]+):([^\:]+):([^\:]+):(.*)$/;

    (defined($quotatype) && defined($quotalimit) && defined($quotaframe)) || return undef;

    my $obj = $class->new($quotatype, $quotalimit, $quotaframe, $quotatarget, $ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $quotatype, $quotalimit, $quotaframe, $quotatarget, $ogroup);
    
    return $obj;
    
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined ogroup: ERROR";
    
    my $new_value = "$self->{quotatype}:$self->{quotalimit}:$self->{quotaframe}:$self->{quotatarget}";
    

    if (defined($self->{id})) {
	# update
	
	$ruledb->{dbh}->do("UPDATE Object SET Value = ? WHERE ID = ?", 
			   undef, $new_value, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->ogroup, $self->otype, $new_value);
    
	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq'); 
    }
	
    return $self->{id};
}

sub _check_domain_quota {
    my ($self, $msginfo, $queue, $dbh) = @_;
    
    my $start = time() - $self->{quotaframe};
    my ($user, $domain) = split('@', $msginfo->{sender}, 2);
    
    my $query = "select count(*) as nbmails from cstatistic,creceivers " .
    "where cid = cstatistic_cid AND rid = cstatistic_rid " . 
    "AND sender like " . $dbh->quote("%\@$domain") .
    "AND time >= ? " .
    "AND blocked = 'f'";
    
    my $sth = $dbh->prepare($query);
    
    $sth->execute($start);
    
    my $res = [];
    while (my $ref = $sth->fetchrow_hashref()) {
        my $count = scalar(@{$msginfo->{targets}}) + $ref->{nbmails};
	    if ($count > $self->{quotalimit})  {
	        syslog(
	            'info', "%s: Sender %s over quota : %s mails in last %s, but limit is %s",
	            $queue->{logid},
	            $msginfo->{sender},
	            $count,
	            $self->{quotaframe},
	            $self->{quotalimit}
	        );
	        
	        return [];
	    }
    }
    
    $sth->finish();
    
    return undef;
}

sub _check_user_quota {
    my ($self, $msginfo, $queue, $dbh) = @_;
    
    my $start = time() - $self->{quotaframe};
    
    my $query = "select count(*) as nbmails from cstatistic,creceivers " .
    "where cid = cstatistic_cid AND rid = cstatistic_rid " . 
    "AND sender = ? " .
    "AND time >= ? " .
    "AND blocked = 'f'";
    
    my $sth = $dbh->prepare($query);
    
    $sth->execute($msginfo->{sender}, $start);
    
    my $res = [];
    while (my $ref = $sth->fetchrow_hashref()) {
        my $count = scalar(@{$msginfo->{targets}}) + $ref->{nbmails};
	    if ($count > $self->{quotalimit})  {
	        syslog(
	            'info', "%s: Sender %s over quota : %s mails in last %s, but limit is %s",
	            $queue->{logid},
	            $msginfo->{sender},
	            $count,
	            $self->{quotaframe},
	            $self->{quotalimit}
            );
            
	        return [];
	    }
    }
    
    $sth->finish();
    
    return undef;
}

sub what_match {
    my ($self, $queue, $entity, $msginfo, $dbh) = @_;
    
    if ($self->{quotatype} =~ /^user$/) {
        if ($msginfo->{sender} eq $self->{quotatarget}) {
            return $self->_check_user_quota($msginfo, $queue, $dbh);   
        }
    } elsif ($self->{quotatype} =~ /^domain$/) {
        my $domain = quotemeta "\@$self->{quotatarget}";
        if ($msginfo->{sender} =~ /$domain$/) {
            return $self->_check_domain_quota($msginfo, $queue, $dbh);
        }
    } elsif ($self->{quotatype} =~ /^anyuser$/) {
        return $self->_check_user_quota($msginfo, $queue, $dbh);
    } elsif ($self->{quotatype} =~ /^anydomain$/) {
        return $self->_check_domain_quota($msginfo, $queue, $dbh);
    }
    
    return undef;
}

sub properties {
    my ($class) = @_;

    return {
    	quotatype => {
    	    description => "Quota type",
    	    type => 'string',
    	    enum => $quotatypes,
    	    maxLength => 1024,
    	},
    	quotalimit => {
    	    description => "Max mails",
    	    type => 'number',
    	    minimum => 0,
    	},
    	quotaframe => {
    	    description => "Time frame (in seconds)",
    	    type => 'number',
    	    minimum => 0,
    	},
    	quotatarget => {
    	    description => "Quota target",
    	    type => 'string',
    	    maxLength => 1024,
    	}
    };
}

sub get {
    my ($self) = @_;

    return { 
        quotatype => $self->{quotatype},
        quotalimit => $self->{quotalimit},
        quotaframe => $self->{quotaframe},
        quotatarget => $self->{quotatarget}
    };
}

sub short_desc {
    my $self = shift;
    
    return "quotarule=$self->{quotatype}:$self->{quotalimit}:$self->{quotaframe}:$self->{quotatarget}";
}

sub update {
    my ($self, $param) = @_;

    $self->{quotatype} = $param->{quotatype};
    $self->{quotalimit} = $param->{quotalimit};
    $self->{quotaframe} = $param->{quotaframe};
    $self->{quotatarget} = $param->{quotatarget};
}


1;

__END__

=head1 PMG::RuleDB::Quota

Email rate limit 
