package PMG::RuleDB::LDAPUser;

use strict;
use warnings;
use DBI;
use Digest::SHA;

use PMG::Utils;
use PMG::RuleDB::Object;
use PMG::LDAPCache;
use PMG::LDAPSet;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 1006;
}

sub oclass {
    return 'who';
}

sub otype_text {
    return 'LDAP User';
}

sub oicon {
    return 'user.gif';
}

sub new {
    my ($type, $ldapuser, $profile, $ogroup) = @_;

    my $class = ref($type) || $type;
 
    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $self->{ldapuser} = $ldapuser // '';
    $self->{profile} = $profile // '';
    
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;

    my $class = ref($type) || $type;

    defined($value) || die "undefined value: ERROR";
    
    my $obj;
    if ($value =~ m/^([^:]*):(.*)$/) {
	$obj = $class->new($2, $1, $ogroup);
	$obj->{digest} = Digest::SHA::sha1_hex($id, $2, $1, $ogroup);
   } else {
	$obj = $class->new($value, '', $ogroup);
	$obj->{digest} = Digest::SHA::sha1_hex ($id, $value, '#', $ogroup);
    }

    $obj->{id} = $id;
    
    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined ogroup: ERROR";
    defined($self->{ldapuser}) || die "undefined ldap user: ERROR";
    defined($self->{profile}) || die "undefined ldap profile: ERROR";

    my $user = $self->{ldapuser};
    my $profile = $self->{profile};
 
    my $confdata = "$profile:$user";
    
    if (defined($self->{id})) {
	# update
	
	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?", 
	    undef, $confdata, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->{ogroup}, $self->otype, $confdata);
    
	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq'); 
    }
	
    return $self->{id};
}

sub test_ldap {
    my ($ldap, $addr, $user, $profile) = @_;

    return $ldap->account_has_address($user, $addr, $profile); 
}

sub who_match {
    my ($self, $addr, $ip, $ldap) = @_;

    return 0 if !$ldap;

    return test_ldap($ldap, $addr, $self->{ldapuser}, $self->{profile});
}

sub short_desc {
    my ($self) = @_;

    my $user = $self->{ldapuser};
    my $profile = $self->{profile};

    my $desc;

    if ($profile) {
	$desc = "$profile: $user";
    } else {
	$desc = "LDAP user without profile - fail always";
    }

    return $desc;
}

sub properties {
    my ($class) = @_;

    return {
	profile => {
	    description => "Profile ID.",
	    type => 'string', format => 'pve-configid',
	},
	account => {
	    description => "LDAP user account name.",
	    type => 'string',
	    maxLength => 1024,
	    minLength => 1,
	},
    };
}

sub get {
    my ($self) = @_;

    return {
	account => $self->{ldapuser},
	profile => $self->{profile},
    };
}

sub update {
    my ($self, $param) = @_;

    my $profile = $param->{profile};
    my $cfg = PVE::INotify::read_file("pmg-ldap.conf");
    my $config = $cfg->{ids}->{$profile};
    die "LDAP profile '$profile' does not exist\n" if !$config;

    my $account = $param->{account};
    my $ldapcache = PMG::LDAPCache->new(
	id => $profile, syncmode => 1, %$config);

    die "LDAP acoount '$account' does not exist\n"
	if !$ldapcache->account_exists($account);

    $self->{ldapuser} = $account;
    $self->{profile} = $profile;
}

1;

__END__

=head1 PMG::RuleDB::LDAPUser

A WHO object to check LDAP users

=head2 Attribues

=head3 ldapuser

An LDAP user account (ignore case).

=head3 profile

The LDAP profile name

=head2 Examples

    $obj = PMG::RuleDB::LDAPUser>new('username', 'profile_name');

