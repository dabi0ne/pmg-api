package PMG::LDAPCache;

use strict;
use warnings;
use File::Path;
use LockFile::Simple;
use Data::Dumper;
use Net::LDAP;
use Net::LDAP::Control::Paged;
use Net::LDAP::Constant qw (LDAP_CONTROL_PAGED);
use DB_File;

use PVE::SafeSyslog;
use PVE::Tools qw(split_list);

use PMG::Utils;
use PMG::LDAPConfig;

$DB_HASH->{'cachesize'} = 10000;
$DB_RECNO->{'cachesize'} = 10000;
$DB_BTREE->{'cachesize'} = 10000;
$DB_BTREE->{'flags'} = R_DUP ;

my $cachedir = '/var/lib/pmg';

my $last_atime = {};
my $ldapcache = {};

# DB Description
#
# users      (hash): UID -> pmail, account, DN
# dnames     (hash): DN -> UID
# accounts   (hash): account -> UID
# mail       (hash): mail -> UID
# groups     (hash): group -> GID
# memberof  (btree): UID -> GID
#
my @dbs = ('users', 'dnames', 'groups', 'mails', 'accounts', 'memberof');

sub new {
    my ($self, %args) = @_;

    my $type   = ref($self) || $self;

    die "undefined ldap id" if !$args{id};

    my $id = $args{id};

    if ($ldapcache->{$id}) {
	$self = $ldapcache->{$id};
    } else {
	$ldapcache->{$id} = $self = bless {}, $type;
	$self->{id} = $id;
    }

    my $config_properties = PMG::LDAPConfig::properties();

    # set defaults for the fields that have one
    foreach my $property (keys %$config_properties) {
	my $d = $config_properties->{$property};
	next if !defined($d->{default});
	$self->{$property} = $args{$property} || $d->{default};
    }

    # split list returns an array not a reference
    $self->{accountattr} = [split_list($self->{accountattr})];
    $self->{mailattr} = [split_list($self->{mailattr})];
    $self->{groupclass} = [split_list($self->{groupclass})];

    $self->{server1} = $args{server1};
    $self->{server2} = $args{server2};
    $self->{binddn} = $args{binddn};
    $self->{bindpw} = $args{bindpw};
    $self->{basedn} = $args{basedn};
    $self->{port} = $args{port};
    $self->{groupbasedn} = $args{groupbasedn};
    $self->{filter} = $args{filter};

    if ($args{syncmode} == 1) {
	# read local data only
	$self->{errors} = '';
	$self->loadcache();
	return $self;
    }

    return $self if !($args{server1});

    if ($args{syncmode} == 2) {
	# force sync
	$self->loaddata(1);
    } else {
	$self->loaddata();
    }

    return $self;
}

sub lockdir {
    my ($id) = @_;

    my $dir = "$cachedir/ldapdb_$id";
    my $scheme = LockFile::Simple->make(
	-warn => 0, -stale => 1, -autoclean => 1);
    my $lock = $scheme->lock($dir);

    return $lock;
}

sub delete {
    my ($class, $id) = @_;

    if (my $lock = lockdir($id)) {
	delete $ldapcache->{$id};
	delete $last_atime->{$id};
	my $dir = "$cachedir/ldapdb_$id";
	rmtree $dir;
	$lock->release;
    } else {
	syslog('err' , "can't lock ldap database '$id'");
    }
}

sub update {
    my ($self, $syncmode) = @_;

    if ($syncmode == 1) {
	# read local data only
	$self->{errors} = '';
	$self->loadcache();
    } elsif ($syncmode == 2) {
	# force sync
	$self->loaddata(1);
    } else {
	$self->loaddata();
    }
}

sub queryusers {
    my ($self, $ldap) = @_;

    my $filter = '(|';
    foreach my $attr (@{$self->{mailattr}}) {
	$filter .= "($attr=*)";
    }
    $filter .= ')';

    if ($self->{filter}) {
	my $tmp = $self->{filter};
	$tmp = "($tmp)" if $tmp !~ m/^\(.*\)$/;

	$filter = "(&${filter}${tmp})";
    }

    my $page = Net::LDAP::Control::Paged->new(size => 900);

    my @args = (
	base     => $self->{basedn},
	scope    => "subtree",
	filter   => $filter,
	control  => [ $page ],
	attrs  => [ @{$self->{mailattr}}, @{$self->{accountattr}}, 'memberOf' ]
	);

    my $cookie;

    while(1) {

	my $mesg = $ldap->search(@args);

	# stop on error
	if ($mesg->code)  {
	    my $err = "ldap user search error: " . $mesg->error;
	    $self->{errors} .= "$err\n";
	    syslog('err', $err);
	    last;
	}

	#foreach my $entry ($mesg->entries) { $entry->dump; }
	foreach my $entry ($mesg->entries) {
	    my $dn = $entry->dn;

	    my $umails = {};
	    my $pmail;

	    foreach my $attr (@{$self->{mailattr}}) {
		foreach my $mail ($entry->get_value($attr)) {
		    $mail = lc($mail);
		    # Test if the Line starts with one of the following lines:
		    # proxyAddresses: [smtp|SMTP]:
		    # and also discard this starting string, so that $mail is only the
		    # address without any other characters...

		    $mail =~ s/^(smtp|SMTP)[\:\$]//gs;

		    if ($mail !~ m/[\{\}\\\/]/ && $mail =~ m/^\S+\@\S+$/) {
			$umails->{$mail} = 1;
			$pmail = $mail if !$pmail;
		    }
		}
	    }
	    my $addresses = [ keys %$umails ];

	    next if !$pmail; # account has no email addresses

	    my $cuid;
	    $self->{dbstat}->{dnames}->{dbh}->get($dn, $cuid);
	    if (!$cuid) {
		$cuid = ++$self->{dbstat}->{dnames}->{idcount};
		$self->{dbstat}->{dnames}->{dbh}->put($dn, $cuid);
	    }

	    foreach my $attr (@{$self->{accountattr}}) {
		my $account = $entry->get_value($attr);
		if ($account && ($account =~ m/^\S+$/s)) {
		    $account = lc($account);
		    $self->{dbstat}->{accounts}->{dbh}->put($account, $cuid);
		    my $data = pack('n/a* n/a* n/a*', $pmail, $account, $dn);
		    $self->{dbstat}->{users}->{dbh}->put($cuid, $data);
		}
	    }

	    foreach my $mail (@$addresses) {
		$self->{dbstat}->{mails}->{dbh}->put($mail, $cuid);
	    }

	    if (!$self->{groupbasedn}) {
		my @groups = $entry->get_value('memberOf');
		foreach my $group (@groups) {
		    my $cgid;
		    $self->{dbstat}->{groups}->{dbh}->get($group, $cgid);
		    if (!$cgid) {
			$cgid = ++$self->{dbstat}->{groups}->{idcount};
			$self->{dbstat}->{groups}->{dbh}->put($group, $cgid);
		    }
		    $self->{dbstat}->{memberof}->{dbh}->put($cuid, $cgid);
		}
	    }
	}

	# Get cookie from paged control
	my ($resp) = $mesg->control(LDAP_CONTROL_PAGED) or last;
	$cookie = $resp->cookie;

	last if (!defined($cookie) || !length($cookie));

	# Set cookie in paged control
	$page->cookie($cookie);
    }


    if (defined($cookie) && length($cookie)) {
	# We had an abnormal exit, so let the server know we do not want any more
	$page->cookie($cookie);
	$page->size(0);
	$ldap->search(@args);
	my $err = "LDAP user query unsuccessful";
	$self->{errors} .= "$err\n";
	syslog('err', $err);
    }
}

sub querygroups {
    my ($self, $ldap) = @_;

    return undef if !$self->{groupbasedn};

    my $filter = "(|";

    for my $class (@{$self->{groupclass}}) {
	$filter .= "(objectclass=$class)";
    }

    $filter .= ")";

    my $page = Net::LDAP::Control::Paged->new(size => 100);

    my @args = ( base     => $self->{groupbasedn},
		 scope    => "subtree",
		 filter   => $filter,
		 control  => [ $page ],
		 attrs  => [ 'member', 'uniqueMember' ],
		 );

    my $cookie;
    while(1) {

	my $mesg = $ldap->search(@args);

	# stop on error
	if ($mesg->code)  {
	    my $err = "ldap group search error: " . $mesg->error;
	    $self->{errors} .= "$err\n";
	    syslog('err', $err);
	    last;
	}

	foreach my $entry ( $mesg->entries ) {
	    my $group = $entry->dn;
	    my @members = $entry->get_value('member');
	    if (!scalar(@members)) {
		@members = $entry->get_value('uniqueMember');
	    }
	    my $cgid;
	    $self->{dbstat}->{groups}->{dbh}->get($group, $cgid);
	    if (!$cgid) {
		$cgid = ++$self->{dbstat}->{groups}->{idcount};
		$self->{dbstat}->{groups}->{dbh}->put($group, $cgid);
	    }

	    foreach my $m (@members) {

		my $cuid;
		$self->{dbstat}->{dnames}->{dbh}->get($m, $cuid);
		if (!$cuid) {
		    $cuid = ++$self->{dbstat}->{dnames}->{idcount};
		    $self->{dbstat}->{dnames}->{dbh}->put($m, $cuid);
		}

		$self->{dbstat}->{memberof}->{dbh}->put($cuid, $cgid);
	    }
	}

	# Get cookie from paged control
	my ($resp) = $mesg->control(LDAP_CONTROL_PAGED) or last;
	$cookie = $resp->cookie or last;

	# Set cookie in paged control
	$page->cookie($cookie);
    }

    if ($cookie) {
	# We had an abnormal exit, so let the server know we do not want any more
	$page->cookie($cookie);
	$page->size(0);
	$ldap->search(@args);
	my $err = "LDAP group query unsuccessful";
	$self->{errors} .= "$err\n";
	syslog('err', $err);
    }
}

sub ldap_connect {
    my ($self) = @_;

    my $hosts = [ $self->{server1} ];

    push @$hosts, $self->{server2} if $self->{server2};

    my $opts = { timeout => 10, onerror => 'die' };

    $opts->{port} = $self->{port} if $self->{port};
    $opts->{schema} = $self->{mode};

    return Net::LDAP->new($hosts, %$opts);
}

sub ldap_connect_and_bind {
     my ($self) = @_;

     my $ldap = $self->ldap_connect() ||
	 die "Can't bind to ldap server '$self->{id}': $!\n";

     my $mesg;

     if ($self->{binddn}) {
	 $mesg = $ldap->bind($self->{binddn}, password => $self->{bindpw});
     } else {
	 $mesg = $ldap->bind(); # anonymous bind
     }

     die "ldap bind failed: " . $mesg->error . "\n" if $mesg->code;

     if (!$self->{basedn}) {
	 my $root = $ldap->root_dse(attrs => [ 'defaultNamingContext' ]);
	 $self->{basedn} = $root->get_value('defaultNamingContext');
     }

     return $ldap;
}

sub sync_database {
    my ($self) = @_;

    my $dir = "ldapdb_" .  $self->{id};
    mkdir "$cachedir/$dir";

    # open ldap connection

    my $ldap;

    eval { $ldap = $self->ldap_connect_and_bind(); };
    if (my $err = $@) {
	$self->{errors} .= "$err\n";
	syslog('err', $err);
	return;
    }

    # open temporary database files

    my $olddbh = {};

    foreach my $db (@dbs) {
	$self->{dbstat}->{$db}->{tmpfilename} = "$cachedir/$dir/${db}_tmp$$.db";
	$olddbh->{$db} = $self->{dbstat}->{$db}->{dbh};
    }

    my $error_cleanup = sub {
	# close and delete all files
	foreach my $db (@dbs) {
	    undef $self->{dbstat}->{$db}->{dbh};
	    unlink $self->{dbstat}->{$db}->{tmpfilename};
	    $self->{dbstat}->{$db}->{dbh} = $olddbh->{$db};
	}
    };

    eval {
	foreach my $db (@dbs) {
	    my $filename = $self->{dbstat}->{$db}->{tmpfilename};
	    $self->{dbstat}->{$db}->{idcount} = 0;
	    unlink $filename;

	    if ($db eq 'memberof') {
		$self->{dbstat}->{$db}->{dbh} =
		    tie (my %h,  'DB_File', $filename,
			 O_CREAT|O_RDWR, 0666, $DB_BTREE);
	    } else {
		$self->{dbstat}->{$db}->{dbh} =
		    tie (my %h,  'DB_File', $filename,
			 O_CREAT|O_RDWR, 0666, $DB_HASH);
	    }

	    die "unable to open database file '$filename': $!\n"
		if !$self->{dbstat}->{$db}->{dbh};
	}
    };
    if (my $err = $@) {
	$error_cleanup->();
	$self->{errors} .= $err;
	syslog('err', $err);
	return;
    }

    $self->querygroups ($ldap) if $self->{groupbasedn};

    $self->queryusers($ldap) if !$self->{errors};

    $ldap->unbind;

    if ($self->{errors}) {
	$error_cleanup->();
	return;
    }

    my $lock = lockdir($self->{id});

    if (!$lock) {
	my $err = "unable to get database lock for ldap database '$self->{id}'";
	$self->{errors} .= "$err\n";
	syslog('err', $err);
	$error_cleanup->();
	return;
    }

    foreach my $db (@dbs) {
	my $filename = $self->{dbstat}->{$db}->{filename} =
	    "$cachedir/$dir/${db}.db";
	$self->{dbstat}->{$db}->{dbh}->sync(); # flush everything
	rename $self->{dbstat}->{$db}->{tmpfilename}, $filename;
    }

    $lock->release;

    $last_atime->{$self->{id}} = time();

    $self->{gcount} = $self->{dbstat}->{groups}->{idcount};
    $self->{ucount} = __count_entries($self->{dbstat}->{accounts}->{dbh});
    $self->{mcount} = __count_entries($self->{dbstat}->{mails}->{dbh});
}

sub __count_entries {
    my ($dbh) = @_;

    return 0 if !$dbh;

    my $key = 0 ;
    my $value = "" ;
    my $count = 0;
    my $status = $dbh->seq($key, $value, R_FIRST());

    while ($status == 0) {
	$count++;
        $status = $dbh->seq($key, $value, R_NEXT());
    }

    return $count;
}

sub loadcache {
    my ($self, $try) = @_;

    my $dir = "ldapdb_" .  $self->{id};
    mkdir "$cachedir/$dir";

    my $filename = "$cachedir/$dir/mails.db";

    return if $last_atime->{$self->{id}} &&
	PMG::Utils::file_older_than ($filename, $last_atime->{$self->{id}});

    eval {
	foreach my $db (@dbs) {
	    my $filename = $self->{dbstat}->{$db}->{filename} =
		"$cachedir/$dir/${db}.db";
	    $self->{dbstat}->{$db}->{idcount} = 0;
	    if ($db eq 'memberof') {
		$self->{dbstat}->{$db}->{dbh} =
		    tie (my %h,  'DB_File', $filename,
			 O_RDONLY, 0666, $DB_BTREE);
	    } else {
		$self->{dbstat}->{$db}->{dbh} =
		    tie (my %h,  'DB_File', $filename,
			 O_RDONLY, 0666, $DB_HASH);
	    }

	    if (!$self->{dbstat}->{$db}->{dbh} && !$try) {
		my $err = "ldap error - unable to open database file '$filename': $!";
		$self->{errors} .= "$err\n";
		syslog('err', $err) if !$self->{dbstat}->{$db}->{dbh};
	    }
	}
    };

    $last_atime->{$self->{id}} = time();

    $self->{gcount} = __count_entries($self->{dbstat}->{groups}->{dbh});
    $self->{ucount} = __count_entries($self->{dbstat}->{accounts}->{dbh});
    $self->{mcount} = __count_entries($self->{dbstat}->{mails}->{dbh});
}

sub loaddata {
    my ($self, $force) = @_;

    $self->{errors} = '';

    if (!$force) {
	# only sync if file is older than 1 hour

	my $dir = "ldapdb_" .  $self->{id};
	mkdir "$cachedir/$dir";
	my $filename = "$cachedir/$dir/mails.db";

	if (-e $filename &&
	    !PMG::Utils::file_older_than($filename, time() - 3600)) {
	    $self->loadcache();
	    return;
	}
    }

    $self->sync_database();

    if ($self->{errors}) {
	$self->loadcache(1);
    }
}

sub get_groups {
    my ($self) = @_;

    my $res = {};

    my $dbh = $self->{dbstat}->{groups}->{dbh};

    return $res if !$dbh;

    my $key = 0 ;
    my $value = "" ;
    my $status = $dbh->seq($key, $value, R_FIRST());

    while ($status == 0) {
	$res->{$value} = $key;
        $status = $dbh->seq($key, $value, R_NEXT());
    }

    return $res;
}

sub get_users {
    my ($self) = @_;

    my $res = {};

    my $dbh = $self->{dbstat}->{users}->{dbh};

    return $res if !$dbh;

    my $key = 0 ;
    my $value = "" ;
    my $status = $dbh->seq($key, $value, R_FIRST());
    my $keys;

    while ($status == 0) {
	my ($pmail, $account, $dn) = unpack('n/a* n/a* n/a*', $value);
	$res->{$key} = {
	    pmail => $pmail,
	    account => $account,
	    dn => $dn,
	};
        $status = $dbh->seq($key, $value, R_NEXT());
    }

    return $res;
}

sub get_gid_uid_map {
    my ($self) = @_;

    my $dbh = $self->{dbstat}->{memberof}->{dbh};

    return [] if !$dbh;

    my $key = 0 ;
    my $value = "" ;

    my $map = {};

    if($dbh->seq($key, $value, R_FIRST()) == 0) {
	do {
	    push @{$map->{$value}}, $key;
	} while($dbh->seq($key, $value, R_NEXT()) == 0);
    }

    return $map;
}

sub list_groups {
    my ($self) = @_;

    my $res = [];

    my $groups = $self->get_groups();

    for my $gid (sort keys %$groups) {
	push @$res, {
	    dn => $groups->{$gid},
	    gid => $gid,
	};
    }

    return $res;
}

sub list_users {
    my ($self, $gid) = @_;

    my $res = [];

    my $users = $self->get_users();

    if (!defined($gid)) {
	$res = [values %$users];
    } else {
	my $gid_uid_map = $self->get_gid_uid_map();
	my $groups = $self->get_groups();
	die "No such Group ID\n"
	    if !defined($groups->{$gid});
	my $memberuids = $gid_uid_map->{$gid};
	for my $uid (@$memberuids) {
	    next if !defined($users->{$uid});
	    push @$res, $users->{$uid};
	}
    }

    return $res;
}

sub list_addresses {
    my ($self, $mail) = @_;

    my $dbhmails = $self->{dbstat}->{mails}->{dbh};
    my $dbhusers = $self->{dbstat}->{users}->{dbh};

    return undef if !$dbhmails || !$dbhusers;

    $mail = lc($mail);

    my $res = [];

    my $cuid;
    $dbhmails->get($mail, $cuid);
    return undef if !$cuid;

    my $rdata;
    $dbhusers->get($cuid, $rdata);
    return undef if !$rdata;

    my ($pmail, $account, $dn) = unpack('n/a* n/a* n/a*', $rdata);

    push @$res, { primary => 1, email => $pmail };

    my $key = 0 ;
    my $value = "" ;
    my $status = $dbhmails->seq($key, $value, R_FIRST());

    while ($status == 0) {
	if ($value == $cuid && $key ne $pmail) {
	    push @$res, { primary => 0, email => $key };
	}
	$status = $dbhmails->seq($key, $value, R_NEXT());
    }

    return $res;
}

sub mail_exists {
    my ($self, $mail) = @_;

    my $dbh = $self->{dbstat}->{mails}->{dbh};
    return 0 if !$dbh;

    $mail = lc($mail);

    my $res;
    $dbh->get($mail, $res);
    return $res;
}

sub account_exists {
    my ($self, $account) = @_;

    my $dbh = $self->{dbstat}->{accounts}->{dbh};
    return 0 if !$dbh;

    $account = lc($account);

    my $res;
    $dbh->get($account, $res);
    return $res;
}

sub group_exists {
    my ($self, $group) = @_;

    my $dbh = $self->{dbstat}->{groups}->{dbh};
    return 0 if !$dbh;

    my $res;
    $dbh->get($group, $res);
    return $res;
}

sub account_has_address {
    my ($self, $account, $mail) = @_;

    my $dbhmails = $self->{dbstat}->{mails}->{dbh};
    my $dbhaccounts = $self->{dbstat}->{accounts}->{dbh};
    return 0 if !$dbhmails || !$dbhaccounts;

    $account = lc($account);
    $mail = lc($mail);

    my $accid;
    $dbhaccounts->get($account, $accid);
    return 0 if !$accid;

    my $mailid;
    $dbhmails->get($mail, $mailid);
    return 0 if !$mailid;

    return ($accid == $mailid);
}

sub user_in_group {
    my ($self, $mail, $group) = @_;

    my $dbhmails = $self->{dbstat}->{mails}->{dbh};
    my $dbhgroups = $self->{dbstat}->{groups}->{dbh};
    my $dbhmemberof = $self->{dbstat}->{memberof}->{dbh};

    return 0 if !$dbhmails || !$dbhgroups || !$dbhmemberof;

    $mail = lc($mail);

    my $cuid;
    $dbhmails->get($mail, $cuid);
    return 0 if !$cuid;

    my $groupid;
    $dbhgroups->get($group, $groupid);
    return 0 if !$groupid;

    my @gida  = $dbhmemberof->get_dup($cuid);

    return grep { $_ eq $groupid } @gida;
}

sub account_info {
    my ($self, $mail, $scan) = @_;

    my $dbhmails = $self->{dbstat}->{mails}->{dbh};
    my $dbhusers = $self->{dbstat}->{users}->{dbh};

    return undef if !$dbhmails || !$dbhusers;

    $mail = lc($mail);

    my $res = {};

    my $cuid;
    $dbhmails->get($mail, $cuid);
    return undef if !$cuid;

    my $rdata;
    $dbhusers->get($cuid, $rdata);
    return undef if !$rdata;

    my ($pmail, $account, $dn) = unpack('n/a* n/a* n/a*', $rdata);

    $res->{dn} = $dn;
    $res->{account} = $account;
    $res->{pmail} = $pmail;

    if ($scan) {
	my $key = 0 ;
	my $value = "" ;
	my $status = $dbhmails->seq($key, $value, R_FIRST());
	my $mails;

	while ($status == 0) {
	    push @$mails, $key if $value == $cuid;
	    $status = $dbhmails->seq($key, $value, R_NEXT());
	}
	$res->{mails} = $mails;
    }

    return $res;
}

1;
