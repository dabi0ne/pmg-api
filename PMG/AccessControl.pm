package PMG::AccessControl;

use strict;
use warnings;
use Authen::PAM;

use PVE::JSONSchema qw(get_standard_option);

my $realm_regex = qr/[A-Za-z][A-Za-z0-9\.\-_]+/;

PVE::JSONSchema::register_format('pmg-realm', \&verify_realm);
sub verify_realm {
    my ($realm, $noerr) = @_;

    if ($realm !~ m/^${realm_regex}$/) {
	return undef if $noerr;
	die "value does not look like a valid realm\n";
    }
    return $realm;
}

PVE::JSONSchema::register_standard_option('realm', {
    description => "Authentication domain ID",
    type => 'string', format => 'pmg-realm',
    maxLength => 32,
});

PVE::JSONSchema::register_format('pmg-userid', \&verify_username);
sub verify_username {
    my ($username, $noerr) = @_;

    $username = '' if !$username;
    my $len = length($username);
    if ($len < 3) {
	die "user name '$username' is too short\n" if !$noerr;
	return undef;
    }
    if ($len > 64) {
	die "user name '$username' is too long ($len > 64)\n" if !$noerr;
	return undef;
    }

    # we only allow a limited set of characters
    # colon is not allowed, because we store usernames in
    # colon separated lists)!
    # slash is not allowed because it is used as pve API delimiter
    # also see "man useradd"
    if ($username =~ m!^([^\s:/]+)\@(${realm_regex})$!) {
	return wantarray ? ($username, $1, $2) : $username;
    }

    die "value '$username' does not look like a valid user name\n" if !$noerr;

    return undef;
}

PVE::JSONSchema::register_standard_option('userid', {
    description => "User ID",
    type => 'string', format => 'pmg-userid',
    maxLength => 64,
});

sub normalize_path {
    my $path = shift;

    $path =~ s|/+|/|g;

    $path =~ s|/$||;

    $path = '/' if !$path;

    $path = "/$path" if $path !~ m|^/|;

    return undef if $path !~ m|^[[:alnum:]\.\-\_\/]+$|;

    return $path;
}


# password should be utf8 encoded
# Note: some plugins delay/sleep if auth fails
sub authenticate_user {
    my ($username, $password, $otp) = @_;

    die "no username specified\n" if !$username;

    my ($ruid, $realm);

    ($username, $ruid, $realm) = verify_username($username);

    if ($realm eq 'pam') {
	is_valid_user_utf8($ruid, $password);
	return $username;
    }

    die "no such realm '$realm'\n";
}

sub domain_set_password {
    my ($realm, $username, $password) = @_;

    die "no auth domain specified" if !$realm;

    die "not implemented";
}

sub check_user_exist {
    my ($usercfg, $username, $noerr) = @_;

    $username = verify_username($username, $noerr);
    return undef if !$username;

    return $usercfg->{users}->{$username} if $usercfg && $usercfg->{users}->{$username};

    die "no such user ('$username')\n" if !$noerr;

    return undef;
}

sub check_user_enabled {
    my ($usercfg, $username, $noerr) = @_;

    my $data = check_user_exist($usercfg, $username, $noerr);
    return undef if !$data;

    return 1 if $data->{enable};

    die "user '$username' is disabled\n" if !$noerr;

    return undef;
}

sub is_valid_user_utf8 {
    my ($username, $password) = @_;

    # user (www-data) need to be able to read /etc/passwd /etc/shadow

    my $pamh = Authen::PAM->new('common-auth', $username, sub {
	my @res;
	while(@_) {
	    my $msg_type = shift;
	    my $msg = shift;
	    push @res, (0, $password);
	}
	push @res, 0;
	return @res;
    });

    if (!ref($pamh)) {
	my $err = $pamh->pam_strerror($pamh);
	die "Error during PAM init: $err";
    }

    my $res;

    if (($res = $pamh->pam_authenticate(0)) != PAM_SUCCESS) {
	my $err = $pamh->pam_strerror($res);
	die "auth failed: $err";
    }

    if (($res = $pamh->pam_acct_mgmt (0)) != PAM_SUCCESS) {
	my $err = $pamh->pam_strerror($res);
	die "auth failed: $err";
    }

    $pamh = 0; # call destructor

    return 1;
}

sub is_valid_user {
    my ($username, $password) = @_;

    return is_valid_user_utf8 ($username, encode("utf8", $password));
}

1;
