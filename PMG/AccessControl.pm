package PMG::AccessControl;

use strict;
use warnings;
use Authen::PAM;
use PVE::Tools;

use PVE::JSONSchema qw(get_standard_option);

use PMG::UserConfig;

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

    ($username, $ruid, $realm) = PMG::Utils::verify_username($username);

    if ($realm eq 'pam') {
	die "invalid pam user (only root allowed)\n" if $ruid ne 'root';
	authenticate_pam_user($ruid, $password);
	return $username;
    }

    if ($realm eq 'pmg') {
	my $usercfg = PMG::UserConfig->new();
	$usercfg->authenticate_user($ruid, $password);
	return $username;
     }

    die "no such realm '$realm'\n";
}

sub domain_set_password {
    my ($realm, $ruid, $password) = @_;

    die "no auth domain specified" if !$realm;

    if ($realm eq 'pam') {
	die "invalid pam user (only root allowed)\n" if $ruid ne 'root';

	my $cmd = ['usermod'];

	my $epw = PMG::Utils::encrypt_pw($password);

	push @$cmd, '-p', $epw, $ruid;

	run_command($cmd, errmsg => "change password for '$ruid' failed");

    } elsif ($realm eq 'pmg') {
	PMG::UserConfig->set_password($ruid, $password);
    } else {
	die "no such realm '$realm'\n";
    }
}

# test if user exists and is enabled
sub check_user_enabled {
    my ($username, $noerr) = @_;

    my ($userid, $ruid, $realm) = PMG::Utils::verify_username($username, 1);

    if ($realm && $ruid) {
	if ($realm eq 'pam') {
	    return 1 if $ruid eq 'root';
	} elsif ($realm eq 'pmg') {
	    my $usercfg = PMG::UserConfig->new();
	    my $data = $usercfg->check_user_exist($ruid, $noerr);
	    return 1 if $data && $data->{enable};
	}
    }

    die "user '$username' is disabled\n" if !$noerr;

    return undef;
}

sub authenticate_pam_user {
    my ($username, $password) = @_;

    # user need to be able to read /etc/passwd /etc/shadow

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

    if (($res = $pamh->pam_acct_mgmt(0)) != PAM_SUCCESS) {
	my $err = $pamh->pam_strerror($res);
	die "auth failed: $err";
    }

    $pamh = 0; # call destructor

    return 1;
}

1;
