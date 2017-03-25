package PMG::UserConfig;


use strict;
use warnings;

use PVE::Tools;
use PVE::INotify;
use PVE::JSONSchema;

use PMG::Utils;

my $inotify_file_id = 'pmg-user.conf';
my $config_filename = '/etc/pmg/user.conf';

sub new {
    my ($type) = @_;

    my $class = ref($type) || $type;

    my $cfg = PVE::INotify::read_file($inotify_file_id);

    return bless $cfg, $class;
}

sub write {
    my ($self) = @_;

    PVE::INotify::write_file($inotify_file_id, $self);
}

my $lockfile = "/var/lock/pmguser.lck";

sub lock_config {
    my ($code, $errmsg) = @_;

    my $p = PVE::Tools::lock_file($lockfile, undef, $code);
    if (my $err = $@) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
}

sub read_user_conf {
    my ($filename, $fh) = @_;

    my $cfg = {};

    if ($fh) {

	my $comment = '';

	while (defined(my $line = <$fh>)) {
	    next if $line =~ m/^\s*$/;
	    if ($line =~ m/^#(.*)$/) {
		$comment = $1;
		next;
	    }
	    if ($line =~ m/^\S+:([01]):\S+:[a-z]+:\S*:$/) {
		my ($userid, $enable, $crypt_pass, $role, $email) = ($1, $2, $3, $4);
		my $d = {
		    userid => $userid,
		    enable => $enable,
		    crypt_pass => $crypt_pass,
		    role => $role,
		};
		$d->{comment} = $comment if $comment;
		$comment = '';
		$d->{email} = $email if $email;
		$cfg->{$userid} = $d;
	    } else {
		warn "$filename: ignore invalid line $.\n";
		$comment = '';
	    }
	}
    }

    $cfg->{root} //= {};
    $cfg->{root}->{userid} = 'root';
    $cfg->{root}->{enable} = 1;
    $cfg->{root}->{comment} = 'Unix Superuser';
    $cfg->{root}->{role} = 'root';
    delete $cfg->{root}->{crypt_pass};

    return $cfg;
}

sub write_user_conf {
    my ($filename, $fh, $cfg) = @_;

    my $raw = '';


    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file($inotify_file_id, $config_filename,
			    \&read_user_conf,
			    \&write_user_conf,
			    undef,
			    always_call_parser => 1);

sub lookup_user_data {
    my ($self, $username, $noerr) = @_;

    return $self->{$username} if $self->{$username};

    die "no such user ('$username')\n" if !$noerr;

    return undef;
}

sub authenticate_user {
    my ($self, $username, $password) = @_;

    die "no password\n" if !$password;

    my $data = $self->lookup_user_data($username);

    if ($data->{crypt_pass}) {
	my $encpw = crypt($password, $data->{crypt_pass});
        die "invalid credentials\n" if ($encpw ne $data->{crypt_pass});
    } else {
	die "no password set\n";
    }

    return 1;
}

sub set_password {
    my ($class, $username, $password) = @_;

    lock_config(sub {
	my $cfg = $class->new();
	my $data = $cfg->lookup_user_data($username); # user exists
	my $epw = PMG::Utils::encrypt_pw($password);
	$data->{crypt_pass} = $epw;
	$cfg->write();
    });
}

1;
