package PMG::UserConfig;


use strict;
use warnings;

use PVE::Tools;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise);

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

my $schema = {
    additionalProperties => 0,
    properties => {
	userid => get_standard_option('username'),
	email => {
	    description => "Users E-Mail address.",
	    text => 'string', format => 'email',
	    optional => 1,
	},
	expire => {
	    description => "Account expiration date, expressed as unix epoch.",
	    type => 'integer',
	    minimum => 0,
	},
	enable => {
	    description => "Flag to enable or disable the account.",
	    type => 'boolean',
	},
	crypt_pass => {
	    description => "Encrypted password (see `man crypt`)",
	    type => 'string',
	    pattern => '\$\d\$[a-zA-Z0-9\.\/]+\$[a-zA-Z0-9\.\/]+',
	    optional => 1,
	},
	role => {
	    description => "User role.",
	    type => 'string',
	    enum => ['root', 'admin', 'qmanager', 'quser', 'audit'],
	},
	first => {
	    description => "First name.",
	    type => 'string',
	    maxLength => 64,
	    optional => 1,
	},
	'last' => {
	    description => "Last name.",
	    type => 'string',
	    maxLength => 64,
	    optional => 1,
	},
	keys => {
	    description => "OTP Keys",
	    type => 'string',
	    maxLength => 128,
	    optional => 1,
	},
    },
};

my $verity_entry = sub {
    my ($entry) = @_;

    my $errors = {};
    PVE::JSONSchema::check_prop($entry, $schema, '', $errors);
    if (scalar(%$errors)) {
	raise "verify entry failed\n", errors => $errors;
    }
};

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

	    if ($line =~ m/^
               (?<userid>(?:[^\s:]+)) :
               (?<enable>[01]) :
               (?<expire>\d+) :
               (?<pass>(?:[^\s:]*)) :
               (?<role>[a-z]+) :
               (?<email>(?:[^\s:]*)) :
               (?<first>(?:[^:]*)) :
               (?<last>(?:[^:]*)) :
               (?<keys>(?:[^:]*)) :
               $/x
	    ) {
		my $d = {
		    userid => $+{userid},
		    enable => $+{enable},
		    expire => $+{expire},
		    crypt_pass => $+{pass},
		    role => $+{role},
		};
		$d->{comment} = $comment if $comment;
		$comment = '';
		foreach my $k (qw(email first last keys)) {
		    $d->{$k} = $+{$k} if $+{$k};
		}
		eval {
		    $verity_entry->($d);
		    $cfg->{$d->{userid}} = $d;
		};
		if (my $err = $@) {
		    warn "$filename: $err";
		}
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

    my $ctime = time();
    my $expire = $data->{expire};

    die "account expired\n" if $expire && ($expire < $ctime);

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
