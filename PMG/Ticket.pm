package PMG::Ticket;

use strict;
use warnings;
use Net::SSLeay;
use Digest::SHA;

use PVE::SafeSyslog;
use PVE::Tools;
use PVE::Ticket;
use PVE::INotify;

use Crypt::OpenSSL::RSA;

use PMG::Utils;

my $min_ticket_lifetime = -60*5; # allow 5 minutes time drift
my $max_ticket_lifetime = 60*60*2; # 2 hours

my $basedir = "/etc/pmg";

my $pmg_api_cert_fn = "$basedir/pmg-api.pem";

# this is just a secret accessable by all API servers
# and is used for CSRF prevention
my $pmg_csrf_key_fn = "$basedir/pmg-csrf.key";

my $authprivkeyfn = "$basedir/pmg-authkey.key";
my $authpubkeyfn = "$basedir/pmg-authkey.pub";

sub generate_api_cert {
    my ($force) = @_;

    my $nodename = PVE::INotify::nodename();

    if (-f $pmg_api_cert_fn) {
	return $pmg_api_cert_fn if !$force;
	unlink $pmg_api_cert_fn;
    }

    my $gid = getgrnam('www-data') ||
	die "user www-data not in group file\n";

    my $tmp_fn = "$pmg_api_cert_fn.tmp$$";

    my $cmd = ['openssl', 'req', '-batch', '-x509', '-newkey', 'rsa:4096',
	       '-nodes', '-keyout', $tmp_fn, '-out', $tmp_fn,
	       '-subj', "/CN=$nodename/",
	       '-days', '3650'];

    eval {
	PMG::Utils::run_silent_cmd($cmd);
	chown(0, $gid, $tmp_fn) || die "chown failed - $!\n";
	chmod(0640, $tmp_fn) || die "chmod failed - $!\n";
	rename($tmp_fn, $pmg_api_cert_fn) || die "rename failed - $!\n";
    };
    if (my $err = $@) {
	unlink $tmp_fn;
	die "unable to generate pmg api cert '$pmg_api_cert_fn':\n$err";
    }

    return $pmg_api_cert_fn;
}

sub generate_csrf_key {

    return if -f $pmg_csrf_key_fn;

    my $gid = getgrnam('www-data') ||
	die "user www-data not in group file\n";

    my $tmp_fn = "$pmg_csrf_key_fn.tmp$$";
    my $cmd = ['openssl', 'genrsa', '-out', $tmp_fn, '2048'];

    eval {
	PMG::Utils::run_silent_cmd($cmd);
	chown(0, $gid, $tmp_fn) || die "chown failed - $!\n";
	chmod(0640, $tmp_fn) || die "chmod failed - $!\n";
	rename($tmp_fn, $pmg_csrf_key_fn) || die "rename failed - $!\n";
    };
    if (my $err = $@) {
	unlink $tmp_fn;
	die "unable to generate pmg csrf key '$pmg_csrf_key_fn':\n$@";
    }

    return $pmg_csrf_key_fn;
}

sub generate_auth_key {

    return if -f "$authprivkeyfn";

    eval {
	my $cmd = ['openssl', 'genrsa', '-out', $authprivkeyfn, '2048'];
	PMG::Utils::run_silent_cmd($cmd);

	$cmd = ['openssl', 'rsa', '-in', $authprivkeyfn, '-pubout',
		'-out', $authpubkeyfn];
	PMG::Utils::run_silent_cmd($cmd);
    };

    die "unable to generate pmg auth key:\n$@" if $@;
}

my $read_rsa_priv_key = sub {
   my ($filename, $fh) = @_;

   local $/ = undef; # slurp mode

   my $input = <$fh>;

   return Crypt::OpenSSL::RSA->new_private_key($input);

};

PVE::INotify::register_file('auth_priv_key', $authprivkeyfn,
			    $read_rsa_priv_key, undef, undef,
			    noclone => 1);

my $read_rsa_pub_key = sub {
   my ($filename, $fh) = @_;

   local $/ = undef; # slurp mode

   my $input = <$fh>;

   return Crypt::OpenSSL::RSA->new_public_key($input);
};

PVE::INotify::register_file('auth_pub_key', $authpubkeyfn,
			    $read_rsa_pub_key, undef, undef,
			    noclone => 1);

my $read_csrf_secret = sub {
   my ($filename, $fh) = @_;

   local $/ = undef; # slurp mode

   my $input = <$fh>;

   return Digest::SHA::sha1_base64($input);
};

PVE::INotify::register_file('csrf_secret', $pmg_csrf_key_fn,
			    $read_csrf_secret, undef, undef,
			    noclone => 1);

sub verify_csrf_prevention_token {
    my ($username, $token, $noerr) = @_;

    my $secret = PVE::INotify::read_file('csrf_secret');

    return PVE::Ticket::verify_csrf_prevention_token(
	$secret, $username, $token, $min_ticket_lifetime,
	$max_ticket_lifetime, $noerr);
}

sub assemble_csrf_prevention_token {
    my ($username) = @_;

    my $secret = PVE::INotify::read_file('csrf_secret');

    return PVE::Ticket::assemble_csrf_prevention_token ($secret, $username);
}

sub assemble_ticket {
    my ($username) = @_;

    my $rsa_priv = PVE::INotify::read_file('auth_priv_key');

    return PVE::Ticket::assemble_rsa_ticket($rsa_priv, 'PMG', $username);
}

sub verify_ticket {
    my ($ticket, $noerr) = @_;

    my $rsa_pub = PVE::INotify::read_file('auth_pub_key');

    return PVE::Ticket::verify_rsa_ticket(
	$rsa_pub, 'PMG', $ticket, undef,
	$min_ticket_lifetime, $max_ticket_lifetime, $noerr);
}

# VNC tickets
# - they do not contain the username in plain text
# - they are restricted to a specific resource path (example: '/vms/100')
sub assemble_vnc_ticket {
    my ($username, $path) = @_;

    my $rsa_priv = PVE::INotify::read_file('auth_priv_key');

    my $secret_data = "$username:$path";

    return PVE::Ticket::assemble_rsa_ticket(
	$rsa_priv, 'PMGVNC', undef, $secret_data);
}

sub verify_vnc_ticket {
    my ($ticket, $username, $path, $noerr) = @_;

    my $rsa_pub = PVE::INotify::read_file('auth_pub_key');

    my $secret_data = "$username:$path";

    return PVE::Ticket::verify_rsa_ticket(
	$rsa_pub, 'PMGVNC', $ticket, $secret_data, -20, 40, $noerr);
}

1;
