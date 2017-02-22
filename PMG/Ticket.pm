package PMG::Ticket;

use strict;
use warnings;
use Net::SSLeay;
use Digest::SHA;

use PVE::Tools;
use PVE::Ticket;
use PVE::INotify;

use Crypt::OpenSSL::RSA;

my $min_ticket_lifetime = -60*5; # allow 5 minutes time drift
my $max_ticket_lifetime = 60*60*2; # 2 hours

my $basedir = "/etc/pmg";

my $pmg_api_cert_fn = "$basedir/pmg-api.pem";

# this is just a secret accessable by all API servers
# and is used for CSRF prevention
my $pmg_csrf_key_fn = "$basedir/pmg-csrf.key";

my $authprivkeyfn = "$basedir/pmg-authkey.key";
my $authpubkeyfn = "$basedir/pmg-authkey.pub";

# only write output if something fails
sub run_silent_cmd {
    my ($cmd) = @_;

    my $outbuf = '';

    my $record_output = sub {
	$outbuf .= shift;
	$outbuf .= "\n";
    };

    eval {
	PVE::Tools::run_command($cmd, outfunc => $record_output,
				errfunc => $record_output);
    };

    my $err = $@;

    if ($err) {
	print STDERR $outbuf;
	die $err;
    }
}

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
	run_silent_cmd($cmd);
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
	run_silent_cmd($cmd);
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
	run_silent_cmd(['openssl', 'genrsa', '-out', $authprivkeyfn, '2048']);

	run_silent_cmd(['openssl', 'rsa', '-in', $authprivkeyfn, '-pubout', '-out', $authpubkeyfn]);
    };

    die "unable to generate pmg auth key:\n$@" if $@;
}

my $pve_auth_priv_key;
sub get_privkey {

    return $pve_auth_priv_key if $pve_auth_priv_key;

    my $input = PVE::Tools::file_get_contents($authprivkeyfn);

    $pve_auth_priv_key = Crypt::OpenSSL::RSA->new_private_key($input);

    return $pve_auth_priv_key;
}

my $pve_auth_pub_key;
sub get_pubkey {

    return $pve_auth_pub_key if $pve_auth_pub_key;

    my $input = PVE::Tools::file_get_contents($authpubkeyfn);

    $pve_auth_pub_key = Crypt::OpenSSL::RSA->new_public_key($input);

    return $pve_auth_pub_key;
}

my $csrf_prevention_secret;
my $get_csrfr_secret = sub {
    if (!$csrf_prevention_secret) {
	my $input = PVE::Tools::file_get_contents($pmg_csrf_key_fn);
	$csrf_prevention_secret = Digest::SHA::sha1_base64($input);
	print "SECRET:$csrf_prevention_secret\n";
    }
    return $csrf_prevention_secret;
};


sub verify_csrf_prevention_token {
    my ($username, $token, $noerr) = @_;

    my $secret =  &$get_csrfr_secret();

    return PVE::Ticket::verify_csrf_prevention_token(
	$secret, $username, $token, $min_ticket_lifetime,
	$max_ticket_lifetime, $noerr);
}

sub assemble_csrf_prevention_token {
    my ($username) = @_;

    my $secret =  &$get_csrfr_secret();

    return PVE::Ticket::assemble_csrf_prevention_token ($secret, $username);
}

sub assemble_ticket {
    my ($username) = @_;

    my $rsa_priv = get_privkey();

    return PVE::Ticket::assemble_rsa_ticket($rsa_priv, 'PMG', $username);
}

sub verify_ticket {
    my ($ticket, $noerr) = @_;

    my $rsa_pub = get_pubkey();

    return PVE::Ticket::verify_rsa_ticket(
	$rsa_pub, 'PMG', $ticket, undef,
	$min_ticket_lifetime, $max_ticket_lifetime, $noerr);
}

# VNC tickets
# - they do not contain the username in plain text
# - they are restricted to a specific resource path (example: '/vms/100')
sub assemble_vnc_ticket {
    my ($username, $path) = @_;

    my $rsa_priv = get_privkey();

    my $secret_data = "$username:$path";

    return PVE::Ticket::assemble_rsa_ticket(
	$rsa_priv, 'PMGVNC', undef, $secret_data);
}

sub verify_vnc_ticket {
    my ($ticket, $username, $path, $noerr) = @_;

    my $rsa_pub = get_pubkey();

    my $secret_data = "$username:$path";

    return PVE::Ticket::verify_rsa_ticket(
	$rsa_pub, 'PMGVNC', $ticket, $secret_data, -20, 40, $noerr);
}

1;
