package PMG::Ticket;

use strict;
use warnings;
use Net::SSLeay;
use Digest::SHA;

use PVE::Tools;
use PVE::Ticket;

use Crypt::OpenSSL::RSA;

my $min_ticket_lifetime = -60*5; # allow 5 minutes time drift
my $max_ticket_lifetime = 60*60*2; # 2 hours

my $basedir = "/etc/proxmox";

my $pmg_api_cert_fn = "$basedir/pmg-api.pem";

# this is just a secret accessable by all API servers
# and is used for CSRF prevention
my $pmg_csrf_key_fn = "$basedir/pmg-csrf.key";


# fixme
my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);

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
    my ($nodename, $force) = @_;

    if (-f $pmg_api_cert_fn) {
	return $pmg_api_cert_fn if !$force;
	unlink $pmg_api_cert_fn;
    }

    my $cmd = ['openssl', 'req', '-batch', '-x509', '-newkey', 'rsa:4096',
	       '-nodes', '-keyout', $pmg_api_cert_fn, '-out', $pmg_api_cert_fn,
	       '-subj', "/CN=$nodename/",
	       '-days', '3650'];

    eval { run_silent_cmd($cmd); };

    die "unable to generate pmg api cert '$pmg_api_cert_fn':\n$@" if $@;

    return $pmg_api_cert_fn;
}

sub generate_csrf_key {

    return if -f $pmg_csrf_key_fn;

    my $cmd = ['openssl', 'genrsa', '-out', $pmg_csrf_key_fn, '2048'];

    eval { run_silent_cmd($cmd); };

    die "unable to generate pmg csrf key '$pmg_csrf_key_fn':\n$@" if $@;
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

    return PVE::Ticket::assemble_rsa_ticket($rsa, 'PMG', $username);
}

sub verify_ticket {
    my ($ticket, $noerr) = @_;

    return PVE::Ticket::verify_rsa_ticket(
	$rsa, 'PMG', $ticket, undef,
	$min_ticket_lifetime, $max_ticket_lifetime, $noerr);
}

# VNC tickets
# - they do not contain the username in plain text
# - they are restricted to a specific resource path (example: '/vms/100')
sub assemble_vnc_ticket {
    my ($username, $path) = @_;

    my $secret_data = "$username:$path";

    return PVE::Ticket::assemble_rsa_ticket(
	$rsa, 'PMGVNC', undef, $secret_data);
}

sub verify_vnc_ticket {
    my ($ticket, $username, $path, $noerr) = @_;

    my $secret_data = "$username:$path";

    return PVE::Ticket::verify_rsa_ticket(
	$rsa, 'PMGVNC', $ticket, $secret_data, -20, 40, $noerr);
}

1;
