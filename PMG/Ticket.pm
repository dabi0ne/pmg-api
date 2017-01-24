package PMG::Ticket;

use strict;
use warnings;
use Net::SSLeay;
use Digest::SHA;

use PVE::Ticket;

use Crypt::OpenSSL::RSA;

my $min_ticket_lifetime = -60*5; # allow 5 minutes time drift
my $max_ticket_lifetime = 60*60*2; # 2 hours

# fixme
my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);

## fixme:
my $csrf_prevention_secret;
my $get_csrfr_secret = sub {
    if (!$csrf_prevention_secret) {
	#my $input = PVE::Tools::file_get_contents($pve_www_key_fn);
	my $input = "ABCD"; # fixme
	$csrf_prevention_secret = Digest::SHA::sha1_base64($input);
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
