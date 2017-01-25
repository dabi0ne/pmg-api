#!/usr/bin/perl

use strict;
use warnings;
use lib '.';

use Socket qw(IPPROTO_TCP TCP_NODELAY SOMAXCONN);
use IO::Socket::IP;
use HTTP::Headers;
use HTTP::Response;
use Data::Dumper;

use PVE::INotify;
use PVE::APIServer::Formatter::Standard;
use PVE::APIServer::Formatter::HTML;

use PMG::HTTPServer;
use PMG::Ticket;

my $nodename = PVE::INotify::nodename();
my $port = 9999;
my $cert_file = PMG::Ticket::generate_api_cert($nodename);

my $socket = IO::Socket::IP->new(
    LocalAddr => $nodename,
    LocalPort => $port,
    Listen => SOMAXCONN,
    Proto  => 'tcp',
    GetAddrInfoFlags => 0,
    ReuseAddr => 1) ||
    die "unable to create socket - $@\n";

# we often observe delays when using Nagle algorithm,
# so we disable that to maximize performance
setsockopt($socket, IPPROTO_TCP, TCP_NODELAY, 1);

my $accept_lock_fn = "simple-demo.lck";
my $lockfh = IO::File->new(">>${accept_lock_fn}") ||
    die "unable to open lock file '${accept_lock_fn}' - $!\n";

my $server = PMG::HTTPServer->new(
    debug => 1,
    socket => $socket,
    lockfile => $accept_lock_fn,
    lockfh => $lockfh,
    title => 'Proxmox Mail Gateway API',
    cookie_name => 'PMG',
    logfh => \*STDOUT,
    tls_ctx  => { verify => 0, cert_file => $cert_file },
    pages => {
	'/' => sub { get_index($nodename, @_) },
    },
);

# NOTE: Requests to non-API pages are not authenticated
# so you must be very careful here

my $root_page = <<__EOD__;
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <title>Simple Demo Server</title>
  </head>
  <body>
    <h1>Proxmox Mail Gateway API ($nodename)</h1>

    You can browse the API <a href='/api2/html' >here</a>. Please sign
    in with usrename <b>demo</b> and passwort <b>demo</b>.

  </body>
</html>
__EOD__
    
sub get_index {
    my ($nodename, $server, $r, $args) = @_;

    my $headers = HTTP::Headers->new(Content_Type => "text/html; charset=utf-8");
    my $resp = HTTP::Response->new(200, "OK", $headers, $root_page);

}

print "demo server listens at: https://$nodename:$port/\n";

$server->run();
