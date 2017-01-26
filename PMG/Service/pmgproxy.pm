package PMG::Service::pmgproxy;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::Daemon;
use HTTP::Response;
use URI;
use URI::QueryParam;
use Data::Dumper;

use PVE::Tools;
use PVE::APIServer::Formatter;
use PVE::APIServer::Formatter::Standard;
use PVE::APIServer::Formatter::HTML;
use PVE::APIServer::AnyEvent;

use PMG::HTTPServer;
use PMG::API2;

#use PMG::ExtJSIndex;

use base qw(PVE::Daemon);

my $cmdline = [$0, @ARGV];

my %daemon_options = (
    max_workers => 3,
    restart_on_error => 5,
    stop_wait_time => 15,
    leave_children_open_on_reload => 1,
    setuid => 'www-data',
    setgid => 'www-data',
    pidfile => '/var/run/pmgproxy/pmgproxy.pid',
);

my $daemon = __PACKAGE__->new('pmgproxy', $cmdline, %daemon_options);

sub add_dirs {
    my ($result_hash, $alias, $subdir) = @_;

    PVE::APIServer::AnyEvent::add_dirs($result_hash, $alias, $subdir);
}

sub init {
    my ($self) = @_;

    my $accept_lock_fn = "/var/lock/pmgproxy.lck";

    my $lockfh = IO::File->new(">>${accept_lock_fn}") ||
	die "unable to open lock file '${accept_lock_fn}' - $!\n";

    my $family = PVE::Tools::get_host_address_family($self->{nodename});
    my $socket = $self->create_reusable_socket(8006, undef, $family);

    my $dirs = {};

    add_dirs($dirs, '/pve2/ext6/', '/usr/share/javascript/extjs/');
    #add_dirs($dirs, '/pve2/images/' => '/usr/share/pve-manager/images/');
    #add_dirs($dirs, '/pve2/css/' => '/usr/share/pve-manager/css/');
    #add_dirs($dirs, '/pve2/js/' => '/usr/share/pve-manager/js/');
    #add_dirs($dirs, '/pve-docs/' => '/usr/share/pve-docs/');
    #add_dirs($dirs, '/vncterm/' => '/usr/share/vncterm/');
    #add_dirs($dirs, '/novnc/' => '/usr/share/novnc-pve/');

    $self->{server_config} = {
	title => 'Proxmox Mail Gateway API',
	cookie_name => 'PMG',
	keep_alive => 100,
	max_conn => 500,
	max_requests => 1000,
	lockfile => $accept_lock_fn,
	socket => $socket,
	lockfh => $lockfh,
	debug => $self->{debug},
	trusted_env => 0, # not trusted, anyone can connect
	logfile => '/var/log/pmgproxy/pmgproxy.log',
	ssl => {
	    # Note: older versions are considered insecure, for example
	    # search for "Poodle"-Attac
	    method => 'any',
	    sslv2 => 0,
	    sslv3 => 0,
	    cipher_list => 'HIGH:MEDIUM:!aNULL:!MD5',
	    cert_file => '/etc/proxmox/pmg-api.pem',
	    dh => 'skip2048',
	},
	# Note: there is no authentication for those pages and dirs!
	pages => {
	    '/' => sub { get_index($self->{nodename}, @_) },
	    # avoid authentication when accessing favicon
#	    '/favicon.ico' => {
#		file => '/usr/share/pve-manager/images/favicon.ico',
#	    },
	},
	dirs => $dirs,
    };
}

sub run {
    my ($self) = @_;

    my $server = PMG::HTTPServer->new(%{$self->{server_config}});
    $server->run();
}

$daemon->register_start_command();
$daemon->register_restart_command(1);
$daemon->register_stop_command();
$daemon->register_status_command();

our $cmddef = {
    start => [ __PACKAGE__, 'start', []],
    restart => [ __PACKAGE__, 'restart', []],
    stop => [ __PACKAGE__, 'stop', []],
    status => [ __PACKAGE__, 'status', [], undef, sub { print shift . "\n";} ],
};

# NOTE: Requests to those pages are not authenticated
# so we must be very careful here
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
    <h1>Proxmox Mail Gateway API</h1>

    You can browse the API <a href='/api2/html' >here</a>. Please sign
    in with usrename <b>demo</b> and passwort <b>demo</b>.

  </body>
</html>
__EOD__
 

sub get_index {
    my ($nodename, $server, $r, $args) = @_;

    my $lang = 'en';
    my $username;
    my $token = 'null';

    if (my $cookie = $r->header('Cookie')) {
	if (my $newlang = ($cookie =~ /(?:^|\s)PMGLangCookie=([^;]*)/)[0]) {
	    if ($newlang =~ m/^[a-z]{2,3}(_[A-Z]{2,3})?$/) {
		$lang = $newlang;
	    }
	}
	my $ticket = PVE::APIServer::Formatter::extract_auth_cookie($cookie, $server->{cookie_name});
	if (($username = PMG::Ticket::verify_ticket($ticket, 1))) {
	    $token = PMG::Ticket::assemble_csrf_prevention_token($username);
	}
    }

    $username = '' if !$username;

    #my $page = PMG::ExtJSIndex::get_index($lang, $username, $token, $args->{console}, $nodename, $server->{debug});
    my $page = $root_page;
    
    my $headers = HTTP::Headers->new(Content_Type => "text/html; charset=utf-8");
    my $resp = HTTP::Response->new(200, "OK", $headers, $page);

    return $resp;
}

1;
