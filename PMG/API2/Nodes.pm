package PMG::API2::NodeInfo;

use strict;
use warnings;

use Time::Local qw(timegm_nocheck);

use PVE::INotify;
use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTEnvironment;
use PVE::SafeSyslog;

use PMG::Ticket;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Node index.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $result = [
	    { name => 'time' },
	    { name => 'vncshell' },
	];

	return $result;
    }});

__PACKAGE__->register_method ({
    name => 'vncshell',
    path => 'vncshell',
    method => 'POST',
    description => "Creates a VNC Shell proxy.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    websocket => {
		optional => 1,
		type => 'boolean',
		description => "use websocket instead of standard vnc.",
		default => 1,
	    },
	},
    },
    returns => {
    	additionalProperties => 0,
	properties => {
	    user => { type => 'string' },
	    ticket => { type => 'string' },
	    port => { type => 'integer' },
	    upid => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $node = $param->{node};

	# we only implement the websocket based VNC here
	my $websocket = $param->{websocket} // 1;
	die "standard VNC not implemented" if !$websocket;

	my $authpath = "/nodes/$node";

	my $restenv = PVE::RESTEnvironment->get();
	my $user = $restenv->get_user();

	my $ticket = PMG::Ticket::assemble_vnc_ticket($user, $authpath);

	my $family = PVE::Tools::get_host_address_family($node);
	my $port = PVE::Tools::next_vnc_port($family);

	my $cmd = ['/usr/bin/vncterm', '-rfbport', $port,
		   '-timeout', 10, '-notls', '-listen', 'localhost',
		   '-c', '/usr/bin/top'];

	my $realcmd = sub {
	    my $upid = shift;

	    syslog ('info', "starting vnc proxy $upid\n");

	    my $cmdstr = join (' ', @$cmd);
	    syslog ('info', "launch command: $cmdstr");

	    eval {
		foreach my $k (keys %ENV) {
		    next if $k eq 'PATH' || $k eq 'TERM' || $k eq 'USER' || $k eq 'HOME';
		    delete $ENV{$k};
		}
		$ENV{PWD} = '/';

		$ENV{PVE_VNC_TICKET} = $ticket; # pass ticket to vncterm

		PVE::Tools::run_command($cmd, errmsg => "vncterm failed");
	    };
	    if (my $err = $@) {
		syslog('err', $err);
	    }

	    return;
	};

	my $upid = $restenv->fork_worker('vncshell', "", $user, $realcmd);

	PVE::Tools::wait_for_vnc_port($port);

	return {
	    user => $user,
	    ticket => $ticket,
	    port => $port,
	    upid => $upid,
	};
    }});

__PACKAGE__->register_method({
    name => 'vncwebsocket',
    path => 'vncwebsocket',
    method => 'GET',
    description => "Opens a weksocket for VNC traffic.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vncticket => {
		description => "Ticket from previous call to vncproxy.",
		type => 'string',
		maxLength => 512,
	    },
	    port => {
		description => "Port number returned by previous vncproxy call.",
		type => 'integer',
		minimum => 5900,
		maximum => 5999,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    port => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $authpath = "/nodes/$param->{node}";

	my $restenv = PVE::RESTEnvironment->get();
	my $user = $restenv->get_user();

	PMG::Ticket::verify_vnc_ticket($param->{vncticket}, $user, $authpath);

	my $port = $param->{port};

	return { port => $port };
    }});

__PACKAGE__->register_method({
    name => 'time',
    path => 'time',
    method => 'GET',
    description => "Read server time and time zone settings.",
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => "object",
	additionalProperties => 0,
	properties => {
	    timezone => {
		description => "Time zone",
		type => 'string',
	    },
	    time => {
		description => "Seconds since 1970-01-01 00:00:00 UTC.",
		type => 'integer',
		minimum => 1297163644,
	    },
	    localtime => {
		description => "Seconds since 1970-01-01 00:00:00 (local time)",
		type => 'integer',
		minimum => 1297163644,
	    },
        },
    },
    code => sub {
	my ($param) = @_;

	my $ctime = time();
	my $ltime = timegm_nocheck(localtime($ctime));
	my $res = {
	    timezone => PVE::INotify::read_file('timezone'),
	    time => time(),
	    localtime => $ltime,
	};

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'set_timezone',
    path => 'time',
    method => 'PUT',
    description => "Set time zone.",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    timezone => {
		description => "Time zone. The file '/usr/share/zoneinfo/zone.tab' contains the list of valid names.",
		type => 'string',
	    },
	},
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	PVE::INotify::write_file('timezone', $param->{timezone});

	return undef;
    }});


package PMG::API2::Nodes;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PMG::API2::NodeInfo",
    path => '{node}',
});

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Cluster node index.",
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{node}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $nodename =  PVE::INotify::nodename();
	my $res = [
	   { node => $nodename },
	];

	return $res;
    }});


1;
