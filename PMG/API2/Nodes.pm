package PMG::API2::NodeInfo;

use strict;
use warnings;

use Time::Local qw(timegm_nocheck);

use PVE::INotify;
use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);
use PMG::RESTEnvironment;
use PVE::SafeSyslog;

use PMG::Ticket;
use PMG::API2::Tasks;
use PMG::API2::Services;
use PMG::API2::Network;
use PMG::API2::ClamAV;
use PMG::API2::Postfix;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Postfix",
    path => 'postfix',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::ClamAV",
    path => 'clamav',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Network",
    path => 'network',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Tasks",
    path => 'tasks',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Services",
    path => 'services',
});

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
	    { name => 'clamav' },
	    { name => 'postfix' },
	    { name => 'services' },
	    { name => 'syslog' },
	    { name => 'tasks' },
	    { name => 'time' },
	    { name => 'vncshell' },
	    { name => 'rrddata' },
	];

	return $result;
    }});

__PACKAGE__->register_method({
    name => 'rrddata',
    path => 'rrddata',
    method => 'GET',
    protected => 1, # fixme: can we avoid that?
    proxyto => 'node',
    description => "Read node RRD statistics",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    timeframe => {
		description => "Specify the time frame you are interested in.",
		type => 'string',
		enum => [ 'hour', 'day', 'week', 'month', 'year' ],
	    },
	    cf => {
		description => "The RRD consolidation function",
		type => 'string',
		enum => [ 'AVERAGE', 'MAX' ],
		optional => 1,
	    },
	},
    },
    returns => {
	type => "array",
	items => {
	    type => "object",
	    properties => {},
	},
    },
    code => sub {
	my ($param) = @_;

	return PMG::Utils::create_rrd_data(
	    "pmg-node-v1.rrd", $param->{timeframe}, $param->{cf});
    }});


__PACKAGE__->register_method({
    name => 'syslog',
    path => 'syslog',
    method => 'GET',
    description => "Read system log",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    start => {
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    limit => {
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    since => {
		type => 'string',
		pattern => '^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?$',
		description => "Display all log since this date-time string.",
		optional => 1,
	    },
	    'until' => {
		type => 'string',
		pattern => '^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?$',
		description => "Display all log until this date-time string.",
		optional => 1,
	    },
	    service => {
		description => "Service ID",
		type => 'string',
		maxLength => 128,
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		n => {
		  description=>  "Line number",
		  type=> 'integer',
		},
		t => {
		  description=>  "Line text",
		  type => 'string',
		}
	    }
	}
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment::get();

	my $service = $param->{service};
	if ($service && $service eq 'postfix') {
	    $service = 'postfix@-';
	}

	my ($count, $lines) = PVE::Tools::dump_journal(
	    $param->{start}, $param->{limit},
	    $param->{since}, $param->{'until'}, $service);

	$restenv->set_result_attrib('total', $count);

	return $lines;
    }});

__PACKAGE__->register_method ({
    name => 'vncshell',
    path => 'vncshell',
    method => 'POST',
    protected => 1,
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

	my $restenv = PMG::RESTEnvironment->get();
	my $user = $restenv->get_user();

	my $ticket = PMG::Ticket::assemble_vnc_ticket($user, $authpath);

	my $family = PVE::Tools::get_host_address_family($node);
	my $port = PVE::Tools::next_vnc_port($family);

	my $shcmd;

	if ($user eq 'root@pam') {
	    $shcmd = [ '/bin/login', '-f', 'root' ];
	} else {
	    $shcmd = [ '/bin/login' ];
	}

	my $cmd = ['/usr/bin/vncterm', '-rfbport', $port,
		   '-timeout', 10, '-notls', '-listen', 'localhost',
		   '-c', @$shcmd];

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

	my $restenv = PMG::RESTEnvironment->get();
	my $user = $restenv->get_user();

	PMG::Ticket::verify_vnc_ticket($param->{vncticket}, $user, $authpath);

	my $port = $param->{port};

	return { port => $port };
    }});

__PACKAGE__->register_method({
    name => 'dns',
    path => 'dns',
    method => 'GET',
    description => "Read DNS settings.",
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
	    search => {
		description => "Search domain for host-name lookup.",
		type => 'string',
		optional => 1,
	    },
	    dns1 => {
		description => 'First name server IP address.',
		type => 'string',
		optional => 1,
	    },
	    dns2 => {
		description => 'Second name server IP address.',
		type => 'string',
		optional => 1,
	    },
	    dns3 => {
		description => 'Third name server IP address.',
		type => 'string',
		optional => 1,
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $res = PVE::INotify::read_file('resolvconf');

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'update_dns',
    path => 'dns',
    method => 'PUT',
    description => "Write DNS settings.",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    search => {
		description => "Search domain for host-name lookup.",
		type => 'string',
	    },
	    dns1 => {
		description => 'First name server IP address.',
		type => 'string', format => 'ip',
		optional => 1,
	    },
	    dns2 => {
		description => 'Second name server IP address.',
		type => 'string', format => 'ip',
		optional => 1,
	    },
	    dns3 => {
		description => 'Third name server IP address.',
		type => 'string', format => 'ip',
		optional => 1,
	    },
	},
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	PVE::INotify::update_file('resolvconf', $param);

	return undef;
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
