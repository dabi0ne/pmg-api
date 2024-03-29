package PMG::API2::Tasks;

use strict;
use warnings;
use POSIX;
use IO::File;
use File::ReadBackwards;
use PVE::Tools;
use PVE::SafeSyslog;
use PVE::RESTHandler;
use PVE::ProcFSTools;
use PMG::RESTEnvironment;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'node_tasks',
    path => '',
    method => 'GET',
    description => "Read task list for one node (finished tasks).",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
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
	    userfilter => {
		type => 'string',
		optional => 1,
	    },
	    errors => {
		type => 'boolean',
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		upid => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{upid}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();

	my $res = [];

	my $filename = "/var/log/pve/tasks/index";

	my $node = $param->{node};
	my $start = $param->{start} || 0;
	my $limit = $param->{limit} || 50;
	my $userfilter = $param->{userfilter};
	my $errors = $param->{errors};

	my $count = 0;
	my $line;

	my $parse_line = sub {
	    if ($line =~ m/^(\S+)(\s([0-9A-Za-z]{8})(\s(\S.*))?)?$/) {
		my $upid = $1;
		my $endtime = $3;
		my $status = $5;
		if ((my $task = PVE::Tools::upid_decode($upid, 1))) {
		    return if $userfilter && $task->{user} !~ m/\Q$userfilter\E/i;
		    return if $errors && $status && $status eq 'OK';
		    return if $count++ < $start;
		    return if $limit <= 0;

		    $task->{upid} = $upid;
		    $task->{endtime} = hex($endtime) if $endtime;
		    $task->{status} = $status if $status;
		    push @$res, $task;
		    $limit--;
		}
	    }
	};

	if (my $bw = File::ReadBackwards->new($filename)) {
	    while (defined ($line = $bw->readline)) {
		&$parse_line();
	    }
	    $bw->close();
	}
	if (my $bw = File::ReadBackwards->new("$filename.1")) {
	    while (defined ($line = $bw->readline)) {
		&$parse_line();
	    }
	    $bw->close();
	}

	$restenv->set_result_attrib('total', $count);

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'upid_index',
    path => '{upid}',
    method => 'GET',
    description => '', # index helper
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    upid => { type => 'string' },
	}
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

	return [
	    { name => 'log' },
	    { name => 'status' }
	    ];
    }});

__PACKAGE__->register_method({
    name => 'stop_task',
    path => '{upid}',
    method => 'DELETE',
    description => 'Stop a task.',
    protected => 1,
    proxyto => 'node',
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    upid => { type => 'string' },
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my ($task, $filename) = PVE::Tools::upid_decode($param->{upid}, 1);
	raise_param_exc({ upid => "unable to parse worker upid" }) if !$task;
	raise_param_exc({ upid => "no such task" }) if ! -f $filename;

	my $restenv = PMG::RESTEnvironment->get();
	PMG::RESTEnvironment->check_worker($param->{upid}, 1);

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'read_task_log',
    path => '{upid}/log',
    method => 'GET',
    protected => 1,
    description => "Read task log.",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    upid => { type => 'string' },
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

	my ($task, $filename) = PVE::Tools::upid_decode($param->{upid}, 1);
	raise_param_exc({ upid => "unable to parse worker upid" }) if !$task;

	my $lines = [];

	my $restenv = PMG::RESTEnvironment->get();

	my $fh = IO::File->new($filename, "r");
	raise_param_exc({ upid => "no such task - unable to open file - $!" }) if !$fh;

	my $start = $param->{start} || 0;
	my $limit = $param->{limit} || 50;
	my $count = 0;
	my $line;
	while (defined ($line = <$fh>)) {
	    next if $count++ < $start;
	    next if $limit <= 0;
	    chomp $line;
	    push @$lines, { n => $count, t => $line};
	    $limit--;
	}

	close($fh);

	# HACK: ExtJS store.guaranteeRange() does not like empty array
	# so we add a line
	if (!$count) {
	    $count++;
	    push @$lines, { n => $count, t => "no content"};
	}

	$restenv->set_result_attrib('total', $count);

	return $lines;
    }});


my $exit_status_cache = {};

__PACKAGE__->register_method({
    name => 'read_task_status',
    path => '{upid}/status',
    method => 'GET',
    protected => 1,
    description => "Read task status.",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    upid => { type => 'string' },
	},
    },
    returns => {
	type => "object",
	properties => {
	    pid => {
		type => 'integer'
	    },
	    status => {
		type => 'string', enum => ['running', 'stopped'],
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my ($task, $filename) = PVE::Tools::upid_decode($param->{upid}, 1);
	raise_param_exc({ upid => "unable to parse worker upid" }) if !$task;
	raise_param_exc({ upid => "no such task" }) if ! -f $filename;

	my $lines = [];

	my $pstart = PVE::ProcFSTools::read_proc_starttime($task->{pid});
	$task->{status} = ($pstart && ($pstart == $task->{pstart})) ?
	    'running' : 'stopped';

	$task->{upid} = $param->{upid}; # include upid

	if ($task->{status} eq 'stopped') {
	    if (!defined($exit_status_cache->{$task->{upid}})) {
		$exit_status_cache->{$task->{upid}} =
		    PVE::Tools::upid_read_status($task->{upid});
	    }
	    $task->{exitstatus} = $exit_status_cache->{$task->{upid}};
	}

	return $task;
    }});

1;
