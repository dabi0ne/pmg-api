package PMG::API2::Services;

use strict;
use warnings;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Exception qw(raise_param_exc);
use PVE::RESTHandler;
use PVE::RESTEnvironment;
use PVE::JSONSchema qw(get_standard_option);

use PMG::Utils;

use base qw(PVE::RESTHandler);

my $service_name_list = [
    'pmgproxy',
    'pmgdaemon',
    'sshd',
    'syslog',
    'cron',
    'postfix',
    'systemd-timesyncd',
    ];

my $get_full_service_state = sub {
    my ($service) = @_;

    my $res;

    my $parser = sub {
	my $line = shift;
	if ($line =~ m/^([^=\s]+)=(.*)$/) {
	    $res->{$1} = $2;
	}
    };

    PVE::Tools::run_command(['systemctl', 'show', $service], outfunc => $parser);

    return $res;
};

my $static_service_list;

sub get_service_list {

    return $static_service_list if $static_service_list;

    my $list = {};
    foreach my $name (@$service_name_list) {
	my $ss;
	eval { $ss = &$get_full_service_state($name); };
	warn $@ if $@;
	next if !$ss;
	next if !defined($ss->{Description});
	$list->{$name} = { name => $name, desc =>  $ss->{Description} };
    }

    $static_service_list = $list;

    return $static_service_list;
}


my $service_prop_desc = {
    description => "Service ID",
    type => 'string',
    enum => $service_name_list,
};

my $service_state = sub {
    my ($service) = @_;

    my $ss;
    eval { $ss = &$get_full_service_state($service); };
    if (my $err = $@) {
	return 'unknown';
    }

    return $ss->{SubState} if $ss->{SubState};

    return 'unknown';
};

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Service list.",
    proxyto => 'node',
    protected => 1,
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
	links => [ { rel => 'child', href => "{service}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	my $service_list = get_service_list();

	foreach my $id (keys %{$service_list}) {
	    push @$res, {
		service => $id,
		name => $service_list->{$id}->{name},
		desc => $service_list->{$id}->{desc},
		state => &$service_state($id),
	    };
	}

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'srvcmdidx',
    path => '{service}',
    method => 'GET',
    description => "Directory index",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    service => $service_prop_desc,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [
	    { subdir => 'state' },
	    { subdir => 'start' },
	    { subdir => 'stop' },
	    { subdir => 'restart' },
	    { subdir => 'reload' },
	    ];

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'service_state',
    path => '{service}/state',
    method => 'GET',
    description => "Read service properties",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    service => $service_prop_desc,
	},
    },
    returns => {
	type => "object",
	properties => {},
    },
    code => sub {
	my ($param) = @_;

	my $service_list = get_service_list();

	my $si = $service_list->{$param->{service}};
	return {
	    service => $param->{service},
	    name => $si->{name},
	    desc => $si->{desc},
	    state => &$service_state($param->{service}),
	};
    }});

__PACKAGE__->register_method ({
    name => 'service_start',
    path => '{service}/start',
    method => 'POST',
    description => "Start service.",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    service => $service_prop_desc,
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PVE::RESTEnvironment::get();

	my $user = $restenv->get_user();

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "starting service $param->{service}: $upid\n");

	    PMG::Utils::service_cmd($param->{service}, 'start');

	};

	return $restenv->fork_worker('srvstart', $param->{service}, $user, $realcmd);
    }});

__PACKAGE__->register_method ({
    name => 'service_stop',
    path => '{service}/stop',
    method => 'POST',
    description => "Stop service.",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    service => $service_prop_desc,
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PVE::RESTEnvironment::get();

	my $user = $restenv->get_user();

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "stoping service $param->{service}: $upid\n");

	    PMG::Utils::service_cmd($param->{service}, 'stop');

	};

	return $restenv->fork_worker('srvstop', $param->{service}, $user, $realcmd);
    }});

__PACKAGE__->register_method ({
    name => 'service_restart',
    path => '{service}/restart',
    method => 'POST',
    description => "Restart service.",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    service => $service_prop_desc,
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PVE::RESTEnvironment::get();

	my $user = $restenv->get_user();

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "re-starting service $param->{service}: $upid\n");

	    PMG::Utils::service_cmd($param->{service}, 'restart');

	};

	return $restenv->fork_worker('srvrestart', $param->{service}, $user, $realcmd);
    }});

__PACKAGE__->register_method ({
    name => 'service_reload',
    path => '{service}/reload',
    method => 'POST',
    description => "Reload service.",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    service => $service_prop_desc,
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PVE::RESTEnvironment::get();

	my $user = $restenv->get_user();

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "reloading service $param->{service}: $upid\n");

	    PMG::Utils::service_cmd($param->{service}, 'reload');

	};

	return $restenv->fork_worker('srvreload', $param->{service}, $user, $realcmd);
    }});
