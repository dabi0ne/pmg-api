package PMG::API2::AdvancedMasterTransport;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use HTTP::Status qw(:constants);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::Config;

use Data::Dumper;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "List master transports entries.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		service => { type => 'string' },
		params => { type => 'array' },
	    },
	},
	links => [ { rel => 'child', href => "{service}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $tmap = PVE::INotify::read_file('advanced_master_transport');

	my $res = [];
	
	foreach my $key (sort keys %$tmap) {
	    push @$res, { 
	    	service => $tmap->{$key}->{service},
	    	params => [
		    	$tmap->{$key}->{'type'},
		    	$tmap->{$key}->{'private'},
		    	$tmap->{$key}->{'unpriv'},
		    	$tmap->{$key}->{'chroot'},
		    	$tmap->{$key}->{'wakeup'},
		    	$tmap->{$key}->{'maxproc'},
		    	$tmap->{$key}->{'command'}
	    	]
	    }
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'reload',
    path => '',
    method => 'POST',
    description => "Reload Postfix configuration files",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {},
    code => sub {
	my ($param) = @_;

	 my $cfg = PMG::Config->new();

    if ($cfg->rewrite_config_postfix()) {
		return PMG::Utils::service_cmd('postfix', 'reload');
    }

    }});

__PACKAGE__->register_method ({
    name => 'read',
    path => '{urlservice}',
    method => 'GET',
    description => "Read mtransport entry.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    urlservice => {
		description => "Transport service.",
		type => 'string',
	    },
	    
	},
    },
    returns => {
	type => "array",
	properties => {
	    option => { type => 'string' },
	    value => { type => 'string'},
	},
    },
    code => sub {
	my ($param) = @_;
	my $name = $param->{urlservice};

	my $tmap = PVE::INotify::read_file('advanced_master_transport');

	my $res = $tmap->{$name}->{options};

	return $res; 

	raise_param_exc({ name => "Transport entry for '$name' does not exist" });
    }});
    
__PACKAGE__->register_method ({
    name => 'deletemtrasport',
    path => '{urlservice}',
    method => 'DELETE',
    description => "Read mtransport entry.",
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    urlservice => {
		description => "Transport service",
		type => 'string',
	    },
	    
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	
	my $code = sub {

	    my $tmap = PVE::INotify::read_file('advanced_master_transport');

	    die "Transport service '$param->{urlservice}' does not exist\n"
		if !$tmap->{$param->{urlservice}};

	    delete $tmap->{$param->{urlservice}};

	    PVE::INotify::write_file('advanced_master_transport', $tmap);

	};

	PMG::Config::lock_config($code, "Delete transport entry failed");

	return undef;
	
    }});
    

    
__PACKAGE__->register_method ({
    name => 'checkservice',
    path => '{urlservice}/option',
    method => 'GET',
    description => "Read mtransport entry.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    urlservice => {
		description => "Transport service.",
		type => 'string',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	my $name = $param->{urlservice};

	my $tmap = PVE::INotify::read_file('advanced_master_transport');

	die "Transport not found" if !defined($tmap->{$name});

	return undef; 

    }});
    
__PACKAGE__->register_method ({
    name => 'addoption',
    path => '{urlservice}/option',
    method => 'POST',
    description => "Add mtransport option",
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    urlservice => {
		description => "Transport service.",
		type => 'string',
	    },
	    option => {
		description => "Option",
		type => 'string',
	    },
	    value => {
		description => "Option's value",
		type => 'string',
		optional => 1
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	
	my $code = sub {
		
		my $service = $param->{urlservice};
	
		my $tmap = PVE::INotify::read_file('advanced_master_transport');
	
		my $data = $tmap->{$service};

	    die "Transport map entry '$param->{name}' does not exist\n" if !$data;
	    
	    die "no options specified\n" if !scalar(keys %$param);
	    
		push @{$tmap->{$service}->{options}}, { option => $param->{option}, value => $param->{value} || "" };

	    PVE::INotify::write_file('advanced_master_transport', $tmap);

	};

	PMG::Config::lock_config($code, "Update master transport failed");

	return undef;

    }});



__PACKAGE__->register_method ({
    name => 'get',
    path => '{urlservice}/object',
    method => 'GET',
    description => "Read mtransport entry.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    urlservice => {
		description => "Transport service.",
		type => 'string',
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    'service' => { type => 'string' },
	    'type' => { type => 'string'},
	    'private' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'unpriv' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'chroot' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'wakeup' => { type => 'integer', minimum => 0, maximum => 65535 },
	    'maxproc' => { type => 'integer', minimum => 1, maximum => 65535 },
	    'command' => { type => 'string', maxLength => 1024 },
	},
    },
    code => sub {
	my ($param) = @_;
	my $name = $param->{urlservice};

	my $tmap = PVE::INotify::read_file('advanced_master_transport');

	my $res = {
	    'service' => $tmap->{$name}->{'service'},
	    'type' => $tmap->{$name}->{'type'},
	    'private' => $tmap->{$name}->{'private'},
	    'unpriv' => $tmap->{$name}->{'unpriv'},
	    'chroot' => $tmap->{$name}->{'chroot'},
	    'wakeup' => $tmap->{$name}->{'wakeup'} == "-" ? 0 : $tmap->{$name}->{'wakeup'},
	    'maxproc' => $tmap->{$name}->{'maxproc'} == "-" ? 100 : $tmap->{$name}->{'maxproc'},
	    'command' => $tmap->{$name}->{'command'},
	    };

	return $res; 

	raise_param_exc({ name => "Transport entry for '$name' does not exist" });
    }});
    
__PACKAGE__->register_method ({
    name => 'put',
    path => '{urlservice}/object',
    method => 'PUT',
    description => "Modify mtransport entry.",
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
		'urlservice' => { type => 'string' },
		'service' => { type => 'string' },
	    'type' => { type => 'string'},
	    'private' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'unpriv' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'chroot' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'wakeup' => { type => 'integer', minimum => 0, maximum => 65535 },
	    'maxproc' => { type => 'integer', minimum => 1, maximum => 65535 },
	    'command' => { type => 'string', maxLength => 1024 },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $tmap = PVE::INotify::read_file('advanced_master_transport');

	    my $service = extract_param($param, 'urlservice');

	    my $data = $tmap->{$service};

	    die "Transport map entry '$param->{name}' does not exist\n" if !$data;

	    die "no options specified\n" if !scalar(keys %$param);

	    for my $prop (qw(service type private unpriv chroot wakeup maxproc command)) {
			$data->{$prop} = $param->{$prop} if defined($param->{$prop});
	    }

	    PVE::INotify::write_file('advanced_master_transport', $tmap);

	};

	PMG::Config::lock_config($code, "Update master transport failed");

	return undef;

	raise_param_exc({ name => "Transport entry for '$param->{service}' does not exist" });
    }});

__PACKAGE__->register_method ({
    name => 'readoption',
    path => '{urlservice}/option/{option}',
    method => 'GET',
    description => "Read mtransport entry.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    urlservice => {
		description => "Transport service.",
		type => 'string',
	    },
	    option => {
		description => "Option.",
		type => 'string',
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    option => { type => 'string' },
	    value => { type => 'string'},
	},
    },
    code => sub {
	my ($param) = @_;
	my $name = $param->{urlservice};
	my $option = $param->{option};

	my $tmap = PVE::INotify::read_file('advanced_master_transport');

	foreach my $entry (@{$tmap->{$name}->{options}}){
		if ($entry->{option} eq $option){
			return $entry;
		}
	}

	raise_param_exc({ name => "Transport option '$name' does not exist" });
    }});


__PACKAGE__->register_method ({
    name => 'updateoption',
    path => '{urlservice}/option/{option}',
    method => 'PUT',
    description => "Update mtransport option.",
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
		urlservice => {
		description => "Transport service",
		type => 'string',
	    },
	    option => {
		description => "Option",
		type => 'string',
	    },
	    value => {
		description => "Option's value",
		type => 'string',
		optional => 1
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	
	my $code = sub {
		
		my $service = $param->{urlservice};
		my $option = $param->{option};
		my $found = 0;
	
		my $tmap = PVE::INotify::read_file('advanced_master_transport');
	
		my $data = $tmap->{$service};

	    die "Transport map entry '$param->{name}' does not exist\n" if !$data;
	    
	    die "no options specified\n" if !scalar(keys %$param);
	    
		foreach my $entry (@{$tmap->{$service}->{options}}){
			if ($entry->{option} eq $option){
				$found = 1;
				$entry->{value} = $param->{value} || "";
				last;
			}
		}
	    
	    die "Option not found" if $found == 0;

	    PVE::INotify::write_file('advanced_master_transport', $tmap);

	};

	PMG::Config::lock_config($code, "Update master transport failed");

	return undef;
	
    }});

__PACKAGE__->register_method ({
    name => 'deleteoption',
    path => '{urlservice}/option/{option}',
    method => 'DELETE',
    description => "Delete mtransport option.",
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
		urlservice => {
		description => "Transport service",
		type => 'string',
	    },
	    option => {
		description => "Option",
		type => 'string',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	
	my $code = sub {
		
		my $service = $param->{urlservice};
		my $option = $param->{option};
		my $found = 0;
	
		my $tmap = PVE::INotify::read_file('advanced_master_transport');
	
		my $data = $tmap->{$service};

	    die "Transport map entry '$param->{name}' does not exist\n" if !$data;
	    
	    die "no options specified\n" if !scalar(keys %$param);
	    
	    my $tmp = [];
	    
		foreach my $entry (@{$tmap->{$service}->{options}}){
			if ($entry->{option} eq $option){
				$found = 1;
			} else {
				push @$tmp, $entry;
			}
		}
	    
	    die "Option not found" if $found == 0;
	    
	    $tmap->{$service}->{options} = $tmp;

	    PVE::INotify::write_file('advanced_master_transport', $tmap);

	};

	PMG::Config::lock_config($code, "Update master transport failed");

	return undef;
	
    }});


__PACKAGE__->register_method ({
    name => 'empty_object',
    path => '{urlservice}/create',
    method => 'GET',
    description => "Read mtransport entry.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    urlservice => {
		description => "Transport service.",
		type => 'string',
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    'service' => { type => 'string' },
	    'type' => { type => 'string'},
	    'private' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'unpriv' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'chroot' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'wakeup' => { type => 'integer', minimum => 0, maximum => 65535 },
	    'maxproc' => { type => 'integer', minimum => 1, maximum => 65535 },
	    'command' => { type => 'string', maxLength => 1024 },
	},
    },
    code => sub {
	my ($param) = @_;

	my $res = {
	    'service' => '',
	    'type' => '',
	    'private' => '-',
	    'unpriv' => '-',
	    'chroot' => '-',
	    'wakeup' => 0,
	    'maxproc' => 100,
	    'command' => '',
	    };

	return $res; 

    }});


__PACKAGE__->register_method ({
    name => 'create_service',
    path => '{urlservice}/create',
    method => 'POST',
    description => "Create mtransport entry.",
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
		'urlservice' => { type => 'string' },
		'service' => { type => 'string' },
	    'type' => { type => 'string'},
	    'private' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'unpriv' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'chroot' => { type => 'string', enum => ['-', 'n', 'y'] },
	    'wakeup' => { type => 'integer', minimum => 0, maximum => 65535 },
	    'maxproc' => { type => 'integer', minimum => 1, maximum => 65535 },
	    'command' => { type => 'string', maxLength => 1024 },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $tmap = PVE::INotify::read_file('advanced_master_transport');

	    my $service = extract_param($param, 'service');

		die "Service name already used" if defined($tmap->{$service});

		
	    my $data = { 
	    	service => $service,
	    	options => [] 
	    };

	    die "Transport map entry '$param->{name}' does not exist\n" if !$data;

	    die "no options specified\n" if !scalar(keys %$param);

	    for my $prop (qw(type private unpriv chroot wakeup maxproc command)) {
	    	die "Parameter $prop required" if !defined($param->{$prop});
			$data->{$prop} = $param->{$prop};
	    }
		
		$tmap->{$service} = $data;
		
	    PVE::INotify::write_file('advanced_master_transport', $tmap);

	};

	PMG::Config::lock_config($code, "Update master transport failed");

	return undef;

    }});
    
    


1;
