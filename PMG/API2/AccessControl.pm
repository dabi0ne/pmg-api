package PMG::API2::AccessControl;

use strict;
use warnings;

use PVE::Exception qw(raise raise_perm_exc);
use PVE::SafeSyslog;
use PVE::RESTEnvironment;
use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);

use PMG::AccessControl;

use Data::Dumper;

use base qw(PVE::RESTHandler);


__PACKAGE__->register_method ({
    name => 'index', 
    path => '', 
    method => 'GET',
    description => "Directory index.",
    permissions => { 
	user => 'all',
    },
    parameters => {
    	additionalProperties => 0,
	properties => {},
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
    
	my $res = [];

	push @$res, { subdir => 'ticket' };
	#push @$res, { subdir => 'password' };

	return $res;
    }});


my $create_ticket = sub {
    my ($rpcenv, $username, $pw_or_ticket, $otp) = @_;

    my $ticketuser;
    if (($ticketuser = PMG::Ticket::verify_ticket($pw_or_ticket, 1)) &&
	($ticketuser eq 'root@pam' || $ticketuser eq $username)) {
	# valid ticket. Note: root@pam can create tickets for other users
    } else {
	$username = PMG::AccessControl::authenticate_user($username, $pw_or_ticket, $otp);
    }

    my $ticket = PMG::Ticket::assemble_ticket($username);
    my $csrftoken = PMG::Ticket::assemble_csrf_prevention_token($username);

    return {
	ticket => $ticket,
	username => $username,
	CSRFPreventionToken => $csrftoken,
    };
};


__PACKAGE__->register_method ({
    name => 'get_ticket', 
    path => 'ticket', 
    method => 'GET',
    permissions => { user => 'world' },
    description => "Dummy. Useful for formaters which want to priovde a login page.",
    parameters => {
	additionalProperties => 0,
    },
    returns => { type => "null" },
    code => sub { return undef; }});
  
__PACKAGE__->register_method ({
    name => 'create_ticket', 
    path => 'ticket', 
    method => 'POST',
    permissions => { 
	description => "You need to pass valid credientials.",
	user => 'world' 
    },
    protected => 1, # else we can't access shadow files
    description => "Create or verify authentication ticket.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    username => {
		description => "User name",
		type => 'string',
		maxLength => 64,
	    },
	    realm =>  get_standard_option('realm', {
		description => "You can optionally pass the realm using this parameter. Normally the realm is simply added to the username <username>\@<relam>.",
		optional => 1,
	    }),
	    password => { 
		description => "The secret password. This can also be a valid ticket.",
		type => 'string',
	    },
	    otp => {
		description => "One-time password for Two-factor authentication.",
		type => 'string',
		optional => 1,
	    },
	}
    },
    returns => {
	type => "object",
	properties => {
	    username => { type => 'string' },
	    ticket => { type => 'string', optional => 1},
	    CSRFPreventionToken => { type => 'string', optional => 1 },
	}
    },
    code => sub {
	my ($param) = @_;

	my $username = $param->{username};
	$username .= "\@$param->{realm}" if $param->{realm};

	my $rpcenv = PVE::RESTEnvironment::get();

	my $usercfg = { users => { 'root@pam' => { enable => 1 } }};
	
	my $res;
	eval {
	    # test if user exists and is enabled
	    PMG::AccessControl::check_user_enabled($usercfg, $username);
	    $res = &$create_ticket($rpcenv, $username, $param->{password}, $param->{otp});
	};
	if (my $err = $@) {
	    my $clientip = $rpcenv->get_client_ip() || '';
	    syslog('err', "authentication failure; rhost=$clientip user=$username msg=$err");
	    # do not return any info to prevent user enumeration attacks
	    die PVE::Exception->new("authentication failure\n", code => 401);
	}

	syslog('info', "successful auth for user '$username'");

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'change_passsword', 
    path => 'password', 
    method => 'PUT',
    protected => 1, # else we can't access shadow files
    description => "Change user password.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	    password => { 
		description => "The new password.",
		type => 'string',
		minLength => 5, 
		maxLength => 64,
	    },
	}
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RESTEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my ($userid, $ruid, $realm) = PMG::AccessControl::verify_username($param->{userid});

	my $usercfg = {}; # fixme;
	
	PMG::AccessControl::check_user_exist($usercfg, $userid);

	if ($authuser eq 'root@pam') {
	    # OK - root can change anything
	} else {
	    if ($authuser eq $userid) {
		PMG::AccessControl::check_user_enabled($usercfg, $userid);
		# OK - each user can change its own password
	    } else {
		raise_perm_exc();
	    }
	}

	PMP::AccessControl::domain_set_password($realm, $ruid, $param->{password});

	syslog('info', "changed password for user '$userid'");

	return undef;
    }});

1;
