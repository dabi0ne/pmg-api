package PMG::RESTEnvironment;

use strict;
use warnings;

use PVE::INotify;
use PVE::RESTEnvironment;

use PMG::Cluster;
use PMG::ClusterConfig;
use PMG::AccessControl;

use base qw(PVE::RESTEnvironment);

my $nodename = PVE::INotify::nodename();

# initialize environment - must be called once at program startup
sub init {
    my ($class, $type, %params) = @_;

    $class = ref($class) || $class;

    my $self = $class->SUPER::init($type, %params);

    $self->{cinfo} = {};
    $self->{usercfg} = {};
    $self->{ticket} = undef;
 
    return $self;
};

# init_request - must be called before each RPC request
sub init_request {
    my ($self, %params) = @_;
    
    $self->SUPER::init_request(%params);
    
    $self->{ticket} = undef;
    $self->{cinfo} = PVE::INotify::read_file("cluster.conf");
    $self->{usercfg} = PVE::INotify::read_file("pmg-user.conf");
}

sub set_ticket {
    my ($self, $ticket) = @_;

    $self->{ticket} = $ticket;
}

sub get_ticket {
    my ($self) = @_;

    return $self->{ticket};
}

sub check_node_is_master {
    my ($self, $noerr);

    my $master = PMG::Cluster::get_master_node($self->{cinfo});

    return 1 if $master eq 'localhost' || $master eq $nodename;

    return undef if $noerr;

    die "this node ('$nodename') is not the master node\n";
}

sub check_api2_permissions {
    my ($self, $perm, $username, $uri_param) = @_;

    return 1 if !$username && $perm->{user} && $perm->{user} eq 'world';

    raise_perm_exc("user == null") if !$username;

    return 1 if $username eq 'root@pam';

    raise_perm_exc('user != root@pam') if !$perm;

    return 1 if $perm->{user} && $perm->{user} eq 'all';

    my $role = PMG::AccessControl::check_user_enabled($self->{usercfg}, $username);

    if (my $allowed_roles = $perm->{check}) {
	return 1 if grep { $_ eq $role } @$allowed_roles;
    }

    raise_perm_exc();
}

1;
