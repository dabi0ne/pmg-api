package PMG::RESTEnvironment;

use strict;
use warnings;

use PVE::INotify;
use PVE::RESTEnvironment;

use PMG::Cluster;
use PMG::ClusterConfig;

use base qw(PVE::RESTEnvironment);

my $nodename = PVE::INotify::nodename();

# initialize environment - must be called once at program startup
sub init {
    my ($class, $type, %params) = @_;

    $class = ref($class) || $class;

    my $self = $class->SUPER::init($type, %params);

    $self->{cinfo} = {};
 
    return $self;
};

# init_request - must be called before each RPC request
sub init_request {
    my ($self, %params) = @_;
    
    $self->SUPER::init_request(%params);
    
    $self->{cinfo} = PVE::INotify::read_file("cluster.conf");
}

sub check_node_is_master {
    my ($self, $noerr);

    my $master = PMG::Cluster::get_master_node($self->{cinfo});

    return 1 if $master eq 'localhost' || $master eq $nodename;

    return undef if $noerr;

    die "this node ('$nodename') is not the master node\n";
}

1;
