package PMG::RESTEnvironment;

use strict;
use warnings;

use PVE::RESTEnvironment;

use PMG::ClusterConfig;

use base qw(PVE::RESTEnvironment);

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

1;
