package PMG::API2::Advanced;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::RESTHandler;


use PMG::Config;
use PMG::API2::AdvancedTransport;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PMG::API2::AdvancedTransport",
    path => 'transport',
});

1;
