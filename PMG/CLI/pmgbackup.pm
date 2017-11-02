package PMG::CLI::pmgbackup;

use strict;
use warnings;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::CLIHandler;

use PMG::RESTEnvironment;
use PMG::API2::Backup;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

our $cmddef = {
    backup => [ 'PMG::API2::Backup', 'backup', undef, { node => $nodename } ],
    restore => [ 'PMG::API2::Backup', 'restore', undef, { node => $nodename } ],
    list => [ 'PMG::API2::Backup', 'list', undef, { node => $nodename } ],
};

1;
