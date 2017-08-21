package PMG::CLI::pmgreport;

use strict;
use Data::Dumper;
use Template;
use POSIX qw(strftime);

use PVE::INotify;
use PVE::CLIHandler;

use PMG::Utils;
use PMG::Config;
use PMG::RESTEnvironment;
use PMG::API2::Nodes;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

my $get_system_table_data = sub {

    my $ni = PMG::API2::NodeInfo->status({ node => $nodename });

    my $data = [];

    push @$data, { text => 'Hostname', value => $nodename };

    my $uptime = $ni->{uptime} ? PMG::Utils::format_uptime($ni->{uptime}) : '-';

    push @$data, { text => 'Uptime', value => $uptime };

    push @$data, { text => 'Version', value => $ni->{pmgversion} };

    my $loadavg15 = '-';
    if (my $d = $ni->{loadavg}) {
	$loadavg15 = $d->[2];
    }
    push @$data, { text => 'Load', value => $loadavg15 };

    my $mem = '-';
    if (my $d = $ni->{memory}) {
	$mem = sprintf("%.2f%%", $d->{used}*100/$d->{total});
    }
    push @$data, { text => 'Memory', value => $mem };

    my $disk = '-';
    if (my $d = $ni->{rootfs}) {
	$disk = sprintf("%.2f%%", $d->{used}*100/$d->{total});
    }
    push @$data, { text => 'Disk', value => $disk };

    return $data
};


__PACKAGE__->register_method ({
    name => 'pmgreport',
    path => 'pmgreport',
    method => 'POST',
    description => "Generate and send daily system report email.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $fqdn = PVE::Tools::get_fqdn($nodename);

	my $end = time(); # fixme

	my $vars = {
	    hostname => $nodename,
	    fqdn => $fqdn,
	    date => strftime("%F", localtime($end - 1)),
	};

	$vars->{system} = $get_system_table_data->();

	my $tt = PMG::Config::get_template_toolkit();

	my $cfg = PMG::Config->new();
	my $email = $cfg->get ('admin', 'email');

	if (!defined($email)) {
	    die "STOPHERE";
	}

	my $mailfrom = "Proxmox Mail Gateway <postmaster>";
	PMG::Utils::finalize_report($tt, 'pmgreport.tt', $vars, $mailfrom, $email, $param->{debug});

	return undef;
    }});

our $cmddef = [ __PACKAGE__, 'pmgreport', [], undef ];

1;
