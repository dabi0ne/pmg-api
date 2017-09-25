package PMG::API2::Subscription;

use strict;
use warnings;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Exception qw(raise_param_exc);
use PVE::RESTHandler;
use PMG::RESTEnvironment;
use PVE::JSONSchema qw(get_standard_option);

use PMG::Utils;

use base qw(PVE::RESTHandler);

PVE::INotify::register_file('subscription', "/etc/pmg/subscription",
			    \&read_etc_pmg_subscription,
			    \&write_etc_pmg_subscription);

sub read_etc_pmg_subscription {
    my ($filename, $fh) = @_;

    my $info = { status => 'Invalid' };

    return $info;
}

sub write_etc_pmg_subscription {
    my ($filename, $fh, $info) = @_;

    die "implement me";

}

__PACKAGE__->register_method ({
    name => 'get',
    path => '',
    method => 'GET',
    description => "Read subscription info.",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'object'},
    code => sub {
	my ($param) = @_;

	my $server_id = PMG::Utils::get_hwaddress();
	my $url = "https://www.proxmox.com/en/proxmox-mail-gateway/pricing";
	my $info = PVE::INotify::read_file('subscription');
	if (!$info) {
	    return {
		status => "NotFound",
		message => "There is no subscription key",
		serverid => $server_id,
		url => $url,
	    }
	}

	$info->{serverid} = $server_id;
	$info->{sockets} = get_sockets();
	$info->{url} = $url;

	return $info
    }});

1;
