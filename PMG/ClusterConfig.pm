package PMG::ClusterConfig::Base;

use strict;
use warnings;
use Data::Dumper;

use PVE::Tools;
use PVE::JSONSchema qw(get_standard_option);
use PVE::SectionConfig;

use base qw(PVE::SectionConfig);

my $defaultData = {
    propertyList => {
	type => { description => "Cluster node type." },
	cid => {
	    description => "Cluster Node ID.",
	    type => 'integer',
	    minimum => 1,
	},
    },
};

sub private {
    return $defaultData;
}

sub parse_section_header {
    my ($class, $line) = @_;

    if ($line =~ m/^(node|master):\s*(\d+)\s*$/) {
	my ($type, $sectionId) = ($1, $2);
	my $errmsg = undef; # set if you want to skip whole section
	my $config = {}; # to return additional attributes
	return ($type, $sectionId, $errmsg, $config);
    }
    return undef;
}

package PMG::ClusterConfig::Node;

use strict;
use warnings;

use base qw(PMG::ClusterConfig::Base);

sub type {
    return 'node';
}
sub properties {
    return {
	ip => {
	    description => "IP address.",
	    type => 'string', format => 'ip',
	},
	name => {
	    description => "Node name.",
	    type => 'string', format =>'pve-node',
	},
	hostrsapubkey => {
	    description => "Public SSH RSA key for the host.",
	    type => 'string',
	    pattern => '^[A-Za-z0-9\.\/\+]{200,}$',
	},
	rootrsapubkey => {
	    description => "Public SSH RSA key for the root user.",
	    type => 'string',
	    pattern => '^[A-Za-z0-9\.\/\+]{200,}$',
	},
	fingerprint => {
	    description => "SSL certificate fingerprint.",
	    type => 'string',
	    pattern => '^(:?[A-Z0-9][A-Z0-9]:){31}[A-Z0-9][A-Z0-9]$',
	},
    };
}

sub options {
    return {
	ip => { fixed => 1 },
	name => { fixed => 1 },
	hostrsapubkey => {},
	rootrsapubkey => {},
	fingerprint => {},
    };
}

package PMG::ClusterConfig::Master;

use strict;
use warnings;

use base qw(PMG::ClusterConfig::Base);

sub type {
    return 'master';
}

sub properties {
    return {
	maxcid => {
	    description => "Maximum used cluster node ID (used internally, do not modify).",
	    type => 'integer',
	    minimum => 1,
	},
    };
}

sub options {
    return {
	maxcid => { fixed => 1 },
	ip => { fixed => 1 },
	name => { fixed => 1 },
	hostrsapubkey => {},
	rootrsapubkey => {},
	fingerprint => {},
    };
}

package PMG::ClusterConfig;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools;
use PVE::INotify;

use PMG::Utils;

PMG::ClusterConfig::Node->register;
PMG::ClusterConfig::Master->register;
PMG::ClusterConfig::Base->init();


sub new {
    my ($type) = @_;

    my $class = ref($type) || $type;

    my $cfg = PVE::INotify::read_file("cluster.conf");

    return bless $cfg, $class;
}

sub write {
    my ($self) = @_;

    PVE::INotify::write_file("cluster.conf", $self);
}

my $lockfile = "/var/lock/pmgcluster.lck";

sub lock_config {
    my ($code, $errmsg) = @_;

    my $res = PVE::Tools::lock_file($lockfile, undef, $code);
    if (my $err = $@) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
    return $res;
}

sub read_cluster_conf {
    my ($filename, $fh) = @_;

    local $/ = undef; # slurp mode

    my $raw = defined($fh) ? <$fh> : undef;

    my $cinfo = PMG::ClusterConfig::Base->parse_config($filename, $raw);

    my $localname = PVE::INotify::nodename();
    my $localip = PMG::Utils::lookup_node_ip($localname);

    $cinfo->{remnodes} = [];
    $cinfo->{configport}->{0} = 83;
    $cinfo->{dbport}->{0} = 5432;

    $cinfo->{local} = {
	cid => 0,
	ip => $localip,
	name => $localname,
    };

    my $maxcid = 0;
    my $names_hash = {};

    my $errprefix = "unable to parse $filename";

    foreach my $cid (keys %{$cinfo->{ids}}) {
	my $d = $cinfo->{ids}->{$cid};

	die "$errprefix: duplicate use of name '$d->{name}'\n" if $names_hash->{$d->{name}};
	$names_hash->{$d->{name}} = 1;

	$d->{cid} = $cid;
	$maxcid = $cid > $maxcid ? $cid : $maxcid;
	$maxcid = $d->{maxcid} if defined($d->{maxcid}) && $d->{maxcid} > $maxcid;
	$cinfo->{master} = $d if $d->{type} eq 'master';
	$cinfo->{'local'} = $d if $d->{name} eq $localname;
    }

    if ($maxcid) {
	die "$errprefix: cluster without master node\n"
	    if !defined($cinfo->{master});
	$cinfo->{master}->{maxcid} = $maxcid;
    }

    my $ind = 0;
    foreach my $cid (sort keys %{$cinfo->{ids}}) {
	if ($cinfo->{'local'}->{cid} == $cid) { # local CID
	    $cinfo->{configport}->{$cid} = 83;
	    $cinfo->{dbport}->{$cid} = 5432;
	} else {
	    my $portid = $ind++;
	    $cinfo->{configport}->{$cid} = 50000 + $portid;
	    $cinfo->{dbport}->{$cid} = 50100 + $portid;
	    push @{$cinfo->{remnodes}}, $cid;
	}
    }

    return $cinfo;
}

sub write_cluster_conf {
    my ($filename, $fh, $cfg) = @_;

    my $raw = PMG::ClusterConfig::Base->write_config($filename, $cfg);

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file('cluster.conf', "/etc/pmg/cluster.conf",
			    \&read_cluster_conf,
			    \&write_cluster_conf,
			    undef,
			    always_call_parser => 1);

1;
