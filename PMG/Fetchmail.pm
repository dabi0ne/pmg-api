package PMG::Fetchmail;

use strict;
use warnings;

use PVE::Tools;
use PVE::INotify;

my $inotify_file_id = 'fetchmailrc';
my $config_filename = '/etc/pmg/fetchmailrc';

sub read_fetchmail_conf {
    my ($filename, $fh) = @_;

    my $cfg = {};

    if ($fh) {

	while (defined(my $line = <$fh>)) {


	}
    }

    return $cfg;
}

sub write_fetchmail_conf {
    my ($filename, $fh, $cfg) = @_;

    my $raw = '';

    my $gid = getgrnam('www-data');
    chown(0, $gid, $fh);
    chmod(0640, $fh);

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file(
    $inotify_file_id, $config_filename,
    \&read_fetchmail_conf,
    \&write_fetchmail_conf,
    undef,
    always_call_parser => 1);



1;
