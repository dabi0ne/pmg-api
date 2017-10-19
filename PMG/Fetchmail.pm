package PMG::Fetchmail;

use strict;
use warnings;
use Data::Dumper;

use PVE::Tools;
use PVE::INotify;

use PMG::Config;

my $inotify_file_id = 'fetchmailrc';
my $config_filename = '/etc/pmg/fetchmailrc';

my $set_fetchmail_defaults = sub {
    my ($item) = @_;

    $item->{protocol} //= 'pop3';
    $item->{interval} //= 1;
    $item->{enable} //= 0;

    if (!$item->{port}) {
	if ($item->{protocol} eq 'pop3') {
	    if ($item->{ssl}) {
		$item->{port} = 995;
	    } else {
		$item->{port} = 110;
	    }
	} elsif ($item->{protocol} eq 'imap') {
	    if ($item->{ssl}) {
		$item->{port} = 993;
	    } else {
		$item->{port} = 143;
	    }
	} else {
	    die "unknown fetchmail protocol '$item->{protocol}'\n";
	}
    }

    return $item;
};

sub read_fetchmail_conf {
    my ($filename, $fh) = @_;

    my $cfg = {};

    if ($fh) {

	# scan for proxmox marker - skip non proxmox lines
	while (defined(my $line = <$fh>)) {
	    last if $line =~ m/^\#\s+proxmox\s+settings.*$/;
	}
	# now parse the rest

	my $data = '';
	my $linenr = 0;

	my $get_next_token = sub {

	    do {
		while ($data =~ /\G("([^"]*)"|\S+|)(?:\s|$)/g) {
		    my ($token, $string) = ($1, $2);
		    if ($1 ne '') {
			$string =~ s/\\x([0-9A-Fa-f]{2})/chr(hex($1))/eg
			    if defined($string);
			return wantarray ? ($token, $string) : $token;
		    }
		}
		$data = <$fh>;
		$linenr = $fh->input_line_number();
	    } while (defined($data));

	    return undef; # EOF
	};

	my $get_token_argument = sub {
	    my ($token, $string) = $get_next_token->();
	    die "line $linenr: missing token arguemnt\n" if !$token;
	    return $string // $token;
	};

	my $finalize_item = sub {
	    my ($item) = @_;
	    $cfg->{$item->{id}} = $item;
	};

	my $item;
	while (my ($token, $string) = $get_next_token->()) {
	    last if !defined($token);
	    if ($token eq 'poll' || $token eq 'skip') {
		$finalize_item->($item) if defined($item);
		my $id = $get_token_argument->();
		$item = { id => $id };
		$item->{enable} = $token eq 'poll' ? 1 : 0;
		next;
	    }

	    die "line $linenr: unexpected token '$token'\n"
		if !defined($item);

	    if ($token eq 'user') {
		$item->{user} = $get_token_argument->();
	    } elsif ($token eq 'via') {
		$item->{server} = $get_token_argument->();
	    } elsif ($token eq 'pass') {
		$item->{pass} = $get_token_argument->();
	    } elsif ($token eq 'to') {
		$item->{target} = $get_token_argument->();
	    } elsif ($token eq 'protocol') {
		$item->{protocol} = $get_token_argument->();
	    } elsif ($token eq 'port') {
		$item->{port} = $get_token_argument->();
	    } elsif ($token eq 'interval') {
		$item->{interval} = $get_token_argument->();
	    } elsif ($token eq 'ssl' || $token eq 'keep' ||
		     $token eq 'dropdelivered') {
		$item->{$token} = 1;
	    } else {
		die "line $linenr: unexpected token '$token' inside entry '$item->{id}'\n";
	    }
	}
	$finalize_item->($item) if defined($item);
    }

    return $cfg;
}

sub write_fetchmail_conf {
    my ($filename, $fh, $fmcfg) = @_;

    my $data = {};

    # Note: we correctly quote data here to make fetchmailrc.tt simpler

    foreach my $id (keys %$fmcfg) {
	my $org = $fmcfg->{$id};
	my $item = { id => $id };
	foreach my $k (keys %$org) {
	    my $v = $org->{$k};
	    $v =~ s/([^A-Za-z0-9\:\@\-\._~])/sprintf "\\x%02x",ord($1)/eg;
	    $item->{$k} = $v;
	}
	$set_fetchmail_defaults->($item);
	my $options = [ 'dropdelivered' ];
	push @$options, 'ssl' if $item->{ssl};
	push @$options, 'keep' if $item->{keep};
	$item->{options} = join(' ', @$options);
	$data->{$id} = $item;
    }

    my $raw = '';

    my $pmgcfg = PMG::Config->new();
    my $vars = $pmgcfg->get_template_vars();
    $vars->{fetchmail_users} = $data;

    my $tt = PMG::Config::get_template_toolkit();
    $tt->process('fetchmailrc.tt', $vars, \$raw) ||
	die $tt->error() . "\n";

    my (undef, undef, $uid, $gid) = getpwnam('fetchmail');
    chown($uid, $gid, $fh) if defined($uid) && defined($gid);
    chmod(0600, $fh);

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file(
    $inotify_file_id, $config_filename,
    \&read_fetchmail_conf,
    \&write_fetchmail_conf,
    undef,
    always_call_parser => 1);

1;
