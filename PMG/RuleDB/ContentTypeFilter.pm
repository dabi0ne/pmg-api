package PMG::RuleDB::ContentTypeFilter;

use strict;
use warnings;
use Carp;
use DBI;

use PVE::SafeSyslog;
use MIME::Words;

use PMG::RuleDB::MatchField;

use base qw(PMG::RuleDB::MatchField);

my $mtypes = {
    'message/delivery-status' => undef,
    'message/disposition-notification' => undef,
    'message/external-body' => undef,
    'message/news' => undef,
    'message/partial' => undef,
    'message/rfc822' => undef,
    'multipart/alternative' => undef,
    'multipart/digest' => undef,
    'multipart/encrypted' => undef,
    'multipart/mixed' => undef,
    'multipart/related' => undef,
    'multipart/report' => undef,
    'multipart/signed' => undef,
};

my $oldtypemap = {
    'application/x-msdos-program' => 'application/x-ms-dos-executable',
    'application/java-vm' => 'application/x-java',
    'application/x-javascript' => 'application/javascript',
};

sub load_mime_types {
    open(DAT, "/usr/share/mime/globs") || 
	croak ("Could not open file $!: ERROR");

    while (my $row = <DAT>) {
        next if $row =~ m/^\#/;
 
	if ($row =~ m/([A-Za-z0-9-_\.]*)\/([A-Za-z0-9-_\+\.]*):\*\.(\S{1,10})\s*$/) {
            
	    my $m = "$1/$2";
	    my $end = $3;

	    $m =~ s/\./\\\./g; # quote '.'
	    $m =~ s/\+/\\\+/g; # quote '+'

	    if (defined ($end)) {
		$mtypes->{"$m"} = $mtypes->{"$m"} ? $mtypes->{"$m"} . ",$end" : $end;
	    }
	}
    }
    close(DAT);
}

load_mime_types ();

sub otype {
    return 3003;
}

sub otype_text {
    return 'ContentType Filter';
}

sub oicon {
    #fixme:
    return 'contentfilter.gif';
}

sub new {
    my ($type, $fvalue, $ogroup) = @_;
    
    my $class = ref($type) || $type;

    # translate old values
    if ($fvalue && (my $nt = $oldtypemap->{$fvalue})) {
	$fvalue = $nt;
    } 

    my $self = $class->SUPER::new('content-type', $fvalue, $ogroup);
    
    $self->{mtypes} = $mtypes;
 
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    my $obj = $class->SUPER::load_attr($ruledb, $id, $ogroup, $value);

    # translate old values
    if ($obj->{field_value} && (my $nt = $oldtypemap->{$obj->{field_value}})) {
	$obj->{field_value} = $nt;
    }

    $obj->{mtypes} = $mtypes;

    return $obj;
}

sub parse_entity {
    my ($self, $entity) = @_;

    my $res;

    # match subtypes? We currently do exact matches only.

    if (my $id = $entity->head->mime_attr ('x-proxmox-tmp-aid')) {
	chomp $id;

	my $header_ct = $entity->head->mime_attr ('content-type');

	my $magic_ct = $entity->{PMX_magic_ct};

	my $glob_ct = $entity->{PMX_glob_ct};

	if ($header_ct && $header_ct =~ m|$self->{field_value}|) {
	    push @$res, $id;
	} elsif ($magic_ct && $magic_ct =~ m|$self->{field_value}|) {
	    push @$res, $id;
	} elsif ($glob_ct && $glob_ct =~ m|$self->{field_value}|) {
	    push @$res, $id;
	}
    }
    
    foreach my $part ($entity->parts)  {
	if (my $match = $self->parse_entity ($part)) {
	    push @$res, @$match;
	}
    }

    return $res;
}

sub what_match {
    my ($self, $queue, $entity, $msginfo) = @_;

    return $self->parse_entity ($entity);
}


1;

__END__

=head1 PMG::RuleDB::ContentTypeFilter

Content type filter.
