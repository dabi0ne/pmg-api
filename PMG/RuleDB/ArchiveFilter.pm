package Proxmox::RuleDB::ArchiveFilter;

use strict;
use vars qw(@ISA);
use Carp;
use DBI;
use Proxmox::Utils;
use Proxmox::RuleDB;
use Proxmox::SafeSyslog;
use MIME::Words;

@ISA = qw(Proxmox::RuleDB::ContentTypeFilter);


sub otype {
    return 3005;
}

sub otype_text {
    return __('Archive Filter');
}

sub oicon {
    return 'contentfilter.gif';
}

my $pmtypes = {
    'proxmox/unreadable-archive' => undef,
};

sub new {
    my ($type, $fvalue, $ogroup) = @_;
    my $class = ref($type) || $type;

    my $self = $class->SUPER::new ($fvalue, $ogroup);
    
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    my $class = ref($type) || $type;

    my $obj = $class->SUPER::load_attr ($ruledb, $id, $ogroup, $value);

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
	} else {
	    # match inside archives 
	    if (my $cts = $entity->{PMX_content_types}) {
		foreach my $ct (keys %$cts) {
		    if ($ct =~ m|$self->{field_value}|) {
			push @$res, $id;
			last;
		    }
		}
	    } 
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

sub push_mthash {
    my ($mime, $mthash) = @_;

    my $lasttype='';

    foreach my $mt (sort (keys %$mthash)) {
	my ($type, $subtype) = split ('/', $mt);

	if ($type ne $lasttype && $type ne 'proxmox') {
	    push @$mime, ["$type/.*", "$type/.*"]; 
	    $lasttype = $type;
	}
    
	my $text =  $mthash->{$mt} ? "$mt ($mthash->{$mt})" : $mt;
	$text =~ s/\\\./\./g;
	$text =~ s/\\\+/\+/g;
    
	push @$mime, [$mt, $text];
    }
}

sub out_form {
    my ($self, $fdata, %args ) = @_;
    my $frm = Proxmox::Form->new ($fdata);

    my $mime = [];

    push_mthash ($mime, $self->{mtypes});
    push_mthash ($mime, $pmtypes);
    
    $frm->add_element("seldropdown", "dynamicdropdown", $fdata->{seltext}, "Choose ContentType", $mime);

    if ($frm->postback) {
	$fdata->{seltext} = $fdata->{seldropdown};
    }

    $frm->add_element("seltext", "text", $fdata->{seltext}, "ContentType");

    # use large dropdown (width >= 300) 
    $frm->set_style ("normal wide");

    return $frm->out_form ("object", %args);
}

sub form_load {
    my ($self, $fdata ) = @_;

    $fdata->{seltext} = $self->{field_value};
}

sub form_save {
    my ($self, $rueldb, $fdata) = @_;

    $self->{field_value} = $fdata->{seltext};
    $self->save($rueldb);
    return undef;
}

1;
__END__

=head1 Proxmox::RuleDB::ArchiveFilter

Content type filter for Archives
