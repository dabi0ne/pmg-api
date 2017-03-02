package PMG::RuleDB::Disclaimer;

use strict;
use warnings;
use DBI;
use Digest::SHA;
use HTML::Parser;
use HTML::Entities;
use MIME::Body;
use IO::File;
use Encode;

use PMG::Utils;
use PMG::ModGroup;
use PMG::RuleDB::Object;;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4009;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'Disclaimer';
}

sub oisedit {
    return 1;   
}

sub final {
    return 0;
}

sub priority {
    return 49;
}

my $std_discl = <<_EOD_;
This e-mail and any attached files are confidential and may be legally privileged. If you are not the addressee, any disclosure, reproduction, copying, distribution, or other dissemination or use of this communication is strictly prohibited. If you have received this transmission in error please notify the sender immediately and then delete this mail.<br>
E-mail transmission cannot be guaranteed to be secure or error free as information could be intercepted, corrupted, lost, destroyed, arrive late or incomplete, or contain viruses. The sender therefore does not accept liability for any errors or omissions in the contents of this message which arise as a result of e-mail transmission or changes to transmitted date not specifically approved by the sender.<br>
If this e-mail or attached files contain information which do not relate to our professional activity we do not accept liability for such information.
_EOD_

sub new {
    my ($type, $value, $ogroup) = @_;
    
    my $class = ref($type) || $type;

    $value //= $std_discl;
    
    my $self = $class->SUPER::new($class->otype(), $ogroup);
   
    $self->{value} = $value;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    defined($value) || die "undefined object attribute: ERROR";
  
    my $obj = $class->new($value, $ogroup);

    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $value, $ogroup);
    
    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined object attribute: ERROR";
    defined($self->{value}) || die "undefined object attribute: ERROR";

    if (defined ($self->{id})) {
	# update
	
	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?", 
	    undef, $self->{value}, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->ogroup, $self->otype, $self->{value});
    
	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq'); 
    }
	
    return $self->{id};
}

sub add_data { 
    my ($self, $entity, $data) = @_;

    $entity->bodyhandle || return undef;

    my $fh;

    # always use the decoded data
    if (my $path = $entity->{PMX_decoded_path}) {
	$fh = IO::File->new("<$path");
    } else {
	$fh = $entity->open("r"); 
    }

    return undef if !$fh;

    # in memory (we cant modify the file, because
    # a.) that would modify all entities (see ModGroup)
    # b.) bad performance 
    my $body = new MIME::Body::InCore || return undef;

    my $newfh = $body->open ("w") || return undef;

    while (defined($_ = $fh->getline())) {
	$newfh->print($_); # copy contents
    }

    $newfh->print("\n"); # add final \n

    $newfh->print($data);

    $newfh->close || return undef;

    $entity->bodyhandle($body);

    return 1;
}

sub sign {
    my ($self, $entity, $html, $text) = @_;

    my $found = 0;

    if ($entity->head->mime_type =~ m{multipart/alternative}) {
	foreach my $p ($entity->parts) {
	    $found = 1 if $self->sign ($p, $html, $text);
	}
    } elsif ($entity->head->mime_type =~ m{multipart/}) {
	foreach my $p ($entity->parts) {
	    if ($self->sign ($p, $html, $text)) {
		$found = 1;
		last;
	    }
	}
    } elsif ($entity->head->mime_type =~ m{text/}) {		
	if ($entity->head->mime_type =~ m{text/html}) {
	    $self->add_data ($entity, $html);
	    $found = 1;
	} elsif ($entity->head->mime_type =~ m{text/plain}) {
	    my $cs = $entity->head->mime_attr("content-type.charset");
	    eval {
		my $enc_text = encode($cs, $text, Encode::FB_CROAK);
		$self->add_data($entity, $enc_text);
	    }; 
	    # simply ignore if we can't represent the disclainer
	    # with that encoding
	    $found = 1;
	} else {
	    # do nothing - unknown format
	}
    }

    return $found;
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets, 
	$msginfo, $vars, $marks) = @_;

    my $subgroups = $mod_group->subgroups($targets);

    foreach my $ta (@$subgroups) {
	my ($tg, $entity) = (@$ta[0], @$ta[1]);

	my $html = "<br>--<br>" . PMG::Utils::subst_values ($self->{value}, $vars);

	my $text = "";
	my $parser = HTML::Parser->new(
	    api_version => 3, text_h => [ sub {$text .= shift;}, "dtext" ]);

	my $tmp = $html;
	$tmp =~ s/\r?\n//g;
	$tmp =~ s/<br>/\n/g;

	$parser->parse($tmp);
	$parser->eof;
	    
	$self->sign($entity, "$html\n", "$text\n");

	return;
    }
}

sub short_desc {
    my $self = shift;

    return "disclaimer";
}


1;

__END__

=head1 PMG::RuleDB::Disclaimer

Add disclaimer.
