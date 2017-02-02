package PMG::DBTools;

use strict;
use warnings;

use POSIX ":sys_wait_h";
use POSIX ':signal_h';
use DBI;

use PVE::Tools;

use PMG::RuleDB;

sub open_ruledb {
    my ($database, $host, $port) = @_;

    $port = 5432 if !$port;

    $database = "Proxmox_ruledb" if !$database;

    if ($host) {

	my $dsn = "dbi:Pg:dbname=$database;host=$host;port=$port;";

	my $timeout = 5;
	# only low level alarm interface works for DBI->connect
	my $mask = POSIX::SigSet->new(SIGALRM);
	my $action = POSIX::SigAction->new(sub { die "connect timeout\n" }, $mask);
	my $oldaction = POSIX::SigAction->new();
	sigaction(SIGALRM, $action, $oldaction);

	my $rdb;

	eval {
	    alarm($timeout);
	    $rdb = DBI->connect($dsn, "postgres", undef,
				{ PrintError => 0, RaiseError => 1 });
	    alarm(0);
	};
	alarm(0);
	sigaction(SIGALRM, $oldaction);  # restore original handler

	die $@ if $@;

	return $rdb;
    } else {
	my $dsn = "DBI:Pg:dbname=$database";

	my $dbh = DBI->connect($dsn, "postgres", undef,
			       { PrintError => 0, RaiseError => 1 });

	return $dbh;
    }
}

sub delete_ruledb {
    my ($dbname) = @_;

    PVE::Tools::run_command(['dropdb', '-U', 'postgres', $dbname]);
}

sub database_list {

    my $database_list = {};

    my $parser = sub {
	my $line = shift;

	my ($name, $owner) = map { PVE::Tools::trim($_) } split(/\|/, $line);
	return if !$name || !$owner;

	$database_list->{$name} = { owner => $owner };
    };

    my $cmd = ['psql', '-U', 'postgres', '--list', '--quiet', '--tuples-only'];

    PVE::Tools::run_command($cmd, outfunc => $parser);

    return $database_list;
}

my $dbfunction_maxint =  <<__EOD;
    CREATE OR REPLACE FUNCTION maxint (INTEGER, INTEGER) RETURNS INTEGER AS
    'BEGIN IF \$1 > \$2 THEN RETURN \$1; ELSE RETURN \$2; END IF; END;' LANGUAGE plpgsql;
__EOD

my $dbfunction_minint =  <<__EOD;
    CREATE OR REPLACE FUNCTION minint (INTEGER, INTEGER) RETURNS INTEGER AS
    'BEGIN IF \$1 < \$2 THEN RETURN \$1; ELSE RETURN \$2; END IF; END;' LANGUAGE plpgsql;
__EOD

# merge function to avoid update/insert race condition
# see: http://www.postgresql.org/docs/9.1/static/plpgsql-control-structures.html#PLPGSQL-ERROR-TRAPPING
my $dbfunction_merge_greylist = <<__EOD;
    CREATE OR REPLACE FUNCTION merge_greylist (in_ipnet VARCHAR, in_host INTEGER, in_sender VARCHAR,
					       in_receiver VARCHAR, in_instance VARCHAR,
					       in_rctime INTEGER, in_extime INTEGER, in_delay INTEGER,
					       in_blocked INTEGER, in_passed INTEGER, in_mtime INTEGER,
					       in_cid INTEGER) RETURNS INTEGER AS
    'BEGIN
      LOOP
        UPDATE CGreylist SET Host = CASE WHEN MTime >= in_mtime THEN Host ELSE in_host END,
                             CID = maxint (CID, in_cid), RCTime = minint (rctime, in_rctime),
			     ExTime = maxint (extime, in_extime),
			     Delay = maxint (delay, in_delay),
			     Blocked = maxint (blocked, in_blocked),
			     Passed = maxint (passed, in_passed)
			     WHERE IPNet = in_ipnet AND Sender = in_sender AND Receiver = in_receiver;

        IF found THEN
          RETURN 0;
        END IF;

	BEGIN
	  INSERT INTO CGREYLIST (IPNet, Host, Sender, Receiver, Instance, RCTime, ExTime, Delay, Blocked, Passed, MTime, CID)
             VALUES (in_ipnet, in_host, in_sender, in_receiver, in_instance, in_rctime, in_extime,
                     in_delay, in_blocked, in_passed, in_mtime, in_cid);
	  RETURN 1;
	  EXCEPTION WHEN unique_violation THEN
	    -- do nothing - continue loop
	END;
      END LOOP;
    END;'  LANGUAGE plpgsql;
__EOD

my $cgreylist_ctablecmd =  <<__EOD;
    CREATE TABLE CGreylist
    (IPNet VARCHAR(16) NOT NULL,
     Host INTEGER NOT NULL,
     Sender VARCHAR(255) NOT NULL,
     Receiver VARCHAR(255) NOT NULL,
     Instance VARCHAR(255),
     RCTime INTEGER NOT NULL,
     ExTime INTEGER NOT NULL,
     Delay INTEGER NOT NULL DEFAULT 0,
     Blocked INTEGER NOT NULL,
     Passed INTEGER NOT NULL,
     CID INTEGER NOT NULL,
     MTime INTEGER NOT NULL,
     PRIMARY KEY (IPNet, Sender, Receiver));

    CREATE INDEX CGreylist_Instance_Sender_Index ON CGreylist (Instance, Sender);

    CREATE INDEX CGreylist_ExTime_Index ON CGreylist (ExTime);

    CREATE INDEX CGreylist_MTime_Index ON CGreylist (MTime);
__EOD

my $clusterinfo_ctablecmd =  <<__EOD;
    CREATE TABLE ClusterInfo
    (CID INTEGER NOT NULL,
     Name VARCHAR NOT NULL,
     IValue INTEGER,
     SValue VARCHAR,
     PRIMARY KEY (CID, Name))
__EOD

my $daily_stat_ctablecmd =  <<__EOD;
    CREATE TABLE DailyStat
    (Time INTEGER NOT NULL UNIQUE,
     CountIn INTEGER NOT NULL,
     CountOut INTEGER NOT NULL,
     BytesIn REAL NOT NULL,
     BytesOut REAL NOT NULL,
     VirusIn INTEGER NOT NULL,
     VirusOut INTEGER NOT NULL,
     SpamIn INTEGER NOT NULL,
     SpamOut INTEGER NOT NULL,
     BouncesIn INTEGER NOT NULL,
     BouncesOut INTEGER NOT NULL,
     GreylistCount INTEGER NOT NULL,
     SPFCount INTEGER NOT NULL,
     PTimeSum REAL NOT NULL,
     MTime INTEGER NOT NULL,
     RBLCount INTEGER DEFAULT 0 NOT NULL,
     PRIMARY KEY (Time));

    CREATE INDEX DailyStat_MTime_Index ON DailyStat (MTime);

__EOD

my $domain_stat_ctablecmd =  <<__EOD;
    CREATE TABLE DomainStat
    (Time INTEGER NOT NULL,
     Domain VARCHAR(255) NOT NULL,
     CountIn INTEGER NOT NULL,
     CountOut INTEGER NOT NULL,
     BytesIn REAL NOT NULL,
     BytesOut REAL NOT NULL,
     VirusIn INTEGER NOT NULL,
     VirusOut INTEGER NOT NULL,
     SpamIn INTEGER NOT NULL,
     SpamOut INTEGER NOT NULL,
     BouncesIn INTEGER NOT NULL,
     BouncesOut INTEGER NOT NULL,
     PTimeSum REAL NOT NULL,
     MTime INTEGER NOT NULL,
     PRIMARY KEY (Time, Domain));

    CREATE INDEX DomainStat_MTime_Index ON DomainStat (MTime);
__EOD

my $statinfo_ctablecmd =  <<__EOD;
    CREATE TABLE StatInfo
    (Name VARCHAR(255) NOT NULL UNIQUE,
     IValue INTEGER,
     SValue VARCHAR(255),
     PRIMARY KEY (Name))
__EOD

my $virusinfo_stat_ctablecmd = <<__EOD;
    CREATE TABLE VirusInfo
    (Time INTEGER NOT NULL,
     Name VARCHAR NOT NULL,
     Count INTEGER NOT NULL,
     MTime INTEGER NOT NULL,
     PRIMARY KEY (Time, Name));

    CREATE INDEX VirusInfo_MTime_Index ON VirusInfo (MTime);

__EOD

# mail storage stable
# QTypes
# V - Virus quarantine
# S - Spam quarantine
# D - Delayed Mails - not implemented
# A - Held for Audit - not implemented
# Status
# N - new
# D - deleted

my $cmailstore_ctablecmd =  <<__EOD;
    CREATE TABLE CMailStore
    (CID INTEGER DEFAULT 0 NOT NULL,
     RID INTEGER NOT NULL,
     ID SERIAL UNIQUE,
     Time INTEGER NOT NULL,
     QType "char" NOT NULL,
     Bytes INTEGER NOT NULL,
     Spamlevel INTEGER NOT NULL,
     Info VARCHAR NULL,
     Sender VARCHAR(255) NOT NULL,
     Header VARCHAR NOT NULL,
     File VARCHAR(255) NOT NULL,
     PRIMARY KEY (CID, RID));
    CREATE INDEX CMailStore_Time_Index ON CMailStore (Time);

    CREATE TABLE CMSReceivers
    (CMailStore_CID INTEGER NOT NULL,
     CMailStore_RID INTEGER NOT NULL,
     PMail VARCHAR(255) NOT NULL,
     Receiver VARCHAR(255),
     TicketID INTEGER NOT NULL,
     Status "char" NOT NULL,
     MTime INTEGER NOT NULL);

    CREATE INDEX CMailStore_ID_Index ON CMSReceivers (CMailStore_CID, CMailStore_RID);

    CREATE INDEX CMSReceivers_MTime_Index ON CMSReceivers (MTime);

__EOD

my $cstatistic_ctablecmd =  <<__EOD;
    CREATE TABLE CStatistic
    (CID INTEGER DEFAULT 0 NOT NULL,
     RID INTEGER NOT NULL,
     ID SERIAL UNIQUE,
     Time INTEGER NOT NULL,
     Bytes INTEGER NOT NULL,
     Direction Boolean NOT NULL,
     Spamlevel INTEGER NOT NULL,
     VirusInfo VARCHAR(255) NULL,
     PTime INTEGER NOT NULL,
     Sender VARCHAR(255) NOT NULL,
     PRIMARY KEY (CID, RID));

    CREATE INDEX CStatistic_Time_Index ON CStatistic (Time);

    CREATE TABLE CReceivers
    (CStatistic_CID INTEGER NOT NULL,
     CStatistic_RID INTEGER NOT NULL,
     Receiver VARCHAR(255) NOT NULL,
     Blocked Boolean NOT NULL);

    CREATE INDEX CStatistic_ID_Index ON CReceivers (CStatistic_CID, CStatistic_RID);
__EOD

# user preferences (black an whitelists, ...)
# Name: perference name ('BL' -> blacklist, 'WL' -> whitelist)
# Data: arbitrary data
my $userprefs_ctablecmd =  <<__EOD;
    CREATE TABLE UserPrefs
    (PMail VARCHAR,
     Name VARCHAR(255),
     Data VARCHAR,
     MTime INTEGER NOT NULL,
     PRIMARY KEY (PMail, Name));

    CREATE INDEX UserPrefs_MTime_Index ON UserPrefs (MTime);

__EOD
    
sub cond_create_dbtable {
    my ($dbh, $name, $ctablecmd) = @_;

    eval {
	$dbh->begin_work;

	my $cmd = "SELECT tablename FROM pg_tables " .
	    "WHERE tablename = lower ('$name')";

	my $sth = $dbh->prepare ($cmd);
    
	$sth->execute();

	if (!(my $ref = $sth->fetchrow_hashref())) {
	    $dbh->do ($ctablecmd);
	}
	
	$sth->finish();

	$dbh->commit;
    };
    if (my $err = $@) {
	$dbh->rollback;
       	croak $err;
    }
}

sub create_ruledb {
    my ($dbname) = @_;

    $dbname = "Proxmox_ruledb" if !$dbname;

    # use sql_ascii to avoid any character set conversions, and be compatible with
    # older postgres versions (update from 8.1 must be possible)
    my $cmd = [ 'createdb', '-U', 'postgres', '-E', 'sql_ascii',
		'-T', 'template0', '--lc-collate=C', '--lc-ctype=C', $dbname ];

    PVE::Tools::run_command($cmd);

    my $dbh = open_ruledb($dbname);

    #$dbh->do ($dbloaddrivers_sql);
    #$dbh->do ($dbfunction_update_modtime);

    $dbh->do ($dbfunction_minint);

    $dbh->do ($dbfunction_maxint);

    $dbh->do ($dbfunction_merge_greylist);

    $dbh->do (
<<EOD
	      CREATE TABLE Attribut
	      (Object_ID INTEGER NOT NULL,
	       Name VARCHAR(20) NOT NULL,
	       Value BYTEA NULL,
	       PRIMARY KEY (Object_ID, Name));

	      CREATE INDEX Attribut_Object_ID_Index ON Attribut(Object_ID);

	      CREATE TABLE Object
	      (ID SERIAL UNIQUE,
	       ObjectType INTEGER NOT NULL,
	       Objectgroup_ID INTEGER NOT NULL,
	       Value BYTEA NULL,
	       PRIMARY KEY (ID));

	      CREATE TABLE Objectgroup
	      (ID SERIAL UNIQUE,
	       Name VARCHAR(255) NOT NULL,
	       Info VARCHAR(255) NULL,
	       Class  VARCHAR(10) NOT NULL,
	       PRIMARY KEY (ID));

	      CREATE TABLE Rule
	      (ID SERIAL UNIQUE,
	       Name VARCHAR(255) NULL,
	       Priority INTEGER NOT NULL,
	       Active INTEGER NOT NULL DEFAULT 0,
	       Direction INTEGER NOT NULL DEFAULT 2,
	       Count INTEGER NOT NULL DEFAULT 0,
	       PRIMARY KEY (ID));

	      CREATE TABLE RuleGroup
	      (Objectgroup_ID INTEGER NOT NULL,
	       Rule_ID INTEGER NOT NULL,
	       Grouptype INTEGER NOT NULL,
	       PRIMARY KEY (Objectgroup_ID, Rule_ID, Grouptype));

	      $cgreylist_ctablecmd;

	      $clusterinfo_ctablecmd;

	      $daily_stat_ctablecmd;

	      $domain_stat_ctablecmd;

	      $statinfo_ctablecmd;

	      $cmailstore_ctablecmd;

	      $cstatistic_ctablecmd;

	      $userprefs_ctablecmd;

	      $virusinfo_stat_ctablecmd;
EOD
	      );

    return $dbh;
}

sub cond_create_action_quarantine {
    my ($ruledb) = @_;

    my $dbh = $ruledb->{dbh};

    eval {
	my $sth = $dbh->prepare(
	    "SELECT * FROM Objectgroup, Object " .
	    "WHERE Object.ObjectType = ? AND Objectgroup.Class = ? " .
	    "AND Object.objectgroup_id = Objectgroup.id");

	my $otype = PMG::RuleDB::Quarantine::otype();
	if ($sth->execute($otype, 'action') <= 0) {
	    my $obj = PMG::RuleDB::Quarantine->new ();
	    my $txt = decode_entities(PMG::RuleDB::Quarantine->otype_text);
	    my $quarantine = $ruledb->create_group_with_obj
		($obj, $txt, PMG::RuleDB::Quarantine->oinfo);
	}
    };
}

sub cond_create_std_actions {
    my ($ruledb) = @_;

    cond_create_action_quarantine($ruledb);

    #cond_create_action_report_spam($ruledb);
}


sub upgradedb {
    my ($ruledb) = @_;

    my $dbh = $ruledb->{dbh};

    $dbh->do ($dbfunction_minint);

    $dbh->do ($dbfunction_maxint);

    $dbh->do ($dbfunction_merge_greylist);

    # make sure we do not use slow sequential scans when upgraing 
    # database (before analyze can gather statistics)
    $dbh->do("set enable_seqscan = false");

    cond_create_dbtable ($dbh, 'DailyStat', $daily_stat_ctablecmd);
    cond_create_dbtable ($dbh, 'DomainStat', $domain_stat_ctablecmd);
    cond_create_dbtable ($dbh, 'StatInfo', $statinfo_ctablecmd);
    cond_create_dbtable ($dbh, 'CMailStore', $cmailstore_ctablecmd);
    cond_create_dbtable ($dbh, 'UserPrefs', $userprefs_ctablecmd);
    cond_create_dbtable ($dbh, 'CGreylist', $cgreylist_ctablecmd);
    cond_create_dbtable ($dbh, 'CStatistic', $cstatistic_ctablecmd); 
    cond_create_dbtable ($dbh, 'ClusterInfo', $clusterinfo_ctablecmd);
    cond_create_dbtable ($dbh, 'VirusInfo', $virusinfo_stat_ctablecmd);

    cond_create_std_actions ($ruledb);

    upgrade_mailstore_db ($dbh);

    upgrade_statistic_db ($dbh);

    upgrade_userprefs_db ($dbh);

    upgrade_greylist_db ($dbh);

    upgrade_dailystat_db ($dbh);

    upgrade_domainstat_db ($dbh);

    # update obsolete content type names
    eval {
	$dbh->do ("UPDATE Object " .
		  "SET value = 'content-type:application/java-vm' ".
		  "WHERE objecttype = 3003 " . 
		  "AND value = 'content-type:application/x-java-vm';");
    };

    eval {
	$dbh->do ("ANALYZE");
    };
}

sub init_ruledb {
    my ($ruledb, $reset, $testmode) = @_;

    my $dbh = $ruledb->{dbh};

    if (!$reset) {
	# Greylist Objectgroup
	my $greylistgroup = PMG::RuleDB::Group->new
	    ("GreyExclusion", "-", "greylist");
	$ruledb->save_group ($greylistgroup);

    } else {
	# we do not touch greylist objects
	my $glids = "SELECT object.ID FROM Object, Objectgroup WHERE " .
	    "objectgroup_id = objectgroup.id and class = 'greylist'";

	$dbh->do ("DELETE FROM Rule; " .
		  "DELETE FROM RuleGroup; " .
		  "DELETE FROM Attribut WHERE Object_ID NOT IN ($glids); " .
		  "DELETE FROM Object WHERE ID NOT IN ($glids); " .
		  "DELETE FROM Objectgroup WHERE class != 'greylist';");
    }

    # WHO Objects

     # Blacklist
    my $obj =  PMG::RuleDB::EMail->new ('nomail@fromthisdomain.com');
    my $blacklist = $ruledb->create_group_with_obj(
	$obj, 'Blacklist', 'Global blacklist');
   
    # Whitelist
    $obj = PMG::RuleDB::EMail->new('mail@fromthisdomain.com');
    my $whitelist = $ruledb->create_group_with_obj(
	$obj, 'Whitelist', 'Global whitelist');

    # WHEN Objects

    # Working hours
    $obj = Proxmox::RuleDB::TimeFrame->new(8*60, 16*60);
    my $working_hours =$ruledb->create_group_with_obj($obj, 'Office Hours' ,
						      'Usual office hours');

    # WHAT Objects

    die "fixme";

    # Images
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('image/.*');
    my $img_content = $ruledb->create_group_with_obj ($obj, 'Images',
						      'All kinds of graphic files');
    # Multimedia
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('audio/.*');
    my $mm_content = $ruledb->create_group_with_obj ($obj, 'Multimedia',
						     'Audio and Video');

    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('video/.*');
    $ruledb->group_add_object ($mm_content, $obj);

    # Office Files
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('application/vnd\.ms-excel');
    my $office_content = $ruledb->create_group_with_obj ($obj, 'Office Files',
							 'Common Office Files');
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('application/vnd\.ms-powerpoint');
    $ruledb->group_add_object ($office_content, $obj);
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('application/msword');
    $ruledb->group_add_object ($office_content, $obj);
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('application/vnd\.openxmlformats-officedocument\..*');
    $ruledb->group_add_object ($office_content, $obj);
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('application/vnd\.oasis\.opendocument\..*');
    $ruledb->group_add_object ($office_content, $obj);
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('application/vnd\.stardivision\..*');
    $ruledb->group_add_object ($office_content, $obj);
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('application/vnd\.sun\.xml\..*');
    $ruledb->group_add_object ($office_content, $obj);
    

    # Dangerous Content
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('application/x-ms-dos-executable');
    my $exe_content = $ruledb->create_group_with_obj ($obj, 'Dangerous Content',
						      'executable files and partial messages');
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('application/x-java');
    $ruledb->group_add_object ($exe_content, $obj);
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('application/javascript');
    $ruledb->group_add_object ($exe_content, $obj);
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('application/x-executable');
    $ruledb->group_add_object ($exe_content, $obj);
    $obj = Proxmox::RuleDB::ContentTypeFilter->new ('message/partial');
    $ruledb->group_add_object ($exe_content, $obj);
    $obj = Proxmox::RuleDB::MatchFilename->new ('.*\.(vbs|pif|lnk|shs|shb)');
    $ruledb->group_add_object ($exe_content, $obj);
    $obj = Proxmox::RuleDB::MatchFilename->new ('.*\.{.+}');
    $ruledb->group_add_object ($exe_content, $obj);

    # Virus
    $obj = Proxmox::RuleDB::Virus->new ();
    my $virus = $ruledb->create_group_with_obj ($obj, 'Virus', 
						'Matches virus infected mail');
    # WHAT Objects

    # Spam
    $obj = Proxmox::RuleDB::Spam->new (3);
    my $spam3 = $ruledb->create_group_with_obj ($obj, 'Spam (Level 3)',
						'Matches possible spam mail');
    $obj = Proxmox::RuleDB::Spam->new (5);
    my $spam5 = $ruledb->create_group_with_obj ($obj, 'Spam (Level 5)',
						'Matches possible spam mail');
    $obj = Proxmox::RuleDB::Spam->new (10);
    my $spam10 = $ruledb->create_group_with_obj ($obj, 'Spam (Level 10)',
						 'Matches possible spam mail');
    

#    $obj = Proxmox::RuleDB::MatchField->new ('content-type', 'application/pdf');
#    $ct_filter = $ruledb->create_group_with_obj ($obj, 'Content Type Filter', 
#						 'Content Type Filter');


    # ACTIONS

    # Mark Spam 
    $obj = Proxmox::RuleDB::ModField->new ('X-SPAM-LEVEL', '__SPAM_INFO__');
    my $mod_spam_level = $ruledb->create_group_with_obj ($obj, 'Modify Spam Level', 
							 'Mark mail as spam by adding a header tag.');

    # Mark Spam
    $obj = Proxmox::RuleDB::ModField->new ('subject', 'SPAM: __SUBJECT__');
    my $mod_spam_subject = $ruledb->create_group_with_obj ($obj, 'Modify Spam Subject', 
							   'Mark mail as spam by modifying the subject.');
    # Remove matching attachments
    $obj = Proxmox::RuleDB::Remove->new (0);
    my $remove = $ruledb->create_group_with_obj ($obj, 'Remove attachments', 
						 'Remove matching attachments');
    # Remove all attachments
    $obj = Proxmox::RuleDB::Remove->new (1);
    my $remove_all = $ruledb->create_group_with_obj ($obj, 
						     'Remove all attachments', 
						     'Remove all attachments');

    # Accept
    $obj = Proxmox::RuleDB::Accept->new ();
    my $accept = $ruledb->create_group_with_obj ($obj, 'Accept', 'Accept mail for Delivery');

    # Block
    $obj = Proxmox::RuleDB::Block->new ();
    my $block = $ruledb->create_group_with_obj ($obj, 'Block', 'Block mail');

    # Quarantine
    $obj = Proxmox::RuleDB::Quarantine->new ();
    my $quarantine = $ruledb->create_group_with_obj ($obj, 'Quarantine', 'Move mail to quarantine');

    # Spam Counter
    #$obj = Proxmox::RuleDB::Counter->new (0);
    #my $count_spam = $ruledb->create_group_with_obj ($obj, 'Count Spam', 
	#					     'Count spam mails');
    # Virus Counter
    #$obj = Proxmox::RuleDB::Counter->new (0);
    #my $count_virus = $ruledb->create_group_with_obj ($obj, 'Count Viruses', 
	#					      'Count virus mails');
    # BCC dietmar
    #$obj = Proxmox::RuleDB::BCC->new ('dietmar@maurer-it.com');
    #$bcc = $ruledb->create_group_with_obj ($obj, 'BCC dietmar', 'send bcc');

    # Store in quarantine
    #$obj = Proxmox::RuleDB::Store->new ('quarantine', 'O');
    #$storeq = $ruledb->create_group_with_obj ($obj, 'Quarantine', ' Store in quarantine');

    # Notify Admin
    $obj = Proxmox::RuleDB::Notify->new ('__ADMIN__');
    my $notify_admin = $ruledb->create_group_with_obj ($obj, 'Notify Admin', 
						       'Send notification');

    # Notify Sender
    $obj = Proxmox::RuleDB::Notify->new ('__SENDER__');
    my $notify_sender = $ruledb->create_group_with_obj ($obj, 'Notify Sender', 
						       'Send notification');

    # Add Disclaimer
    $obj = Proxmox::RuleDB::Disclaimer->new ();
    my $add_discl = $ruledb->create_group_with_obj ($obj, 'Disclaimer', 
						    'Add Disclaimer');

    # Attach original mail
    #$obj = Proxmox::RuleDB::Attach->new ();
    #my $attach_orig = $ruledb->create_group_with_obj ($obj, 'Attach Original Mail', 
    #					      'Attach Original Mail');

    ####################### RULES ##################################

    ## Block Dangerous  Files
    my $rule = Proxmox::RuleDB::Rule->new ('Block Dangerous Files', 93, 1, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $exe_content);
    $ruledb->rule_add_action ($rule, $remove);

    ## Block Viruses
    $rule = Proxmox::RuleDB::Rule->new ('Block Viruses', 96, 1, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $virus);
    $ruledb->rule_add_action ($rule, $notify_admin);
    
    if ($testmode) {
	$ruledb->rule_add_action ($rule, $block);
    } else {
	$ruledb->rule_add_action ($rule, $quarantine);
    }

    ## Virus Alert
    $rule = Proxmox::RuleDB::Rule->new ('Virus Alert', 96, 1, 1);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $virus);
    $ruledb->rule_add_action ($rule, $notify_sender);
    $ruledb->rule_add_action ($rule, $notify_admin);
    $ruledb->rule_add_action ($rule, $block);
    
    ## Blacklist
    $rule = Proxmox::RuleDB::Rule->new ('Blacklist', 98, 1, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_from_group ($rule, $blacklist);
    $ruledb->rule_add_action ($rule, $block);

    ## Modify header
    if (!$testmode) {
	$rule = Proxmox::RuleDB::Rule->new ('Modify Header', 90, 1, 0);
	$ruledb->save_rule ($rule);
	$ruledb->rule_add_action ($rule, $mod_spam_level);
    }

    ## Whitelist
    $rule = Proxmox::RuleDB::Rule->new ('Whitelist', 85, 1, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_from_group ($rule, $whitelist);
    $ruledb->rule_add_action ($rule, $accept);

    if ($testmode) {
	$rule = Proxmox::RuleDB::Rule->new ('Mark Spam', 80, 1, 0);
	$ruledb->save_rule ($rule);

	$ruledb->rule_add_what_group ($rule, $spam10);
	$ruledb->rule_add_action ($rule, $mod_spam_level);
	$ruledb->rule_add_action ($rule, $mod_spam_subject);
    } else {
	# Quarantine/Mark Spam (Level 3)
	$rule = Proxmox::RuleDB::Rule->new ('Quarantine/Mark Spam (Level 3)', 80, 1, 0);
	$ruledb->save_rule ($rule);

	$ruledb->rule_add_what_group ($rule, $spam3);
	$ruledb->rule_add_action ($rule, $mod_spam_subject);
	$ruledb->rule_add_action ($rule, $quarantine);
	#$ruledb->rule_add_action ($rule, $count_spam);
    }

    # Quarantine/Mark Spam (Level 5)
    $rule = Proxmox::RuleDB::Rule->new ('Quarantine/Mark Spam (Level 5)', 79, 0, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $spam5);
    $ruledb->rule_add_action ($rule, $mod_spam_subject);
    $ruledb->rule_add_action ($rule, $quarantine);

    ## Block Spam Level 10
    $rule = Proxmox::RuleDB::Rule->new ('Block Spam (Level 10)', 78, 0, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $spam10);
    $ruledb->rule_add_action ($rule, $block);

    ## Block Outgoing Spam
    $rule = Proxmox::RuleDB::Rule->new ('Block outgoing Spam', 70, 0, 1);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $spam3);
    $ruledb->rule_add_action ($rule, $notify_admin);
    $ruledb->rule_add_action ($rule, $notify_sender);
    $ruledb->rule_add_action ($rule, $block);

    ## Add disclaimer
    $rule = Proxmox::RuleDB::Rule->new ('Add Disclaimer', 60, 0, 1);
    $ruledb->save_rule ($rule);
    $ruledb->rule_add_action ($rule, $add_discl);

    # Block Multimedia Files
    $rule = Proxmox::RuleDB::Rule->new ('Block Multimedia Files', 87, 0, 2);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $mm_content);
    $ruledb->rule_add_action ($rule, $remove);

    #$ruledb->rule_add_from_group ($rule, $anybody);
    #$ruledb->rule_add_from_group ($rule, $trusted);
    #$ruledb->rule_add_to_group ($rule, $anybody);
    #$ruledb->rule_add_what_group ($rule, $ct_filter);
    #$ruledb->rule_add_action ($rule, $add_discl);
    #$ruledb->rule_add_action ($rule, $remove);
    #$ruledb->rule_add_action ($rule, $bcc);
    #$ruledb->rule_add_action ($rule, $storeq);
    #$ruledb->rule_add_action ($rule, $accept);

    cond_create_std_actions ($ruledb);
}

1;
