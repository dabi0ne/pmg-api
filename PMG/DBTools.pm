package PMG::DBTools;

use strict;
use warnings;

use POSIX ":sys_wait_h";
use POSIX ':signal_h';
use DBI;

use PVE::Tools;

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

1;
