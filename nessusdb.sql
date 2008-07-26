DROP DATABASE nessus;
CREATE DATABASE nessus;

DROP TABLE IF EXISTS nessus.results;
CREATE TABLE nessus.results (
  id int(11) NOT NULL auto_increment,
  network varchar(40) NOT NULL DEFAULT '',
  host varchar(40) NOT NULL DEFAULT '',
  service varchar(255) NOT NULL DEFAULT '',
  protocol varchar(5) NOT NULL DEFAULT '',
  pluginid smallint(5) DEFAULT NULL,
  summary text,
  description text,
  cve CHAR(20) DEFAULT 'XXX-0000-0000',				# CVE # from NVD
  riskval tinyint(1) DEFAULT '0',
  PRIMARY KEY  (`id`),
  KEY `host` (`host`),
  KEY `host_2` (`host`,`service`)
) ENGINE=MyISAM COMMENT='Scan Results';

DROP TABLE IF EXISTS nessus.timestamps;
CREATE TABLE nessus.timestamps (
  id int(11) NOT NULL auto_increment,				# Unique Identifier
  datetime DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00', 	# Date & time of scan event
  progress varchar(40) NOT NULL DEFAULT '',			# Scan status
  host varchar(40) NOT NULL DEFAULT '',			# Host IP address
  PRIMARY KEY  (`id`),
  KEY `host` (`host`)
) ENGINE=MyISAM COMMENT='All timestamp info related to scan status';
