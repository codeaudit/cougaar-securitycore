drop  database if exists TestResults;
create database TestResults;
use TestResults;


create table results(
	ID int(11) NOT NULL auto_increment,
	endtime varchar(64) default NULL,
	success int(11),
	failure int(11),
	total int(11),
	plugin varchar(64) default NULL,
	agent varchar(64) default NULL,
	starttime varchar(64) default NULL,
	experimentName varchar(50) NOT NULL,
	PRIMARY KEY  (ID)
)TYPE=MyISAM;
