# expanded from sql_logger.bro  original author: Scott Campbell Oct 1, 2013
# aashish sharma, Feb, 14, 2014 
#
# The database needs to be created before hand with the record type being
#  identical as the Log record type.

@load base/protocols/smtp 

redef LogSQLite::unset_field = "(unset)";

module Phish;

export {
        redef enum Log::ID += { MAIL_LINKS };
	type mail_links_table: record {
		link: string; 
		ts: time; 
		uid: string; 
		mfrom: string; 
		mto: string;
		subject: string;
		url_md5: string ; 
	} &log ; 
	

	redef Input::accept_unsupported_types = T;

	global sql_write_mail_links_db: function(link: string, mi: Phish::mi):bool ;
	global mail_links_db: string = "" ; 


	}

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )

function sql_write_mail_links_db(link: string, mi: Phish::mi): bool 
{
	# since the database is living on the management node, we need to use a simple test 
	# to avoid untold pain and suffering...
	#

	Phish::log_reporter(fmt("EVENT: sql_write_mail_links_db: VARS: links: %s, mi:%s, write_lock: %s", link, mi, Phish::WRITE_LOCK),10); 

	local pat: pattern = /\x97/; 
	local subject=gsub(mi$subject,pat,""); 

	if (! is_ascii(mi$subject) || ! is_ascii(link) || ! is_ascii(mi$from) || ! is_ascii(mi$to)) 
	{ 
		Phish::log_reporter(fmt ("NON-UTF-8 : %s", mi),0);
		#return F ; 	
	} 

	if ( Cluster::local_node_type() == Cluster::MANAGER  || ! Cluster::is_enabled()) {
		#Phish::log_reporter(fmt ("WWWWWWWWWWWWWWWWWWWWWWWW SQL WRITING  sql_write_mail_links_db: %s, %s", link, mi),0) ;
		Log::write(Phish::MAIL_LINKS, [$link=escape_string(link), $ts=mi$ts, $uid=mi$uid, $mfrom=escape_string(mi$from), $mto=escape_string(mi$to), $subject=escape_string(mi$subject), $url_md5=md5_hash(escape_string(link))]);
		#Log::write(Phish::MAIL_LINKS, [ $link=link, $ts=mi$ts, $uid=mi$uid, $mfrom=mi$from, $mto=mi$to, $subject=mi$subject]);
		}

	return T ; 

}

event bro_init()
{
	# This will initialize a database at the $path location with table name $name. 
	# Will open to append in the event that data already exists there.


        Log::create_stream(Phish::MAIL_LINKS, [$columns=mail_links_table]);


	@ifdef ( Log::WRITER_POSTGRESQL )
	local filter: Log::Filter = [$name="postgres_b", $path="mail_links", $writer=Log::WRITER_POSTGRESQL, $config=table(["conninfo"]="host=localhost dbname=bro_test user=bro password=")];
        Log::add_filter(Phish::MAIL_LINKS, filter);

	local m: Phish::mi; 
		m$ts=network_time();
		m$uid=fmt("xxxxx"); 
		m$from=fmt("ash@lbl.gov");
		m$to=fmt("as@lbl.gov");
		m$subject=fmt("subject"); 

	if (Phish::sql_write_mail_links_db("www.google.com", m)) 
		print fmt ("Write success"); 
	@endif 
}

@endif 
