@load base/protocols/smtp 

redef LogSQLite::unset_field = "(unset)";

module Phish;

export 
{
        redef enum Log::ID += { SMTP_FROM_EMAIL };
	redef Input::accept_unsupported_types = T;

	global sql_write_smtp_from_email_db: function(fr: from_email_rec):bool ;
	global smtp_from_email_db: string = "" ; 

}

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )

function sql_write_smtp_from_email_db(fr: from_email_rec): bool 
{
	Phish::log_reporter(fmt("EVENT: sql_write_smtp_from_email_db: VARS: from_email_rec: %s", fr),10); 

	if ( Cluster::local_node_type() == Cluster::MANAGER  || ! Cluster::is_enabled()) {
		Phish::log_reporter(fmt ("FROM_REC: SQL WRITING  sql_write_smtp_from_email_db: %s", fr),10) ;
		Log::write(Phish::SMTP_FROM_EMAIL, fr); 
		}
	return T ; 
}

event bro_init()
{

        #Log::remove_filter(Phish::SMTP_FROM_EMAIL, "default");

        Log::create_stream(Phish::SMTP_FROM_EMAIL, [$columns=from_email_rec]);

@ifdef ( Log::WRITER_POSTGRESQL )
	local filter: Log::Filter = [$name="postgres_from_email_rec", $path="smtp_from_email", $writer=Log::WRITER_POSTGRESQL, $config=table(["conninfo"]="host=localhost dbname=bro_test user=bro password=")];
        Log::add_filter(Phish::SMTP_FROM_EMAIL, filter);

@endif 
}


event bro_init()
{

@ifdef ( Log::WRITER_POSTGRESQL )

	   Input::add_table( [
			$source="select t1.* from smtp_from_email t1 JOIN (select from_email, MAX(emails_sent) as max_emails_sent from smtp_from_email where last_seen > (select extract(epoch from now()) - (86400*30)) group by from_email, last_seen) t2 ON t1.from_email = t2.from_email AND t1.emails_sent = max_emails_sent",
			 $name="smtp_from_email_table",
			$idx=from_email_rec_idx,
			$val=from_email_rec, 
			$destination=smtp_from_email, 
			$reader=Input::READER_POSTGRESQL,
			$config=table(["conninfo"]="host=localhost dbname=bro_test user=bro password=")
		]);


@endif 



} 
@endif 





event Phish::sql_read_smtp_from_email_db(link: string)
{
}

event Input::end_of_data(name: string, source:string) 
{
	if ( name == "smtp_from_email_table") 
	{ 
		Input::remove("smtp_from_email_table"); 
		FINISHED_READING_SMTP_FROM_EMAIL = T ; 
		log_reporter(fmt("FINISHED_READING_SMTP_FROM_EMAIL: %s", FINISHED_READING_SMTP_FROM_EMAIL),0); 
		 event check_db_read_status();
	} 
}


