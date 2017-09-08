@load base/protocols/smtp 

redef LogSQLite::unset_field = "(unset)";

module Phish;

export 
{
        redef enum Log::ID += { SMTP_FROM_NAME };
	redef Input::accept_unsupported_types = T;

	global sql_write_smtp_from_name_db: function(fr: from_name_rec):bool ;
	global smtp_from_name_db: string = "" ; 

}

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )

function sql_write_smtp_from_name_db(fr: from_name_rec): bool 
{
	 Phish::log_reporter(fmt("EVENT: sql_write_smtp_from_name_db: VARS: from_email_rec: %s", fr),10);

	if ( Cluster::local_node_type() == Cluster::MANAGER  || ! Cluster::is_enabled()) {
		Phish::log_reporter(fmt ("FROM_REC: SQL WRITING  sql_write_smtp_from_name_db: %s", fr),10) ;
		Log::write(Phish::SMTP_FROM_NAME, fr); 
		}
	return T ; 
}

event bro_init()
{
        Log::create_stream(Phish::SMTP_FROM_NAME, [$columns=from_name_rec]);
        #Log::remove_filter(Phish::SMTP_FROM_NAME, "default");

@ifdef ( Log::WRITER_POSTGRESQL )
	local filter: Log::Filter = [$name="postgres_from_name_rec", 
				     $path="smtp_from_name", 
				     $writer=Log::WRITER_POSTGRESQL, 
				     $config=table(["conninfo"]="host=localhost dbname=bro_test user=bro password=")];

	Log::add_filter(Phish::SMTP_FROM_NAME, filter);
@endif 

}


event bro_init()
{

@ifdef ( Log::WRITER_POSTGRESQL )
	   Input::add_table( [
			$source="select t1.* from smtp_from_name t1 JOIN (select from_name, MAX(emails_sent) as max_emails_sent from smtp_from_name where last_seen > (select extract(epoch from now()) - (86400*30)) group by from_name, last_seen) t2 ON t1.from_name = t2.from_name AND t1.emails_sent = max_emails_sent ;",
			$name="smtp_from_name_table",
			$idx=from_name_rec_idx,
			$val=from_name_rec, 
			$destination=smtp_from_name, 
			$reader=Input::READER_POSTGRESQL,
			$config=table(["conninfo"]="host=localhost dbname=bro_test user=bro password=")
		]);

@endif 

} 

@endif 


event read_smtp_from_name(description: Input::EventDescription, t: Input::Event, data: Val) {
        # do something here...
        # print "DDDDDDDDDDDDDDDDDDDDDDD data:", data;
}


event Phish::sql_read_smtp_from_name_db(from_name: string)
{

@ifdef ( Log::WRITER_POSTGRESQL )

	          Input::add_event( [
                        $source="select t1.* from smtp_from_name t1 JOIN (select from_name, MAX(emails_sent) as max_emails_sent from smtp_from_name  where from_name = '$from_name' group by from_name) t2 ON t1.from_name = t2.from_name AND t1.emails_sent = max_emails_sent ;",
                        $name="read_smtp_from_name",
			$fields=from_name_rec, 
			$ev=read_smtp_from_name, 
                        $reader=Input::READER_POSTGRESQL,
                        $config=table(["conninfo"]="host=localhost dbname=bro_test user=bro password=")
                ]);
	
@endif 
}

event Input::end_of_data(name: string, source:string) 
{
	if ( name == "smtp_from_name_table") 
	{ 
		Input::remove("smtp_from_name_table"); 
		FINISHED_READING_SMTP_FROM_NAME = T ; 
		log_reporter(fmt("FINISHED_READING_SMTP_FROM_NAME: %s", FINISHED_READING_SMTP_FROM_NAME),0);
		 event check_db_read_status();
	} 
}


