# expanded from sql_logger.bro  original author: Scott Campbell Oct 1, 2013
# aashish sharma, Feb, 14, 2014 
#
# The database needs to be created before hand with the record type being
#  identical as the Log record type.

@load base/protocols/smtp 

redef LogSQLite::unset_field = "(unset)";

module Phish;

export {
	global db_loaded = 1;
        redef enum Log::ID += { HTTP_REPUTE };

        type Log: record {
		ts: time ;    
		domain: string;
		} &log;

	redef Input::accept_unsupported_types = T;
	global sql_write_http_reputation_db : event(hf: fqdn_rec); 

	global http_reputation_db: string = "" ; 


	}

event sql_write_http_reputation_db(hf: fqdn_rec)
	{
	# since the database is living on the management node, we need to use a simple test 
	#  to avoid untold pain and suffering...
	#

	log_reporter(fmt("EVENT: sql_write_http_reputation_db: hf: %s", hf),20); 

	if ( Cluster::local_node_type() == Cluster::MANAGER  || ! Cluster::is_enabled()) {
		Log::write(Phish::HTTP_REPUTE, hf); 
		}
	}

event bro_init()
{
	# This will initialize a database at the $path location with table name $name. 
	# Will open to append in the event that data already exists there.
	# 
	#print fmt("Initializing sql logger ...");

        Log::remove_filter(Phish::HTTP_REPUTE, "default");
        Log::create_stream(Phish::HTTP_REPUTE, [$columns=fqdn_rec]);
	
	@ifdef ( Log::WRITER_POSTGRESQL )

	local filter: Log::Filter = [$name="postgres", $path="http_fqdn", $writer=Log::WRITER_POSTGRESQL, $config=table(["conninfo"]="host=localhost dbname=bro_test user=bro password=")]; 
        Log::add_filter(Phish::HTTP_REPUTE, filter);
	@endif 
	


}
