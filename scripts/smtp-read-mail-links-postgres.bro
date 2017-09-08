module Phish; 

export { 

	type Idx: record {
		url_md5: string;
	};

	type Val: record {
		link: string;
		ts: time ;
		uid: string &default="" ;
		mfrom: string &default="" ;
		mto: string &default="" ;
		subject: string &default="" ;
		url_md5: string &default="" ;
	} ;

	global tmp_mail_links_expire: function(t: table[string] of Val, hash: string): interval ;
	global tmp_mail_links: table[string] of Val &create_expire=10 secs &expire_func=tmp_mail_links_expire ;
	global tmp_link_set: set[string] &create_expire=3 secs ; 
	global Phish::sql_read_mail_links_db: event(link: string); 

}
	
function Phish::tmp_mail_links_expire(t: table[string] of Val, hash: string): interval
	{

	log_reporter(fmt("EVENT: Phish::tmp_mail_links_expire: VARS: hash: %s, t: %s", hash, t[hash]),10); 

	local m: mi = [$ts=t[hash]$ts, $uid=t[hash]$uid, $from=t[hash]$mfrom, $to=t[hash]$mto, $subject=t[hash]$subject] ; 
	local link=t[hash]$link ; 
	run_heuristics(link, m, tmp_link_cache[link]);

	#log_reporter(fmt("CALLLING EXPIRE FUNC calling tmp_mail_links_expire: link: %s, t[hash]: %s, m: %s, tmp_link_cache[link]:%s", hash, t[hash], m, tmp_link_cache[link]),0);

	return 0 secs ; 
	}

event Phish::sql_read_mail_links_db(link: string)
	{
	@ifdef ( Log::WRITER_POSTGRESQL )
		### log_reporter(fmt("EVENT: Phish::sql_read_mail_links_db: VARS: link: %s", link),10); 

		if (link !in tmp_link_set)
		{
			### log_reporter(fmt("SQL READ: sql_read_mail_links_db: %s", link),0); 
			add tmp_link_set[link];

			local query = fmt("select * from mail_links where url_md5 = '%s' order by ts desc limit 1 ;",md5_hash(link)) ; 
			log_reporter(fmt("ABABABABABBA: %s QQQQQQQQQQ: %s", link, query),0); 

			Input::add_table( [
				$source=query, 
				$name=md5_hash(link), 
				$idx=Idx, 
				$val=Val, 
				$destination=tmp_mail_links,
				$reader=Input::READER_POSTGRESQL,	
				$config=table(["conninfo"]="host=localhost dbname=bro_test user=bro password=")
			]);
				#$config=table(["dbname"]="adhoc.lbl.gov", ["hostname"]="localhost")
			Input::remove(md5_hash(link)); 
		}

	@endif 
	} 

event Input::end_of_data(name: string, source:string)
	{

		local query = fmt ("select * from mail_links where url_md5 = '%s' order by ts desc limit 1 ;",name); 

		### log_reporter(fmt ("AAAAA FINISHED READING from the DB now : end_of_data: name %s, source: %s", name, source ),0); 

		if ( name in source && query == source  )
		{ 
			Input::remove(name);
			log_reporter(fmt ("BBBBB FINISHED READING from the DB now : end_of_data: name %s, source: %s", name, source ),0); 

			if (name in tmp_mail_links) 
			{ 
				local m: mi = [ $ts=tmp_mail_links[name]$ts, $uid=tmp_mail_links[name]$uid, 
						$from=tmp_mail_links[name]$mfrom, $to=tmp_mail_links[name]$mto, 
						$subject=tmp_mail_links[name]$subject] ; 

				local link = tmp_mail_links[name]$link ; 	
				#run_heuristics(link, m, tmp_link_cache[link]);
				#print fmt ("Populated : tmp_mail_links: %s", tmp_mail_links[name]); 
			} 
			else 
				log_reporter(fmt("Missing Record: no DB entry for : %s", name ),0); 

		} 
	}
