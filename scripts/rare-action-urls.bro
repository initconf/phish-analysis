module Phish; 

export {


	const SECS_ONE_DAY: interval  = 86400 secs; 
	#const SECS_ONE_DAY: interval  = 3600 secs; 
	#const SECS_ONE_DAY: interval  = 1 secs; 

	const HTTP_NUM_DAYS_TO_WATCH: count  = 10 ; 
	#const HTTP_NUM_DAYS_TO_WATCH: count  = 5 ; 

	global EXPIRE_INTERVAL: interval = 1 days &redef ; 

	global http_fqdn_tbuf: set[string] &create_expire=SECS_ONE_DAY; 

	#type fqdn_rec : record { 
	#	days_visited: vector of time  ; 
	#	num_requests: count &default=0 ; 
	#	last_visited: time ; 
	#	trustworthy: bool &default=T  ; 
	# } ; 

	#global http_fqdn: table[string] of fqdn_rec ; 

	global m_w_http_fqdn_stop: event (host: string); 
	global w_m_http_fqdn_new: event (host: string, ts: time); 

	#global uninteresting_fqdns : opaque of bloomfilter ;
	
}


event bro_init()
{

        EXPIRE_INTERVAL += double_to_interval(interval_to_double(SECS_ONE_DAY) * HTTP_NUM_DAYS_TO_WATCH) ;
	uninteresting_fqdns = bloomfilter_basic_init(0.0001, 400000); 
} 

### clusterization 

@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /Phish::m_w_http_fqdn_stop/;
redef Cluster::worker2manager_events += /Phish::w_m_http_fqdn_new/;
@endif


@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event Phish::m_w_http_fqdn_stop (host: string)
{
	log_reporter(fmt("EVENT: Phish::m_w_http_fqdn_stop: VARS: host: %s", host),10); 

	### we wamt to make sure that even if a worker sees a popular domain 
	### for the first time it ignores it 

	bloomfilter_add(uninteresting_fqdns, host);  

	## if domain in table, clear it out. 

	if (host in http_fqdn) 	
	{ 
		#log_reporter(fmt("m_w_http_fqdn_stop: %s, %s", host, http_fqdn[host]),0);
		delete http_fqdn[host] ; 
	} 
}
@endif


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || ! Cluster::is_enabled() )
event Phish::w_m_http_fqdn_new(host: string, ts: time) 
{
	local seen = bloomfilter_lookup(uninteresting_fqdns, host);
	
	if (seen > 0)	
		return ; 


	if (host !in http_fqdn)
        {
                local a: fqdn_rec;
                a$days_visited = vector();

                http_fqdn[host]= a ;
        }

        http_fqdn[host]$domain = host ;
        http_fqdn[host]$last_visited = ts ;

        local n = |http_fqdn[host]$days_visited|;

        ####     watch for 10 days
        if (n < HTTP_NUM_DAYS_TO_WATCH)
        {
                if ( n == 0 )
                {
                        http_fqdn[host]$days_visited[|http_fqdn[host]$days_visited|] = ts ;
                        log_reporter(fmt("N== 0 inside network_time() - http_fqdn[host]$days_visited[n-1] > SECS_ONE_DAY: : http_fqdn: %s,%s", host, http_fqdn[host]),20);

			@ifdef ( Log::WRITER_POSTGRESQL )
				event Phish::sql_write_http_reputation_db(http_fqdn[host]);
			@endif 

                }
                else if (network_time() - http_fqdn[host]$days_visited[n-1] > SECS_ONE_DAY  )
                {
                        http_fqdn[host]$days_visited[|http_fqdn[host]$days_visited|] = ts ;
                        log_reporter(fmt("N > 0: inside network_time() - http_fqdn[host]$days_visited[n-1] > SECS_ONE_DAY: : http_fqdn: %s,%s", host, http_fqdn[host]),20);
	
			@ifdef ( Log::WRITER_POSTGRESQL )
				event Phish::sql_write_http_reputation_db(http_fqdn[host]);
			@endif 
                }
		
        }
	else 
	{
       		http_fqdn[host]$trustworthy = T ; 
        	log_reporter(fmt("TrustworthyDomain: m_w_http_fqdn_stop and deleting: %s, %s", host, http_fqdn[host]),0);
		
		## prevent table from growing or keeping uninteresting fqdns 
		bloomfilter_add(uninteresting_fqdns, host);  

		@ifdef ( Log::WRITER_POSTGRESQL )
			event Phish::sql_write_http_reputation_db(http_fqdn[host]);
		@endif 

		delete http_fqdn[host] ; 
		event Phish::m_w_http_fqdn_stop(host);
	} 
}
@endif


function get_fqdn(s: string): string
{

	log_reporter(fmt("EVENT: function get_fqdn: s: %s", s),10);

	local domains = sub(s, /^([a-zA-Z\-]{3,5})(:\/\/)/, "");

	local parts = split_string(domains,/\/|\\/); 

	return parts[0] ; 

} 

#### too late to use log_http event 


event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-1
{
	if (!is_orig)	
		return ; 

	log_reporter(fmt("EVENT: http_message_done: VARS: c: %s", c$http),10); 

	local rec = c$http ; 

	local host: string = ""  ; 
	local ts = rec$ts ;
	local n = 0 ; 

	host = rec?$host ? rec$host : cat(rec$id$resp_h) ; 
	local seen = bloomfilter_lookup(uninteresting_fqdns, host);

        if (seen > 0 &&  host in http_fqdn)
	{ 
		delete http_fqdn[host] ; 
		return ;
	} 
	else if (seen > 0 ) 
		return ; 

	if (host !in http_fqdn_tbuf) 
	{ 
		add http_fqdn_tbuf[host];
		event Phish::w_m_http_fqdn_new(host, rec$ts);
	} 
} 

event http_stats (c: connection, stats: http_stats_rec)
{
	if (! c?$http)
	{ 
		return ;
	} 

	local host = c$http?$host ? c$http$host : "" ; 
	if (host in http_fqdn)
		http_fqdn[host]$num_requests += stats$num_requests ;
} 
