module Phish; 

export {

@ifndef (SECS_ONE_DAY) 
	#const SECS_ONE_DAY=86400 secs;
	#const SECS_ONE_DAY=3600 secs;
	#const SECS_ONE_DAY=1 secs;
@endif 

	const NUM_DAYS_TO_WATCH = 10 ; 

	global add_to_from_email: function(sr: smtp_rec); 
	global add_to_from_name: function(sr: smtp_rec); 
	global add_to_from: function(sr: smtp_rec) ; 
	
	#global Phish::w_m_smtp_rec_new: event (sr: smtp_rec) ; 
	global Phish::w_m_smtp_rec_new: event (rec: SMTP::Info) ; 
	global Phish::m_w_smtpurls_stop : event (sr: SMTP::Info) ; 

	global update_recv_stats: function (rec: SMTP::Info); 


}

event bro_init()
{
	 uninteresting_smtp_from = bloomfilter_basic_init(0.0001, 400000);
	 uninteresting_smtp_from_name  = bloomfilter_basic_init(0.0001, 400000);
	 uninteresting_smtp_from_email  = bloomfilter_basic_init(0.0001, 400000);

} 

@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /Phish::m_w_smtp_rec_stop/;
redef Cluster::worker2manager_events += /Phish::w_m_smtp_rec_new/;
@endif


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || ! Cluster::is_enabled()) 
event Phish::m_w_smtp_rec_stop (sr: SMTP::Info) 
{
	log_reporter(fmt("EVENT: Phish::m_w_smtp_rec_stop VARS: sr: %s", sr),10);

	#log_reporter(fmt("m_w_smtpurls_stop: %s", rs),5);
	return ; 
}
@endif


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || ! Cluster::is_enabled()) 

#event Phish::w_m_smtp_rec_new(sr: smtp_rec) 
event Phish::w_m_smtp_rec_new(rec: SMTP::Info) 
{
	log_reporter(fmt("EVENT: Phish::w_m_smtp_rec_new: VARS: rec: %s", rec),10); 
	
	update_recv_stats(rec); 

	local sr: smtp_rec ;

        sr$ts = rec$ts ;
        sr$from = rec$from ;

	add_to_from(sr); 
	add_to_from_name(sr); 
	add_to_from_email(sr); 

}
@endif

function update_recv_stats(rec: SMTP::Info)
{

	log_reporter(fmt("EVENT: function update_recv_stats: VARS: rec: %s", rec),10); 

	# mailfrom        rcptto  date    from    to      cc      reply_to

	if (rec?$rcptto)
	{ 	
		for (to in rec$rcptto)
		{ 
			local to_email = get_email_address(to); 	
			#print fmt ("to_email: %s", to_email); 
         	
			if (to_email !in email_recv_to_address)
           		{
                                local a = [$address=to_email, $emails_recv=0 ] ;
                                email_recv_to_address[to_email]=a ;
                        }
			email_recv_to_address[to_email]$emails_recv += 1; 
		} 
	} 

	if (rec?$to)
	{ 
		for (to in rec$to)
		{ 
			local to_name: string = "" ; 
			to_email = "" ; 
			#print fmt("TOOOOOO: to: %s", to); 
			to_name = get_email_name(to); 
			to_email = get_email_address(to); 	

			#print fmt("to_name: %s, to_email: %s", to_name, to_email); 
	
			if (to_name != "")
			{  
				if (to_name !in email_recv_to_name)
				{ 
					#print fmt("NEW to_name: %s", to_name); 
					local b = [ $name=to_name, $emails_recv=0] ; 
					email_recv_to_name[to_name]=b ; 
				} 

				Phish::email_recv_to_name[to_name]$emails_recv += 1; 
			 } 

			if (to_email !in email_recv_to_address) 
			{ 
				#print fmt("NEW to_email: %s", to_email); 
				local c = [$address=to_email, $emails_recv=0] ; 
				email_recv_to_address[to_email]=c ; 
			} 

			Phish::email_recv_to_address[to_email]$emails_recv += 1; 


			#print fmt ("EMAILS RECV TO addrss: %s, %s", to_email, email_recv_to_address ); 
		} 
	} 

	if (rec?$cc)
	{ 
		for (cc in rec$cc)
		{ 
			#print fmt("TOOOOOO: cc: %s", cc); 
			to_name = get_email_name(cc); 
			to_email = get_email_address(cc); 	
			
			if (to_name != "")
                        {
                                if (to_name !in email_recv_to_name)
                                {
                                        local d = [$name=to_name, $emails_recv = 0 ] ; 
                                        email_recv_to_name[to_name]=d ;
                                }

                                email_recv_to_name[to_name]$emails_recv += 1;
                         }

                        if (to_email !in email_recv_to_address)
                        {
                                local e = [$address=to_email, $emails_recv = 0] ; 
                                email_recv_to_address[to_email]=e ;
                        }

                        email_recv_to_address[to_email]$emails_recv += 1;
	
		}
	} 
	
} 


function add_to_from(rec: smtp_rec)
{ 
	log_reporter(fmt("EVENT: function add_to_from : VARS: rec: %s", rec),10); 

	local from_name = rec?$from ? get_email_name(rec$from) : "" ;
	local from_email = rec?$from ? get_email_address(rec$from) : ""  ; 
	local from = rec?$from ? rec$from : "" ; 

	from_name = escape_string(from_name); 
	from = escape_string(from);

	if (from_name  == "" ) 
		from_name = from_email ; 


	local seen = bloomfilter_lookup(uninteresting_smtp_from, from);
	
	if(seen >0)
		return ;


	if (from !in smtp_from)
        {
                local c:from_rec;
                c$days_sent = vector();
		c$email = set() ; 

                smtp_from[from]=c;
        }

        smtp_from[from]$m_from = from ; 
        smtp_from[from]$emails_sent += 1 ;
        smtp_from[from]$last_seen = rec$ts ;
	
	if (from_email !in smtp_from[from]$email) 
		add smtp_from[from]$email [from_email];

        local n = |smtp_from[from]$days_sent| ;
	
        if (n < NUM_DAYS_TO_WATCH)
        {
                if (n == 0 )
		{
                	smtp_from[from]$days_sent[|smtp_from[from]$days_sent|] = rec$ts ;

			@ifdef ( Log::WRITER_POSTGRESQL )
				sql_write_smtp_from_db(smtp_from[from]); 
			@endif 
		}
                else if ( network_time() - smtp_from[from]$days_sent[n-1] > SECS_ONE_DAY)
		{
                        smtp_from[from]$days_sent[|smtp_from[from]$days_sent|] = rec$ts ;

			@ifdef ( Log::WRITER_POSTGRESQL )
				sql_write_smtp_from_db(smtp_from[from]); 
			@endif 
		} 
        }
	else 
	{ 
		smtp_from[from]$trustworthy =  T ; 
		log_reporter(fmt("TrustworthyFrom: %s, %s", from, smtp_from[from]),5);
		bloomfilter_add(uninteresting_smtp_from, from);

		@ifdef ( Log::WRITER_POSTGRESQL )
			sql_write_smtp_from_db(smtp_from[from]);
		@endif 

	} 

} 

function add_to_from_name(rec: smtp_rec)
{ 

	log_reporter(fmt("EVENT: function add_to_from_name: VARS: rec: %s", rec),10);

	local from_name = rec?$from ? get_email_name(rec$from) : "" ;
	local from_email = rec?$from ? get_email_address(rec$from) : ""  ; 
	local from = rec?$from ? rec$from : "" ; 

	from_name = escape_string(from_name);
	from = escape_string(from); 

	### if the sender has no name we use email as a name for this sender 
	if (from_name == "" ) 
		from_name = from_email ; 
	
	local seen = bloomfilter_lookup(uninteresting_smtp_from_name, from_name);

        if(seen >0)
                return ;

	#### how many email addresses a given from name has 
	### how many messages a given from_name has sent 
	### how often

	if (from_name !in smtp_from_name)
	{
		local b :from_name_rec; 
		b$days_sent = vector(); 
		b$email=set() &mergeable ; 

		smtp_from_name[from_name]=b; 

	} 

	smtp_from_name[from_name]$from_name = from_name ; 
	smtp_from_name[from_name]$emails_sent += 1 ; 
	smtp_from_name[from_name]$last_seen = rec$ts ;

	if (from_email !in smtp_from_name[from_name]$email) 
		add smtp_from_name[from_name]$email [from_email]; 
		
	local n = |smtp_from_name[from_name]$days_sent| ; 

	if (n < NUM_DAYS_TO_WATCH)
	{
		if (n == 0 )
		{
			smtp_from_name[from_name]$days_sent[|smtp_from_name[from_name]$days_sent|] = rec$ts ; 

			@ifdef ( Log::WRITER_POSTGRESQL )
				sql_write_smtp_from_name_db(smtp_from_name[from_name]); 
			@endif 
		} 
		else if ( network_time() - smtp_from_name[from_name]$days_sent[n-1] > SECS_ONE_DAY)
		{
			smtp_from_name[from_name]$days_sent[|smtp_from_name[from_name]$days_sent|] = rec$ts ;
			@ifdef ( Log::WRITER_POSTGRESQL )
				sql_write_smtp_from_name_db(smtp_from_name[from_name]); 
			@endif 
		} 
	} 
	else 
	{ 
		smtp_from_name[from_name]$trustworthy =  T ; 
		log_reporter(fmt("TrustworthyFromName: %s, %s", from_name, smtp_from_name[from_name]),5);

		@ifdef ( Log::WRITER_POSTGRESQL )
			sql_write_smtp_from_name_db(smtp_from_name[from_name]); 
		@endif 

		bloomfilter_add(uninteresting_smtp_from_name, from_name);
	} 
}


function add_to_from_email(rec: smtp_rec) 
{
	log_reporter(fmt("EVENT: function add_to_from_email : VARS: rec: %s", rec),10);

	local from_name = rec?$from ? get_email_name(rec$from) : "" ;
	local from_email = rec?$from ? get_email_address(rec$from) : ""  ; 
	local from = rec?$from ? rec$from : "" ; 

	from_name= escape_string(from_name);
	from = escape_string(from);

	if (from_name == "" ) 
		from_name = from_email ; 

	local seen = bloomfilter_lookup(uninteresting_smtp_from_email, from_email);

        if(seen >0)
                return ;
		
	#### how many from names a given email address has 
	### how many messages a given email address has sent 
	### how often 

	if (from_email !in smtp_from_email)
	{
		local a:from_email_rec; 
		a$days_sent = vector(); 
		a$name = set() &mergeable ;

		smtp_from_email[from_email]=a; 

	} 

	smtp_from_email[from_email]$from_email = from_email ; 
	smtp_from_email[from_email]$emails_sent += 1 ; 
	smtp_from_email[from_email]$last_seen = rec$ts ;

	if (from_name !in smtp_from_email[from_email]$name ) 
		add smtp_from_email[from_email]$name[from_name]; 

	if (from_email in email_recv_to_address) 
		smtp_from_email[from_email]$emails_recv = email_recv_to_address[from_email]$emails_recv ; 


	local n = |smtp_from_email[from_email]$days_sent| ; 

	if (n < NUM_DAYS_TO_WATCH)
	{
		if (n == 0 )
		{
			smtp_from_email[from_email]$days_sent[|smtp_from_email[from_email]$days_sent|] = rec$ts ; 

			@ifdef ( Log::WRITER_POSTGRESQL )
				sql_write_smtp_from_email_db(smtp_from_email[from_email]); 
			@endif 
		} 
		else if ( network_time() - smtp_from_email[from_email]$days_sent[n-1] > SECS_ONE_DAY)
		{
			smtp_from_email[from_email]$days_sent[|smtp_from_email[from_email]$days_sent|] = rec$ts ;

			@ifdef ( Log::WRITER_POSTGRESQL )
				sql_write_smtp_from_email_db(smtp_from_email[from_email]); 
			@endif 
		} 
	}
	else 
	{ 
		bloomfilter_add(uninteresting_smtp_from_email, from_email);
		smtp_from_email[from_email]$trustworthy =  T ; 
		log_reporter(fmt("TrustworthyFromEmail: %s, %s", from_email, smtp_from_email[from_email]),5);

		@ifdef ( Log::WRITER_POSTGRESQL )
			sql_write_smtp_from_email_db(smtp_from_email[from_email]); 
		@endif 

	} 
}

event SMTP::log_smtp(rec : SMTP::Info)
{

	log_reporter(fmt("EVENT: SMTP::log_smtp: VARS: rec: %s", rec),10); 

	#if (/250 ok/ !in rec$last_reply ) 
	#	return ; 

	if (! rec?$from)
		return ; 

	event Phish::w_m_smtp_rec_new(rec); 
	
} 

#### [ts=1478544472.00721, uid=CSThuVID7RQUhU4td, id=[orig_h=128.3.63.21, orig_p=59130/tcp, resp_h=184.169.177.108, resp_p=80/tcp], trans_depth=1, method=GET, host=http.00.s.sophosxl.net, uri=/V3/01/181.50.89.52.ip/, referrer=<uninitialized>, version=1.1, user_agent=SXL/3.1, request_body_len=0, response_body_len=2, status_code=200, status_msg=OK, info_code=<uninitialized>, info_msg=<uninitialized>, tags={\x0a\x0a}, username=<uninitialized>, password=<uninitialized>, capture_password=F, proxied=<uninitialized>, range_request=F, orig_fuids=<uninitialized>, orig_filenames=<uninitialized>, orig_mime_types=<uninitialized>, resp_fuids=[FSW18c3ENGSVm4YNgk], resp_filenames=<uninitialized>, resp_mime_types=<uninitialized>, current_entity=<uninitialized>, orig_mime_depth=1, resp_mime_depth=1]

# SMTP record: [ts=1447239496.283309, uid=CdxXhu1NmUoJ6x5Ete, id=[orig_h=209.85.220.42, orig_p=33920/tcp, resp_h=128.3.41.120, resp_p=25/tcp], trans_depth=1, helo=mail-pa0-f42.google.com, mailfrom=aashish043@gmail.com, rcptto={\x0aasharma@lbl.gov\x0a}, date=Wed, 11 Nov 2015 02:58:14 -0800, from=Aashish Sharma <aashish043@gmail.com>, to={\x0aContacts <asharma@lbl.gov>\x0a}, cc=<uninitialized>, reply_to=<uninitialized>, msg_id=<CFEB0CB3-38FB-425F-9FFF-5DE3FE5EBE65@gmail.com>, in_reply_to=<uninitialized>, subject=dude click on this link , x_originating_ip=<uninitialized>, first_received=from [192.168.0.20] (c-50-173-240-3.hsd1.ca.comcast.net. [50.173.240.3])        by smtp.gmail.com with ESMTPSA id j5sm8870813pbq.74.2015.11.11.02.58.15        for <asharma@lbl.gov>        (version=TLSv1/SSLv3 cipher=OTHER);        Wed, 11 Nov 2015 02:58:15 -0800 (PST), second_received=by padhx2 with SMTP id hx2so28530313pad.1        for <asharma@lbl.gov>; Wed, 11 Nov 2015 02:58:16 -0800 (PST), last_reply=250 ok:  Message 4466494 accepted, path=[128.3.41.120, 209.85.220.42, 50.173.240.3], user_agent=Apple Mail (2.3094), tls=F, process_received_from=T, has_client_activity=T, entity=<uninitialized>, fuids=[FZfq0c1FW3RslSbJGd, Fyhta5NxJtGwP31Jj]]
