module Phish;

export {

	global isRareURLClick : function(domain: string): bool ; 
	global isHistoricallyNewAttacker : function(domain: string, from_name: string, from_address: string): bool ; 
	global isSpoofworthyFromName : function(from_name: string ): bool ; 
	global isNameSpoofer : function(domain: string, from_name: string,  full_from: string): bool ; 
	global isSpoofworthyFromAddress : function(from_address: string): bool ;
	global isAddressSpoofer : function(domain: string, from_address: string, full_from: string ): bool ; 

} 

function isRareURLClick(domain: string): bool 
{
	log_reporter(fmt("EVENT: function isRareURLClick VARS: domain: %s", domain),10); 


       # the paper the definition we used:
        # If a domain has been seen fewer than 3 times in previous
        # HTTP clicks, it is rare.
        # If a domain has been seen at least 3 times in prior HTTP
        # traffic, and the time of the 3rd visit was more than 3 days
        # ago, it is rare.
        # Otherwise, it is not-rare.
        #if (domain in http_fqdn && ( (|http_fqdn[domain]$days_visited| >= 3 && (network_time() - http_fqdn[domain]$days_visited[3] > 3 days)) || (http_fqdn[domain]$num_requests < 3)))

        if (domain in http_fqdn && (((network_time() - http_fqdn[domain]$days_visited[0] ) < 3 days ) || (http_fqdn[domain]$num_requests < 3)))
	{ 
		return T; 
	} 

	return F; 
} 


function isHistoricallyNewAttacker(domain: string, from_name: string, from_address: string): bool 
{	

	log_reporter(fmt("EVENT: function isHistoricallyNewAttacker VARS: domain: %s, from_name: %s, from_address: %s", domain, from_name, from_address),10); 
# - *Historically New Attacker*
#	generate alert for historically new attacker
#      - if (RareURLClick && *from_name:days_sent <= 2* && *from_email_addr:days_sent  <= 2*)

	if (from_name !in smtp_from_name)
	{ 
		log_reporter(fmt("MYERROR 42  - from_name not in smtp_from_name: %s", from_name),0);
		#return F ; 
	} 
	if (isRareURLClick(domain) && |smtp_from_name[from_name]$days_sent| <= 2 && |smtp_from_email[from_address]$days_sent| <= 2) 
	{ 
		return T ; 
	} 

	return F ; 

}
########### from_name #################
# smtp_from_name 
#Frank Zuidema -> [days_sent=[1481050625.922146], email={\x0afzuidema@lbl.gov\x0a}, emails_sent=4, interesting=F]

function isSpoofworthyFromName(from_name: string ): bool 
{
	log_reporter(fmt("EVENT: function isSpoofworthyFromName VARS: from_name: %s", from_name),10); 

#	- SpoofworthyFromName is a boolean OR-clause where:
#         (from_name:days_sent >= 14 || from_name:num_clicks > 1 || from_name:emails_recv > 1)
	
	if (|smtp_from_name[from_name]$days_sent| >= 14 || smtp_from_name[from_name]$num_clicks > 1 || smtp_from_name[from_name]$emails_recv > 1) 
		return T ; 
	
	return F; 

} 

########### smtp_from #################
# smtp_from 
#Frank Zuidema <fzuidema@lbl.gov> -> [days_sent=[1481050625.922146], email={\x0afzuidema@lbl.gov\x0a}, emails_sent=4, interesting=F]

function isNameSpoofer(domain: string, from_name: string,  full_from: string): bool 
{
	log_reporter(fmt("EVENT: function isNameSpoofer VARS: domain: %s, from_name: %s, full_from: %s", domain, from_name, full_from),10); 

# *Name spoofer* 
#	- generate alert for rare name spoofer
#  - if (RareURLClick && *SpoofworthyFromName* && *full_from_field:days_sent <= 1*)

	if (isRareURLClick(domain) && isSpoofworthyFromName(from_name) && |smtp_from[full_from]$days_sent| <= 1)
		return T;

	return F ; 
} 

########### from_email #################
# smtp_from_email 
#fzuidema@lbl.gov -> [days_sent=[1481050625.922146], name={\x0aFrank Zuidema\x0a}, emails_sent=4, interesting=F]


function isSpoofworthyFromAddress(from_address: string): bool
{
	log_reporter(fmt("EVENT: function isSpoofworthyFromAddress VARS: from_address: %s", from_address),10); 

#         - To compute mail_from:days_sent, we can simply take the MAILFROM
#         header in the current alert's email and look up its value in the mail_from table
#         - (The paper's criteria is a bit more complicated, but we can ignore the extra stuff for now)


#         - SpoofworthyFromAddress is a boolean OR-clause where:
#         (from_address:days_sent >= 14 || from_address:num_clicks > 1 || from_address:emails_recv > 1)


	if (|smtp_from_email[from_address]$days_sent| >= 14 || smtp_from_email[from_address]$num_clicks > 1 || smtp_from_email[from_address]$emails_recv > 1)
		return T ;

	return F ; 

} 

########### smtp_from #################
# smtp_from 
#Frank Zuidema <fzuidema@lbl.gov> -> [days_sent=[1481050625.922146], email={\x0afzuidema@lbl.gov\x0a}, emails_sent=4, interesting=F]

function isAddressSpoofer(domain: string, from_address: string, full_from: string ): bool 
{ 
	
	log_reporter(fmt("EVENT: function isAddressSpoofer VARS: domain: %s, from_address: %s, full_from: %s", domain, from_address, full_from),10); 
# *Address spoofer*
# 	generate alert for rare address spoofer
#   	- if (RareURLClick && *SpoofworthyFromAddress* && *mail_from:days_sent <= 1*)

	if (isRareURLClick(domain) && isSpoofworthyFromAddress(from_address) && |smtp_from[full_from]$days_sent| <= 1)
		return T ; 

	return F; 
}


##############################


### this also only runs on manager
@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
function Phish::run_heuristics(link: string, mail_info: mi, c: connection)
{

	log_reporter(fmt("EVENT: function Phish::run_heuristics: VARS: link: %s, mail_info: %s", link, mail_info),10); 

       	log_reporter(fmt("clicked_URL : conn: %s, link: %s, mail_info: %s, smtp_from: %s", c$id, link, mail_info, smtp_from[mail_info$from]),0);
        local _msg = "" ;
        local domain = extract_host(link);

        local from_name = get_email_name(mail_info$from) ;
        local from_address = get_email_address(mail_info$from) ;
        local full_from=mail_info$from ;


	######### 
	#### at moment if its an expired URL there is 
	# a possibilitythat from_name, from_address and full_from
	# might not be in the tables because: expired or bro restart 
	# need to think about storing and reading those. 
	####### 

        ### to update the number of clicks seen by a perticular
        ### from_name and a from_address

	local sr: smtp_rec ;
       	sr$ts = mail_info$ts ;
	sr$from = mail_info$from ;

        if (from_name != "") 
		if (from_name !in smtp_from_name)
		{ 
			add_to_from_name(sr); 	
			smtp_from_name[from_name]$num_clicks+=1;
		} 

	if (from_address !in smtp_from_email)
	{
		add_to_from_email(sr); 
	}
	smtp_from_email[from_address]$num_clicks +=1 ;

	if (full_from !in smtp_from) 
	{
		add_to_from(sr); 
	}
	smtp_from[full_from]$num_clicks+= 1;

        if (isRareURLClick(domain) )
        {
                _msg = fmt("%s #### %s #### %s", link, mail_info, http_fqdn[domain]);
                log_reporter(fmt ("%s",_msg),0);
                local n: Notice::Info = [$note=Phish::RareURLClick, $msg=_msg, $conn=c];
                NOTICE(n) ; 
		batch_notice_2(n); 

                if (isHistoricallyNewAttacker(domain, from_name, from_address) )
                {
                        n = [$note=Phish::HistoricallyNewAttacker, $msg=_msg, $conn=c];
                	NOTICE(n) ; 
			batch_notice_2(n); 
                }

                if (isNameSpoofer(domain, from_name, full_from) )
                {
                        n  =[$note=Phish::NameSpoofer, $msg=_msg, $conn=c];
                	NOTICE(n) ; 
			batch_notice_2(n); 

                }

                if (isAddressSpoofer(domain, from_address, full_from) )
                {
                        n = [$note=Phish::AddressSpoofer, $msg=_msg, $conn=c];
                	NOTICE(n) ; 
			batch_notice_2(n); 
                }

        }
}
@endif
 
###############

##### relevant data structures  ########
# http_fqdn: 
#lbl.gov.invoicenotices.com  - [days_visited=[1481051156.986024, 1481062180.295358], num_requests=48, last_visited=1481062276.631609, interesting=T]
#google.com  - [days_visited=[1481062158.249375], num_requests=2, last_visited=1481062158.249375, interesting=T]
########### from_name #################
# smtp_from_name 
#Frank Zuidema -> [days_sent=[1481050625.922146], email={\x0afzuidema@lbl.gov\x0a}, emails_sent=4, interesting=F]
########### from_email #################
# smtp_from_email 
#fzuidema@lbl.gov -> [days_sent=[1481050625.922146], name={\x0aFrank Zuidema\x0a}, emails_sent=4, interesting=F]
########### smtp_from #################
# smtp_from 
#Frank Zuidema <fzuidema@lbl.gov> -> [days_sent=[1481050625.922146], email={\x0afzuidema@lbl.gov\x0a}, emails_sent=4, interesting=F]
########################################
