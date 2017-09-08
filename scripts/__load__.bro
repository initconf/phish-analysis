module Phish ; 

#redef exit_only_after_terminate = T; 
redef table_expire_interval = 1 secs ;
redef table_incremental_step=20000 ; 



@load ./base-vars.bro 

@load ./email-alerts-batch.bro

@load ./smtp-write-http_fqdn-postgres.bro
@load ./smtp-read-http_fqdn-postgres.bro

@load ./smtp-write-mail-links-postgres.bro 
@load ./smtp-read-mail-links-postgres.bro


@load ./smtp-postgres-smtp_from.bro 
@load ./smtp-postgres-smtp_from_name.bro 
@load ./smtp-postgres-smtp_from_email.bro 

@load ./log-smtp-urls.bro 
@load ./log-clicked-urls.bro

@load ./smtp-sensitive-uris.bro                 
@load ./smtp-malicious-indicators.bro 

@load ./rare-action-urls.bro                    
@load ./rare-action-email.bro

@load ./distribute-smtp-urls-workers.bro
@load ./smtp-url-clicks.bro

@load ./main-logic.bro 

@load ./http-sensitive_POSTs.bro
@load ./smtp-file-download.bro

@load ./smtp-postgres-addressbook.bro
@load ./smtp-addressbook.bro 

#@load ./configure-variables-in-this-file-lbl.bro    
@load ./configure-variables-in-this-file.bro    
@load ./bro-done.bro 
@load ./smtp-analysis-notice-policy.bro

@load ./manager 
@load ./smtp-thresholds.bro 

#@load ./smtp-notice-policies.bro 

