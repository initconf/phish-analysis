Phishing detection package for Bro: this package implements the technology defined in : https://people.eecs.berkeley.edu/~grantho/papers/usenix2017-spearphish.pdf 

The bro package works primarily using postgres as backend where it creates and maintains reputation data. Postgres is helpful in preserving states across BRO restarts.  For postgres backend support you'd need to install bro-postgresql package from: https://github.com/0xxon/bro-postgresql.git

However, you can run this without postgres support. In that case, there will be limitation on how many URLs you can store in memory and keep track of. Historically we can keep up to 300-500K URLs without much problems.

For customization specific to your site/need please see: scripts/configure-variables-in-this-file.bro 




Contact : Aashish Sharma, asharma@lbl.gov if you have further questions/interests 
