#!/bin/bash
 
#Required
domain=elk.local
commonname=$domain
 
#Change to your company details
country=NZ
state=Discombobulation
locality=SomewhereFun
organization=DonWilliamsShouldBeWatched
organizationalunit=ItsATrap
email=administrator@nowheresville.net
 
#Optional
password=kibana

#Create the request
openssl req -x509 -newkey rsa:2048 -keyout $domain.key -out $domain.pem -nodes -days 3650 \
    -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"

#Move keys to directories
mv $domain.pem /etc/ssl/certs/.
mv $domain.key /etc/ssl/private/. 
