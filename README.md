## Script is not working yet

# owrtngxsslrprxyscript
openwrt nginx ssl https reverse proxy script with acme.sh support

# use
first chmod -x the script 

you need a minimal nginx.conf 

script will create serveral directories under /var/www/ 

if you use external drives append your config or change script! 

the script will always assume www.domain.ltd as second subdomain 


./ngrproxy.sh {-r [remoteDomain] | -i [remoteIpAddress]} -d [localDomain] {-s -g}

-r RemoteDomain - If you want to proxy a domain

-i RemoteIpAddress - If you want to proxy a IpAddress (ipv4/ipv6)

-s create SiteSpecificNginxConfig with ssl and execute acme.sh for letsencrypt cert

-g create non ssl SiteSpecificNginxConfig

-h no help help

