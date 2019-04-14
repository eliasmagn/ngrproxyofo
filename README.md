# owrtngxsslrprxyscript
openwrt nginx ssl https reverse proxy script with acme.sh support

# use
first chmod -x the script 

you need a minimal nginx.conf 

script will create serveral directories under /var/www/ 

if you use external drives append your config or change script! 

the script will always assume www.domain.ltd as second subdomain 

ngrpconf80 will config http and asks for https(starts ngrpconf_443)

./ngrpconf_80 domain.ltd ipadresstobeproxied 

or https only 

./ngrpconf_443 domain.ltd ipadresstobeproxied 

