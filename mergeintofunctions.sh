#!/bin/bash 

########################SIMPLE NGINX CONFIG FOR REVERSE PROXY IN OPENWRT#############
#MAKE SURE uhttpd IS NOT LISTENING ON PORT 80 NOR 443
#opkg install nginx 
#open icmp in firewall
#ping is needed 
#curl https://raw.githubusercontent.com/Neilpang/acme.sh/master/acme.sh > acme.sh
#chmod a+x "acme.sh"
#./acme.sh --install
#

echo "simple nginx reverse proxy configuration with acme support"
echo "install nginx with ssl compile option"
echo " wan adress and open firewall ports for port 80"
echo "change uhttpd listen port 80 and 443 when u use luci on wan address"
echo "nginx will be listen on port 80 and 443 by default"  
startdir=$PWD
if [[ $(cat /proc/version | grep -q OpenWrt) -eq 0 ]] || [[ $(cat /etc/os-release | grep -q OpenWrt) -eq 0 ]]; then
echo "running on non openwrt"
openwrt=true
else 
echo "OpenWrt detected nice!"
fi


######################################################DISCLAIMER#################################
function disclaimer {
echo "I am not a software developer neither a studied IT specialist in any means, more likely i am an it enthusiast."
echo "This makes this software a potential risk to use for any production system even when i plan to do so."
echo "If you find any bugs or you can give me advice please contribute on github https://github.com/eliasmagn"
}


######################################################HELP#################################
function helpme {

echo 'here should be a help'
echo 'there is not ? '
echo 'blame yourself to not have contributed this function yet'
echo ' or just do it ;-)'
}



function yesorno {
ask=true
while [[ $ask == true ]]; do
 read yesno
 case $yesno in

        [yY] | [yY][Ee][Ss] )
            ask=false
            echo 'y'
            return 0
            ;;
  
        [nN] | [n|N][O|o] )
            ask=false
            echo 'n'
            return 1
            ;;

          *) echo "What? "
            ask=true;
            ;;

  esac
done
ask=''
}

######################################################GOODIP################################
###parameter is ipv4 or ipv6 address#
function goodip {
if [[ $1 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || [[ $1 =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then 
  echo $1   
else
  echo 1;
  return 1;
fi

}

function parseping {

ip=$(ping -4 -c1 $1)
ip=${ip%%')'*}
ip="$(goodip ${ip#[a-zA-Z0-9]*'('})"
ip6=$(ping -6 -c1 $1)
ip6=${ip6%%')'*}
ip6="$(goodip ${ip6#[a-zA-Z0-9]*'('})"
if [[ $ip != 1 ]] || [[ $ip6 != 1 ]]; then
  # echo "$ip $ip6" | grep -q "ping: sendto: Permission denied"
  # if [[ $? -eq 0 ]]; then 
  # >&2 echo "ping: sendto: Permission denied --> is your ipv6 not set up correctly?"
  # echo "$ip"
  # else 
echo "$ip $ip6" 
  # fi
else
  echo 1
  return 1
fi
}

######################################################DOMAINPOINTSTO########################
function domainpointsto {
##TestIfDomainPointsOnLocalNetworkInterface
echo "probing with ping -c1 for ipv4 and ipv6 addresses"

ips=parseping $1
case $? in 
  2)
    echo "network fault"
    echo "are we connected to a network?"
    ping -4 -c2 $1
    exit 1
    ;;
  1)
    echo "host does not answer"
    echo "could blocking our packets"
    echo '"pinging"'
    ping -4 -c1 $1
    echo '"nslooking"'
    nslookup $1
    echo "FQDN points to VALID ip"
    ;;
  0) 
    echo "FQDN points to $ips"

esac

for ip in "${ips[@]}"
do
  ip a | grep -q "$ip"
  if [[ $? -ne 0 ]]; then
    echo "The address of domain $1 is not pointing on any local interface(ping command) -> abort script? (y/n)"
    echo "$ip not found on local interface"
    yesorno
    if [[ $? = 1 ]]; then
      exit 1
    fi
  else
    echo "$ip found address pointing on me"
    return 0
  fi
done

} 

#####################################NGINCONF80### ARGS $1=ipaddresstobeproxied $2=FQDN ###########
function nginxconf80 {
PROXYIP=$1
FQDN=$1

echo "using $PROXYIP for $FQDN"
echo "setting up directory /var/www/$FQDN"
mkdir -p /var/www/$FQDN
mkdir -p /etc/nginx/rproxy-sites_available
mkdir -p /etc/nginx/rproxy-sites_enabled
mkdir -p /var/www/$FQDN/.well-known/acme_challenge/
http_host='$http_host'
remote_addr='$remote_addr'
proxy_add_x_forwarded_for='$proxy_add_x_forwarded_for'
scheme='$scheme'
host='$host'
echo "Set proxy pass to https? Yes/No?"
yesorno
if [[ $? -eq 0 ]]; then
  proxy_pass='proxy_pass https://$PROXYIP;'
  echo "set proxy_ssl_verify on ? Yes/No?"
  yesorno
  if [[ $? -eq 0 ]]
  echo "set to on!"
  proxy_ssl_verify='proxy_ssl_verify on;'
  else
  echo "set to off!"
  proxy_ssl_verify='proxy_ssl_verify off;'
  fi
else
  proxy_pass='proxy_pass http://$PROXYIP;'
fi
echo ""

if [[ ! -f /etc/nginx/rproxy-sites_available/$FQDN.conf ]]; then

####configFILE

cat >> /etc/nginx/rproxy-sites_available/$FQDN.conf << EOF

####server_$FQDN
    server {
        server_name   $FQDN;
        server_name   www.$FQDN;
        listen        80;

        error_page    500 502 503 504  /50x.html;

        location      /.well-known/acme-challenge/ {
            root      /var/www/$FQDN/;

       }

         location / {
               add_header       X-Host          $host;
               proxy_set_header        Host            $http_host;
               proxy_set_header        X-Real-IP       $remote_addr;
               proxy_pass_request_headers on;
               proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
               proxy_set_header X-Forwarded-Host $host;
               proxy_set_header X-Forwarded-Proto $scheme;
               proxy_set_header X-Forwarded-Server $http_host;
               client_max_body_size    10m;
               client_body_buffer_size 128k;
               proxy_connect_timeout   90;
               proxy_send_timeout      90;
               proxy_read_timeout      90;
               proxy_buffers           32 4k;
               $proxy_pass
               $proxy_ssl_verify
          }


 }
####server_$FQDN

EOF
####configFILEend
fi

}


##################################NGINCONF443### ARGS $1=ipaddresstobeproxied $2=FQDN ###########
function nginxconf443 {

PROXYIP=$1
FQDN=$2

echo "using $PROXYIP for $FQDN"
echo "setting up directories "# /var/www/$FQDN"
echo "#"
mkdir -p /var/www/$FQDN
mkdir -p /etc/nginx/rproxy-sites_ssl_available
mkdir -p /etc/nginx/rproxy-sites_ssl_enabled
mkdir -p /var/www/$FQDN/.well-known/acme_challenge/
http_host='$http_host'
remote_addr='$remote_addr'
proxy_add_x_forwarded_for='$proxy_add_x_forwarded_for'
scheme='$scheme'
host='$host'
echo "Set proxy pass to https? Yes/No?"
yesorno
if [[ $? -eq 0 ]]; then
  proxy_pass='proxy_pass https://$PROXYIP;'
  echo "set proxy_ssl_verify on ? Yes/No?"
  yesorno
  if [[ $? -eq 0 ]]
  echo "set to on!"
  proxy_ssl_verify='proxy_ssl_verify on;'
  else
  echo "set to off!"
  proxy_ssl_verify='proxy_ssl_verify off;'
  fi
else
  proxy_pass='proxy_pass http://$PROXYIP;'
fi
if [[ ! -f /etc/nginx/rproxy-sites_ssl_available/$FQDN.conf ]]; then
  echo "setting up directory /etc/nginx/acme.sh/$FQDN"
  echo "for certificates"
  echo "#"
  mkdir -p /etc/nginx/acme.sh/$FQDN

 if [[ ! -f /etc/nginx/dh4096.pem ]]; then

    echo "creating diffi hellman file! in /etc/nginx/dh4096.pem"
    openssl dhparam -out /etc/nginx/dh4096.pem 4096
  fi

  echo "issuing letsencrypt certificates"
  echo "used command:"
  echo "./root/acme.sh --issue -k 4096 -d $FQDN -d www.$FQDN -w /var/www/$FQDN -ecc --cert-file /etc/nginx/acme.sh/$FQDN/cert.pem --key-file /etc/nginx/acme.sh/$FQDN/key.pem --fullchain-file /etc/nginx/acme.sh/$FQDN/fullchain.pem --nginx --debug --force > acme_ngrpconf_443.log"
  echo "acme.sh autput is stored in acme-$FQDN-443.log"
  /root/acme.sh --issue -k 4096 -d $FQDN -d www.$FQDN -w /var/www/$FQDN --cert-file /etc/nginx/acme.sh/$FQDN/cert.pem --key-file /etc/nginx/acme.sh/$FQDN/key.pem --fullchain-file /etc/nginx/acme.sh/$FQDN/fullchain.pem --nginx --debug --force --log acme_ngrpconf-$FQDN-443.log


####configFILE


cat >> /etc/nginx/rproxy-sites_ssl_available/$FQDN.conf << EOF

####server_$FQDN
    server {
        server_name   $FQDN;
        server_name   www.$FQDN;
        listen        443;

        error_page    500 502 503 504  /50x.html;

	ssl on;
	ssl_certificate /etc/nginx/acme.sh/$FQDN/fullchain.pem;
	ssl_certificate_key     /etc/nginx/acme.sh/$FQDN/key.pem;
 	ssl_trusted_certificate /etc/nginx/acme.sh/$FQDN/cert.pem;
        ssl_session_cache shared:SSL:10m;
        ssl_prefer_server_ciphers on;
        ssl_protocols TLSv1.2; # TLSv1.3; #enable tlsv1.3 with nginx 1.13 or higher
        ssl_dhparam /etc/nginx/dh4096.pem;
#	ssl_ciphers  EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA384:EECDH+aRSA+SHA256:EECDH:EDH+aRSA:HIGH:!aNULL:!eNULL:!LOW:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!SEED:!DSS:!CAMELLIA:!Medium;
        ssl_ciphers 'ECDHE:DHE:!AES128:HIGH:!aNULL:!eNULL:!LOW:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!SEED:!DSS:!CAMELLIAD';
#	ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:!aNULL:!eNULL:!LOW:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!SEED:!DSS:!CAMELLIA:!Medium;
        ssl_ecdh_curve secp384r1;
        ssl_session_timeout  10m;
        ssl_session_cache shared:SSL:10m;
        #ssl_session_tickets off; #enable only for nginx > 1.5.9
        #ssl_stapling on; #enable only for nginx > 1.3.7
        #ssl_stapling_verify on; #enable only for nginx > 1.3.7
        #resolver $DNS-IP-1 $DNS-IP-2 valid=300s;
        #resolver_timeout 5s;
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";

         location / {
               add_header       X-Host          $host;
               proxy_set_header        Host            $http_host;
               proxy_set_header        X-Real-IP       $remote_addr;
               proxy_pass_request_headers on;
               proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
               proxy_set_header X-Forwarded-Host $host;
               proxy_set_header X-Forwarded-Proto $scheme;
               proxy_set_header X-Forwarded-Server $http_host;
               client_max_body_size    10m;
               client_body_buffer_size 128k;
               proxy_connect_timeout   90;
               proxy_send_timeout      90;
               proxy_read_timeout      90;
               proxy_buffers           32 4k;
               $proxy_pass
               $proxy_ssl_verify
          }


 }
####server_$FQDN

EOF
####configFILEend
fi
}

#####################################################TESTNGINXCONF###### ARGS NONE ####################
function testnginxconf {
  if [[ ! -f /etc/nginx/nginx.conf ]]; then
   echo "/etc/nginx/nginx.conf  does not exist!"
   echo "pls install nginx with minimal nginx.conf"
   exit 1
  fi
  #echo "$FQDN" > /var/www/$FQDN/.well-known/acme_challenge/index.html

  nginx -t
  if 
  if [[ $? -ne 0 ]]; then
    echo "Nginx config is faulty pls be kind and examine /etc/nginx/rproxy-sites/$FQDN.conf"
    echo "and /etc/nginx/nginx.conf!"
    else
    echo "echo config looks good starting nginx"
    /etc/init.d/nginx restart
  fi

}

########################################################DONE############ ARGS NONE ################
function done {
  echo "starting nginx"
  /etc/init.d/nginx start
 
  echo '/########################################\'
  echo '# you need to make sure directive:       #'
  echo '# include /etc/nginx/rproxy-sites/*.conf #'
  echo '# is included in /etc/nginx/nginx.conf   #'
  echo '\########################################/'
  echo -e "\e[39mgg & glhf"
  echo 'end of script'
}

#############################################GETARGS############ ARGS ALL INPUT in any order ##########


function getargs {

if [[ "$0" = "/bin/bash" ]]; then
   echo -e "\e[92mscript is tested to run on bash not on $0 openwrt defaults to ash "
   echo -e "\e[92m script is known to not run on ash!"
   echo -e "\e[92mpls install bash and start script from bash"
   echo -e "\e[92mopkg install bash"
   echo -e "\e[39maborting!"  
   exit 1
fi 

for opt in "$@"
do 
case $opt in
  #-f)
    #add read options from file
    #while IFS='' read -r line || [[ -n "$line" ]]; do
    #    ###script to be wrapped
    #done < "$3"
   # ;;

  -r) 
    shift 
    rem_address="$1"
    ;;

  -i)  
    shift
    if [[ $(goodip "$1") -eq "$1" ]];
      rem_address="$1"
    else
      echo 'ip is not correct format?'
      echo 'exiting.'
    fi
    ;;

  -d) 
    shift
    local_ips="$(domainpointsto $1)"
    if [[ $local_ips != 1 ]]; then
      fqdn="$1"
    else
      echo "dns fault!"
      nslookup "$1"
      exit 1
    fi
    ;;

  -s)
    nginx -V 2>&1 | grep -q ssl 
    if [[ "$?" -eq 0 ]];
      https=true;
    else
      echo 'nginx not build with ssl support?'
      echo 'or script was run with missing permissions?'
      echo 'exiting.'
      exit 1
    fi
    ;;

  -g) 
    nginx -V 2>&1 | grep -q "nginx version: nginx"
    if [[ "$?" -eq 0 ]];
    http=true;
    else
      echo 'nginx not found?'
      echo 'or script was run with missing permissions?'
      echo 'exiting.'
      exit 1
    fi
    ;;

  -h)
    helpme
    exit 1
    ;;

   *) 
    shift
    ;;

esac
done

#needed args are set if then else?



} 

########################################################SCRIPT#######################

getargs $@
if [[ $https == true ]]; then
  nginxconf443 "$rem_address" "$fqdn"
elif [[ $http == true ]]; then
  nginxconf80 "$rem_address" "$fqdn"
else
echo 'nope?'
helpme
fi
