#!/bin/bash 

# Copyright (C) 2016-2021 Elias Haisch
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

########################SIMPLE NGINX CONFIG FOR REVERSE PROXY IN OPENWRT#############

#opkg install nginx 
#open icmp in firewall
#ping is needed 
#curl https://raw.githubusercontent.com/Neilpang/acme.sh/master/acme.sh > acme.sh
#chmod a+x "acme.sh"
#./acme.sh --install
#


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

######################################################HELP#################################


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
  
        [nN] | [Nn][Oo] )
            ask=false
            echo 'n'
            return 1
            ;;

          *) echo 'What? '
            ask=true;
            ;;

  esac
done
ask=''
}

######################################################GOODIP################################
###parameter is ipv4 or ipv6 address#

function goodip {
if [[ $1 =~ ^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) ]] || [[ $1 =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then 
  echo $1   
else
  echo 1  
  return 1;
fi

}
######################################################PARSEPING################################

function parseping {

ip=$(ping -4 -c1 $1 2>/dev/null)
ip=${ip%%')'*}
ip="$(goodip ${ip#[a-zA-Z0-9]*'('})"
ip6=$(ping -6 -c1 $1 2>/dev/null)
ip6=${ip6%%')'*}
ip6="$(goodip ${ip6#[a-zA-Z0-9]*'('})"
if [[ $ip != 1 ]] || [[ $ip6 != 1 ]]; then
  if [[ $ip != 1 ]]; then
  # echo "$ip $ip6" | grep -q "ping: sendto: Permission denied"
  # if [[ $? -eq 0 ]]; then 
  # >&2 echo "ping: sendto: Permission denied --> is your ipv6 not set up correctly?"
  # echo "$ip"
  # else 
    echo -n "$ip"
  fi
  if [[ $ip6 != 1 ]]; then
    echo -n " $ip6"
  fi
else
  return 2
fi
echo ""
}

######################################################DOMAINPOINTSTO########################
function domainpointsto {
##TestIfDomainPointsOnLocalNetworkInterface
echo "probing with ping -c1 for ipv4 and ipv6 addresses"

ips="$(parseping $1)"
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
    nslookup $1                             #######missing everything here
    echo "FQDN points to VALID ip"
    ;;
  0) 
    echo "FQDN points to $ips"

esac

for ip in ${ips[@]}
do
  ip a | grep -q "$ip"
  if [[ $? -ne 0 ]]; then
    echo "$1 POINTS ON $ip WHICH IS not found on local interface"
  else
    echo "$ip found $1 is pointing on me"
    local_ips+="$ip"
  fi
done
if [[ -z local_ips ]]; then
    echo "$ip not found on local interface"
    echo "The address of domain $1 is not pointing on any local interface(ping command) -> abort script? (y/n)"
    yesorno
    if [[ $? == 1 ]]; then
      return 2
    fi
else
  return 0
fi

} 

function clisten {

for ip in "${local_ips[@]}"
do
  echo "listen      $ip $1;"
done

}
#####################################NGINCONF### ARGS ?????????????????? ###########

function nginxconf {

#echo " how many WORKER_PROCESSES?"
WORKER_PROCESSES=4
WORKER_CONNECTIONS=512


cat >> /etc/nginx/nginx.conf << EOF
####This file is created by the ngrproxy script.
$ngrconfID

worker_processes  $WORKER_PROCESSES;
user nobody nogroup;

events {
  use           epoll;
  worker_connections  $WORKER_CONNECTIONS;
}

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;


http {
    server_tokens off;
    include       mime.types;
    charset       utf-8;
    keepalive_timeout  65;
    #access_log    logs/access.log  combined;

    include /etc/nginx/rproxy-sites_enabled/*
    include /etc/nginx/rproxy-sites_ssl_enabled/*
}


EOF

}

#####################################NGINCONF80### ARGS $1=ipaddresstobeproxied $2=FQDN ###########
function nginxconf80 {
PROXYIP=$1
FQDN=$2
echo "######## creating http config for $FQDN ########"  
echo ""
echo "webserver @ $PROXYIP will be served as $FQDN"
echo "setting up directories"
echo "/var/www/$FQDN"
mkdir -p /var/www/$FQDN
echo "/var/www/$FQDN/.well-known/acme_challenge/"
mkdir -p /var/www/$FQDN/.well-known/acme_challenge/
echo "/etc/nginx/rproxy-sites_available"
mkdir -p /etc/nginx/rproxy-sites_available
echo "/etc/nginx/rproxy-sites_enabled"
mkdir -p /etc/nginx/rproxy-sites_enabled
echo ""
HTTP_HOST='$http_host'
REMOTE_ADDR='$remote_addr'
PROXY_ADD_X_FORWARDED_FOR='$proxy_add_x_forwarded_for'
SCHEME='$scheme'
HOST='$host'
echo "Set proxy pass to https? Yes/No?"
yesorno
if [[ $? -eq 0 ]]; then
  PROXY_PASS="proxy_pass https://$PROXYIP;"
  echo "set proxy_ssl_verify on ? Yes/No?"
  yesorno
  if [[ $? -eq 0 ]]; then
    echo "set to on!"
    PROXY_SSL_VERIFY='proxy_ssl_verify on;'
  else
    echo "set to off!"
    PROXY_SSL_VERIFY='proxy_ssl_verify off;'
  fi
else
  PROXY_PASS="proxy_pass http://$PROXYIP;"
fi
echo ""

if [[ ! -f /etc/nginx/rproxy-sites_available/$FQDN.conf ]]; then

####configFILE

CLIENT_MAX_BODY_SIZE="10m"
CLIENT_BODY_BUFFER_SIZE="128k"
PROXY_CONNECT_TIMEOUT="90"
PROXY_SEND_TIMEOUT="90"
PROXY_READ_TIMEOUT="90"
PROXY_BUFFERS="32 4k"


cat >> /etc/nginx/rproxy-sites_available/$FQDN.conf << EOF

####server_$FQDN
    server {
        server_name   $FQDN;
        server_name   www.$FQDN;
        $(clisten $http)

        error_page    500 502 503 504  /50x.html;

        location      /ngrproxy/ { root      /var/www/$FQDN/; }

        location      /.well-known/acme-challenge/ {
            root      /var/www/$FQDN/.well-known/acme-challenge/;

       }

         location / {
               add_header       X-Host          $HOST;
               proxy_set_header        Host            $HTTP_HOST;
               proxy_set_header        X-Real-IP       $REMOTE_ADDR;
               proxy_pass_request_headers on;
               proxy_set_header X-Forwarded-For $PROXY_ADD_X_FORWARDED_FOR;
               proxy_set_header X-Forwarded-Host $HOST;
               proxy_set_header X-Forwarded-Proto $SCHEME;
               proxy_set_header X-Forwarded-Server $HTTP_HOST;
               client_max_body_size    $CLIENT_MAX_BODY_SIZE;
               client_body_buffer_size $CLIENT_BODY_BUFFER_SIZE;
               proxy_connect_timeout   $PROXY_CONNECT_TIMEOUT;
               proxy_send_timeout      $PROXY_SEND_TIMEOUT;
               proxy_read_timeout      $PROXY_READ_TIMEOUT;
               proxy_buffers           $PROXY_BUFFERS;
               $PROXY_PASS
               $PROXY_SSL_VERIFY
          }


 }
####server_$FQDN
EOF
####configFILEend

  if [[ -f /etc/nginx/rproxy-sites_available/$FQDN.conf ]]; then
    echo "wrote /etc/nginx/rproxy-sites_available/$FQDN.conf"
    echo "should we create a symbolic link to enable the new configuration? Yes/No"
    if yesorno; then
      ln -s /etc/nginx/rproxy-sites_available/$FQDN.conf /etc/nginx/rproxy-sites_enabled/$FQDN.conf
      if nginx -t; then
        if [[ $openwrt == true ]]; then 
          /etc/init.d/nginx stop 
          /etc/init.d/nginx start
        else
          systemctl stop nginx
          systemctl start nginx
        fi
        ident="$(dd if=/dev/urandom bs=3 count=1 | sha256sum)"
        echo "ident" > /var/www/$FQDN/ident
        if curl http://$FQDN/ident | grep -q "$ident"; then
          echo "nginx just serving fine. from local filesystem"
          echo "you need to test the remote server on your own (proxy function)"
          echo "to do so go to http://$FQDN with your http client/browser software"
        else 
          echo "There is an issue with your network."
        fi
        rm /var/www/$FQDN/ident
        vi -c "%s/location      /ngrproxy/ { root      /var/www/$FQDN/; }/#location      /ngrproxy/ { root      /var/www/$FQDN/; }/gc" -c "wq!" /etc/nginx/rproxy-sites_available/$FQDN.conf

      else 
        echo "There is an unknown issue with nginx pls resolve it yourself"
        nginx -t
        echo "exiting"                                                                          ###should we offer to delete changes ?
        exit 1
      fi  
    fi
    return 0
  else 
    echo $?
    echo "could not create file: /etc/nginx/rproxy-sites_available/$FQDN.conf"
    return 1
  fi
else 
  echo "/etc/nginx/rproxy-sites_available/$FQDN.conf exists -- creation omitted "
  return 0
fi
}

function ngxwellknown80 {   
  echo "dont use this hazardous function it needs to be changed when needed at all"

# if [[ ! -f /etc/nginx/rproxy-sites_enabled/$FQDN.conf ]]; then
#   echo "LetsEncrypt needs a minimal server running on port 80 to verify origin of the domain!"
#   echo "create it?"
#   if yesorno; then 

# cat >> /etc/nginx/rproxy-sites_available/$FQDN.conf << EOF

# ####server_$FQDN
#     server {
#         server_name   $FQDN;
#         server_name   www.$FQDN;
#         $(clisten $http)

#         error_page    500 502 503 504  /50x.html;

#         location      /.well-known/acme-challenge/ {
#             root      /var/www/$FQDN/;

#        }
# }
# ####server_$FQDN
# EOF     
#   else
#     echo "you have to transfer the file which will be created by the acme.sh in"
#     echo "/var/www/$FQDN/.well-known/acme-challenge/SOMEFILE"
#     echo "to the server root serving on port 80"
#     echo "do you want to continue"
#     if yesorno; then
#       manfileacme=true
#     else
#       echo "ok exiting script"
#       exit 1
#     fi
#   fi
# fi
}

##################################NGINCONF443### ARGS $1=ipaddresstobeproxied $2=FQDN ###########
function nginxconf443 {

PROXYIP=$1
FQDN=$2

echo "######## creating http config for $FQDN ########"  
echo ""
echo "webserver @ $PROXYIP will be served as $FQDN"
echo "setting up directories"
echo "/etc/nginx/rproxy-sites_ssl_available"
mkdir -p /etc/nginx/rproxy-sites_ssl_available
echo "/etc/nginx/rproxy-sites_ssl_enabled"
mkdir -p /etc/nginx/rproxy-sites_ssl_enabled
echo ""
HTTP_HOST='$http_host'
REMOTE_ADDR='$remote_addr'
PROXY_ADD_X_FORWARDED_FOR='$proxy_add_x_forwarded_for'
SCHEME='$scheme'
HOST='$host'
echo "Set proxy pass to https? Yes/No?"
yesorno
if [[ $? -eq 0 ]]; then
  PROXY_PASS="proxy_pass https://$PROXYIP;"
  echo "set proxy_ssl_verify on ? Yes/No?"
  yesorno
  if [[ $? -eq 0 ]]; then
    echo "set to on!"
    PROXY_SSL_VERIFY='proxy_ssl_verify on;'
  else
    echo "set to off!"
    PROXY_SSL_VERIFY='proxy_ssl_verify off;'
  fi
else
  PROXY_PASS="proxy_pass http://$PROXYIP;"
fi
echo ""
if [[ ! -f /etc/nginx/rproxy-sites_ssl_available/$FQDN.conf ]]; then
  echo "setting up directory /etc/nginx/acme.sh/$FQDN"
  echo "for certificates"
  echo "#"
  mkdir -p /etc/nginx/acme.sh/$FQDN

  if [[ ! -f /etc/nginx/dh4096.pem ]]; then

    echo "creating diffi hellman file! in /etc/nginx/dh4096.pem"
    openssl dhparam -out /etc/nginx/dh4096.pem 4096
  fi
ask='y'
while [[ $ask == 'y' ]]; do
  
  echo "issuing letsencrypt certificates"
  echo "used command:"
  echo "acmesh --issue -k 4096 -d $FQDN -d www.$FQDN -w /var/www/$FQDN -ecc --cert-file /etc/nginx/acme.sh/$FQDN/cert.pem --key-file /etc/nginx/acme.sh/$FQDN/key.pem --fullchain-file /etc/nginx/acme.sh/$FQDN/fullchain.pem --nginx --debug --force > acme_ngrpconf_$https.log"
  echo "acme.sh output is stored in acme_ngrpconf-$FQDN-$https.log"
  $acmesh --issue -k 4096 -d $FQDN -d www.$FQDN -w /var/www/$FQDN --cert-file /etc/nginx/acme.sh/$FQDN/cert.pem --key-file /etc/nginx/acme.sh/$FQDN/key.pem --fullchain-file /etc/nginx/acme.sh/$FQDN/fullchain.pem --nginx --debug --force --log acme_ngrpconf-$FQDN_$https.log
  if [[ $? -ne 0 ]]; then
    echo 'Issueing certificate was not successfull.'
    grep "$FQDN:Verify error" acme_ngrpconf-$FQDN-$https.log
    if grep -q "refused" acme_ngrpconf-$FQDN-$https.log; then
      echo "Connection was refused looks like a firewall issue."
    fi
    echo "we can wait here.. till you solved that issue or just restart the script later."
    echo 'Just tell me if you want to retry? Yes/No '
    ask=yesorno
  else
    ask='n'
  fi
done

####configFILE
  SSL_ECDH_CURVE='secp384r1';
  SSL_SESSION_TIMEOUT="10"'m';
  SSL_SESSION_CACHE='shared:SSL:'"10"'m';
  CLIENT_MAX_BODY_SIZE="10"'m'
  CLIENT_BODY_BUFFER_SIZE="128"'k'
  PROXY_CONNECT_TIMEOUT="90"
  PROXY_SEND_TIMEOUT="90"
  PROXY_READ_TIMEOUT="90"
  NPB="32"
  SPB="8"
  PROXY_BUFFERS="$NPB $SPB"'k'
  ngv=$(nginx -V 2>&1 | grep version)
  ngv=${ngv%%'('*}
  ngv=$(echo ${ngv#[a-zA-Z0-9]*'/'} | tr -d '.')
  if [[ $ngv > 1000 ]]; then  
    ngv=$(( $ngv * 10 ))
  fi
  if [[ $ngv -lt 1130 ]]; then  
    SSLPV="3"
  else 
    SSLPV="2"
  fi
  SSL_PROTOCOLS='TLSv1.'"$SSLPV"


  cat >> /etc/nginx/rproxy-sites_ssl_available/$FQDN.conf << EOF

####server_$FQDN
    server {
        server_name   $FQDN;
        server_name   www.$FQDN;
        $(clisten $https)

        error_page    500 502 503 504  /50x.html;

	      ssl on;
	      ssl_certificate /etc/nginx/acme.sh/$FQDN/fullchain.pem;
	      ssl_certificate_key     /etc/nginx/acme.sh/$FQDN/key.pem;
 	      ssl_trusted_certificate /etc/nginx/acme.sh/$FQDN/cert.pem;
        ssl_prefer_server_ciphers on;
        ssl_protocols $SSL_PROTOCOLS;  #enable tlsv1.3 with nginx 1.13 or higher
        ssl_dhparam /etc/nginx/dh4096.pem;
      #	ssl_ciphers  EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA384:EECDH+aRSA+SHA256:EECDH:EDH+aRSA:HIGH:!aNULL:!eNULL:!LOW:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!SEED:!DSS:!CAMELLIA:!Medium;
        ssl_ciphers 'ECDHE:DHE:!AES128:HIGH:!aNULL:!eNULL:!LOW:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!SEED:!DSS:!CAMELLIAD';
      #	ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:!aNULL:!eNULL:!LOW:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!SEED:!DSS:!CAMELLIA:!Medium;
        ssl_ecdh_curve $SSL_ECDH_CURVE;
        ssl_session_timeout $SSL_SESSION_TIMEOUT;
        ssl_session_cache $SSL_SESSION_CACHE;
        #ssl_session_tickets off; #enable only for nginx > 1.5.9
        #ssl_stapling on; #enable only for nginx > 1.3.7
        #ssl_stapling_verify on; #enable only for nginx > 1.3.7
        #resolver $DNS-IP-1 $DNS-IP-2 valid=300s;
        #resolver_timeout 5s;
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";

        location      /ngrproxy/ { root      /var/www/$FQDN/; }

        location / {
              add_header       X-Host          $HOST;
              proxy_set_header        Host            $HTTP_HOST;
              proxy_set_header        X-Real-IP       $REMOTE_ADDR;
              proxy_pass_request_headers on;
              proxy_set_header X-Forwarded-For $PROXY_ADD_X_FORWARDED_FOR;
              proxy_set_header X-Forwarded-Host $HOST;
              proxy_set_header X-Forwarded-Proto $SCHEME;
              proxy_set_header X-Forwarded-Server $HTTP_HOST;
              client_max_body_size    $CLIENT_MAX_BODY_SIZE;
              client_body_buffer_size $CLIENT_BODY_BUFFER_SIZE;
              proxy_connect_timeout   $PROXY_CONNECT_TIMEOUT;
              proxy_send_timeout      $PROXY_SEND_TIMEOUT;
              proxy_read_timeout      $PROXY_READ_TIMEOUT;
              proxy_buffers           $PROXY_BUFFERS;
              $PROXY_PASS
              $PROXY_SSL_VERIFY
        }


 }
####server_$FQDN

EOF
####configFILEend
  if [[ -f /etc/nginx/rproxy-sites_ssl_available/$FQDN.conf ]]; then
    echo "wrote /etc/nginx/rproxy-sites_ssl_available/$FQDN.conf"
    echo "should we create a symbolic link to enable the new configuration?"
    if yesorno; then
      ln -s /etc/nginx/rproxy-sites_ssl_available/$FQDN.conf /etc/nginx/rproxy-sites_ssl_enabled/$FQDN.conf
      if nginx -t; then
        if [[ openwrt == true ]]; then 
          /etc/init.d/nginx stop 
          /etc/init.d/nginx start
        else
          systemctl stop nginx
          systemctl start nginx
        fi
        ident="$(dd if=/dev/urandom bs=3 count=1 | sha256sum)"
        echo "ident" > /var/www/$FQDN/ident
        if curl https://$FQDN/ident | grep -q "$ident"; then
          echo "nginx just serving fine. from local filesystem"
          echo "you need to test the remote server on your own (proxy function)"
          echo "to do so go to https://$FQDN with your http client/browser software"
        else 
          echo "There is an issue with your network."
        fi
        rm /var/www/$FQDN/ident
        vi -c "%s/location      /ngrproxy/ { root      /var/www/$FQDN/; }/#location      /ngrproxy/ { root      /var/www/$FQDN/; }/gc" -c "wq!" /etc/nginx/rproxy-sites_ssl_available/$FQDN.conf
      else 
        echo "There is an unknown issue with nginx pls resolve it yourself"
        nginx -t
        echo "exiting"                                                                          ###should we offer to delete changes ?
        exit 1
      fi  
    fi
  else 
    echo "could not create file: /etc/nginx/rproxy-sites_ssl_available/$FQDN.conf"
    return 1
  fi
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


#####################################################uhttpdconf############ ARGS ipaddress port ##########
#ADD IPV6!!!!!!!!!!!!!!!!!!!!!

function uhttpdconf {

if [[ $openwrt != true ]]; then
  echo "not runing openwrt, you have to reconfigure that yourself"
else
  echo "nice openwrt detected"
  while [[ $(netstat -l -p -n | grep -E 0.0.0.0:$2 | grep -q uhttpd) -eq 0 ]] || [[ $(netstat -l -p -n | grep -E $1:$2 | grep -q uhttpd) -eq 0 ]]; 
  do
    echo 'uhttpd-config backup will be created as /etc/config/uhttpd.old'
    echo -n 'Should i change the port of uhttpd(p), its listen address(a), both(pa) or nothing(n) pls enter(p/a/pa/n)?: '
    read pan
    case $pan in
  
        p)  #/etc/config/uhttpd
            echo -n 'please give me the new port uhttpd should listen on instead of' "$2"': '
            read port
            cp /etc/config/uhttpd /etc/config/uhttpd.old
            vi -c %s/0.0.0.0:$2/0.0.0.0:$port/gc -c wq! /etc/config/uhttpd
            vi -c %s/$1:$2/$1:$port/gc -c wq! /etc/config/uhttpd
            /etc/init.d/uhttpd restart
            ;;
        a)  #/etc/config/uhttpd
            echo 'local ip addresses'
            i=0
            local_addresses="$(ip a | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]{1,2})" | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")"
            for ip in ${local_addresses[@]}
            do 
              echo "$i: $ip"
              i=$(($i+1))
            done
            echo ""
            echo -n 'please give me the new IPAddress uhttpd should listen on instead of '"$1"': '
            read pick
            cp /etc/config/uhttpd /etc/config/uhttpd.old
            vi -c %s/0.0.0.0/${local_addresses[$pick]}/gc -c wq! /etc/config/uhttpd
            vi -c %s/$1/${local_addresses[$pick]}/gc -c wq! /etc/config/uhttpd
            /etc/init.d/uhttpd restart
            ;;
        pa)
            echo -n 'please give me the new port uhttpd should listen on instead of '"$2"': '
            read port
            cp /etc/config/uhttpd /etc/config/uhttpd.old
            vi -c %s/0.0.0.0:$2/0.0.0.0:$port/gc -c wq! /etc/config/uhttpd            
            vi -c %s/$1:$2/$1:$port/gc -c wq! /etc/config/uhttpd
            echo 'local ip addresses'
            i=0
            local_addresses="$(ip a | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]{1,2})" | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")"
            for ip in ${local_addresses[@]}
            do 
              echo "$i: $ip"
              i=$(($i+1))
            done
            echo ""
            echo -n 'please give me the new IPAddress uhttpd should listen on instead of '"$1"': '
            read pick
            cp /etc/config/uhttpd /etc/config/uhttpd.old
            vi -c %s/0.0.0.0/${local_addresses[$pick]}/gc -c wq! /etc/config/uhttpd
            vi -c %s/$1/${local_addresses[$pick]}/gc -c wq! /etc/config/uhttpd
            /etc/init.d/uhttpd restart
            ;;
        n)
          echo '####################FAULT##################################'
          echo -n "port is in use by "
          netstat -l -p -n | grep -E 0.0.0.0:80
          echo "choose different port or ip for one of the services and try again."
          echo '###########################################################'
          exit1
          ;;
    esac
  done  
fi

}


#####################################################WHOLISTENS############ ARGS ipaddress port ##########
#This function should be changed to not call uhttpdconf by itself but report conflicting processes  
function wholistensp {

listens=$(netstat -l -p -n | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\:([0-9]{1,5})")
netstat -l -p -n | grep -E -q 0.0.0.0:80
if [[ $? -ne 0 ]]; then
  for process in ${listens[@]}
  do
    if [[ $(echo $process | grep -o "$1:$2") == "$1:$2" ]]; then 
      echo "port $2 is in use on ip $1"
      echo $process
    fi
done 
else
  echo '####################FAULT##################################'
  echo "port $2 and address $1 is in use by "
  netstat -l -p -n | grep -E 0.0.0.0:80 | grep uhttp 
  if [[ $? -ne 0 ]] || [[ $openwrt != true ]]; then
      echo "choose different port or ip for one of the services and try again."
  else
   # uhttpdconf $1 $2
   echo "CHANGE PORT OR IPADDRESS OF UHTTPD!"
   echo "CHANGE PORT OR IPADDRESS OF UHTTPD!"
   echo "CHANGE PORT OR IPADDRESS OF UHTTPD!"
  fi
  echo '###########################################################'
fi
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

  -r) ####remote_domain example.com
    shift 
    rem_address="$1"
    ;;

  -i)  ####remote_ip
    shift
    if [[ "$(goodip "$1")" == "$1" ]]; then
      rem_address="$1"
    else
      echo 'ip is not correct format?'
      echo 'exiting.'
    fi
    ;;

  -d) ####pointing_domain  example.com
    shift
    domainpointsto $1
    if [[ $? == 0 ]]; then
      FQDN="$1"
    elif [[ $? == 2 ]]; then
      echo "remember that no one will be able to connect to your service via asking an DNS-server"
      echo "using domain $1"
      FQDN="$1"
    else
      echo "dns fault!"
      nslookup "$1"
      exit 1
    fi
    ;;

  -s) #### https port defaults to 443
    # future me: realize with function and/or case statement?
    shift
    nginx -V 2>&1 | grep -q ssl 
    if [[ "$?" -eq 0 ]]; then
      wholistensp $local_ips $1
      if [[ "$?" -eq 0 ]]; then
        https=$1;
      else
        echo "port in use by: $(wholistensp $1)"
      fi
    else
      echo 'nginx not build with ssl support?'
      echo 'or script was run with missing permissions?'
      echo 'exiting.'
      exit 1
    fi
    ;;

  -g)
    # future me: realize in with function and/or case statement?
    shift
    nginx -V 2>&1 | grep -q "nginx version: nginx"
    if [[ "$?" -eq 0 ]]; then
      wholistensp $local_ips $1
      if [[ "$?" -eq 0 ]]; then
        http=$1
      else
        echo "port in use by: $(wholistensp $1)"
      fi
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
if [[ $? == 0 ]]; then
  if [[ -z $FQDN ]] || [[ -z $rem_address ]]; then
    echo "wrong number of arguments"
    helpme
    exit 1
  fi
else 
  echo "aborted script due to faults!"
  exit 1
fi
} 

########################################################SCRIPT#######################


echo "simple nginx reverse proxy configuration with letsencrypt acme if needed"
echo "install nginx with ssl compile option"
echo "nginx will be listen on port 80 and 443 by default"  

local_ips=""
http=""
https=""
rem_address=""
FQDN=""
startdir=$PWD
if [[ $(cat /proc/version | grep -q OpenWrt) -eq 0 ]] || [[ $(cat /etc/os-release | grep -q OpenWrt) -eq 0 ]]; then
  echo "running on openwrt"
  openwrt=true
fi
getargs $@

echo "running openwrt: $openwrt"
echo "local ips: ${local_ips[@]}"
echo "http port: $http"
echo "https: $https"
echo "address to be proxied: $rem_address"
echo "Domain : $FQDN"
if [[ -n $http ]] || [[ -n $http ]]; then
  if ngrconfID =$(grep "#ngrconfid# id =" /nginx/nginx.conf); then
    echo 'found ngrconf "nginx.conf" configuration assuming compatibility'
  else   
    echo 'unknown status of nginx configuration'
    echo 'do you want me to create a default nginx conf compatible with this script,'
    echo 'backup of current config file will be at /etc/nginx/nginx.conf.old ? Yes/No'
    if yesorno; then
      mv /nginx/nginx.conf /etc/nginx/nginx.conf.old
      ngrconfID="#ngrconfid# id = $(dd if=/dev/urandom bs=6 count=1 | sha256sum)"                     ###########for future features 
      nginxconf
    else
      echo 'you need to at least include the following directories  in the extisting nginx conf'
      echo '/etc/nginx/rproxy-sites_enabled'
      echo '/etc/nginx/rproxy-sites_ssl_enabled'
      echo 'this script will throw errors at you otherwise!'
      echo 'press enter to go on'
      read
    # echo 'do you want me to do this? Yes/No'
    # if yesorno; then                                                                             ########later to add
    # fi 
    fi
  fi
  if [[ -n $http ]]; then
      nginxconf80 "$rem_address" "$FQDN"
    fi
    if [[ -n $https ]]; then
      if ls acme.sh >/dev/null 2>&1; then
        echo "acme.sh found https enabled"
        acme=true
        acmesh="$PWD/acme.sh"
        nginxconf443 "$rem_address" "$FQDN"
      else
        echo "we need to download acme.sh y/n (https://raw.githubusercontent.com/Neilpang/acme.sh)?"
        if yesorno; then
          curl https://raw.githubusercontent.com/Neilpang/acme.sh/master/acme.sh > acme.sh
          acmesh="$PWD/acme.sh"
          nginxconf80 "$rem_address" "$FQDN"
        else
          echo "without acme.sh https configuration is currently not supported" 
          echo "exiting" 
          exit 1
        fi
      fi
    fi
  fi    
  return 0
else
  echo 'nope?'
  helpme
  return 1
fi
