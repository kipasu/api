#!/bin/bash
export TERM=xterm

pup=$1
if [ -z "$pup" ]; then
    pup=30
fi

# Ambil informasi sistem
IP=$(curl -sS ipv4.icanhazip.com)
domain=$(cat /etc/xray/domain)
ISP=$(cat /root/.isp)
CITY=$(cat /root/.city)

touch /etc/slowdns/server.pub
hostslow=$(cat /etc/slowdns/server.pub)

touch /etc/xray/dns
serverpub=$(cat /etc/xray/dns)

if [[ -z "/etc/crme" ]] &> /dev/null ; then
curl -s https://raw.githubusercontent.com/goldax7/os/main/credit | base64 -d > /etc/crme
chmod +x /etc/crme
fi

if [[ -z "/etc/port.txt" ]] &> /dev/null ; then
curl -s https://raw.githubusercontent.com/goldax7/os/main/prot | base64 -d > /etc/port
fi

# Port
tls=$(cat /etc/port.txt | grep 'ssh tls' | awk '{print $5}')
ntls=$(cat /etc/port.txt | grep 'ssh ntls' | awk '{print $5}')
openssh=$(cat /etc/port.txt | grep 'openssh' | awk '{print $4 $5}')
badvpn=$(cat /etc/port.txt | grep 'openssh' | awk '{print $4 $5 $6}')
squid=$(cat /etc/port.txt | grep 'squid' | awk '{print $4}')
openvpn=$(cat /etc/port.txt | grep 'openvpn' | awk '{print $4 $5 $6}')
udp=$(cat /etc/port.txt | grep 'udp-custom' | awk '{print $4}')
slowdns=$(cat /etc/port.txt | grep 'slowdns' | awk '{print $4}')
dropbear=$(cat /etc/port.txt | grep 'dropbear' | awk '{print $4 $5}')

user=$1
Pass=$2
exp=$(date -d "$3 days" +"%Y-%m-%d")
iplimit=$4

# Membuat directory
mkdir -p /etc/xray/limit/ssh/ip/
echo "$iplimit" > /etc/xray/limit/ssh/ip/$user

hariini=$(date -d "0 days" +"%Y-%m-%d") 
useradd -e ${exp} -s /bin/false -M $user
expi="$(chage -l $user | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n"|passwd $user &> /dev/null
exp="$pup minutes"
echo "killusr ssh $user" | at now +$pup minutes >/dev/null 2>&1

echo -e "
————————————————————————————————————————
           SSH OVPN ACCOUNT             
————————————————————————————————————————
 Username     : $user
 Password     : $Pass
 Limit IP     : ${iplimit} Device
————————————————————————————————————————
 SSH Port 80 : ${domain}:80@${user}:${Pass}
 UDP Custom  : ${domain}:54-65535@${user}:${Pass}
————————————————————————————————————————
 SSH SlowDNS  : $slowdns
 Host Slowdns : $hostslow
 Pubkey       : $serverpub
————————————————————————————————————————
 ISP          : $ISP
 Country      : $CITY
 Host/IP      : $domain
 OpenSSH      : $openssh
 SSH UDP      : $udp
 Dropbear     : $dropbear
 OpenVPN      : $openvpn
 Proxy Squid  : $squid
 BadVPN       : $badvpn
 WSS SSL/TLS  : $tls
 WSS none TLS : $ntls
————————————————————————————————————————
 OVPN Download    : https://$domain:89/
————————————————————————————————————————
 Save Link Account: https://$domain:89/ssh-$user.txt
————————————————————————————————————————
 Payload NTLS:
 GET / HTTP/1.1[crlf]host: ${domain}[crlf]Upgrade: Websocket[crlf][crlf]
————————————————————————————————————————
 Payload  TLS:
 GET http://bug.con/ HTTP/1.1[crlf]host: ${domain}[crlf]Upgrade: Websocket[crlf][crlf]
————————————————————————————————————————
   Created On : $hariini
   Expired On : $exp
————————————————————————————————————————"
/etc/crme
