#!/bin/sh

#Author: Lyon Yang Shiwei
#Email: lyon.yang.s@gmail.com
#Description: Host review Script
#Version: 1.0

echo "Creating Directories ..."
NODE=`uname -n`
mkdir $NODE
directory=$NODE
auto_directory=$directory/auto
manual_directory=$directory/manual
mkdir $auto_directory
mkdir $manual_directory
filetowriteto=""

echo "Running automatic checks ..."

# hardcoded checks for problematic commands
ruleid=""
command=""
#************** CHECK LATEST SERVICE PACK AND UPDATE **************
ruleid="SV-27060r2_rule"
filetowriteto=$auto_directory/$ruleid
oslevel -s | awk '$1!="7100-03-01-1341" {print $1}' >>  $filetowriteto
#************** CHECK LATEST SERVICE PACK AND UPDATE **************
ruleid="SV-12489r2_rule"
filetowriteto=$auto_directory/$ruleid
find / -name .rhosts >>  $filetowriteto
ruleid="SV-12489r2_rule"
filetowriteto=$auto_directory/$ruleid
find / -name .shosts >>  $filetowriteto
ruleid="SV-12489r2_rule"
filetowriteto=$auto_directory/$ruleid
find / -name hosts.equiv >>  $filetowriteto
ruleid="SV-12489r2_rule"
filetowriteto=$auto_directory/$ruleid
find / -name shosts.equiv >>  $filetowriteto
ruleid="SV-40862r1_rule"
filetowriteto=$auto_directory/$ruleid
grep -i Protocol /etc/ssh/sshd_config | awk '!(/#/) {print}' >>  $filetowriteto
ruleid="SV-40384r1_rule"
filetowriteto=$auto_directory/$ruleid
ls -l /etc/ntp.conf | awk '{k=0;for(i=0;i<=8;i++)k+=((substr($1,i+2,1)~/[rwx]/)*2^(8-i));if(k)printf("%0o ",k);print}' | awk ' ($1>640) {print $1, $2, $10}' >>  $filetowriteto
ruleid="SV-38935r1_rule"
filetowriteto=$auto_directory/$ruleid
last | if [[ $(wc -l) -eq 0 ]]; then printf "login logging not set"; fi >>  $filetowriteto
ruleid="SV-773r2_rule"
filetowriteto=$auto_directory/$ruleid
grep ":0:" /etc/passwd | awk -F":" '{print$1":"$3":"}' | grep ":0:" | awk -F":" '$1!="root >>  $filetowriteto" {print $1}'
ruleid="SV-901r2_rule"
filetowriteto=$auto_directory/$ruleid
cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld | awk '{k=0;for(i=0;i<=8;i++)k+=((substr($1,i+2,1)~/[rwx]/)*2^(8-i));if(k)printf("%0o ",k);print}' | awk ' ($1>750) {print $1, $2, $10}' >>  $filetowriteto
ruleid="SV-38683r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser -a rlogin root | awk '$2!="rlogin=false" {print $1" "$2}' >>  $filetowriteto
ruleid="SV-38684r1_rule"
filetowriteto=$auto_directory/$ruleid
find / -name sshd_config -ls | awk '{print $11}' | grep -v "^#" $1 | grep -i permitrootlogin | if [[ $(wc -l) -eq 0 ]]; then find / -name sshd_config -ls | awk '{print $11}'; fi >>  $filetowriteto
ruleid="SV-38680r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser -a sugroups root | awk '$2=="sugroups=ALL"{print}' >>  $filetowriteto
ruleid="SV-38680r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser -a sugroups root | if [[ $(wc -l) -eq 0 ]]; then printf "sugroups parameter not set"; fi >>  $filetowriteto
ruleid="SV-27154r1_rule"
filetowriteto=$auto_directory/$ruleid
cat /var/adm/sulog | if [[ $(wc -l) -eq 0 ]]; then printf "SV-27154r1_rule"; fi >>  $filetowriteto
ruleid="SV-38769r1_rule"
filetowriteto=$auto_directory/$ruleid
cat /etc/passwd | awk -F':'  '$2!="!"&&$2!="*"&&length($2)>1{ print $1 }' >>  $filetowriteto
ruleid="SV-38769r1_rule"
filetowriteto=$auto_directory/$ruleid
cat /etc/security/passwd | grep password | awk '!(/{ssha/ ) && $3 != "*"{print "ssha256 not found"}' >>  $filetowriteto
ruleid="SV-38670r1_rule"
filetowriteto=$auto_directory/$ruleid
grep maxlogins /etc/security/login.cfg | grep -v \* | awk '$3>10 {print $3}' >>  $filetowriteto
ruleid="SV-38670r1_rule"
filetowriteto=$auto_directory/$ruleid
grep maxlogins /etc/security/login.cfg | grep -v \*  | if [[ $(wc -l) -eq 0 ]]; then printf "maxlogins not set"; fi >>  $filetowriteto
ruleid="SV-38932r1_rule"
filetowriteto=$auto_directory/$ruleid
grep herald /etc/security/login.cfg | grep -v \* | awk 'length($3)==0 {print "No Login Banner Set"}' >>  $filetowriteto
ruleid="SV-38932r1_rule"
filetowriteto=$auto_directory/$ruleid
grep herald /etc/security/login.cfg | grep -v \* | if [[ $(wc -l) -eq 0 ]]; then printf "herald parameter not set"; fi >>  $filetowriteto
ruleid="SV-38839r1_rule"
filetowriteto=$auto_directory/$ruleid
grep logindelay /etc/security/login.cfg | grep -v \* | if [[ $(wc -l) -eq 0 ]]; then printf "logindelay parameter not set";fi >>  $filetowriteto
ruleid="SV-38938r1_rule"
filetowriteto=$auto_directory/$ruleid
grep pwd_algorithm /etc/security/login.cfg | grep -v \* | awk '!(/ssha/ ) && $3 != "*"{print "pwd_algorithm not set to ssha256"}' >>  $filetowriteto
ruleid="SV-38938r1_rule"
filetowriteto=$auto_directory/$ruleid
grep pwd_algorithm /etc/security/login.cfg | grep -v \* | if [[ $(wc -l) -eq 0 ]]; then printf "pwd_algorithm parameter not set to ssha256"; fi >>  $filetowriteto
ruleid="SV-38741r1_rule"
filetowriteto=$auto_directory/$ruleid
grep -p usw: /etc/security/login.cfg | grep "shells =" | if [[ $(wc -l) -eq 0 ]]; then printf "shells parameter not set"; fi >>  $filetowriteto
ruleid="SV-38796r1_rule"
filetowriteto=$auto_directory/$ruleid
/usr/sbin/no -o clean_partial_conns | awk '$3==0 {print}' >>  $filetowriteto
ruleid="SV-38948r1_rule"
filetowriteto=$auto_directory/$ruleid
/usr/sbin/no -o ipsrcrouteforward | awk '$3!=0 {print}' >>  $filetowriteto
ruleid="SV-38949r1_rule"
filetowriteto=$auto_directory/$ruleid
/usr/sbin/no -o ipsrcroutesend | awk '$3!=0 {print}' >>  $filetowriteto
ruleid="SV-38827r1_rule"
filetowriteto=$auto_directory/$ruleid
/usr/sbin/no -o ip6srcrouteforward | awk '$3!=0 {print}' >>  $filetowriteto
ruleid="SV-38828r1_rule"
filetowriteto=$auto_directory/$ruleid
/usr/sbin/no -o ipsrcrouterecv | awk '$3!=0 {print}' >>  $filetowriteto
ruleid="SV-38829r1_rule"
filetowriteto=$auto_directory/$ruleid
/usr/sbin/no -o bcastping | awk '$3!=0 {print}' >>  $filetowriteto
ruleid="SV-38826r1_rule"
filetowriteto=$auto_directory/$ruleid
/usr/sbin/no -o ipsendredirects | awk '$3!=0 {print}' >>  $filetowriteto
ruleid="SV-38825r1_rule"
filetowriteto=$auto_directory/$ruleid
/usr/sbin/no -o ipignoreredirects | awk '$3!=1 {print}' >>  $filetowriteto
ruleid="SV-12536r2_rule"
filetowriteto=$auto_directory/$ruleid
lsuser ALL | awk '/SYSTEM=NONE/ {print $1}' >>  $filetowriteto
ruleid="SV-38683r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser -a rlogin root | awk '/rlogin=true/ {print $1}' >>  $filetowriteto
ruleid="SV-38671r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser ALL | awk '/loginretries=0|loginretries=1|loginretries=2/ {print $1}' >>  $filetowriteto
ruleid="SV-38768r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser ALL | awk '/minage=0/ {print $1}' >>  $filetowriteto
ruleid="SV-38939r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser ALL | awk '{if (/maxage=1|maxage=2|maxage=3|maxage=4|maxage=5|maxage=6|maxage=7|maxage=8/) {} else {print $1}}' >>  $filetowriteto
ruleid="SV-38936r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser ALL | awk '/minlen=0|minlen=1|minlen=2|minlen=3|minlen=4|minlen=5|minlen=6|minlen=7|minlen=8|minlen=9|minlen=10|minlen=11|minlen=12|minlen=13/ {print $1}' >>  $filetowriteto
ruleid="SV-39503r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser ALL | awk '/minother=0/ {print $1}' >>  $filetowriteto
ruleid="SV-38675r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser ALL | awk '{if (/maxrepeats=0|maxrepeats=1|maxrepeats=2|maxrepeats=3/) {} else {print $1}}' >>  $filetowriteto
ruleid="SV-38677r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser ALL | awk '{if (/mindiff=0|mindiff=1|mindiff=2|mindiff=3/) {print $1}}' >>  $filetowriteto
ruleid="SV-38679r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser ALL | awk '/histsize=0|histsize=1|histsize=2|histsize=3|histsize=4|histsize=5|/ {print $1}' >>  $filetowriteto
ruleid="SV-38680r1_rule"
filetowriteto=$auto_directory/$ruleid
lsuser -a sugroups root | awk '/sugroups=ALL/ {print $1}' >>  $filetowriteto
ruleid="SV-38741r1_rule"
filetowriteto=$auto_directory/$ruleid
cat /etc/shells | if [[ $(wc -l) -eq 0 ]]; then printf "/etc/shells file not created"; fi >>  $filetowriteto
ruleid="SV-38847r1_rule"
filetowriteto=$auto_directory/$ruleid
cat /etc/shells | xargs -n1 ls -l | awk '!($3=="root") && !($3=="bin") {print $3, $4, $9}' | sort | uniq -u >>  $filetowriteto
ruleid="SV-38848r1_rule"
filetowriteto=$auto_directory/$ruleid
cat /etc/shells | xargs -n1 ls -l | awk '!($4=="root") && !($4=="bin") && !($4=="sys") && !($4=="system") {print $3, $4, $9}' | sort | uniq -u >>  $filetowriteto
ruleid="SV-38848r1_rule"
filetowriteto=$auto_directory/$ruleid
find / -name "*.sh" | xargs -n1 ls -l | awk '!($4=="root") && !($4=="bin") && !($4=="sys") && !($4=="system") {print $3, $4, $9}' | sort | uniq -u >>  $filetowriteto
ruleid="SV-38846r1_rule"
filetowriteto=$auto_directory/$ruleid
cat /etc/shells | xargs -n1 ls -l | awk '{k=0;for(i=0;i<=8;i++)k+=((substr($1,i+2,1)~/[rwx]/)*2^(8-i));if(k)printf("%0o ",k);print}'| awk ' ($1>=755) {print $1, $2, $10}' >>  $filetowriteto
ruleid="SV-38846r1_rule"
filetowriteto=$auto_directory/$ruleid
grep shells /etc/security/login.cfg | grep -v \* | cut -f 2 -d = | sed s/,/\ /g | xargs -n1 ls -l | awk '{k=0;for(i=0;i<=8;i++)k+=((substr($1,i+2,1)~/[rwx]/)*2^(8-i));if(k)printf("%0o ",k);print}' | awk ' ($1>=755) {print $1, $2, $10}' >>  $filetowriteto
ruleid="SV-38848r1_rule"
filetowriteto=$auto_directory/$ruleid
grep shells /etc/security/login.cfg | grep -v \* | cut -f 2 -d = | sed s/,/\ /g | xargs -n1 ls -l | awk '!($4=="root") && !($4=="bin") && !($4=="sys") && !($4=="system") {print $3, $4, $9}' | sort | uniq -u >>  $filetowriteto
ruleid="SV-38847r1_rule"
filetowriteto=$auto_directory/$ruleid
grep shells /etc/security/login.cfg | grep -v \* | cut -f 2 -d = | sed s/,/\ /g | xargs -n1 ls -l | awk '!($3=="root") && !($3=="bin") {print $3,$4,$9}' | sort | uniq -u >>  $filetowriteto

echo "Logging records for manual checks ..."

filename="excessive_services"
filetowriteto=$manual_directory/$filename
echo "============================================" >> $filetowriteto
echo "inetd.conf file (if rshd, rexec, telnet is present it is a finding):" >> $filetowriteto
echo "============================================" >> $filetowriteto
grep -v "^#" /etc/inetd.conf >> $filetowriteto
echo "============================================" >> $filetowriteto
echo "netstat -na:" >> $filetowriteto
echo "============================================" >> $filetowriteto
netstat -na >> $filetowriteto
echo "============================================" >> $filetowriteto

filename="unneccessary_accounts"
filetowriteto=$manual_directory/$filename
echo "============================================" >> $filetowriteto
echo "/etc/passwd file (Some examples of unnecessary accounts includes guest, uucp, games, news, gopher, ftp, and lp. If any unnecessary accounts are found, this is a finding.):" >> $filetowriteto
echo "============================================" >> $filetowriteto
cat /etc/passwd>> $filetowriteto
echo "============================================" >> $filetowriteto

filename="patch_fixes"
filetowriteto=$manual_directory/$filename
echo "============================================" >> $filetowriteto
echo "Service Pack:" >> $filetowriteto
echo "============================================" >> $filetowriteto
oslevel -s >> $filetowriteto
echo "============================================" >> $filetowriteto
echo "List of fixes" >> $filetowriteto
echo "============================================" >> $filetowriteto
/usr/sbin/instfix -i >> $filetowriteto
echo "============================================" >> $filetowriteto

filename="world_writable"
filetowriteto=$manual_directory/$filename
echo "============================================" >> $filetowriteto
echo "World writable files and directories:" >> $filetowriteto
echo "============================================" >> $filetowriteto
/usr/bin/find / -perm -2 -a \( -type d -o -type f \) -exec ls -ld {} \; | grep -v "/tmp" | grep -v "/dev/null" | awk '{print $1" "$3" "$4" "$9}' >> $filetowriteto
echo "============================================" >> $filetowriteto

filename="suid"
filetowriteto=$manual_directory/$filename
echo "============================================" >> $filetowriteto
echo "SUID:" >> $filetowriteto
echo "============================================" >> $filetowriteto
/usr/bin/find / -perm -4000 -user 0 -ls | grep -v "/tmp" | grep -v "/dev/null"| awk '{print $3" "$5" "$6" "$11}' >> $filetowriteto
echo "============================================" >> $filetowriteto
echo "SGID:" >> $filetowriteto
echo "============================================" >> $filetowriteto
/usr/bin/find / -perm -2000 -user 0 -ls | grep -v "/tmp" | grep -v "/dev/null"| awk '{print $3" "$5" "$6" "$11}' >> $filetowriteto
echo "============================================" >> $filetowriteto

echo "tarring results"
tarname=$directory"_new"
tar cvzf $tarname.tar.gz $directory
if test $? -ne 0
then
tar cvf $tarname.tar $directory
fi

echo "Results has been archived"

echo "Removing directory"
rm -r $directory
echo "done"