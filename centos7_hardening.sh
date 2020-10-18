#!/bin/bash

## Hardenning script for centos7 servers
##Author: Serge March 2019
##Modified: Jun 2020

AUDITDIR="/tmp/$(HOSTNAME)_audit"
TIME="$(date +%F_%T)"

mkdir -p $AUDITOR

echo "Disabling Lagacy Filesystems"

cat > /etc/modprobe.d/CIS.conf << "EOF"
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squahfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

echo "Removing GCC compiler..."

yum -y remove gcc*

echo "Removing legacy services..."

yum -y remove rsh-server rsh ypserv tftp tftp-server talk talk-server telnet-server xinetd >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling LDAP..."

yum -y remove openldap-servers >> $AUDITDIR/service_remove_$TIME.log
yum -y remove openldap-clients >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling DNS..."

yum -y remove bind >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling FTP Server..."

yum -y remove vsftpd >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling Dovecot..."

yum -y remove dovecot >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling Samba..."

yum -y remove samba >> $AUDITDIR/service_remove_$TIME.log
echo "Disabling HTTP Proxy Server..."

yum -y remove squid >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling SNMP..."

yum -y remove net-snmp >> $AUDITDIR/service_remove_$TIME.log

echo "Setting Daemon umask..."

cp /etc/init.d/functions $AUDITDIR/functions_$TIME.bak
echo "umask 027" >> /etc/init.d/functions

echo "Disabling Unnecessary Services..."

servicelist=(dhcpd avahi-daemon cups nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd)
for i in ${servicelist[@]}; do
  [ $(systemctl disable $i 2> /dev/null) ] || echo "$i is Disabled"
done

echo "Upgrading password hashing algorithm to SHA512..."

authconfig --passalgo=sha512 --update


echo "Setting core dump security limits..."

echo '* hard core 0' > /etc/security/limits.conf
echo "Generating additional logs..."
echo 'auth,user.* /var/log/user' >> /etc/rsyslog.conf
echo 'kern.* /var/log/kern.log' >> /etc/rsyslog.conf
echo 'daemon.* /var/log/daemon.log' >> /etc/rsyslog.conf
echo 'syslog.* /var/log/syslog' >> /etc/rsyslog.conf
echo 'lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log' >> /etc/rsyslog.conf
touch /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chmod og-rwx /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chown root:root /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log

echo "Enabling auditd service..."

systemctl enable auditd

echo "Configuring Audit Log Storage Size..."

cp -a /etc/audit/auditd.conf /etc/audit/auditd.conf.bak
sed -i 's/^space_left_action.*$/space_left_action = SYSLOG/' /etc/audit/auditd.conf
sed -i 's/^action_mail_acct.*$/action_mail_acct = root/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action.*$/admin_space_left_action = SYSLOG/' /etc/audit/auditd.conf

echo "Setting audit rules..."

cat > /etc/audit/audit.rules << "EOF"
-D
-b 320

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

-w /etc/sudoers -p wa -k scope

-w /var/log/sudo.log -p wa -k actions

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-e 2
EOF
echo "Configuring Cron and Anacron..."
yum -y install cronie-anacron >> $AUDITDIR/service_install_$TIME.log
systemctl enable crond
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
/bin/rm -f /etc/cron.deny

echo "Creating Banner..."
sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" /etc/ssh/sshd_config
cp -p /etc/issue.net $AUDITDIR/issue.net_$TIME.bak
cat > /etc/issue.net << 'EOF'
/------------------------------------------------------------------------\
|                       *** NOTICE TO USERS ***                          |
|                                                                        |
| This computer system is the private property of YOUR_COMPANY_NAME      |
| It is for authorized use only.                                         |
|                                                                        |
| Users (authorized or unauthorized) have no explicit or implicit        |
| expectation of privacy.                                                |
|                                                                        |
| Any or all uses of this system and all files on this system may be     |
| intercepted, monitored, recorded, copied, audited, inspected, and      |
| disclosed to your employer, to authorized site, government, and law    |
| enforcement personnel, as well as authorized officials of government   |
| agencies, both domestic and foreign.                                   |
|                                                                        |
| By using this system, the user consents to such interception,          |
| monitoring, recording, copying, auditing, inspection, and disclosure   |
| at the discretion of such personnel or officials.  Unauthorized or     |
| improper use of this system may result in civil and criminal penalties |
| and administrative or disciplinary action, as appropriate. By          |
| continuing to use this system you indicate your awareness of and       |
| consent to these terms and conditions of use. LOG OFF IMMEDIATELY if   |
| you do not agree to the conditions stated in this warning.             |
\------------------------------------------------------------------------/
EOF
cp -p /etc/motd /etc/motd_$TIME.bak
cat > /etc/motd << 'EOF'
YOUR_COMPANY_NAME AUTHORIZED USE ONLY
EOF

echo "Configuring SSH..."
cp /etc/ssh/sshd_config $AUDITDIR/sshd_config_$TIME.bak
sed -i 's/#LogLevel INFO/LogLevel VERBOSE/g' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/g' /etc/ssh/sshd_config
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g' /etc/ssh/sshd_config
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config

