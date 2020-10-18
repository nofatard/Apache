#!/bin/bash


#Describtion: Set a CentOS 7 server for troubleshooting practice.
#Author: Serge 
#Date: August 2020


echo -e "\nChecking the network configuration ...\n"
sleep 2
ping  google.com  -c4 >/dev/null 2>&1

if [ $? -ne 0 ]
then
echo -e "\nplease check your network and make sure you can succesfully ping google.com"
exit 1
fi
echo "Installing packages "

rm -rf /var/run/yum.pid
yum install lsof netstat nginx httpd -y
yum install python-pip -y
pip install flask

echo -e "\Port configuration\n"

systemctl start firewalld
systemctl enable firewalld
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --reload

echo "Configure user Carlos"

id u2082020 || useradd -d /home/u2082020 -s /bin/bash -c "Carlos Montero"  u2082020 -m 
echo "u2082020:school123" | chpasswd
#service nginx start

#if [ $? -eq 0 ]

#then
#  echo " nginx started successfully"
#  sleep 3
#fi


if  [ -f app.py ] 
then 
   echo ""
else 
echo -e "\n Creating the python app\n"

cat > app.py << "EOF"
from flask import Flask
app = Flask(__name__)

@app.route('/')
@app.route('/hello')
def helloWorld():
    return "Hello World"

if __name__ == '__main__':
    app.debug = True
    app.run(host = '0.0.0.0' , port = 80 )
EOF

fi

if [ -d /opt/deployment/dev/ ]
then 
  echo ""
else
   echo -e "\n Creating the deployment directory\n"
 
   mkdir -p /opt/deployment/dev/
fi

if [ -f /opt/deployment/dev/deploy.cfg ]
then 
   echo ""
else

   echo -e "\n Creating the deployment file\n"
sleep 2
cat > /opt/deployment/dev/deploy.cfg << "EOF"
### Section 1: Global Environment
      #
      ServerType standalone
      ServerRoot "/etc/httpd"
      PidFile /var/run/httpd.pid
      ResourceConfig /dev/null
      AccessConfig /dev/null
      Timeout 300
      KeepAlive On
      MaxKeepAliveRequests 0
      KeepAliveTimeout 15
      MinSpareServers 16
      MaxSpareServers 64
      StartServers 16
      MaxClients 512
      MaxRequestsPerChild 100000

      ### Section 2: 'Main' server configuration
      #
      Port 80

      <IfDefine SSL>
      Listen 80
      Listen 443
      </IfDefine>

      User www
      Group www
      ServerAdmin admin@openna.com
      ServerName www.openna.com
      DocumentRoot "/home/httpd/ona"

      <Directory />
      Options None
      AllowOverride None
      Order deny,allow
      Deny from all
      </Directory>

      <Directory "/home/httpd/ona">
      Options None
      AllowOverride None
      Order allow,deny
      Allow from all
      </Directory>

      <Files .pl>
      Options None
      AllowOverride None
      Order deny,allow
      Deny from all
      </Files>

      <IfModule mod_dir.c>
      DirectoryIndex index.htm index.html index.php index.php3 default.html index.cgi
      </IfModule>

      #<IfModule mod_include.c>
      #Include conf/mmap.conf
      #</IfModule>

      UseCanonicalName On

      <IfModule mod_mime.c>
      TypesConfig /etc/httpd/conf/mime.types
      </IfModule>

      DefaultType text/plain
      HostnameLookups Off

      ErrorLog /var/log/httpd/error_log
      LogLevel warn
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
      SetEnvIf Request_URI \.gif$ gif-image
      CustomLog /var/log/httpd/access_log combined env=!gif-image
      ServerSignature Off

      <IfModule mod_alias.c>
      ScriptAlias /cgi-bin/  "/home/httpd/cgi-bin/"
      <Directory "/home/httpd/cgi-bin">
      AllowOverride None
      Options None
      Order allow,deny
      Allow from all
      </Directory>
      </IfModuleGT;

      <IfModule mod_mime.c>
      AddEncoding x-compress Z
      AddEncoding x-gzip gz tgz

      AddType application/x-tar .tgz
      </IfModule>

      ErrorDocument 500 "The server made a boo boo.
      ErrorDocument 404 http://192.168.1.1/error.htm
      ErrorDocument 403 "Access Forbidden -- Go away.

      <IfModule mod_setenvif.c>
      BrowserMatch "Mozilla/2" nokeepalive
      BrowserMatch "MSIE 4\.0b2;" nokeepalive downgrade-1.0 force-response-1.0
      BrowserMatch "RealPlayer 4\.0" force-response-1.0
      BrowserMatch "Java/1\.0" force-response-1.0
      BrowserMatch "JDK/1\.0" force-response-1.0
      </IfModule>

      ### Section 3: Virtual Hosts
      #
      <IfDefine SSL>
      AddType application/x-x509-ca-cert .crt
      AddType application/x-pkcs7-crl    .crl
      </IfDefine>

      <IfModule mod_ssl.c>
      SSLPassPhraseDialog     builtin
      SSLSessionCache         dbm:/var/run/ssl_scache
      SSLSessionCacheTimeout  300

      SSLMutex  file:/var/run/ssl_mutex

      SSLRandomSeed startup builtin
      SSLRandomSeed connect builtin

      SSLLog      /var/log/httpd/ssl_engine_log
      SSLLogLevel warn
      </IfModule>

      <IfDefine SSL>
      <VirtualHost _default_:443>

      DocumentRoot "/home/httpd/ona"
      ServerName www.openna.com
      ServerAdmin admin@openna.com
      ErrorLog /var/log/httpd/error_log

      SSLEngine on
      SSLCipherSuite ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL

      SSLCertificateFile      /etc/ssl/certs/server.crt
      SSLCertificateKeyFile   /etc/ssl/private/server.key
      SSLCACertificatePath    /etc/ssl/certs
      SSLCACertificateFile    /etc/ssl/certs/ca.crt
      SSLCARevocationPath     /etc/ssl/crl
      SSLVerifyClient none
      SSLVerifyDepth  10

      SSLOptions +ExportCertData +StrictRequire
      SetEnvIf User-Agent ".*MSIE.*" nokeepalive ssl-unclean-shutdown
      SetEnvIf Request_URI \.gif$ gif-image
      CustomLog /var/log/httpd/ssl_request_log \
      "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b" env=!gif-image
      </VirtualHost>
      </IfDefine>
EOF

fi

[ -d /root/scripts ] || mkdir /root/scripts

cat > /root/scripts/java << "EOF"
#!/bin/bash

while cat /opt/deployment/dev/deploy.cfg ; read line
do

echo $line
done
EOF

chmod +x /root/scripts/java


echo -e "\n Setting up the cron jobs\n"
grep server_troubleshoot.sh /var/spool/cron/root || echo "@reboot /root/scripts/server_troubleshoot.sh" >> /var/spool/cron/root
grep java /var/spool/cron/root || echo "@reboot /root/scripts/java" >> /var/spool/cron/root


if [ -f /home/u2082020/AppRun ]
then
  echo ""
else 
echo "sha1sum /dev/zero &" > /home/u2082020/AppRun
chown u2082020:u2082020 /home/u2082020/AppRun
chmod +x /home/u2082020/AppRun
pkill AppRun || runuser u2082020 -c '/home/u2082020/AppRun'
fi


python app.py &
