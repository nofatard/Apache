#!/bin/bash


#Description: Docker installation on CentOS7 

#AUthor: Serge K
#Date: sept 2019
#Modified: Jan 2020
#Modified: May 2020


### Uninstall old versions if exist on the system 


echo -e "\n Checking if your server is connected to the network...."

sleep 4

ping google.com -c 4  > /dev/null 2>&1

if 
  [[ ${?} -ne 0 ]]
 then
 echo -e "\nPlease verify that your server is connected!!\n"
 exit 2
 fi

echo -e "\n Uninstalling Older version of Docker...."

sleep 4
yum remove docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate  docker-logrotate docker-engine -y

## Install required packages

echo -e "\n Installing required packages...."

sleep 4

yum install -y yum-utils device-mapper-persistent-data lvm2

## Set up repository

echo -e "\n Setting up Docker repository...."

sleep 4

echo "nameserver 8.8.8.8" >> /etc/resolv.conf

yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

yum-config-manager --enable docker-ce-nightly
yum-config-manager --enable docker-ce-test
yum-config-manager --enable docker-ce-edge


## Install Docker 

echo -e "\n Installing Docker...."

sleep 4

yum install docker-ce docker-ce-cli containerd.io -y 

##Start docker daemons

echo -e "\n Starting docker Daemon..."

sleep 4

systemctl start docker

systemctl enable docker

#Creating User for Docker 

echo -e "\n Creating user dockeruser\n"

useradd dockeruser -G docker -s /bin/bash  -m
echo "school1" | passwd --stdin dockeruser

##Checking if installtion successful

echo -e "\n Checking if installation went well"

sleep 4

docker ps  > /dev/null 2>&1

  if 
    [[ ${?} -eq 0 ]]
  then
   echo -e "\n The installtion was successfull!!"
   echo -e "\nyou can now start using Docker...\n\n\n"
   echo -e "\nPlease run the command: su - dockeruser and start using docker\n\n"
  else
  echo "please verify that the installation is done correctly or that the docker daemon is started."
  exit 1
  fi
exit 0
