#!/bin/bash


root_user()
{

  if  

     [ ${UID} -ne 0 ]
  then
echo -e "\nOnly root user can execute this script \n"
  exit 1
fi
}


root_user


echo -n " What daemon do you intend to work on? "

read D


echo -n "what do you want to do with that daemon? " 


read ANS 

sleep 3


    if 

         [ ${ANS} == status ]

then 

echo -e "\nwe are checking the status of your daemon\n"


sleep 3

service ${D} status

elif 


     [ ${ANS} == start ]

then

echo -e "\nStarting the daemon\n"

sleep 3

service ${D} start

elif 

     [ ${ANS} == stop ]

then

echo -e "\nStoping the daemon\n"

sleep 3

service $D stop


elif

     [ ${ANS} == restart ]

then

echo -e "\nRestarting the daemon\n"

sleep 3

service $D restart

elif 

    [ ${ANS} != status ] && [ ${ANS} != start ] && [ ${ANS} != stop ] && [ ${ANS} != restart ]

then

echo -e "\n Invalid entry please choose one of these 'start|status|stop|restart' \n"
exit 99
fi 
