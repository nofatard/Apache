#!/bin/bash

#Reset User password

for items in $(cat /var/tmp/usernames);
do
echo "password" | passwd $items --stdin
passwd -e $items
done

