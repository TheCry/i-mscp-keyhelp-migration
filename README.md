# imscp-keyhelp-migration
Mit diesem Script kann man einzelne Kunden zu KeyHelp migrieren.
Das Script ist noch in der Entwicklung und nicht Produktiv!

## Requirements
* min. phython 3.5
* run the script on the KeyHelp server

## Required settings in KeyHelp
* SETTINGS => Configuration => Database => Allow remote access = enable
* SETTINGS => Configuration => Miscellaneous => Notifications => Send 'Email account has been setup successfully' notification = disable
* SETTINGS => Configuration => Account Templates => Database remote access = enable
* SETTINGS => Configuration => FTP server => Custom FTP usernames = enable

## Installation packages
```
apt-get install pv sshpass python3-requests python3-paramiko python3-distutils-extra
python3 -m pip install mysql-connector
```

## Create the RSA Key Pair as root and copy to i-MSCP server (optional)
python paramiko ssh has a problem mit public key authentication if your ssh keys was not created like below (https://github.com/paramiko/paramiko/issues/340)
```
cd ~
ssh-keygen -b 4096 -m PEM -t rsa
ssh-copy-id -i .ssh/id_rsa.pub -p 22 FQDN-Remote-Server
```
## Doings if something went wrong with API communication
* First delete the new added KeyHelp user
* Check as admin wheter a SSL cert was added while the last run and delete it

## Doings after migration
* Set the correct home dir of the ftp users
* Set the correct path for the htaccess users
* Check the database name, database user and database password of the websites