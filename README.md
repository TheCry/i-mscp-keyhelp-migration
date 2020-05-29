# imscp-keyhelp-migration
Mit diesem Script kann man einzelne Kunden zu KeyHelp migrieren.
Das Script ist noch in der Entwicklung und nicht Produktiv!

## Requirements
* min. phython 3.5
* run the script on the KeyHelp server

## Installation packages
```
apt-get install python3-requests python3-paramiko python3-distutils-extra
python3 -m pip install mysql-connector
```

## Create the RSA Key Pair as root and copy to i-MSCP server (optional)
python paramiko ssh has a problem mit public key authentication if your ssh keys were not created like below (https://github.com/paramiko/paramiko/issues/340)
```
cd ~
ssh-keygen -b 4096 -m PEM -t rsa
ssh-copy-id -i .ssh/id_rsa.pub -p 22 FQDN-Remote-Server
```
