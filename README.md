# imscp-keyhelp-migration
With this script you are able to migrate every customer from the i-MSCP server to your new KeyHelp server. Also you have the possibility to migrate multiple 
i-MSCP accounts to one KeyHelp account.

## Requirements
* run the script on the KeyHelp server
* min. phython 3.5
* i-MSCP server must have the version 1.5.3

## Required settings in KeyHelp
* SETTINGS => Configuration => Database => Allow remote access = enable
* SETTINGS => Configuration => Miscellaneous => Notifications => Send 'Email account has been setup successfully' notification = disable (enable sends for every added email address an email)
* SETTINGS => Configuration => Account Templates => Database remote access = enable
* SETTINGS => Configuration => FTP server => Custom FTP usernames = enable

## Installation packages
```
apt-get install pv sshpass python3-pip python3-requests python3-paramiko python3-distutils-extra python3-tqdm python3-setuptools python3-wheel
python3 -m pip install mysql-connector inquirer
```

## Create the RSA Key Pair as root and copy to i-MSCP server (optional)
python paramiko ssh has a problem with public key authentication if your ssh keys was not created like below (https://github.com/paramiko/paramiko/issues/340)
```
cd ~
ssh-keygen -b 4096 -m PEM -t rsa
ssh-copy-id -i .ssh/id_rsa.pub -p 22 FQDN-Remote-Server
```

## Error message of "python paramiko"
If you get some messages like the following while running the migration script:
```
CryptographyDeprecationWarning: Support for unsafe construction of public numbers from encoded data will be removed in a future version
```
Upgrade the package "paramiko" to version 2.5.0
```
pip3 install paramiko==2.5.0
```

## How to use the migration script
* apt-get install git
* git clone https://github.com/TheCry/i-mscp-keyhelp-migration
* Edit the file "migration-config.cfg" and add you credentials
* Make the file "i-mscp_keyhelp_migration.py" executable (chmod +x i-mscp_keyhelp_migration.py)
* Start the migration by running the script "i-mscp_keyhelp_migration.py" (./i-mscp_keyhelp_migration.py)

## Doings if using roundcube contact migration
* Before starting migration, note the "user_id" in the KeyHep table "users" of the database "roundcube"
* If you need to restart the migration for the same user delete all entries after the noted "user_id" the table above

## Doings if something went wrong with API communication
* First delete the new added KeyHelp user
* Check as admin whether a SSL cert was added while the last run and delete it

## Doings after migration
* Set the correct home dir of the ftp users
* Set the correct path for the htaccess users
* Check the database name, database user and database password of the websites

## Security Advice
After activating:
* SETTINGS => Configuration => Database => Allow remote access = enable
* SETTINGS => Configuration => Account Templates => Database remote access = enable

you have a security issue on your server. While migration this settings are needed. 
But if no of you customer needs a remote connection to the MySQL daemon disable this setting after migration. Otherwise use Fail2Ban to protect the MySQL Port.
For this you have to extend 2 settings:
##### Extend your MySQL settings
```
[mysqld]
log_warnings    = 2
log-error       = /var/log/mysql/error.log
```

##### Activate mysql-auth in Fail2Ban
```
[mysqld-auth]
enabled  = true
port     = 3306
filter   = mysqld-auth
action   = iptables-multiport[name=mysqld-auth, port="3306", protocol=tcp]
			sendmail-whois[name=mysqld-auth, dest="mysql-alarm@your-domain.tld"]
logpath  = /var/log/mysql/error.log
findtime = 1800
mta = sendmail
sender = fail2ban-mysql@hostname.your-domain.tld
destemail = mysql-alarm@your-domain.tld
maxretry = 2
bantime  = 259200
```

##### Restart MySQL and Fail2Ban
```
systemctl reload fail2ban.service
systemctl restart mysqld.service
```
