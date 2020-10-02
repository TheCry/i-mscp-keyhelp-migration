# Contribtions
* reCreateSieveFile.pl

## reCreateSieveFile.pl
With this script you can recreate a sieve file for every email mailbox to move spam and virus emails directly to the junk folder.
The Script copies the "Standard.sieve" file in the correct folder and creates a symbolic link "active.sieve" (active.sieve -> Standard.sieve).

#### Required packages
* liblchown-perl

#### Installation packages
```
apt-get install liblchown-perl
```

#### Using the script
```
perl reCreateSieveFile.pl
```
