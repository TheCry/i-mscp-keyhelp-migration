#!/usr/bin/perl -w
# Need to install apt-get install liblchown-perl
use strict;
use File::Path qw(make_path);
use File::Copy;
use Lchown;
my $uid = getpwnam 'vmail';
my $gid = getgrnam 'vmail';
my @domainDirsEmailAccounts = glob "/var/mail/vhosts/*/*";
my $standardSieveFile ='./Standard.sieve';
my $error;
if (!-f $standardSieveFile)
{
        print "The template file $standardSieveFile does not exist\n";
        exit;
}
foreach my $domainDirsEmailAccount (@domainDirsEmailAccounts)
{
        $error = 0;
        print "Checking email domain: $domainDirsEmailAccount!\n";
        if (!-d $domainDirsEmailAccount.'/sieve')
        {
                print "\tFolder $domainDirsEmailAccount/sieve not found. Will create it now!\n";
                if(!make_path($domainDirsEmailAccount.'/sieve', { verbose => 0, mode => 0700, owner => 'vmail', group => 'vmail' }))
                {
                        print "\tError while creating folder: $domainDirsEmailAccount/sieve !\n";
                        $error = 1;
                } else {
                        print "\tFolder $domainDirsEmailAccount/sieve created successfully.\n";
                }
        } else {
                print "\tFolder $domainDirsEmailAccount/sieve exists!\n";
        }
        if($error == 0)
        {
                if (!-f $domainDirsEmailAccount.'/sieve/Standard.sieve')
                {
                        print "\t\tMissing file $domainDirsEmailAccount/sieve/Standard.sieve ! Will copy now!\n";
                        copy($standardSieveFile,$domainDirsEmailAccount."/sieve/Standard.sieve");
                        print "\t\tFile $domainDirsEmailAccount/sieve/Standard.sieve copied successfully!\n";
                        chown $uid, $gid, $domainDirsEmailAccount."/sieve/Standard.sieve";
                        chmod 0600, $domainDirsEmailAccount."/sieve/Standard.sieve";
                        print "\t\tFile owner set to vmail:vmail!\n";
                }
                if (!-l $domainDirsEmailAccount.'/sieve/active.sieve')
                {
                        print "\t\tMissing symbolic link $domainDirsEmailAccount/sieve/active.sieve ! Will create now!\n";
                        chdir "$domainDirsEmailAccount/sieve";
                        symlink("Standard.sieve", "active.sieve");
                        print "\t\tSymbolic link $domainDirsEmailAccount/sieve/active.sieve created successfully!\n";
                        lchown $uid, $gid, $domainDirsEmailAccount."/sieve/active.sieve";
                        print "\t\tFile owner set to vmail:vmail!\n";
                }
        }
}
