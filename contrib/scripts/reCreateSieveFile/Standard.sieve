require ["fileinto"];
# rule:[Spam]
if anyof (header :contains "subject" "***SPAM***", header :contains "subject" "VIRUS")
{
        fileinto "INBOX.Junk";
        stop;
}
