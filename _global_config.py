import os, configparser, ast
from distutils.util import strtobool

config = configparser.ConfigParser()
config.read('migration-config.cfg')

#### General ####
configSection = str(config['general']['configSection'])
loggingFolder = '.'
logfolderfolders = str(config['general']['neededScriptFolders'])
logfolderfolders = ast.literal_eval(logfolderfolders)

for key, value in logfolderfolders.items():
	if key == 'logfolder':
		loggingFolder = value

logFile = str(loggingFolder+'/'+config['general']['logFile'])

keyhelpDefaultHostingplan = str(config['general']['keyhelpDefaultHostingplan'])
keyhelpSendloginCredentials = str(config['general']['keyhelpSendloginCredentials'])
keyhelpCreateSystemDomain = str(config['general']['keyhelpCreateSystemDomain'])
keyhelpActivateDnsForDomain = str(config['general']['keyhelpActivateDnsForDomain'])
if keyhelpActivateDnsForDomain == 'ask':
	keyhelpActivateDnsForDomain = str(keyhelpActivateDnsForDomain)
elif keyhelpActivateDnsForDomain == 'false' or keyhelpActivateDnsForDomain == 'true':
	keyhelpActivateDnsForDomain = bool(strtobool(str(config['general']['keyhelpActivateDnsForDomain'])))
else:
	keyhelpActivateDnsForDomain = False

#### KeyHelp ####
apiServerFqdn = str(config['keehelp-'+configSection]['apiServerFqdn'])
apiKey = str(config['keehelp-'+configSection]['apiKey'])
apiTimeout = int(config['keehelp-'+configSection]['apiTimeout'])
keyhelpMinPasswordLenght = int(config['keehelp-'+configSection]['keyhelpMinPasswordLenght'])
apiServerFqdnVerify = bool(strtobool(str(config['keehelp-'+configSection]['apiServerFqdnVerify'])))
showDebug = bool(strtobool(str(config['general']['showDebug'])))
keyhelpConfigfile = str(config['keehelp-'+configSection]['keyhelpConfigfile'])

#### i-MSCP ####
imscpServerFqdn = str(config['imscp-'+configSection]['imscpServerFqdn'])
imscpSshUsername = str(config['imscp-'+configSection]['imscpSshUsername'])
imscpSshPort = str(config['imscp-'+configSection]['imscpSshPort'])
imscpSshTimeout = int(config['imscp-'+configSection]['imscpSshTimeout'])
imscpRootPassword = str(config['imscp-'+configSection]['imscpRootPassword'])
imscpSshPublicKey = str(config['imscp-'+configSection]['imscpSshPublicKey'])
imscpDbDumpFolder = str(config['imscp-'+configSection]['imscpDbDumpFolder'])

def createNeededScriptFolders():
	for folderKey, folderName in logfolderfolders.items():
		if not os.path.exists(folderName):
			os.makedirs(folderName)

def write_log(*logData):
	logFileOutputFile = open(logFile, "a+")
	line = ' '.join([str(a) for a in logData])
	logFileOutputFile.write(line+'\n')
	logFileOutputFile.close()

def write_migration_log(migrationLogfile,*logData):
	logFileOutputFile = open(migrationLogfile, "a+")
	line = ' '.join([str(a) for a in logData])
	logFileOutputFile.write(line+'\n')
	logFileOutputFile.close()


def ask_Yes_No(answer):
	yes = set(['yes', 'y', 'ye', ''])
	no = set(['no', 'n'])

	while True:
		choice = input(answer).lower()
		if choice in yes:
			return True
		elif choice in no:
			return False
		else:
			print('Please respond with "yes" or "no"')

def init():
    global loggingFolder, logFile, keyhelpDefaultHostingplan, keyhelpSendloginCredentials, keyhelpCreateSystemDomain, keyhelpActivateDnsForDomain, \
    apiServerFqdn, apiKey, apiTimeout, keyhelpMinPasswordLenght, apiServerFqdnVerify, showDebug, keyhelpConfigfile, \
    imscpServerFqdn, imscpSshUsername, imscpSshPort, imscpSshTimeout, imscpRootPassword, imscpSshPublicKey, imscpDbDumpFolder
