import ast
import configparser
import os
from distutils.util import strtobool

config = configparser.ConfigParser()
config.read('migration-config.cfg')

# General
configSection = str(config['general']['configSection'])
loggingFolder = '.'
logfolderfolders = str(config['general']['neededScriptFolders'])
logfolderfolders = ast.literal_eval(logfolderfolders)

for key, value in logfolderfolders.items():
	if key == 'logfolder':
		loggingFolder = value

logFile = str(loggingFolder+'/'+config['general']['logFile'])

# KeyHelp
apiServerFqdn = str(config['keyhelp']['apiServerFqdn'])
apiKey = str(config['keyhelp']['apiKey'])
apiTimeout = int(config['keyhelp']['apiTimeout'])
keyhelpMinPasswordLenght = int(config['keyhelp']['keyhelpMinPasswordLenght'])
apiServerFqdnVerify = bool(strtobool(str(config['keyhelp']['apiServerFqdnVerify'])))
showDebug = bool(strtobool(str(config['general']['showDebug'])))
keyhelpConfigfile = str(config['keyhelp']['keyhelpConfigfile'])
keyhelpSleeptime = str(config['keyhelp']['keyhelpSleeptime'])
keyhelpDefaultHostingplan = str(config['keyhelp']['keyhelpDefaultHostingplan'])
keyhelpCreateRandomPassword = str(config['keyhelp']['keyhelpCreateRandomPassword'])
keyhelpSendloginCredentials = str(config['keyhelp']['keyhelpSendloginCredentials'])
keyhelpCreateSystemDomain = str(config['keyhelp']['keyhelpCreateSystemDomain'])
keyhelpDisableDnsForDomain = str(config['keyhelp']['keyhelpDisableDnsForDomain'])
if keyhelpDisableDnsForDomain == 'ask':
	keyhelpDisableDnsForDomain = str(keyhelpDisableDnsForDomain)
elif keyhelpDisableDnsForDomain == 'false' or keyhelpDisableDnsForDomain == 'true':
	keyhelpDisableDnsForDomain = bool(strtobool(str(config['keyhelp']['keyhelpDisableDnsForDomain'])))
else:
	keyhelpDisableDnsForDomain = False

# i-MSCP
imscpServerFqdn = str(config['imscp-'+configSection]['imscpServerFqdn'])
imscpSshUsername = str(config['imscp-'+configSection]['imscpSshUsername'])
imscpSshPort = int(config['imscp-'+configSection]['imscpSshPort'])
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
	global loggingFolder, logFile, keyhelpSleeptime, keyhelpDefaultHostingplan, keyhelpSendloginCredentials, \
		keyhelpCreateSystemDomain, keyhelpDisableDnsForDomain, apiServerFqdn, apiKey, apiTimeout, \
		keyhelpMinPasswordLenght, apiServerFqdnVerify, showDebug, keyhelpConfigfile, imscpServerFqdn, imscpSshUsername, \
		imscpSshPort, imscpSshTimeout, imscpRootPassword, imscpSshPublicKey, imscpDbDumpFolder, \
		keyhelpCreateRandomPassword
