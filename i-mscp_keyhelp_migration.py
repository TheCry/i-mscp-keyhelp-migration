#!/usr/bin/python3

# apt-get install python3-requests python3-paramiko python3-distutils-extra

import requests, time, json, re, configparser, io, os, sys, idna, paramiko, mysql.connector
from distutils.util import strtobool
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, SSHException
from mysql.connector import errorcode

import _global_config

_global_config.init()
_global_config.createNeededScriptFolders()

#### General ####
loggingFolder = _global_config.loggingFolder
logFile = _global_config.logFile
keyhelpDefaultHostingplan = _global_config.keyhelpDefaultHostingplan
keyhelpSendloginCredentials = _global_config.keyhelpSendloginCredentials
keyhelpCreateSystemDomain = _global_config.keyhelpCreateSystemDomain
keyhelpActivateDnsForDomain = _global_config.keyhelpActivateDnsForDomain

if keyhelpActivateDnsForDomain == 'ask':
    keyhelpActivateDnsForDomain = str(keyhelpActivateDnsForDomain)
elif keyhelpActivateDnsForDomain == 'false' or keyhelpActivateDnsForDomain == 'true':
    keyhelpActivateDnsForDomain = _global_config.keyhelpActivateDnsForDomain
else:
    keyhelpActivateDnsForDomain = False

#### General ####
showDebug = _global_config.showDebug

#### KeyHelp ####
apiServerFqdn = _global_config.apiServerFqdn
apiKey = _global_config.apiKey
apiTimeout = _global_config.apiTimeout
keyhelpMinPasswordLenght = _global_config.keyhelpMinPasswordLenght
apiServerFqdnVerify = _global_config.apiServerFqdnVerify
keyhelpConfigfile = _global_config.keyhelpConfigfile

#### i-MSCP ####
imscpServerFqdn = _global_config.imscpServerFqdn
imscpSshUsername = _global_config.imscpSshUsername
imscpSshPort = _global_config.imscpSshPort
imscpSshTimeout = _global_config.imscpSshTimeout
imscpRootPassword = _global_config.imscpRootPassword
imscpSshPublicKey = _global_config.imscpSshPublicKey
imscpDbDumpFolder = _global_config.imscpDbDumpFolder

if not apiServerFqdnVerify:
    from urllib3.exceptions import InsecureRequestWarning

    # Suppress only the single warning from urllib3 needed.
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

apiUrl = 'https://' + apiServerFqdn + '/api/v1/'
apiEndpointServer = 'server'
apiEndpointClients = 'clients'
apiEndpointHostingplans = 'hosting-plans'
apiEndpointDomains = 'domains'
apiEndpointCertificates = 'certificates'
apiEndPointEmails = 'emails'
apiEndpointDatabases = 'databases'
apiEndpointFtpusers = 'ftp-users'
headers = {
    'X-API-Key': apiKey
}

try:
    from tqdm import tqdm
except ImportError:
    class TqdmWrap(object):
        # tqdm not installed - construct and return dummy/basic versions
        def __init__(self, *a, **k):
            pass

        def viewBar(self, a, b):
            # original version
            if b < 1:
                b = 1

            res = a / int(b) * 100
            sys.stdout.write('\rTranfer Complete precent: %.2f %%' % (res))
            sys.stdout.flush()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
else:
    class TqdmWrap(tqdm):
        def viewBar(self, a, b):
            self.total = int(b)
            self.update(int(a - self.n))  # update pbar with increment

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    if not sys.version_info >= (3, 5, 3):
        print('Python version too low. You need min. 3.5.3')
        print('Your version is: ' + str(sys.version_info))
        exit(1)

    print('Starting migration i-MSCP to KeyHelp\n')

    if os.path.exists(logFile):
        os.remove(logFile)

    ##### Start get KeyHelp information #####
    from _keyhelp import KeyhelpGetData, KeyHelpAddDataToServer

    keyhelpInputData = KeyhelpGetData()
    try:
        responseApi = requests.get(apiUrl + apiEndpointServer + '/', headers=headers, timeout=apiTimeout,
                                   verify=apiServerFqdnVerify)
        apiGetData = responseApi.json()
        if responseApi.status_code == 200:
            # print (responseApi.text)
            if not keyhelpInputData.getServerDatabaseCredentials(keyhelpConfigfile):
                exit(1)

            _global_config.write_log('Debug KeyHelp informations:\nKeyHelp API Login successfull\n')
            print('KeyHelp API Login successfull.')
            keyhelpInputData.getServerInformations(apiGetData)
            print('Checking wheter Default hostingplan "' + keyhelpDefaultHostingplan + '" exist.')
            if keyhelpInputData.checkExistDefaultHostingplan(keyhelpDefaultHostingplan):
                if showDebug:
                    print('\nDebug KeyHelp informations:\n' + str(keyhelpInputData.keyhelpData) + '\n')
                while not keyhelpInputData.keyhelpDataComplete():
                    while not keyhelpInputData.checkExistKeyhelpUsername(
                            input("Geben Sie einen KeyHelp Usernamen an: ")):
                        continue
                    while not keyhelpInputData.KeyhelpPassword(input(
                            "Geben Sie einen KeyHelp Passwwort ein (min. " + str(
                                keyhelpMinPasswordLenght) + " Zeichen): "), keyhelpMinPasswordLenght):
                        continue
                    while not keyhelpInputData.KeyhelpEmailaddress(input("Geben Sie eine Emailadresse ein: ")):
                        continue
                    while not keyhelpInputData.KeyhelpSurname(input("Geben Sie eine Vornamen ein: ")):
                        continue
                    while not keyhelpInputData.KeyhelpName(input("Geben Sie eine Nachnamen ein: ")):
                        continue
                    while not keyhelpInputData.KeyhelpHostingplan(input(
                            "Welcher Hostingplan soll genutzt werden (Enter um den Default Hostingplan zu nutzen)? ")):
                        continue

                print('Alle KeyHelp Daten sind nun komplett.\n\n')
                _global_config.write_log('Debug KeyHelp informations:\n' + str(keyhelpInputData.keyhelpData) + '\n')
                _global_config.write_log('======================= End data for KeyHelp =======================\n\n\n')

                if showDebug:
                    print('\nDebug KeyHelp informations:\n' + str(keyhelpInputData.keyhelpData) + '\n')
            else:
                exit(1)
        else:
            _global_config.write_log("KeyHelp API Message: %i - %s, Message %s" % (
                responseApi.status_code, responseApi.reason, apiGetData['message']) + "\n")
            print("KeyHelp API Message: %i - %s, Message %s" % (
                responseApi.status_code, responseApi.reason, apiGetData['message']))
            exit(1)
    except requests.Timeout as e:
        _global_config.write_log("KeyHelp API Message: " + str(e) + "\n")
        print("KeyHelp API Message: " + str(e))
        exit(1)

    ##### Start get i-MSCP information #####

    from _imscp import imscpGetData

    imscpInputData = imscpGetData()
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        while not imscpInputData.imscpDataComplete():
            imscpInputData.getImscpMySqlCredentials(client)
            while not imscpInputData.getImscpUserWebData(input("Geben Sie den i-MSCP Benutzernamen ein: "), client):
                continue

        print('Alle i-MSCP Daten sind nun komplett.\n')

        _global_config.write_log('\nDebug i-MSCP informations:\n' + str(imscpInputData.imscpData) + '\n')
        _global_config.write_log('i-MSCP sub domains:\n' + str(imscpInputData.imscpDomainSubDomains) + '\n')
        _global_config.write_log('i-MSCP alias domains:\n' + str(imscpInputData.imscpDomainAliases) + '\n')
        _global_config.write_log('i-MSCP alias sub domains:\n' + str(imscpInputData.imscpAliasSubDomains) + '\n')
        _global_config.write_log(
            'i-MSCP emailadresses domain (normal):\n' + str(imscpInputData.imscpDomainEmailAddressNormal) + '\n')
        _global_config.write_log('i-MSCP emailadresses domain (normal forward):\n' + str(
            imscpInputData.imscpDomainEmailAddressNormalForward) + '\n')
        _global_config.write_log(
            'i-MSCP emailadresses domain (forward):\n' + str(imscpInputData.imscpDomainEmailAddressForward) + '\n')
        _global_config.write_log(
            'i-MSCP emailadresses sub domain (normal):\n' + str(imscpInputData.imscpDomainSubEmailAddressNormal) + '\n')
        _global_config.write_log('i-MSCP emailadresses sub domain (normal forward):\n' + str(
            imscpInputData.imscpDomainSubEmailAddressNormalForward) + '\n')
        _global_config.write_log('i-MSCP emailadresses sub domain (forward):\n' + str(
            imscpInputData.imscpDomainSubEmailAddressForward) + '\n')
        _global_config.write_log(
            'i-MSCP emailadresses alias domains (normal):\n' + str(imscpInputData.imscpAliasEmailAddressNormal) + '\n')
        _global_config.write_log('i-MSCP emailadresses alias domains (normal forward):\n' + str(
            imscpInputData.imscpAliasEmailAddressNormalForward) + '\n')
        _global_config.write_log('i-MSCP emailadresses alias domains (forward):\n' + str(
            imscpInputData.imscpAliasEmailAddressForward) + '\n')
        _global_config.write_log('i-MSCP emailadresses alias sub domains (normal):\n' + str(
            imscpInputData.imscpAliasSubEmailAddressNormal) + '\n')
        _global_config.write_log('i-MSCP emailadresses alias sub domains (normal forward):\n' + str(
            imscpInputData.imscpAliasSubEmailAddressNormalForward) + '\n')
        _global_config.write_log('i-MSCP emailadresses alias sub domains (forward):\n' + str(
            imscpInputData.imscpAliasSubEmailAddressForward) + '\n')
        _global_config.write_log('i-MSCP domain databases):\n' + str(imscpInputData.imscpDomainDatabases) + '\n')
        _global_config.write_log(
            'i-MSCP domain database usernames:\n' + str(imscpInputData.imscpDomainDatabaseUsers) + '\n')

        if os.path.exists(
                loggingFolder + '/' + imscpInputData.imscpData['iUsernameDomainIdna'] + '_get_data_from_imscp.log'):
            os.remove(
                loggingFolder + '/' + imscpInputData.imscpData['iUsernameDomainIdna'] + '_get_data_from_imscp.log')
        if os.path.exists(logFile):
            os.rename(logFile, loggingFolder + '/' + imscpInputData.imscpData[
                'iUsernameDomainIdna'] + '_get_data_from_imscp.log')

        if showDebug:
            print('\nDebug i-MSCP informations:\n' + str(imscpInputData.imscpData) + '\n')
            print('i-MSCP sub domains:\n' + str(imscpInputData.imscpDomainSubDomains) + '\n')
            print('i-MSCP alias domains:\n' + str(imscpInputData.imscpDomainAliases) + '\n')
            print('i-MSCP alias sub domains:\n' + str(imscpInputData.imscpAliasSubDomains) + '\n')
            print('i-MSCP emailadresses domain (normal):\n' + str(imscpInputData.imscpDomainEmailAddressNormal) + '\n')
            print('i-MSCP emailadresses domain (normal forward):\n' + str(
                imscpInputData.imscpDomainEmailAddressNormalForward) + '\n')
            print(
                'i-MSCP emailadresses domain (forward):\n' + str(imscpInputData.imscpDomainEmailAddressForward) + '\n')
            print('i-MSCP emailadresses sub domain (normal):\n' + str(
                imscpInputData.imscpDomainSubEmailAddressNormal) + '\n')
            print('i-MSCP emailadresses sub domain (normal forward):\n' + str(
                imscpInputData.imscpDomainSubEmailAddressNormalForward) + '\n')
            print('i-MSCP emailadresses sub domain (forward):\n' + str(
                imscpInputData.imscpDomainSubEmailAddressForward) + '\n')
            print('i-MSCP emailadresses alias domains (normal):\n' + str(
                imscpInputData.imscpAliasEmailAddressNormal) + '\n')
            print('i-MSCP emailadresses alias domains (normal forward):\n' + str(
                imscpInputData.imscpAliasEmailAddressNormalForward) + '\n')
            print('i-MSCP emailadresses alias domains (forward):\n' + str(
                imscpInputData.imscpAliasEmailAddressForward) + '\n')
            print('i-MSCP emailadresses alias sub domains (normal):\n' + str(
                imscpInputData.imscpAliasSubEmailAddressNormal) + '\n')
            print('i-MSCP emailadresses alias sub domains (normal forward):\n' + str(
                imscpInputData.imscpAliasSubEmailAddressNormalForward) + '\n')
            print('i-MSCP emailadresses alias sub domains (forward):\n' + str(
                imscpInputData.imscpAliasSubEmailAddressForward) + '\n')
            print('i-MSCP domain databases):\n' + str(imscpInputData.imscpDomainDatabases) + '\n')
            print('i-MSCP domain database users:\n' + str(imscpInputData.imscpDomainDatabaseUsers) + '\n')

    except AuthenticationException:
        print('Authentication failed, please verify your credentials!')
        exit(1)
    except SSHException as sshException:
        print("Unable to establish SSH connection: %s" % sshException)
        exit(1)
    except BadHostKeyException as badHostKeyException:
        print("Unable to verify server's host key: %s" % badHostKeyException)
        exit(1)
    finally:
        client.close()

    print('\nWe are ready to start. Check the logfile "' + imscpInputData.imscpData[
        'iUsernameDomainIdna'] + '_get_data_from_imscp.log".')

    if _global_config.ask_Yes_No('Do you want to start now [y/n]? '):
        #### KeyHelp Daten welche befüllt wurden
        # keyhelpInputData.keyhelpData['kdatabaseRoot']
        # keyhelpInputData.keyhelpData['kdatabaseRootPassword']
        # keyhelpInputData.keyhelpData['kipaddresses']
        # keyhelpInputData.keyhelpData['kusername']
        # keyhelpInputData.keyhelpData['kpassword']
        # keyhelpInputData.keyhelpData['kemailaddress']
        # keyhelpInputData.keyhelpData['ksurname']
        # keyhelpInputData.keyhelpData['kname']
        # keyhelpInputData.keyhelpData['kdefaulthostingplan']
        # keyhelpInputData.keyhelpData['kdefaulthostingplanid']
        # keyhelpInputData.keyhelpData['khostingplan']
        # keyhelpInputData.keyhelpData['khostingplanid']
        keyhelpAddData = KeyHelpAddDataToServer()
        keyhelpSetDnsForDomain = False
        print('Adding User "' + keyhelpInputData.keyhelpData['kusername'] + '" to Keyhelp')
        keyhelpAddData.addKeyHelpDataToApi(apiEndpointClients, keyhelpInputData.keyhelpData)
        if keyhelpAddData.status:
            addedKeyHelpUserId = keyhelpAddData.keyhelpApiReturnData['keyhelpUserId']
            print('KeyHelpUser "' + keyhelpInputData.keyhelpData['kusername'] + '" added successfully.')
            print('Adding first domain "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '" to KeyHelpUser "' +
                  keyhelpInputData.keyhelpData['kusername'] + '".')
            if keyhelpActivateDnsForDomain == 'ask':
                if _global_config.ask_Yes_No('Do you want to active the dns zone for this domain [y/n]? '):
                    keyhelpSetDnsForDomain = False
                else:
                    keyhelpSetDnsForDomain = True

            keyhelpAddApiData = imscpInputData.imscpData
            keyhelpAddApiData['keyhelpSetDnsForDomain'] = keyhelpSetDnsForDomain
            keyhelpAddApiData['addedKeyHelpUserId'] = addedKeyHelpUserId
            keyhelpAddData.addKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
            if keyhelpAddData.status:
                keyHelpParentDomainId = keyhelpAddData.keyhelpApiReturnData['keyhelpDomainId']
                print('Domain "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '" added successfully.\n')

                # Adding sub domains for domain
                for imscpSubDomainsArrayKey, imscpSubDomainsArrayValue in imscpInputData.imscpDomainSubDomains.items():
                    # print(imscpSubDomainsArrayKey, '->', imscpSubDomainsArrayValue)
                    keyhelpAddApiData = {}
                    keyhelpAddApiData['addedKeyHelpUserId'] = addedKeyHelpUserId
                    keyhelpAddApiData['iParentDomainId'] = keyHelpParentDomainId
                    for subDomainKey, subSomainValue in imscpSubDomainsArrayValue.items():
                        # print(subDomainKey, '->', subSomainValue)
                        if subDomainKey == 'iSubDomainIdna':
                            keyhelpAddApiData['iSubDomainIdna'] = subSomainValue
                        if subDomainKey == 'iSubDomainData':
                            keyhelpAddApiData['iSubDomainData'] = subSomainValue

                    print('Adding i-MSCP sub domain "' + keyhelpAddApiData['iSubDomainIdna'] + '" to domain "' +
                          imscpInputData.imscpData['iUsernameDomainIdna'] + '".')
                    if keyhelpActivateDnsForDomain == 'ask':
                        if _global_config.ask_Yes_No('Do you want to active the dns zone for this domain [y/n]? '):
                            keyhelpSetDnsForDomain = False
                        else:
                            keyhelpSetDnsForDomain = True

                    keyhelpAddApiData['keyhelpSetDnsForDomain'] = keyhelpSetDnsForDomain
                    keyhelpAddData.addKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
                    if keyhelpAddData.status:
                        print('Sub domain "' + keyhelpAddApiData['iSubDomainIdna'] + '" added successfully.\n')
                    # TODO: Adding sub domain email addresses to KeyHelp
                    else:
                        _global_config.write_log('ERROR "' + keyhelpAddApiData['iSubDomainIdna'] + '" failed to add.')
                        print('ERROR "' + keyhelpAddApiData['iSubDomainIdna'] + '" failed to add.\n')

            # TODO: Adding domain email addresses to KeyHelp
            else:
                _global_config.write_log(
                    'ERROR "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '" failed to add.')
                print('ERROR "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '" failed to add.\n')

            # Adding i-MSCP alias domains
            for imscpDomainAliasesArrayKey, imscpDomainAliasesArrayValue in imscpInputData.imscpDomainAliases.items():
                # print(imscpDomainAliasesArrayKey, '->', imscpDomainAliasesArrayValue)
                keyhelpAddApiData = {}
                aliasDomainParentId = ''
                keyhelpAddApiData['addedKeyHelpUserId'] = addedKeyHelpUserId
                for domainAliasKey, domainAliasValue in imscpDomainAliasesArrayValue.items():
                    # print(domainAliasKey, '->', domainAliasValue)
                    if domainAliasKey == 'iAliasDomainId':
                        aliasDomainParentId = domainAliasValue
                    if domainAliasKey == 'iAliasDomainIdna':
                        aliasDomainParentName = domainAliasValue
                        keyhelpAddApiData['iAliasDomainIdna'] = domainAliasValue
                    if domainAliasKey == 'iAliasDomainData':
                        keyhelpAddApiData['iAliasDomainData'] = domainAliasValue

                print('Adding i-MSCP alias domain "' + keyhelpAddApiData['iAliasDomainIdna'] + '" to KeyHelpUser "' +
                      keyhelpInputData.keyhelpData['kusername'] + '".')
                if keyhelpActivateDnsForDomain == 'ask':
                    if _global_config.ask_Yes_No('Do you want to active the dns zone for this domain [y/n]? '):
                        keyhelpSetDnsForDomain = False
                    else:
                        keyhelpSetDnsForDomain = True

                keyhelpAddApiData['keyhelpSetDnsForDomain'] = keyhelpSetDnsForDomain
                keyhelpAddData.addKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
                if keyhelpAddData.status:
                    keyHelpParentDomainId = keyhelpAddData.keyhelpApiReturnData['keyhelpDomainId']
                    print('Domain "' + keyhelpAddApiData['iAliasDomainIdna'] + '" added successfully.\n')

                    # Adding sub domains for alias domain
                    for imscpAliasSubDomainsArrayKey, imscpAliasSubDomainsArrayValue in \
                            imscpInputData.imscpAliasSubDomains['aliasid-' + aliasDomainParentId].items():
                        # print(imscpAliasSubDomainsArrayKey, '->', imscpAliasSubDomainsArrayValue)
                        keyhelpAddApiData = {}
                        keyhelpAddApiData['addedKeyHelpUserId'] = addedKeyHelpUserId
                        keyhelpAddApiData['iParentDomainId'] = keyHelpParentDomainId
                        for subAliasSubDomainKey, subAliasSubDomainValue in imscpAliasSubDomainsArrayValue.items():
                            # print(subAliasSubDomainKey, '->', subAliasSubDomainValue)
                            if subAliasSubDomainKey == 'iAliasSubDomainIdna':
                                keyhelpAddApiData['iAliasSubDomainIdna'] = subAliasSubDomainValue
                            if subAliasSubDomainKey == 'iAliasSubDomainData':
                                keyhelpAddApiData['iAliasSubDomainData'] = subAliasSubDomainValue

                        print('Adding i-MSCP alias sub domain "' + keyhelpAddApiData[
                            'iAliasSubDomainIdna'] + '" to alias domain "' + aliasDomainParentName + '".')
                        if keyhelpActivateDnsForDomain == 'ask':
                            if _global_config.ask_Yes_No('Do you want to active the dns zone for this domain [y/n]? '):
                                keyhelpSetDnsForDomain = False
                            else:
                                keyhelpSetDnsForDomain = True

                        keyhelpAddApiData['keyhelpSetDnsForDomain'] = keyhelpSetDnsForDomain
                        keyhelpAddData.addKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
                        if keyhelpAddData.status:
                            print('Alias sub domain "' + keyhelpAddApiData[
                                'iAliasSubDomainIdna'] + '" added successfully.\n')
                        # TODO: Adding alias sub domain email addresses to KeyHelp
                        else:
                            _global_config.write_log(
                                'ERROR "' + keyhelpAddApiData['iAliasSubDomainIdna'] + '" failed to add.')
                            print('ERROR "' + keyhelpAddApiData['iAliasSubDomainIdna'] + '" failed to add.\n')

                # TODO: Adding alias domain email addresses to KeyHelp
                else:
                    _global_config.write_log('ERROR "' + keyhelpAddApiData['iAliasDomainIdna'] + '" failed to add.')
                    print('ERROR "' + keyhelpAddApiData['iAliasDomainIdna'] + '" failed to add.\n')
        else:
            _global_config.write_log('ERROR "' + keyhelpInputData.keyhelpData['kusername'] + '" failed to add.')
            print('ERROR "' + keyhelpInputData.keyhelpData['kusername'] + '" failed to add.\n')

        # TODO: Remove this exit
        exit()
        print('Dumping i-MSCP databases and copy on this server')
        if not os.path.exists(imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps'):
            os.makedirs(imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps')

        #### Daten welche befüllt wurden
        # imscpInputData.imscpData['iUsernameDomainId']
        # imscpInputData.imscpData['iUsernameDomain']
        # imscpInputData.imscpData['iUsernameDomainIdna']
        # imscpInputData.imscpDomainDatabaseNames
        # imscpInputData.imscpDomainDatabaseUsernames

        if imscpInputData.imscpDomainDatabases:
            try:
                if os.path.exists(
                        imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps/migration_database.log'):
                    os.remove(imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps/migration_database.log')

                client = paramiko.SSHClient()
                client.load_system_host_keys()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                if imscpSshPublicKey:
                    client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                                   key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
                else:
                    client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                                   password=imscpRootPassword, timeout=imscpSshTimeout)

                # Create MySQL dump folder if not exist
                print('Check remote MySQL dump folder wheter exists. If not, i will create it!\n')
                client.exec_command('test ! -d ' + imscpDbDumpFolder + ' && mkdir -p ' + imscpDbDumpFolder)

                for databaseKey, databaseValue in imscpInputData.imscpDomainDatabases.items():
                    # print(databaseKey, '->', databaseValue)
                    if databaseKey == 'iDatabaseName':
                        # open sftp connection
                        sftp_client = client.open_sftp()
                        print(
                            'Dumping database "' + databaseValue + '" to "' + imscpDbDumpFolder + '/' + databaseValue + '_sql.gz".')
                        client.exec_command(
                            'mysqldump -h' + imscpInputData.imscpData['imysqlhost'] + ' -P' + imscpInputData.imscpData[
                                'imysqlport'] + ' -u' + imscpInputData.imscpData['imysqluser'] + ' -p' +
                            imscpInputData.imscpData[
                                'imysqlpassword'] + ' ' + databaseValue + ' | gzip > ' + imscpDbDumpFolder + '/' + databaseValue + '_sql.gz')

                        with TqdmWrap(ascii=True, unit='b', unit_scale=True) as pbar:
                            print('Transfering "' + imscpDbDumpFolder + '/' + databaseValue + '_sql.gz" to ' +
                                  imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps/' + time.strftime(
                                "%d%m%Y") + '_' + databaseValue + '_sql.gz.')
                            get_remote_file = sftp_client.get(imscpDbDumpFolder + '/' + databaseValue + '_sql.gz',
                                                              imscpInputData.imscpData[
                                                                  'iUsernameDomainIdna'] + '_mysqldumps/' + time.strftime(
                                                                  "%d%m%Y") + '_' + databaseValue + '_sql.gz',
                                                              callback=pbar.viewBar)
                        # remove the remote sql dump
                        print(
                            '\nRemoving database dump "' + imscpDbDumpFolder + '/' + databaseValue + '_sql.gz" on remote server.\n')
                        client.exec_command('rm ' + imscpDbDumpFolder + '/' + databaseValue + '_sql.gz')
                        _global_config.write_migration_log(
                            imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps/migration_databases.log',
                            'MySQL dump for i-MSCP database "' + databaseValue + '" => ' + time.strftime(
                                "%d%m%Y") + '_' + databaseValue + '_sql.gz')
            except AuthenticationException:
                print('Authentication failed, please verify your credentials!')
                exit(1)
            except SSHException as sshException:
                print("Unable to establish SSH connection: %s" % sshException)
                exit(1)
            except BadHostKeyException as badHostKeyException:
                print("Unable to verify server's host key: %s" % badHostKeyException)
                exit(1)
            finally:
                client.close()
        else:
            print('No databases available for the i-MSCP domain ' + imscpInputData.imscpData['iUsernameDomain'])
    else:
        print('Migration stopped!')
