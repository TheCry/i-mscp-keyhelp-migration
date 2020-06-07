#!/usr/bin/python3

# apt-get install python3-requests python3-paramiko python3-distutils-extra

import requests, time, json, re, configparser, io, os, sys, idna, paramiko, mysql.connector, subprocess
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
keyhelpCreateRandomPassword = _global_config.keyhelpCreateRandomPassword
keyhelpSendloginCredentials = _global_config.keyhelpSendloginCredentials
keyhelpCreateSystemDomain = _global_config.keyhelpCreateSystemDomain
keyhelpDisableDnsForDomain = _global_config.keyhelpDisableDnsForDomain

if keyhelpDisableDnsForDomain == 'ask':
    keyhelpDisableDnsForDomain = str(keyhelpDisableDnsForDomain)
elif keyhelpDisableDnsForDomain == 'false' or keyhelpDisableDnsForDomain == 'true':
    keyhelpDisableDnsForDomain = _global_config.keyhelpDisableDnsForDomain
else:
    keyhelpDisableDnsForDomain = True

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
                    if keyhelpCreateRandomPassword:
                        print('Passwort wird automatisch generiert!')
                        keyhelpInputData.keyhelpCreateRandomPassword(keyhelpMinPasswordLenght)
                    else:
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
        _global_config.write_log('i-MSCP catchall emailadresses domain (catchall):\n' + str(
            imscpInputData.imscpDomainEmailAddressNormalCatchAll) + '\n')
        _global_config.write_log(
            'i-MSCP emailadresses domain (normal):\n' + str(imscpInputData.imscpDomainEmailAddressNormal) + '\n')
        _global_config.write_log('i-MSCP emailadresses domain (normal forward):\n' + str(
            imscpInputData.imscpDomainEmailAddressNormalForward) + '\n')
        _global_config.write_log(
            'i-MSCP emailadresses domain (forward):\n' + str(imscpInputData.imscpDomainEmailAddressForward) + '\n')
        _global_config.write_log('i-MSCP catch emailadresses sub domain (catchall):\n' + str(
            imscpInputData.imscpDomainSubEmailAddressNormalCatchAll) + '\n')
        _global_config.write_log(
            'i-MSCP emailadresses sub domain (normal):\n' + str(imscpInputData.imscpDomainSubEmailAddressNormal) + '\n')
        _global_config.write_log('i-MSCP emailadresses sub domain (normal forward):\n' + str(
            imscpInputData.imscpDomainSubEmailAddressNormalForward) + '\n')
        _global_config.write_log('i-MSCP emailadresses sub domain (forward):\n' + str(
            imscpInputData.imscpDomainSubEmailAddressForward) + '\n')
        _global_config.write_log('i-MSCP catchall emailadresses alias domains (catchall):\n' + str(
            imscpInputData.imscpAliasEmailAddressNormalCatchAll) + '\n')
        _global_config.write_log(
            'i-MSCP emailadresses alias domains (normal):\n' + str(imscpInputData.imscpAliasEmailAddressNormal) + '\n')
        _global_config.write_log('i-MSCP emailadresses alias domains (normal forward):\n' + str(
            imscpInputData.imscpAliasEmailAddressNormalForward) + '\n')
        _global_config.write_log('i-MSCP emailadresses alias domains (forward):\n' + str(
            imscpInputData.imscpAliasEmailAddressForward) + '\n')
        _global_config.write_log('i-MSCP catchall emailadresses alias sub domains (catchall):\n' + str(
            imscpInputData.imscpAliasSubEmailAddressNormalCatchAll) + '\n')
        _global_config.write_log('i-MSCP emailadresses alias sub domains (normal):\n' + str(
            imscpInputData.imscpAliasSubEmailAddressNormal) + '\n')
        _global_config.write_log('i-MSCP emailadresses alias sub domains (normal forward):\n' + str(
            imscpInputData.imscpAliasSubEmailAddressNormalForward) + '\n')
        _global_config.write_log('i-MSCP emailadresses alias sub domains (forward):\n' + str(
            imscpInputData.imscpAliasSubEmailAddressForward) + '\n')
        _global_config.write_log('i-MSCP domain databases:\n' + str(imscpInputData.imscpDomainDatabaseNames) + '\n')
        _global_config.write_log(
            'i-MSCP domain database usernames:\n' + str(imscpInputData.imscpDomainDatabaseUsernames) + '\n')

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
            print('i-MSCP catchall emailadresses domain (catchall):\n' + str(
                imscpInputData.imscpDomainEmailAddressNormalCatchAll) + '\n')
            print('i-MSCP emailadresses domain (normal):\n' + str(imscpInputData.imscpDomainEmailAddressNormal) + '\n')
            print('i-MSCP emailadresses domain (normal forward):\n' + str(
                imscpInputData.imscpDomainEmailAddressNormalForward) + '\n')
            print(
                'i-MSCP emailadresses domain (forward):\n' + str(imscpInputData.imscpDomainEmailAddressForward) + '\n')
            print('i-MSCP catch emailadresses sub domain (catchall):\n' + str(
                imscpInputData.imscpDomainSubEmailAddressNormalCatchAll) + '\n')
            print('i-MSCP emailadresses sub domain (normal):\n' + str(
                imscpInputData.imscpDomainSubEmailAddressNormal) + '\n')
            print('i-MSCP emailadresses sub domain (normal forward):\n' + str(
                imscpInputData.imscpDomainSubEmailAddressNormalForward) + '\n')
            print('i-MSCP emailadresses sub domain (forward):\n' + str(
                imscpInputData.imscpDomainSubEmailAddressForward) + '\n')
            print('i-MSCP catchall emailadresses alias domains (catchall):\n' + str(
                imscpInputData.imscpAliasEmailAddressNormalCatchAll) + '\n')
            print('i-MSCP emailadresses alias domains (normal):\n' + str(
                imscpInputData.imscpAliasEmailAddressNormal) + '\n')
            print('i-MSCP emailadresses alias domains (normal forward):\n' + str(
                imscpInputData.imscpAliasEmailAddressNormalForward) + '\n')
            print('i-MSCP emailadresses alias domains (forward):\n' + str(
                imscpInputData.imscpAliasEmailAddressForward) + '\n')
            print('i-MSCP catchall emailadresses alias sub domains (catchall):\n' + str(
                imscpInputData.imscpAliasSubEmailAddressNormalCatchAll) + '\n')
            print('i-MSCP emailadresses alias sub domains (normal):\n' + str(
                imscpInputData.imscpAliasSubEmailAddressNormal) + '\n')
            print('i-MSCP emailadresses alias sub domains (normal forward):\n' + str(
                imscpInputData.imscpAliasSubEmailAddressNormalForward) + '\n')
            print('i-MSCP emailadresses alias sub domains (forward):\n' + str(
                imscpInputData.imscpAliasSubEmailAddressForward) + '\n')
            print('i-MSCP domain databases):\n' + str(imscpInputData.imscpDomainDatabaseNames) + '\n')
            print('i-MSCP domain database users:\n' + str(imscpInputData.imscpDomainDatabaseUsernames) + '\n')

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
        keyhelpSetDisableDnsForDomain = True
        print('Adding User "' + keyhelpInputData.keyhelpData['kusername'] + '" to Keyhelp')

        keyhelpAddData.addKeyHelpDataToApi(apiEndpointClients, keyhelpInputData.keyhelpData)
        if keyhelpAddData.status:
            addedKeyHelpUserId = keyhelpAddData.keyhelpApiReturnData['keyhelpUserId']
            print('KeyHelpUser "' + keyhelpInputData.keyhelpData['kusername'] + '" added successfully.')
            print('Adding first domain "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '" to KeyHelpUser "' +
                  keyhelpInputData.keyhelpData['kusername'] + '".')
            if keyhelpDisableDnsForDomain == 'ask':
                if _global_config.ask_Yes_No('Do you want to active the dns zone for this domain [y/n]? '):
                    keyhelpSetDisableDnsForDomain = False
                else:
                    keyhelpSetDisableDnsForDomain = True

            keyhelpAddApiData = imscpInputData.imscpData
            keyhelpAddApiData['keyhelpSetDisableDnsForDomain'] = keyhelpSetDisableDnsForDomain
            keyhelpAddApiData['addedKeyHelpUserId'] = addedKeyHelpUserId

            keyhelpAddData.addKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
            if keyhelpAddData.status:
                keyHelpParentDomainId = keyhelpAddData.keyhelpApiReturnData['keyhelpDomainId']
                domainParentId = imscpInputData.imscpData['iUsernameDomainId']
                print('Domain "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '" added successfully.\n')

                # Adding sub domains for domain
                for imscpSubDomainsArrayKey, imscpSubDomainsArrayValue in imscpInputData.imscpDomainSubDomains.items():
                    # print(imscpSubDomainsArrayKey, '->', imscpSubDomainsArrayValue)
                    keyhelpAddApiData = {'addedKeyHelpUserId': addedKeyHelpUserId,
                                         'iParentDomainId': keyHelpParentDomainId,
                                         'iFirstDomainIdna': imscpInputData.imscpData['iUsernameDomainIdna']}

                    subDomainId = imscpSubDomainsArrayValue.get('iSubDomainId')
                    keyhelpAddApiData['iSubDomainIdna'] = imscpSubDomainsArrayValue.get('iSubDomainIdna')
                    keyhelpAddApiData['iSubDomainData'] = imscpSubDomainsArrayValue.get('iSubDomainData')

                    print('Adding i-MSCP sub domain "' + keyhelpAddApiData['iSubDomainIdna'] + '" to domain "' +
                          imscpInputData.imscpData['iUsernameDomainIdna'] + '".')
                    if keyhelpDisableDnsForDomain == 'ask':
                        if _global_config.ask_Yes_No('Do you want to active the dns zone for this domain [y/n]? '):
                            keyhelpSetDisableDnsForDomain = False
                        else:
                            keyhelpSetDisableDnsForDomain = True

                    keyhelpAddApiData['keyhelpSetDisableDnsForDomain'] = keyhelpSetDisableDnsForDomain

                    keyhelpAddData.addKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
                    if keyhelpAddData.status:
                        print('Sub domain "' + keyhelpAddApiData['iSubDomainIdna'] + '" added successfully.\n')
                        print('Adding email addresses for sub domain "' + keyhelpAddApiData['iSubDomainIdna'] + '".')

                        # Adding i-MSCP sub domain normal email addresses
                        for imscpEmailsSubDomainsArrayKey, imscpEmailsSubDomainsArrayValue in \
                                imscpInputData.imscpDomainSubEmailAddressNormal['subid-' + subDomainId].items():
                            # print(imscpEmailsSubDomainsArrayKey, '->', imscpEmailsSubDomainsArrayValue)
                            keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                                 'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                            if bool(imscpInputData.imscpDomainSubEmailAddressNormalCatchAll['subid-' + subDomainId]):
                                for domKey, domValue in imscpInputData.imscpDomainSubEmailAddressNormalCatchAll['subid-' + subDomainId].items():
                                    keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                            keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                            keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData[
                                'kdatabaseRootPassword']
                            keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsSubDomainsArrayValue.get('iEmailMailQuota')
                            keyhelpAddApiData['iEmailAddress'] = imscpEmailsSubDomainsArrayValue.get('iEmailAddress')
                            keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsSubDomainsArrayValue.get('iEmailMailPassword')

                            keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                            keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                            if keyhelpAddData.status:
                                print(
                                    'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.\n')
                            else:
                                _global_config.write_log(
                                    'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                                print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                        # Adding i-MSCP sub domain normal forward email addresses
                        for imscpEmailsSubDomainsArrayKey, imscpEmailsSubDomainsArrayValue in \
                                imscpInputData.imscpDomainSubEmailAddressNormalForward['subid-' + subDomainId].items():
                            # print(imscpEmailsSubDomainsArrayKey, '->', imscpEmailsSubDomainsArrayValue)
                            keyhelpAddApiData = {'emailStoreForward': True, 'iEmailCatchall': '',
                                                 'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                            if bool(imscpInputData.imscpDomainSubEmailAddressNormalCatchAll['subid-' + subDomainId]):
                                for domKey, domValue in imscpInputData.imscpDomainSubEmailAddressNormalCatchAll['subid-' + subDomainId].items():
                                    keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                            keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                            keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData[
                                'kdatabaseRootPassword']
                            keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsSubDomainsArrayValue.get('iEmailMailQuota')
                            keyhelpAddApiData['iEmailMailForward'] = imscpEmailsSubDomainsArrayValue.get('iEmailMailForward')
                            keyhelpAddApiData['iEmailAddress'] = imscpEmailsSubDomainsArrayValue.get('iEmailAddress')
                            keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsSubDomainsArrayValue.get('iEmailMailPassword')

                            keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                            keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                            if keyhelpAddData.status:
                                print(
                                    'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.\n')
                            else:
                                _global_config.write_log(
                                    'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                                print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                        # Adding i-MSCP sub domain forward email addresses
                        for imscpEmailsSubDomainsArrayKey, imscpEmailsSubDomainsArrayValue in \
                                imscpInputData.imscpDomainSubEmailAddressForward['subid-' + subDomainId].items():
                            # print(imscpEmailsSubDomainsArrayKey, '->', imscpEmailsSubDomainsArrayValue)
                            keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                                 'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': False}
                            if bool(imscpInputData.imscpDomainSubEmailAddressNormalCatchAll['subid-' + subDomainId]):
                                for domKey, domValue in imscpInputData.imscpDomainSubEmailAddressNormalCatchAll[
                                    'subid-' + subDomainId].items():
                                    keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                            # 5MB for only Forward
                            keyhelpAddApiData['iEmailMailQuota'] = '5242880'
                            keyhelpAddApiData['iEmailMailForward'] = imscpEmailsSubDomainsArrayValue.get('iEmailMailForward')
                            keyhelpAddApiData['iEmailAddress'] = imscpEmailsSubDomainsArrayValue.get('iEmailAddress')
                            # False because there is no need to update the password with an old one
                            keyhelpAddApiData['iEmailMailPassword'] = False

                            keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                            keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                            if keyhelpAddData.status:
                                print(
                                    'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.\n')
                            else:
                                _global_config.write_log(
                                    'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                                print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')
                    else:
                        _global_config.write_log('ERROR "' + keyhelpAddApiData['iSubDomainIdna'] + '" failed to add.')
                        print('ERROR "' + keyhelpAddApiData['iSubDomainIdna'] + '" failed to add.\n')

                # Adding i-MSCP domain normal email addresses
                for imscpEmailsDomainsArrayKey, imscpEmailsDomainsArrayValue in \
                        imscpInputData.imscpDomainEmailAddressNormal.items():
                    # print(imscpEmailsDomainsArrayKey, '->', imscpEmailsDomainsArrayValue)
                    keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                         'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                    if bool(imscpInputData.imscpDomainEmailAddressNormalCatchAll):
                        for domKey, domValue in imscpInputData.imscpDomainEmailAddressNormalCatchAll.items():
                            keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                    keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                    keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData['kdatabaseRootPassword']
                    keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsDomainsArrayValue.get('iEmailMailQuota')
                    keyhelpAddApiData['iEmailAddress'] = imscpEmailsDomainsArrayValue.get('iEmailAddress')
                    keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsDomainsArrayValue.get('iEmailMailPassword')

                    keyhelpAddApiData['iEmailMailInitialPassword'] = \
                        keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                    keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                    if keyhelpAddData.status:
                        print(
                            'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.\n')
                    else:
                        _global_config.write_log(
                            'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                        print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                # Adding i-MSCP domain normal forward email addresses
                for imscpEmailsDomainsArrayKey, imscpEmailsDomainsArrayValue in \
                        imscpInputData.imscpDomainEmailAddressNormalForward.items():
                    # print(imscpEmailsDomainsArrayKey, '->', imscpEmailsDomainsArrayValue)
                    keyhelpAddApiData = {'emailStoreForward': True, 'iEmailCatchall': '',
                                         'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                    if bool(imscpInputData.imscpDomainEmailAddressNormalCatchAll):
                        for domKey, domValue in imscpInputData.imscpDomainEmailAddressNormalCatchAll.items():
                            keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                    keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                    keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData['kdatabaseRootPassword']
                    keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsDomainsArrayValue.get('iEmailMailQuota')
                    keyhelpAddApiData['iEmailMailForward'] = imscpEmailsDomainsArrayValue.get('iEmailMailForward')
                    keyhelpAddApiData['iEmailAddress'] = imscpEmailsDomainsArrayValue.get('iEmailAddress')
                    keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsDomainsArrayValue.get('iEmailMailPassword')

                    keyhelpAddApiData['iEmailMailInitialPassword'] = \
                        keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                    keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                    if keyhelpAddData.status:
                        print(
                            'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.\n')
                    else:
                        _global_config.write_log(
                            'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                        print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                # Adding i-MSCP domain forward email addresses
                for imscpEmailsDomainsArrayKey, imscpEmailsDomainsArrayValue in \
                        imscpInputData.imscpDomainEmailAddressForward.items():
                    # print(imscpEmailsDomainsArrayKey, '->', imscpEmailsDomainsArrayValue)
                    keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                         'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': False}
                    if bool(imscpInputData.imscpDomainEmailAddressNormalCatchAll):
                        for domKey, domValue in imscpInputData.imscpDomainEmailAddressNormalCatchAll.items():
                            keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                    # 5MB for only Forward
                    keyhelpAddApiData['iEmailMailQuota'] = '5242880'
                    keyhelpAddApiData['iEmailMailForward'] = imscpEmailsDomainsArrayValue.get('iEmailMailForward')
                    keyhelpAddApiData['iEmailAddress'] = imscpEmailsDomainsArrayValue.get('iEmailAddress')
                    # False because there is no need to update the password with an old one
                    keyhelpAddApiData['iEmailMailPassword'] = False

                    keyhelpAddApiData['iEmailMailInitialPassword'] = \
                        keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                    keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                    if keyhelpAddData.status:
                        print(
                            'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.\n')
                    else:
                        _global_config.write_log(
                            'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                        print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')
            else:
                _global_config.write_log(
                    'ERROR "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '" failed to add.')
                print('ERROR "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '" failed to add.\n')

            # Adding i-MSCP alias domains
            for imscpDomainAliasesArrayKey, imscpDomainAliasesArrayValue in imscpInputData.imscpDomainAliases.items():
                # print(imscpDomainAliasesArrayKey, '->', imscpDomainAliasesArrayValue)
                keyhelpAddApiData = {'addedKeyHelpUserId': addedKeyHelpUserId,
                                     'iFirstDomainIdna': imscpInputData.imscpData['iUsernameDomainIdna']}
                aliasDomainParentId = imscpDomainAliasesArrayValue.get('iAliasDomainId')
                aliasDomainParentName = imscpDomainAliasesArrayValue.get('iAliasDomainIdna')
                keyhelpAddApiData['iAliasDomainIdna'] = imscpDomainAliasesArrayValue.get('iAliasDomainIdna')
                keyhelpAddApiData['iAliasDomainData'] = imscpDomainAliasesArrayValue.get('iAliasDomainData')

                print('Adding i-MSCP alias domain "' + keyhelpAddApiData['iAliasDomainIdna'] + '" to KeyHelpUser "' +
                      keyhelpInputData.keyhelpData['kusername'] + '".')
                if keyhelpDisableDnsForDomain == 'ask':
                    if _global_config.ask_Yes_No('Do you want to active the dns zone for this domain [y/n]? '):
                        keyhelpSetDisableDnsForDomain = False
                    else:
                        keyhelpSetDisableDnsForDomain = True

                keyhelpAddApiData['keyhelpSetDisableDnsForDomain'] = keyhelpSetDisableDnsForDomain

                keyhelpAddData.addKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
                if keyhelpAddData.status:
                    keyHelpParentDomainId = keyhelpAddData.keyhelpApiReturnData['keyhelpDomainId']
                    print('Domain "' + keyhelpAddApiData['iAliasDomainIdna'] + '" added successfully.\n')

                    # Adding sub domains for alias domain
                    for imscpAliasSubDomainsArrayKey, imscpAliasSubDomainsArrayValue in \
                            imscpInputData.imscpAliasSubDomains['aliasid-' + aliasDomainParentId].items():
                        # print(imscpAliasSubDomainsArrayKey, '->', imscpAliasSubDomainsArrayValue)
                        keyhelpAddApiData = {'addedKeyHelpUserId': addedKeyHelpUserId,
                                             'iParentDomainId': keyHelpParentDomainId,
                                             'iFirstDomainIdna': imscpInputData.imscpData['iUsernameDomainIdna']}

                        aliasSubDomainId = imscpAliasSubDomainsArrayValue.get('iAliasSubDomainId')
                        keyhelpAddApiData['iAliasSubDomainIdna'] = imscpAliasSubDomainsArrayValue.get('iAliasSubDomainIdna')
                        keyhelpAddApiData['iAliasSubDomainData'] = imscpAliasSubDomainsArrayValue.get('iAliasSubDomainData')

                        print('Adding i-MSCP alias sub domain "' + keyhelpAddApiData[
                            'iAliasSubDomainIdna'] + '" to alias domain "' + aliasDomainParentName + '".')
                        if keyhelpDisableDnsForDomain == 'ask':
                            if _global_config.ask_Yes_No('Do you want to active the dns zone for this domain [y/n]? '):
                                keyhelpSetDisableDnsForDomain = False
                            else:
                                keyhelpSetDisableDnsForDomain = True

                        keyhelpAddApiData['keyhelpSetDisableDnsForDomain'] = keyhelpSetDisableDnsForDomain

                        keyhelpAddData.addKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
                        if keyhelpAddData.status:
                            print('Alias sub domain "' + keyhelpAddApiData[
                                'iAliasSubDomainIdna'] + '" added successfully.\n')

                            # Adding i-MSCP alias sub domain normal email addresses
                            for imscpEmailsAliasSubDomainsArrayKey, imscpEmailsAliasSubDomainsArrayValue in \
                                    imscpInputData.imscpAliasSubEmailAddressNormal['subid-' + aliasSubDomainId].items():
                                # print(imscpEmailsAliasSubDomainsArrayKey, '->', imscpEmailsAliasSubDomainsArrayValue)
                                keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                                     'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                                if bool(imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                            'subid-' + aliasSubDomainId]):
                                    for domKey, domValue in imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                        'subid-' + aliasSubDomainId].items():
                                        keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                                keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                                keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData[
                                    'kdatabaseRootPassword']
                                keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsAliasSubDomainsArrayValue.get(
                                    'iEmailMailQuota')
                                keyhelpAddApiData['iEmailAddress'] = imscpEmailsAliasSubDomainsArrayValue.get(
                                    'iEmailAddress')
                                keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsAliasSubDomainsArrayValue.get(
                                    'iEmailMailPassword')

                                keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                    keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                                keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                                if keyhelpAddData.status:
                                    print(
                                        'Email address "' + keyhelpAddApiData[
                                            'iEmailAddress'] + '" added successfully.\n')
                                else:
                                    _global_config.write_log(
                                        'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                                    print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                            # Adding i-MSCP alias sub domain normal forward email addresses
                            for imscpEmailsAliasSubDomainsArrayKey, imscpEmailsAliasSubDomainsArrayValue in \
                                    imscpInputData.imscpAliasSubEmailAddressNormalForward[
                                        'subid-' + aliasSubDomainId].items():
                                # print(imscpEmailsAliasSubDomainsArrayKey, '->', imscpEmailsAliasSubDomainsArrayValue)
                                keyhelpAddApiData = {'emailStoreForward': True, 'iEmailCatchall': '',
                                                     'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                                if bool(imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                            'subid-' + aliasSubDomainId]):
                                    for domKey, domValue in imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                        'subid-' + aliasSubDomainId].items():
                                        keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                                keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                                keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData[
                                    'kdatabaseRootPassword']
                                keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsAliasSubDomainsArrayValue.get(
                                    'iEmailMailQuota')
                                keyhelpAddApiData['iEmailMailForward'] = imscpEmailsAliasSubDomainsArrayValue.get(
                                    'iEmailMailForward')
                                keyhelpAddApiData['iEmailAddress'] = imscpEmailsAliasSubDomainsArrayValue.get(
                                    'iEmailAddress')
                                keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsAliasSubDomainsArrayValue.get(
                                    'iEmailMailPassword')

                                keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                    keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                                keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                                if keyhelpAddData.status:
                                    print(
                                        'Email address "' + keyhelpAddApiData[
                                            'iEmailAddress'] + '" added successfully.\n')
                                else:
                                    _global_config.write_log(
                                        'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                                    print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                            # Adding i-MSCP alias sub domain forward email addresses
                            for imscpEmailsAliasSubDomainsArrayKey, imscpEmailsAliasSubDomainsArrayValue in \
                                    imscpInputData.imscpAliasSubEmailAddressForward[
                                        'subid-' + aliasSubDomainId].items():
                                # print(imscpEmailsAliasSubDomainsArrayKey, '->', imscpEmailsAliasSubDomainsArrayValue)
                                keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                                     'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': False}
                                if bool(imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                            'subid-' + aliasSubDomainId]):
                                    for domKey, domValue in imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                        'subid-' + aliasSubDomainId].items():
                                        keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                                # 5MB for only Forward
                                keyhelpAddApiData['iEmailMailQuota'] = '5242880'
                                keyhelpAddApiData['iEmailMailForward'] = imscpEmailsAliasSubDomainsArrayValue.get(
                                    'iEmailMailForward')
                                keyhelpAddApiData['iEmailAddress'] = imscpEmailsAliasSubDomainsArrayValue.get(
                                    'iEmailAddress')
                                # False because there is no need to update the password with an old one
                                keyhelpAddApiData['iEmailMailPassword'] = False

                                keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                    keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                                keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                                if keyhelpAddData.status:
                                    print(
                                        'Email address "' + keyhelpAddApiData[
                                            'iEmailAddress'] + '" added successfully.\n')
                                else:
                                    _global_config.write_log(
                                        'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                                    print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')
                        else:
                            _global_config.write_log(
                                'ERROR "' + keyhelpAddApiData['iAliasSubDomainIdna'] + '" failed to add.')
                            print('ERROR "' + keyhelpAddApiData['iAliasSubDomainIdna'] + '" failed to add.\n')

                    # Adding i-MSCP alias domain normal email addresses
                    for imscpEmailsAliasDomainsArrayKey, imscpEmailsAliasDomainsArrayValue in \
                            imscpInputData.imscpAliasEmailAddressNormal['aliasid-' + aliasDomainParentId].items():
                        # print(imscpEmailsAliasDomainsArrayKey, '->', imscpEmailsAliasDomainsArrayValue)
                        keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                             'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                        if bool(imscpInputData.imscpAliasEmailAddressNormalCatchAll):
                            for domKey, domValue in imscpInputData.imscpAliasEmailAddressNormalCatchAll['aliasid-' + aliasDomainParentId].items():
                                keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                        keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                        keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData[
                            'kdatabaseRootPassword']
                        keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsAliasDomainsArrayValue.get('iEmailMailQuota')
                        keyhelpAddApiData['iEmailAddress'] = imscpEmailsAliasDomainsArrayValue.get('iEmailAddress')
                        keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsAliasDomainsArrayValue.get(
                            'iEmailMailPassword')

                        keyhelpAddApiData['iEmailMailInitialPassword'] = \
                            keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                        keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                        if keyhelpAddData.status:
                            print(
                                'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.\n')
                        else:
                            _global_config.write_log(
                                'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                            print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                    # Adding i-MSCP alias domain normal forward email addresses
                    for imscpEmailsAliasDomainsArrayKey, imscpEmailsAliasDomainsArrayValue in \
                            imscpInputData.imscpAliasEmailAddressNormalForward[
                                'aliasid-' + aliasDomainParentId].items():
                        # print(imscpEmailsAliasDomainsArrayKey, '->', imscpEmailsAliasDomainsArrayValue)
                        keyhelpAddApiData = {'emailStoreForward': True, 'iEmailCatchall': '',
                                             'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                        if bool(imscpInputData.imscpAliasEmailAddressNormalCatchAll['aliasid-' + aliasDomainParentId]):
                            for domKey, domValue in imscpInputData.imscpAliasEmailAddressNormalCatchAll[
                                'aliasid-' + aliasDomainParentId].items():
                                keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                        keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                        keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData[
                            'kdatabaseRootPassword']
                        keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsAliasDomainsArrayValue.get('iEmailMailQuota')
                        keyhelpAddApiData['iEmailMailForward'] = imscpEmailsAliasDomainsArrayValue.get(
                            'iEmailMailForward')
                        keyhelpAddApiData['iEmailAddress'] = imscpEmailsAliasDomainsArrayValue.get('iEmailAddress')
                        keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsAliasDomainsArrayValue.get(
                            'iEmailMailPassword')

                        keyhelpAddApiData['iEmailMailInitialPassword'] = \
                            keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                        keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                        if keyhelpAddData.status:
                            print(
                                'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.\n')
                        else:
                            _global_config.write_log(
                                'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                            print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                    # Adding i-MSCP alias domain forward email addresses
                    for imscpEmailsAliasDomainsArrayKey, imscpEmailsAliasDomainsArrayValue in \
                            imscpInputData.imscpAliasEmailAddressForward['aliasid-' + aliasDomainParentId].items():
                        # print(imscpEmailsAliasDomainsArrayKey, '->', imscpEmailsAliasDomainsArrayValue)
                        keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                             'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': False}
                        if bool(imscpInputData.imscpAliasEmailAddressNormalCatchAll['aliasid-' + aliasDomainParentId]):
                            for domKey, domValue in imscpInputData.imscpAliasEmailAddressNormalCatchAll['aliasid-' + aliasDomainParentId].items():
                                keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                        # 5MB for only Forward
                        keyhelpAddApiData['iEmailMailQuota'] = '5242880'
                        keyhelpAddApiData['iEmailMailForward'] = imscpEmailsAliasDomainsArrayValue.get(
                            'iEmailMailForward')
                        keyhelpAddApiData['iEmailAddress'] = imscpEmailsAliasDomainsArrayValue.get('iEmailAddress')
                        # False because there is no need to update the password with an old one
                        keyhelpAddApiData['iEmailMailPassword'] = False

                        keyhelpAddApiData['iEmailMailInitialPassword'] = \
                            keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                        keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                        if keyhelpAddData.status:
                            print(
                                'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.\n')
                        else:
                            _global_config.write_log(
                                'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                            print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')
                else:
                    _global_config.write_log('ERROR "' + keyhelpAddApiData['iAliasDomainIdna'] + '" failed to add.')
                    print('ERROR "' + keyhelpAddApiData['iAliasDomainIdna'] + '" failed to add.\n')

            # Adding databases and database usernames
            if bool(imscpInputData.imscpDomainDatabaseNames):
                print('Start adding databses and database usernames.\n')
                keyhelpAddedDatabases = {}
                for imscpDatabasesArrayKey, imscpDatabasesArrayValue in imscpInputData.imscpDomainDatabaseNames.items():
                    # print(imscpDatabasesArrayKey, '->', imscpDatabasesArrayValue)
                    databaseParentId = imscpDatabasesArrayValue.get('iDatabaseId')
                    if re.match("^\d+", str(imscpDatabasesArrayValue.get('iDatabaseName'))):
                        keyhelpAddApiData['iDatabaseName'] = re.sub("^\d+", 'db'+str(addedKeyHelpUserId),
                                                                    str(imscpDatabasesArrayValue.get('iDatabaseName')),
                                                                    flags=re.UNICODE)
                    else:
                        keyhelpAddApiData['iDatabaseName'] = 'db'+str(addedKeyHelpUserId) + '_' + imscpDatabasesArrayValue.get(
                            'iDatabaseName')

                    keyhelpAddApiData['iOldDatabaseName'] = imscpDatabasesArrayValue.get('iDatabaseName')
                    keyhelpAddApiData['iOldDatabaseUsername'] = ''
                    keyhelpAddApiData['iDatabaseUsername'] = ''

                    keyhelpAddedDatabases[keyhelpAddApiData['iDatabaseName']] = imscpDatabasesArrayValue.get(
                        'iDatabaseName')

                    if bool(imscpInputData.imscpDomainDatabaseUsernames):
                        for dbUserKey, dbUserValue in imscpInputData.imscpDomainDatabaseUsernames.items():
                            # print(dbUserKey, '->', dbUserValue)
                            if keyhelpAddApiData['iDatabaseUsername'] == '':
                                if databaseParentId == dbUserValue.get('iDatabaseId'):
                                    if re.match("^\d+", str(dbUserValue.get('iDatabaseUsername'))):
                                        keyhelpAddApiData['iDatabaseUsername'] = re.sub("^\d+", 'dbu'+str(addedKeyHelpUserId),
                                                                                        str(dbUserValue.get(
                                                                                            'iDatabaseUsername')),
                                                                                        flags=re.UNICODE)
                                    else:
                                        keyhelpAddApiData[
                                            'iDatabaseUsername'] = 'dbu'+str(addedKeyHelpUserId) + '_' + str(dbUserValue.get(
                                            'iDatabaseUsername'))

                                    keyhelpAddApiData['iDatabaseUserHost'] = str(dbUserValue.get('iDatabaseUserHost'))
                                    keyhelpAddApiData[
                                        'iDatabaseUserPassword'] = keyhelpAddData.keyhelpCreateRandomDatabaseUserPassword(10)

                                # If an i-MSCP has only one db user we need to extend teh username
                                while True:
                                    i = 1
                                    if keyhelpAddApiData['iDatabaseUsername'] in keyhelpAddData.keyhelpAddedDbUsernames:
                                        keyhelpAddApiData['iDatabaseUsername'] = str(keyhelpAddApiData['iDatabaseUsername'])+'_'+str(i)
                                        i += 1
                                    else:
                                        break

                                keyhelpAddApiData['iOldDatabaseUsername'] = dbUserValue.get('iDatabaseUsername')

                    keyhelpAddData.addKeyHelpDataToApi(apiEndpointDatabases, keyhelpAddApiData)
                    if keyhelpAddData.status:
                        print('Database "' + keyhelpAddApiData['iDatabaseName'] + '" added successfully.\n')
                    else:
                        _global_config.write_log('ERROR "' + keyhelpAddApiData['iDatabaseName'] + '" failed to add.')
                        print('ERROR "' + keyhelpAddApiData['iDatabaseName'] + '" failed to add.\n')
        else:
            _global_config.write_log('ERROR "' + keyhelpInputData.keyhelpData['kusername'] + '" failed to add.')
            print('ERROR "' + keyhelpInputData.keyhelpData['kusername'] + '" failed to add.\n')

        if os.path.exists(logFile):
            os.rename(logFile, loggingFolder + '/' + imscpInputData.imscpData[
                'iUsernameDomainIdna'] + '_keyhelp_migration_data.log')

        print('\nAll i-MSCP data were added to KeyHelp. Check the logfile "' + imscpInputData.imscpData[
            'iUsernameDomainIdna'] + '_keyhelp_migration_data.log".')
        if _global_config.ask_Yes_No('Should we start to copy all data to the KeyHelp Server [y/n]? '):
            print('Dumping i-MSCP databases and copy on this server')
            if not os.path.exists(imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps'):
                os.makedirs(imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps')

            #### Daten welche befüllt wurden
            # imscpInputData.imscpData['iUsernameDomainId']
            # imscpInputData.imscpData['iUsernameDomain']
            # imscpInputData.imscpData['iUsernameDomainIdna']
            # imscpInputData.imscpDomainDatabaseNames
            # imscpInputData.imscpDomainDatabaseUsernames

            if keyhelpAddedDatabases:
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

                    for newDatabaseName, oldDatabaseName in keyhelpAddedDatabases.items():
                        # print(newDatabaseName, '->', oldDatabaseName)
                        # open sftp connection
                        sftp_client = client.open_sftp()
                        print(
                            'Dumping database "' + oldDatabaseName + '" to "' + imscpDbDumpFolder + '/' + oldDatabaseName + '_sql.gz".')
                        client.exec_command(
                            'mysqldump -h' + imscpInputData.imscpData['imysqlhost'] + ' -P' + imscpInputData.imscpData[
                                'imysqlport'] + ' -u' + imscpInputData.imscpData['imysqluser'] + ' -p' +
                            imscpInputData.imscpData[
                                'imysqlpassword'] + ' ' + oldDatabaseName + ' | gzip > ' + imscpDbDumpFolder + '/' + oldDatabaseName + '_sql.gz')

                        with TqdmWrap(ascii=True, unit='b', unit_scale=True) as pbar:
                            print('Transfering "' + imscpDbDumpFolder + '/' + oldDatabaseName + '_sql.gz" to ' +
                                  imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps/' + str(
                                newDatabaseName) + '__' + str(oldDatabaseName) + '_sql.gz.')

                            # Workarround for sftp - An error for the local file appears, if not exist
                            if not os.path.isfile(str(imscpInputData.imscpData['iUsernameDomainIdna']) + '_mysqldumps/' + str(newDatabaseName) + '__' + str(oldDatabaseName) + '_sql.gz'):
                                open(str(imscpInputData.imscpData['iUsernameDomainIdna']) + '_mysqldumps/' + str(newDatabaseName) + '__' + str(oldDatabaseName) + '_sql.gz', 'a').close()
                                time.sleep(1)

                            get_remote_file = sftp_client.get(str(imscpDbDumpFolder) + '/' + str(oldDatabaseName) + '_sql.gz',
                                                              str(imscpInputData.imscpData['iUsernameDomainIdna']) + '_mysqldumps/' + str(newDatabaseName) + '__' + str(oldDatabaseName) + '_sql.gz', callback=pbar.viewBar)
                        # remove the remote sql dump
                        print(
                            '\nRemoving database dump "' + imscpDbDumpFolder + '/' + oldDatabaseName + '_sql.gz" on remote server.\n')
                        client.exec_command('rm ' + imscpDbDumpFolder + '/' + oldDatabaseName + '_sql.gz')
                        _global_config.write_migration_log(
                            imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps/migration_databases.log',
                            'MySQL dump for i-MSCP database "' + oldDatabaseName + '" => ' + newDatabaseName + '__' + oldDatabaseName + '_sql.gz')

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

                #### KeyHelp Daten welche befüllt wurden
                # keyhelpInputData.keyhelpData['kdatabaseRoot']
                # keyhelpInputData.keyhelpData['kdatabaseRootPassword']
                print('Start import i-MSCP database dumps.')
                for newDatabaseName, oldDatabaseName in keyhelpAddedDatabases.items():
                    if os.path.isfile(str(imscpInputData.imscpData['iUsernameDomainIdna']) + '_mysqldumps/' + str(
                            newDatabaseName) + '__' + str(oldDatabaseName) + '_sql.gz'):
                        print('Start import i-MSCP database dump "' + str(newDatabaseName) + '__' + str(
                            oldDatabaseName) + '_sql.gz" to database "' + str(newDatabaseName) + '"')

                        os.system("zcat " + str(imscpInputData.imscpData['iUsernameDomainIdna']) + "_mysqldumps/" + str(
                            newDatabaseName) + "__" + str(oldDatabaseName) + "_sql.gz | mysql -u" + str(
                            keyhelpInputData.keyhelpData['kdatabaseRoot']) + " -p" + str(
                            keyhelpInputData.keyhelpData['kdatabaseRootPassword']) + " " + str(newDatabaseName))

                print('\nStart syncing emails.... Please wait')
                for rsyncEmailAddress in keyhelpAddData.keyhelpAddedEmailAddresses:
                    emailAddressData = rsyncEmailAddress.split("@")
                    emailAddressData[1].strip()
                    if imscpSshPublicKey:
                        cmd = 'rsync -aHAXSz --info=progress --numeric-ids -e "ssh -i ' + imscpSshPublicKey + ' -p ' + \
                                imscpSshPort + ' -q" --rsync-path="rsync" --exclude={"dovecot.sieve"} ' + \
                                imscpSshUsername + '@' + imscpServerFqdn + ':/var/mail/virtual/' + \
                                emailAddressData[1] + '/' + emailAddressData[0] + '/ /var/mail/vhosts/' + \
                                emailAddressData[1] + '/' + emailAddressData[0] + '/'
                    else:
                        cmd = 'rsync -aHAXSz --info=progress --numeric-ids -e "sshpass -p ' + imscpRootPassword + ' ssh -p ' + \
                              imscpSshPort + ' -q" --rsync-path="rsync" --exclude={"dovecot.sieve"} ' + \
                              imscpSshUsername + '@' + imscpServerFqdn + ':/var/mail/virtual/' + \
                              emailAddressData[1] + '/' + emailAddressData[0] + '/ /var/mail/vhosts/' + \
                              emailAddressData[1] + '/' + emailAddressData[0] + '/'
                    proc = subprocess.Popen(cmd, shell=True,    stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    while True:
                        output = proc.stdout.readline().decode('utf-8')
                        if not output:
                            break
                        if '-chk' in str(output):
                            m = re.findall(r'-chk=(\d+)/(\d+)', str(output))
                            total_files = int(m[0][1])
                            progress = (100 * (int(m[0][1]) - int(m[0][0]))) / total_files
                            sys.stdout.write('\rSyncing of emails for ' + str(rsyncEmailAddress) + ' done: ' + str(round(progress, 2)) + '%')
                            sys.stdout.flush()
                            if int(m[0][0]) == 0:
                                break
                    print('\nFinished syncing email address "' + str(rsyncEmailAddress) + '".')
                    os.system('chown -R vmail:vmail /var/mail/vhosts/' + emailAddressData[1] + '/' + emailAddressData[
                        0] + '/')
                    print('System owner for email address "' + str(rsyncEmailAddress) + '". successfully updated.\n')
                    time.sleep(1)
            else:
                print('No databases available for the i-MSCP domain ' + imscpInputData.imscpData['iUsernameDomain'])
        else:
            print('Migration stopped!')
    else:
        print('Migration stopped!')
