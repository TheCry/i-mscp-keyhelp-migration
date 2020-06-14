#!/usr/bin/python3

from __future__ import division
import os
import paramiko
import re
import requests
import subprocess
import sys
import time
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, SSHException
from tqdm import tqdm

import _global_config

_global_config.init()
_global_config.createNeededScriptFolders()

# General
showDebug = _global_config.showDebug
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

# KeyHelp
apiServerFqdn = _global_config.apiServerFqdn
apiKey = _global_config.apiKey
apiTimeout = _global_config.apiTimeout
keyhelpMinPasswordLenght = _global_config.keyhelpMinPasswordLenght
apiServerFqdnVerify = _global_config.apiServerFqdnVerify
keyhelpConfigfile = _global_config.keyhelpConfigfile

# i-MSCP
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
            print('Checking whether Default hostingplan "' + keyhelpDefaultHostingplan + '" exist.')
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
        _global_config.write_log('i-MSCP domain FTP users):\n' + str(imscpInputData.imscpFtpUserNames) + '\n')
        _global_config.write_log('i-MSCP SSL certs:\n' + str(imscpInputData.imscpSslCerts) + '\n')
        _global_config.write_log('i-MSCP HTACCESS users:\n' + str(imscpInputData.imscpDomainHtAcccessUsers) + '\n')

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
            print('i-MSCP domain FTP users):\n' + str(imscpInputData.imscpFtpUserNames) + '\n')
            print('i-MSCP SSL certs:\n' + str(imscpInputData.imscpSslCerts) + '\n')
            print('i-MSCP HTACCESS users:\n' + str(imscpInputData.imscpDomainHtAcccessUsers) + '\n')

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
            # Check whether the system user was added by KeyHelp
            loop_starts = time.time()
            while True:
                now = time.time()
                sys.stdout.write('\rWaiting since {0} seconds for Keyhelp. KeyHelp user was not added yet!'.format(
                    int(now - loop_starts)))
                sys.stdout.flush()
                time.sleep(1)
                getUid = os.system('id ' + str(keyhelpInputData.keyhelpData['kusername'].lower()) + ' > /dev/null 2>&1')
                if getUid == 0:
                    break
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
                print('Domain "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '" added successfully.')

                # Adding ftp users
                if bool(imscpInputData.imscpFtpUserNames):
                    print('\nStart adding FTP users.')
                    for ftpUserKey, ftpUserValue in imscpInputData.imscpFtpUserNames.items():
                        # print(ftpUserKey, '->', ftpUserValue)
                        keyhelpAddApiData = {'iFtpUsername': str(ftpUserValue.get('iFtpUsername')),
                                             'iFtpUserPassword': str(ftpUserValue.get('iFtpUserPassword')),
                                             'iFtpUserHomeDir': imscpInputData.imscpData['iUsernameDomainIdna'],
                                             'iOldFtpUserHomeDir': str(ftpUserValue.get('iFtpUserHomeDir')),
                                             'addedKeyHelpUserId': addedKeyHelpUserId,
                                             'iFtpInitialPassword': keyhelpAddData.keyhelpCreateRandomFtpPassword(
                                                 keyhelpMinPasswordLenght),
                                             'kdatabaseRoot': keyhelpInputData.keyhelpData['kdatabaseRoot'],
                                             'kdatabaseRootPassword': keyhelpInputData.keyhelpData[
                                                 'kdatabaseRootPassword']}
                        keyhelpAddData.addKeyHelpDataToApi(apiEndpointFtpusers, keyhelpAddApiData)
                        if keyhelpAddData.status:
                            print('FTP user "' + keyhelpAddApiData['iFtpUsername'] + '" added successfully.\n')
                        else:
                            _global_config.write_log('ERROR "' + keyhelpAddApiData['iFtpUsername'] + '" failed to add.')
                            print('ERROR "' + keyhelpAddApiData['iFtpUsername'] + '" failed to add.\n')
                else:
                    print('No FTP users to add.\n')

                # Adding htaccess users
                if bool(imscpInputData.imscpDomainHtAcccessUsers):
                    print('\nStart adding HTACCESS users.')
                    for HtAccessUserKey, HtAccessUserValue in imscpInputData.imscpDomainHtAcccessUsers.items():
                        # print(HtAccessUserKey, '->', HtAccessUserValue)
                        keyhelpAddApiData = {'iHtAccessUserame': str(HtAccessUserValue.get('iHtAccessUserame')),
                                             'iHtAccessPassword': str(HtAccessUserValue.get('iHtAccessPassword')),
                                             'iHtAccessPath': '/home/users/' + str(
                                                 keyhelpInputData.keyhelpData['kusername'].lower()) + '/www/' + str(
                                                 imscpInputData.imscpData['iUsernameDomainIdna']),
                                             'iHtAccessAuthName': 'Migrated from i-MSCP - ' + str(
                                                 HtAccessUserValue.get('iHtAccessUserame')),
                                             'addedKeyHelpUserId': addedKeyHelpUserId,
                                             'kdatabaseRoot': keyhelpInputData.keyhelpData['kdatabaseRoot'],
                                             'kdatabaseRootPassword': keyhelpInputData.keyhelpData[
                                                 'kdatabaseRootPassword']}

                        keyhelpAddData.addHtAccessUsersFromImscp(keyhelpAddApiData)
                        print('HTACCESS user "' + keyhelpAddApiData['iHtAccessUserame'] + '" added successfully.\n')
                else:
                    print('No HTACCESS users to add.\n')

                if bool(imscpInputData.imscpSslCerts['domainid-' + imscpInputData.imscpData['iUsernameDomainId']]):
                    # Adding SSL cert if exist
                    print('\nAdding SSL cert for domain "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '".')
                    for imscpSslKey, imscpSslValue in imscpInputData.imscpSslCerts[
                        'domainid-' + imscpInputData.imscpData['iUsernameDomainId']].items():
                        # print(imscpSslKey, '->', imscpSslValue)
                        keyhelpAddApiData = {'addedKeyHelpUserId': addedKeyHelpUserId,
                                             'keyhelpDomainId': keyhelpAddData.keyhelpApiReturnData[
                                                 'keyhelpDomainId'],
                                             'iSslDomainIdna': imscpInputData.imscpData['iUsernameDomainIdna'],
                                             'iSslPrivateKey': imscpSslValue.get('iSslPrivateKey'),
                                             'iSslCertificate': imscpSslValue.get('iSslCertificate'),
                                             'iSslCaBundle': imscpSslValue.get('iSslCaBundle'),
                                             'iSslHstsMaxAge': imscpSslValue.get('iSslHstsMaxAge')}

                        if imscpSslValue.get('iSslAllowHsts') == 'on':
                            keyhelpAddApiData['iSslAllowHsts'] = 'true'
                        else:
                            keyhelpAddApiData['iSslAllowHsts'] = 'false'
                        if imscpSslValue.get('iSslHstsIncludeSubdomains') == 'on':
                            keyhelpAddApiData['iSslHstsIncludeSubdomains'] = 'true'
                        else:
                            keyhelpAddApiData['iSslHstsIncludeSubdomains'] = 'false'

                    keyhelpAddData.addKeyHelpDataToApi(apiEndpointCertificates, keyhelpAddApiData)
                    if keyhelpAddData.status:
                        print('SSL cert for domain "' + keyhelpAddApiData['iSslDomainIdna'] + '" added successfully.')
                        print('Update "' + keyhelpAddApiData['iSslDomainIdna'] + '" with SSL cert.')

                        keyhelpAddApiData['keyhelpSslId'] = keyhelpAddData.keyhelpApiReturnData[
                            'keyhelpSslId']

                        keyhelpAddData.updateKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
                        if keyhelpAddData.status:
                            print('Domain "' + keyhelpAddApiData[
                                'iSslDomainIdna'] + '" updated succesfully with SSL cert.')
                        else:
                            _global_config.write_log(
                                'ERROR updating "' + keyhelpAddApiData['iSslDomainIdna'] + '" with SSL cert.')
                            print('ERROR updating "' + keyhelpAddApiData['iSslDomainIdna'] + '" with SSL cert.\n')
                    else:
                        _global_config.write_log(
                            'ERROR SSL cert for "' + keyhelpAddApiData['iSslDomainIdna'] + '" failed to add.')
                        print('ERROR SSL cert for "' + keyhelpAddApiData['iSslDomainIdna'] + '" failed to add.\n')

                print('\nAdding email addresses for domain "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '".')
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
                            'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.')
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
                            'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.')
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
                            'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.')
                    else:
                        _global_config.write_log(
                            'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                        print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                # Adding sub domains for domain
                for imscpSubDomainsKey, imscpSubDomainsValue in imscpInputData.imscpDomainSubDomains.items():
                    # print(imscpSubDomainsKey, '->', imscpSubDomainsValue)
                    keyhelpAddApiData = {'addedKeyHelpUserId': addedKeyHelpUserId,
                                         'iParentDomainId': keyHelpParentDomainId,
                                         'iFirstDomainIdna': imscpInputData.imscpData['iUsernameDomainIdna']}

                    subDomainId = imscpSubDomainsValue.get('iSubDomainId')
                    keyhelpAddApiData['iSubDomainIdna'] = imscpSubDomainsValue.get('iSubDomainIdna')
                    keyhelpAddApiData['iSubDomainData'] = imscpSubDomainsValue.get('iSubDomainData')

                    print('\nAdding i-MSCP sub domain "' + keyhelpAddApiData['iSubDomainIdna'] + '" to domain "' +
                          imscpInputData.imscpData['iUsernameDomainIdna'] + '".')
                    if keyhelpDisableDnsForDomain == 'ask':
                        if _global_config.ask_Yes_No('Do you want to active the dns zone for this domain [y/n]? '):
                            keyhelpSetDisableDnsForDomain = False
                        else:
                            keyhelpSetDisableDnsForDomain = True

                    keyhelpAddApiData['keyhelpSetDisableDnsForDomain'] = keyhelpSetDisableDnsForDomain

                    iSubDomainIdna = imscpSubDomainsValue.get('iSubDomainIdna')

                    keyhelpAddData.addKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
                    if keyhelpAddData.status:
                        print('Sub domain "' + keyhelpAddApiData['iSubDomainIdna'] + '" added successfully.')
                        if bool(imscpInputData.imscpSslCerts['subid-' + subDomainId]):
                            # Adding SSL cert if exist
                            print(
                                '\nAdding SSL cert for sub domain "' + keyhelpAddApiData['iSubDomainIdna'] + '".')
                            for imscpSslKey, imscpSslValue in imscpInputData.imscpSslCerts[
                                'subid-' + subDomainId].items():
                                # print(imscpSslKey, '->', imscpSslValue)
                                keyhelpAddApiData = {'addedKeyHelpUserId': addedKeyHelpUserId,
                                                     'keyhelpDomainId': keyhelpAddData.keyhelpApiReturnData[
                                                         'keyhelpDomainId'],
                                                     'iSslDomainIdna': iSubDomainIdna,
                                                     'iSslPrivateKey': imscpSslValue.get('iSslPrivateKey'),
                                                     'iSslCertificate': imscpSslValue.get('iSslCertificate'),
                                                     'iSslCaBundle': imscpSslValue.get('iSslCaBundle'),
                                                     'iSslHstsMaxAge': imscpSslValue.get('iSslHstsMaxAge')}

                                if imscpSslValue.get('iSslAllowHsts') == 'on':
                                    keyhelpAddApiData['iSslAllowHsts'] = 'true'
                                else:
                                    keyhelpAddApiData['iSslAllowHsts'] = 'false'
                                if imscpSslValue.get('iSslHstsIncludeSubdomains') == 'on':
                                    keyhelpAddApiData['iSslHstsIncludeSubdomains'] = 'true'
                                else:
                                    keyhelpAddApiData['iSslHstsIncludeSubdomains'] = 'false'

                            keyhelpAddData.addKeyHelpDataToApi(apiEndpointCertificates, keyhelpAddApiData)
                            if keyhelpAddData.status:
                                print('SSL cert for domain "' + keyhelpAddApiData[
                                    'iSslDomainIdna'] + '" added successfully.')
                                print('Update "' + keyhelpAddApiData['iSslDomainIdna'] + '" with SSL cert.')

                                keyhelpAddApiData['keyhelpSslId'] = keyhelpAddData.keyhelpApiReturnData[
                                    'keyhelpSslId']

                                keyhelpAddData.updateKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
                                if keyhelpAddData.status:
                                    print('Domain "' + keyhelpAddApiData[
                                        'iSslDomainIdna'] + '" updated succesfully with SSL cert.')
                                else:
                                    _global_config.write_log(
                                        'ERROR updating "' + keyhelpAddApiData['iSslDomainIdna'] + '" with SSL cert.')
                                    print(
                                        'ERROR updating "' + keyhelpAddApiData['iSslDomainIdna'] + '" with SSL cert.\n')
                            else:
                                _global_config.write_log(
                                    'ERROR SSL cert for "' + keyhelpAddApiData['iSslDomainIdna'] + '" failed to add.')
                                print(
                                    'ERROR SSL cert for "' + keyhelpAddApiData['iSslDomainIdna'] + '" failed to add.\n')

                        print('\nAdding email addresses for sub domain "' + iSubDomainIdna + '".')
                        # Adding i-MSCP sub domain normal email addresses
                        for imscpEmailsSubDomainsArrayKey, imscpEmailsSubDomainsArrayValue in \
                                imscpInputData.imscpDomainSubEmailAddressNormal['subid-' + subDomainId].items():
                            # print(imscpEmailsSubDomainsArrayKey, '->', imscpEmailsSubDomainsArrayValue)
                            keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                                 'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                            if bool(imscpInputData.imscpDomainSubEmailAddressNormalCatchAll['subid-' + subDomainId]):
                                for domKey, domValue in imscpInputData.imscpDomainSubEmailAddressNormalCatchAll[
                                    'subid-' + subDomainId].items():
                                    keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                            keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                            keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData[
                                'kdatabaseRootPassword']
                            keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsSubDomainsArrayValue.get(
                                'iEmailMailQuota')
                            keyhelpAddApiData['iEmailAddress'] = imscpEmailsSubDomainsArrayValue.get('iEmailAddress')
                            keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsSubDomainsArrayValue.get(
                                'iEmailMailPassword')

                            keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                            keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                            if keyhelpAddData.status:
                                print(
                                    'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.')
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
                                for domKey, domValue in imscpInputData.imscpDomainSubEmailAddressNormalCatchAll[
                                    'subid-' + subDomainId].items():
                                    keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                            keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                            keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData[
                                'kdatabaseRootPassword']
                            keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsSubDomainsArrayValue.get(
                                'iEmailMailQuota')
                            keyhelpAddApiData['iEmailMailForward'] = imscpEmailsSubDomainsArrayValue.get(
                                'iEmailMailForward')
                            keyhelpAddApiData['iEmailAddress'] = imscpEmailsSubDomainsArrayValue.get('iEmailAddress')
                            keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsSubDomainsArrayValue.get(
                                'iEmailMailPassword')

                            keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                            keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                            if keyhelpAddData.status:
                                print(
                                    'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.')
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
                            keyhelpAddApiData['iEmailMailForward'] = imscpEmailsSubDomainsArrayValue.get(
                                'iEmailMailForward')
                            keyhelpAddApiData['iEmailAddress'] = imscpEmailsSubDomainsArrayValue.get('iEmailAddress')
                            # False because there is no need to update the password with an old one
                            keyhelpAddApiData['iEmailMailPassword'] = False

                            keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                            keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                            if keyhelpAddData.status:
                                print(
                                    'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.')
                            else:
                                _global_config.write_log(
                                    'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                                print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')
                    else:
                        _global_config.write_log('ERROR "' + keyhelpAddApiData['iSubDomainIdna'] + '" failed to add.')
                        print('ERROR "' + keyhelpAddApiData['iSubDomainIdna'] + '" failed to add.\n')
            else:
                _global_config.write_log(
                    'ERROR "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '" failed to add.')
                print('ERROR "' + imscpInputData.imscpData['iUsernameDomainIdna'] + '" failed to add.\n')

            # Adding i-MSCP alias domains
            for imscpDomainAliasesKey, imscpDomainAliasesValue in imscpInputData.imscpDomainAliases.items():
                # print(imscpDomainAliasesKey, '->', imscpDomainAliasesValue)
                keyhelpAddApiData = {'addedKeyHelpUserId': addedKeyHelpUserId,
                                     'iFirstDomainIdna': imscpInputData.imscpData['iUsernameDomainIdna']}
                aliasDomainParentId = imscpDomainAliasesValue.get('iAliasDomainId')
                aliasDomainParentName = imscpDomainAliasesValue.get('iAliasDomainIdna')
                keyhelpAddApiData['iAliasDomainIdna'] = imscpDomainAliasesValue.get('iAliasDomainIdna')
                keyhelpAddApiData['iAliasDomainData'] = imscpDomainAliasesValue.get('iAliasDomainData')

                print('\nAdding i-MSCP alias domain "' + keyhelpAddApiData['iAliasDomainIdna'] + '" to KeyHelpUser "' +
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
                    print('Domain "' + keyhelpAddApiData['iAliasDomainIdna'] + '" added successfully.')

                    if bool(imscpInputData.imscpSslCerts['aliasid-' + aliasDomainParentId]):
                        # Adding SSL cert if exist
                        print(
                            'Adding SSL cert for alias domain "' + aliasDomainParentName + '".')
                        for imscpSslKey, imscpSslValue in imscpInputData.imscpSslCerts[
                            'aliasid-' + aliasDomainParentId].items():
                            # print(imscpSslKey, '->', imscpSslValue)
                            keyhelpAddApiData = {'addedKeyHelpUserId': addedKeyHelpUserId,
                                                 'keyhelpDomainId': keyhelpAddData.keyhelpApiReturnData[
                                                     'keyhelpDomainId'],
                                                 'iSslDomainIdna': aliasDomainParentName,
                                                 'iSslPrivateKey': imscpSslValue.get('iSslPrivateKey'),
                                                 'iSslCertificate': imscpSslValue.get('iSslCertificate'),
                                                 'iSslCaBundle': imscpSslValue.get('iSslCaBundle'),
                                                 'iSslHstsMaxAge': imscpSslValue.get('iSslHstsMaxAge')}

                            if imscpSslValue.get('iSslAllowHsts') == 'on':
                                keyhelpAddApiData['iSslAllowHsts'] = 'true'
                            else:
                                keyhelpAddApiData['iSslAllowHsts'] = 'false'
                            if imscpSslValue.get('iSslHstsIncludeSubdomains') == 'on':
                                keyhelpAddApiData['iSslHstsIncludeSubdomains'] = 'true'
                            else:
                                keyhelpAddApiData['iSslHstsIncludeSubdomains'] = 'false'

                        keyhelpAddData.addKeyHelpDataToApi(apiEndpointCertificates, keyhelpAddApiData)
                        if keyhelpAddData.status:
                            print('SSL cert for domain "' + keyhelpAddApiData[
                                'iSslDomainIdna'] + '" added successfully.')
                            print('Update "' + keyhelpAddApiData['iSslDomainIdna'] + '" with SSL cert.')

                            keyhelpAddApiData['keyhelpSslId'] = keyhelpAddData.keyhelpApiReturnData[
                                'keyhelpSslId']

                            keyhelpAddData.updateKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
                            if keyhelpAddData.status:
                                print('Domain "' + keyhelpAddApiData[
                                    'iSslDomainIdna'] + '" updated succesfully with SSL cert.')
                            else:
                                _global_config.write_log(
                                    'ERROR updating "' + keyhelpAddApiData['iSslDomainIdna'] + '" with SSL cert.')
                                print(
                                    'ERROR updating "' + keyhelpAddApiData['iSslDomainIdna'] + '" with SSL cert.\n')
                        else:
                            _global_config.write_log(
                                'ERROR SSL cert for "' + keyhelpAddApiData['iSslDomainIdna'] + '" failed to add.')
                            print(
                                'ERROR SSL cert for "' + keyhelpAddApiData['iSslDomainIdna'] + '" failed to add.\n')

                    print('\nAdding email addresses for alias domain "' + aliasDomainParentName + '".')
                    # Adding i-MSCP alias domain normal email addresses
                    for imscpEmailsAliasDomainsArrayKey, imscpEmailsAliasDomainsArrayValue in \
                            imscpInputData.imscpAliasEmailAddressNormal['aliasid-' + aliasDomainParentId].items():
                        # print(imscpEmailsAliasDomainsArrayKey, '->', imscpEmailsAliasDomainsArrayValue)
                        keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                             'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                        if bool(imscpInputData.imscpAliasEmailAddressNormalCatchAll):
                            for domKey, domValue in imscpInputData.imscpAliasEmailAddressNormalCatchAll[
                                'aliasid-' + aliasDomainParentId].items():
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
                                'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.')
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
                                'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.')
                        else:
                            _global_config.write_log(
                                'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                            print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                    # Adding i-MSCP alias domain forward email addresses
                    for imscpEmailsAliasDomainsKey, imscpEmailsAliasDomainsValue in \
                            imscpInputData.imscpAliasEmailAddressForward['aliasid-' + aliasDomainParentId].items():
                        # print(imscpEmailsAliasDomainsKey, '->', imscpEmailsAliasDomainsValue)
                        keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                             'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': False}
                        if bool(imscpInputData.imscpAliasEmailAddressNormalCatchAll['aliasid-' + aliasDomainParentId]):
                            for domKey, domValue in imscpInputData.imscpAliasEmailAddressNormalCatchAll[
                                'aliasid-' + aliasDomainParentId].items():
                                keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                        # 5MB for only Forward
                        keyhelpAddApiData['iEmailMailQuota'] = '5242880'
                        keyhelpAddApiData['iEmailMailForward'] = imscpEmailsAliasDomainsValue.get(
                            'iEmailMailForward')
                        keyhelpAddApiData['iEmailAddress'] = imscpEmailsAliasDomainsValue.get('iEmailAddress')
                        # False because there is no need to update the password with an old one
                        keyhelpAddApiData['iEmailMailPassword'] = False

                        keyhelpAddApiData['iEmailMailInitialPassword'] = \
                            keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                        keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                        if keyhelpAddData.status:
                            print(
                                'Email address "' + keyhelpAddApiData['iEmailAddress'] + '" added successfully.')
                        else:
                            _global_config.write_log(
                                'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                            print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                    # Adding sub domains for alias domain
                    for imscpAliasSubDomainsKey, imscpAliasSubDomainsValue in \
                            imscpInputData.imscpAliasSubDomains['aliasid-' + aliasDomainParentId].items():
                        # print(imscpAliasSubDomainsKey, '->', imscpAliasSubDomainsValue)
                        keyhelpAddApiData = {'addedKeyHelpUserId': addedKeyHelpUserId,
                                             'iParentDomainId': keyHelpParentDomainId,
                                             'iFirstDomainIdna': imscpInputData.imscpData['iUsernameDomainIdna']}

                        aliasSubDomainId = imscpAliasSubDomainsValue.get('iAliasSubDomainId')
                        keyhelpAddApiData['iAliasSubDomainIdna'] = imscpAliasSubDomainsValue.get(
                            'iAliasSubDomainIdna')
                        keyhelpAddApiData['iAliasSubDomainData'] = imscpAliasSubDomainsValue.get(
                            'iAliasSubDomainData')

                        iAliasSubDomainIdna = imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')

                        print('\nAdding i-MSCP alias sub domain "' + keyhelpAddApiData[
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
                                'iAliasSubDomainIdna'] + '" added successfully.')

                            if bool(imscpInputData.imscpSslCerts['aliassubid-' + aliasSubDomainId]):
                                # Adding SSL cert if exist
                                print(
                                    '\nAdding SSL cert for sub alias domain "' + iAliasSubDomainIdna + '".')
                                for imscpSslKey, imscpSslValue in imscpInputData.imscpSslCerts[
                                    'aliassubid-' + aliasSubDomainId].items():
                                    # print(imscpSslKey, '->', imscpSslValue)
                                    keyhelpAddApiData = {'addedKeyHelpUserId': addedKeyHelpUserId,
                                                         'keyhelpDomainId': keyhelpAddData.keyhelpApiReturnData[
                                                             'keyhelpDomainId'],
                                                         'iSslDomainIdna': iAliasSubDomainIdna,
                                                         'iSslPrivateKey': imscpSslValue.get('iSslPrivateKey'),
                                                         'iSslCertificate': imscpSslValue.get('iSslCertificate'),
                                                         'iSslCaBundle': imscpSslValue.get('iSslCaBundle'),
                                                         'iSslHstsMaxAge': imscpSslValue.get('iSslHstsMaxAge')}

                                    if imscpSslValue.get('iSslAllowHsts') == 'on':
                                        keyhelpAddApiData['iSslAllowHsts'] = 'true'
                                    else:
                                        keyhelpAddApiData['iSslAllowHsts'] = 'false'
                                    if imscpSslValue.get('iSslHstsIncludeSubdomains') == 'on':
                                        keyhelpAddApiData['iSslHstsIncludeSubdomains'] = 'true'
                                    else:
                                        keyhelpAddApiData['iSslHstsIncludeSubdomains'] = 'false'

                                keyhelpAddData.addKeyHelpDataToApi(apiEndpointCertificates, keyhelpAddApiData)
                                if keyhelpAddData.status:
                                    print('SSL cert for domain "' + keyhelpAddApiData[
                                        'iSslDomainIdna'] + '" added successfully.')
                                    print('Update "' + keyhelpAddApiData['iSslDomainIdna'] + '" with SSL cert.')

                                    keyhelpAddApiData['keyhelpSslId'] = keyhelpAddData.keyhelpApiReturnData[
                                        'keyhelpSslId']

                                    keyhelpAddData.updateKeyHelpDataToApi(apiEndpointDomains, keyhelpAddApiData)
                                    if keyhelpAddData.status:
                                        print('Domain "' + keyhelpAddApiData[
                                            'iSslDomainIdna'] + '" updated succesfully with SSL cert.')
                                    else:
                                        _global_config.write_log(
                                            'ERROR updating "' + keyhelpAddApiData[
                                                'iSslDomainIdna'] + '" with SSL cert.')
                                        print(
                                            'ERROR updating "' + keyhelpAddApiData[
                                                'iSslDomainIdna'] + '" with SSL cert.\n')
                                else:
                                    _global_config.write_log(
                                        'ERROR SSL cert for "' + keyhelpAddApiData[
                                            'iSslDomainIdna'] + '" failed to add.')
                                    print(
                                        'ERROR SSL cert for "' + keyhelpAddApiData[
                                            'iSslDomainIdna'] + '" failed to add.\n')

                            print('\nAdding email addresses for alias sub domain "' + iAliasSubDomainIdna + '".')
                            # Adding i-MSCP alias sub domain normal email addresses
                            for imscpEmailsAliasSubDomainsKey, imscpEmailsAliasSubDomainsValue in \
                                    imscpInputData.imscpAliasSubEmailAddressNormal['aliassubid-' + aliasSubDomainId].items():
                                # print(imscpEmailsAliasSubDomainsKey, '->', imscpEmailsAliasSubDomainsValue)
                                keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                                     'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                                if bool(imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                            'aliassubid-' + aliasSubDomainId]):
                                    for domKey, domValue in imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                        'aliassubid-' + aliasSubDomainId].items():
                                        keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                                keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                                keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData[
                                    'kdatabaseRootPassword']
                                keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsAliasSubDomainsValue.get(
                                    'iEmailMailQuota')
                                keyhelpAddApiData['iEmailAddress'] = imscpEmailsAliasSubDomainsValue.get(
                                    'iEmailAddress')
                                keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsAliasSubDomainsValue.get(
                                    'iEmailMailPassword')

                                keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                    keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                                keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                                if keyhelpAddData.status:
                                    print(
                                        'Email address "' + keyhelpAddApiData[
                                            'iEmailAddress'] + '" added successfully.')
                                else:
                                    _global_config.write_log(
                                        'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                                    print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                            # Adding i-MSCP alias sub domain normal forward email addresses
                            for imscpEmailsAliasSubDomainsKey, imscpEmailsAliasSubDomainsValue in \
                                    imscpInputData.imscpAliasSubEmailAddressNormalForward[
                                        'aliassubid-' + aliasSubDomainId].items():
                                # print(imscpEmailsAliasSubDomainsKey, '->', imscpEmailsAliasSubDomainsArrayValue)
                                keyhelpAddApiData = {'emailStoreForward': True, 'iEmailCatchall': '',
                                                     'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': True}
                                if bool(imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                            'aliassubid-' + aliasSubDomainId]):
                                    for domKey, domValue in imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                        'aliassubid-' + aliasSubDomainId].items():
                                        keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                                keyhelpAddApiData['kdatabaseRoot'] = keyhelpInputData.keyhelpData['kdatabaseRoot']
                                keyhelpAddApiData['kdatabaseRootPassword'] = keyhelpInputData.keyhelpData[
                                    'kdatabaseRootPassword']
                                keyhelpAddApiData['iEmailMailQuota'] = imscpEmailsAliasSubDomainsValue.get(
                                    'iEmailMailQuota')
                                keyhelpAddApiData['iEmailMailForward'] = imscpEmailsAliasSubDomainsValue.get(
                                    'iEmailMailForward')
                                keyhelpAddApiData['iEmailAddress'] = imscpEmailsAliasSubDomainsValue.get(
                                    'iEmailAddress')
                                keyhelpAddApiData['iEmailMailPassword'] = imscpEmailsAliasSubDomainsValue.get(
                                    'iEmailMailPassword')

                                keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                    keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                                keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                                if keyhelpAddData.status:
                                    print(
                                        'Email address "' + keyhelpAddApiData[
                                            'iEmailAddress'] + '" added successfully.')
                                else:
                                    _global_config.write_log(
                                        'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                                    print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')

                            # Adding i-MSCP alias sub domain forward email addresses
                            for imscpEmailsAliasSubDomainsKey, imscpEmailsAliasSubDomainsValue in \
                                    imscpInputData.imscpAliasSubEmailAddressForward[
                                        'aliassubid-' + aliasSubDomainId].items():
                                # print(imscpEmailsAliasSubDomainsKey, '->', imscpEmailsAliasSubDomainsValue)
                                keyhelpAddApiData = {'emailStoreForward': False, 'iEmailCatchall': '',
                                                     'addedKeyHelpUserId': addedKeyHelpUserId, 'emailNeedRsync': False}
                                if bool(imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                            'aliassubid-' + aliasSubDomainId]):
                                    for domKey, domValue in imscpInputData.imscpAliasSubEmailAddressNormalCatchAll[
                                        'subid-' + aliasSubDomainId].items():
                                        keyhelpAddApiData['iEmailCatchall'] = domValue.get('iEmailAddress')

                                # 5MB for only Forward
                                keyhelpAddApiData['iEmailMailQuota'] = '5242880'
                                keyhelpAddApiData['iEmailMailForward'] = imscpEmailsAliasSubDomainsValue.get(
                                    'iEmailMailForward')
                                keyhelpAddApiData['iEmailAddress'] = imscpEmailsAliasSubDomainsValue.get(
                                    'iEmailAddress')
                                # False because there is no need to update the password with an old one
                                keyhelpAddApiData['iEmailMailPassword'] = False

                                keyhelpAddApiData['iEmailMailInitialPassword'] = \
                                    keyhelpAddData.keyhelpCreateRandomEmailPassword(keyhelpMinPasswordLenght)

                                keyhelpAddData.addKeyHelpDataToApi(apiEndPointEmails, keyhelpAddApiData)
                                if keyhelpAddData.status:
                                    print(
                                        'Email address "' + keyhelpAddApiData[
                                            'iEmailAddress'] + '" added successfully.')
                                else:
                                    _global_config.write_log(
                                        'ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.')
                                    print('ERROR "' + keyhelpAddApiData['iEmailAddress'] + '" failed to add.\n')
                        else:
                            _global_config.write_log(
                                'ERROR "' + keyhelpAddApiData['iAliasSubDomainIdna'] + '" failed to add.')
                            print('ERROR "' + keyhelpAddApiData['iAliasSubDomainIdna'] + '" failed to add.\n')
                else:
                    _global_config.write_log('ERROR "' + keyhelpAddApiData['iAliasDomainIdna'] + '" failed to add.')
                    print('ERROR "' + keyhelpAddApiData['iAliasDomainIdna'] + '" failed to add.\n')

            # Adding databases and database usernames
            if bool(imscpInputData.imscpDomainDatabaseNames):
                print('\nStart adding databases and database usernames.\n')
                keyhelpAddedDatabases = {}
                for imscpDatabasesKey, imscpDatabasesValue in imscpInputData.imscpDomainDatabaseNames.items():
                    # print(imscpDatabasesKey, '->', imscpDatabasesValue)
                    databaseParentId = imscpDatabasesValue.get('iDatabaseId')
                    if re.match("^\d+", str(imscpDatabasesValue.get('iDatabaseName'))):
                        keyhelpAddApiData['iDatabaseName'] = re.sub("^\d+", 'db' + str(addedKeyHelpUserId),
                                                                    str(imscpDatabasesValue.get('iDatabaseName')),
                                                                    flags=re.UNICODE)
                    else:
                        keyhelpAddApiData['iDatabaseName'] = 'db' + str(
                            addedKeyHelpUserId) + '_' + imscpDatabasesValue.get(
                            'iDatabaseName')

                    keyhelpAddApiData['iOldDatabaseName'] = imscpDatabasesValue.get('iDatabaseName')
                    keyhelpAddApiData['iOldDatabaseUsername'] = ''
                    keyhelpAddApiData['iDatabaseUsername'] = ''

                    keyhelpAddedDatabases[keyhelpAddApiData['iDatabaseName']] = imscpDatabasesValue.get(
                        'iDatabaseName')

                    if bool(imscpInputData.imscpDomainDatabaseUsernames):
                        for dbUserKey, dbUserValue in imscpInputData.imscpDomainDatabaseUsernames.items():
                            # print(dbUserKey, '->', dbUserValue)
                            if keyhelpAddApiData['iDatabaseUsername'] == '':
                                if databaseParentId == dbUserValue.get('iDatabaseId'):
                                    if re.match("^\d+", str(dbUserValue.get('iDatabaseUsername'))):
                                        keyhelpAddApiData['iDatabaseUsername'] = re.sub("^\d+",
                                                                                        'dbu' + str(addedKeyHelpUserId),
                                                                                        str(dbUserValue.get(
                                                                                            'iDatabaseUsername')),
                                                                                        flags=re.UNICODE)
                                    else:
                                        keyhelpAddApiData[
                                            'iDatabaseUsername'] = 'dbu' + str(addedKeyHelpUserId) + '_' + str(
                                            dbUserValue.get(
                                                'iDatabaseUsername'))

                                    keyhelpAddApiData['iDatabaseUserHost'] = str(dbUserValue.get('iDatabaseUserHost'))
                                    keyhelpAddApiData[
                                        'iDatabaseUserPassword'] = keyhelpAddData.keyhelpCreateRandomDatabaseUserPassword(
                                        10)

                                # If an i-MSCP has only one db user we need to extend teh username
                                while True:
                                    i = 1
                                    if keyhelpAddApiData['iDatabaseUsername'] in keyhelpAddData.keyhelpAddedDbUsernames:
                                        keyhelpAddApiData['iDatabaseUsername'] = str(
                                            keyhelpAddApiData['iDatabaseUsername']) + '_' + str(i)
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
                keyhelpAddedDatabases = False
                print('\nNo databases and database usernames to add.\n')

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
                            os.remove(
                                imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps/migration_database.log')

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
                        print('Check remote MySQL dump folder whether exists. If not, i will create it!\n')
                        client.exec_command('test ! -d ' + imscpDbDumpFolder + ' && mkdir -p ' + imscpDbDumpFolder)

                        # open sftp connection
                        sftp_client = client.open_sftp()

                        for newDatabaseName, oldDatabaseName in keyhelpAddedDatabases.items():
                            # print(newDatabaseName, '->', oldDatabaseName)
                            exit_status = ''
                            print(
                                'Please wait... Dumping database "' + oldDatabaseName + '" to "' + imscpDbDumpFolder + '/' + oldDatabaseName + '_sql.gz".')
                            stdin, stdout, stderr = client.exec_command(
                                'mysqldump -h' + imscpInputData.imscpData['imysqlhost'] + ' -P' +
                                imscpInputData.imscpData[
                                    'imysqlport'] + ' -u' + imscpInputData.imscpData['imysqluser'] + ' -p' +
                                imscpInputData.imscpData[
                                    'imysqlpassword'] + ' ' + oldDatabaseName + ' | gzip > ' + imscpDbDumpFolder + '/' + oldDatabaseName + '_sql.gz')

                            while True:
                                exit_status = stdout.channel.recv_exit_status()
                                if exit_status >= 0:
                                    break
                            if exit_status == 0:
                                print('Transferring "' + imscpDbDumpFolder + '/' + oldDatabaseName + '_sql.gz" to ' +
                                      imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps/' + str(
                                    newDatabaseName) + '__' + str(oldDatabaseName) + '_sql.gz.')

                                remoteFile = sftp_client.stat(
                                    str(imscpDbDumpFolder) + '/' + str(oldDatabaseName) + '_sql.gz')
                                with TqdmWrap(ascii=False, unit='b', unit_scale=True, leave=True, miniters=1,
                                              desc='Transferring SQL Dump......', total=remoteFile.st_size, ncols=150) as pbar:
                                    sftp_client.get(str(imscpDbDumpFolder) + '/' + str(oldDatabaseName) + '_sql.gz', str(
                                        imscpInputData.imscpData['iUsernameDomainIdna']) + '_mysqldumps/' + str(
                                        newDatabaseName) + '__' + str(oldDatabaseName) + '_sql.gz', callback=pbar.viewBar)
                                print('Transferring SQL Dump finished')

                                # remove the remote sql dump
                                print(
                                    '\nRemoving database dump "' + imscpDbDumpFolder + '/' + oldDatabaseName + '_sql.gz" on remote server.\n')
                                client.exec_command('rm ' + imscpDbDumpFolder + '/' + oldDatabaseName + '_sql.gz')
                                _global_config.write_migration_log(
                                    imscpInputData.imscpData['iUsernameDomainIdna'] + '_mysqldumps/migration_databases.log',
                                    'MySQL dump for i-MSCP database "' + oldDatabaseName + '" => ' + newDatabaseName + '__' + oldDatabaseName + '_sql.gz')
                            else:
                                print('Something went wrong while dumping the database "' + oldDatabaseName + '"')

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
                        sftp_client.close()
                        client.close()

                    #### KeyHelp Daten welche befüllt wurden
                    # keyhelpInputData.keyhelpData['kdatabaseRoot']
                    # keyhelpInputData.keyhelpData['kdatabaseRootPassword']
                    for newDatabaseName, oldDatabaseName in keyhelpAddedDatabases.items():
                        if os.path.isfile(str(imscpInputData.imscpData['iUsernameDomainIdna']) + '_mysqldumps/' + str(
                                newDatabaseName) + '__' + str(oldDatabaseName) + '_sql.gz'):
                            print('Please wait...')
                            print('Start import i-MSCP database dump "' + str(newDatabaseName) + '__' + str(
                                oldDatabaseName) + '_sql.gz" to database "' + str(newDatabaseName) + '"')

                            pv = subprocess.Popen(
                                ["pv", "-f",
                                 str(imscpInputData.imscpData['iUsernameDomainIdna']) + "_mysqldumps/" + str(
                                     newDatabaseName) + "__" + str(oldDatabaseName) + "_sql.gz"],
                                shell=False,  # optional, since this is the default
                                bufsize=1,
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                universal_newlines=True,
                            )
                            zcat = subprocess.Popen(
                                ['zcat'],
                                stdin=pv.stdout,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                            )
                            mysql = subprocess.Popen(["mysql",
                                                      "-u{}".format(str(keyhelpInputData.keyhelpData['kdatabaseRoot'])),
                                                      "-p{}".format(
                                                          str(keyhelpInputData.keyhelpData['kdatabaseRootPassword'])),
                                                      str(newDatabaseName)],
                                                     shell=False,
                                                     stdout=subprocess.PIPE,
                                                     stderr=subprocess.DEVNULL,
                                                     stdin=zcat.stdout,
                                                     )

                            zcat.stdout.close()  # Allow pv to receive a SIGPIPE if mysql exits.
                            pv.stdout.close()  # Allow pv to receive a SIGPIPE if mysql exits.

                            for output in pv.stderr:
                                sys.stdout.write('\rDB Import in progress: ' + output.strip())
                                sys.stdout.flush()

                            print('\nFinished - Dump ' + str(newDatabaseName) + '__' + str(
                                oldDatabaseName) + '_sql.gz succesfully imported to DB: ' + str(newDatabaseName) + '\n')
                else:
                    print('No databases available for the i-MSCP domain ' + imscpInputData.imscpData['iUsernameDomain'])

                print('\nStart syncing emails.... Please wait')
                for rsyncEmailAddress in keyhelpAddData.keyhelpAddedEmailAddresses:
                    emailAddressData = rsyncEmailAddress.split("@")
                    emailAddressData[0].strip()
                    emailAddressData[1].strip()
                    print('Please wait.... Checking whether Keyhelp is ready with folder creation.')
                    loop_starts = time.time()
                    while True:
                        now = time.time()
                        sys.stdout.write('\rWaiting since {0} seconds for Keyhelp.'.format(int(now - loop_starts)))
                        sys.stdout.flush()
                        time.sleep(1)
                        if os.path.exists(
                                '/var/mail/vhosts/' + emailAddressData[1] + '/' + emailAddressData[0] + '/'):
                            break

                        seconds = format(int(now - loop_starts))
                        if int(seconds) > 2:
                            os.makedirs('/var/mail/vhosts/' + emailAddressData[1] + '/' + emailAddressData[0] + '/')
                            os.system(
                                'chown -R vmail:vmail /var/mail/vhosts/' + emailAddressData[1] + '/' +
                                emailAddressData[
                                    0] + '/')

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

                    proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    while True:
                        output = proc.stdout.readline().decode('utf-8')
                        if output == '' and proc.poll() is not None:
                            break
                        if '-chk' in str(output):
                            m = re.findall(r'-chk=(\d+)/(\d+)', str(output))
                            total_files = int(m[0][1])
                            progress = (100 * (int(m[0][1]) - int(m[0][0]))) / total_files
                            sys.stdout.write('\rSyncing of emails for ' + str(rsyncEmailAddress) + ' done: ' + str(
                                round(progress, 2)) + '%')
                            sys.stdout.flush()
                            if int(m[0][0]) == 0:
                                break

                    proc.stdout.close()
                    print('\nFinished syncing email address "' + str(rsyncEmailAddress) + '".')
                    os.system(
                        'chown -R vmail:vmail /var/mail/vhosts/' + emailAddressData[1] + '/' + emailAddressData[
                            0] + '/')
                    print(
                        'System owner for email address "' + str(rsyncEmailAddress) + '". successfully updated.\n')
                    time.sleep(1)

                print('\nStart syncing webspace.... Please wait')
                firstDomainIdna = str(imscpInputData.imscpData['iUsernameDomainIdna'])
                # Rsync i-MSCP first domain
                if imscpInputData.imscpData['iUsernameDomainRsync'] and imscpInputData.imscpData[
                    'iUsernameDomainIdna'] in keyhelpAddData.keyhelpAddedDomains:
                    keyHelpUsername = str(keyhelpInputData.keyhelpData['kusername'].lower())
                    print('Please wait.... Checking whether Keyhelp is ready with folder creation.')
                    loop_starts = time.time()
                    while True:
                        now = time.time()
                        sys.stdout.write('\rWaiting since {0} seconds for Keyhelp.'.format(int(now - loop_starts)))
                        sys.stdout.flush()
                        time.sleep(1)
                        if os.path.exists('/home/users/' + keyHelpUsername + '/www/' + str(
                                imscpInputData.imscpData['iUsernameDomainIdna']) + '/'):
                            break
                        seconds = format(int(now - loop_starts))
                        if int(seconds) > 20:
                            os.makedirs('/home/users/' + keyHelpUsername + '/www/' + str(
                                imscpInputData.imscpData['iUsernameDomainIdna']) + '/')

                    print('Syncing webspace from domain "' + str(
                        imscpInputData.imscpData['iUsernameDomainIdna']) + '" :')
                    additionalDomainData = imscpInputData.imscpData['iDomainData'].split("|")
                    additionalDomainData[1].strip()
                    remoteRsyncFolder = '/var/www/virtual/' + firstDomainIdna + str(additionalDomainData[1]) + '/'
                    localRsyncFolder = '/home/users/' + keyHelpUsername + '/www/' + str(
                        imscpInputData.imscpData['iUsernameDomainIdna']) + '/'

                    if imscpSshPublicKey:
                        cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "ssh -i ' + \
                              imscpSshPublicKey + ' -p ' + imscpSshPort + ' -q" --rsync-path="rsync" ' + \
                              imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + localRsyncFolder
                    else:
                        cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "sshpass -p ' + \
                              imscpRootPassword + ' ssh -p ' + \
                              imscpSshPort + ' -q" --rsync-path="rsync" --exclude={"dovecot.sieve"} ' + \
                              imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + localRsyncFolder

                    proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    while True:
                        output = proc.stdout.readline().decode('utf-8')
                        if output == '' and proc.poll() is not None:
                            break
                        if '-chk' in str(output):
                            m = re.findall(r'-chk=(\d+)/(\d+)', str(output))
                            total_files = int(m[0][1])
                            progress = (100 * (int(m[0][1]) - int(m[0][0]))) / total_files
                            sys.stdout.write('\rSyncing of webspace ' + str(
                                imscpInputData.imscpData['iUsernameDomainIdna']) + ' done: ' + str(
                                round(progress, 2)) + '%')
                            sys.stdout.flush()
                            if int(m[0][0]) == 0:
                                break

                    proc.stdout.close()
                    print('\nFinished syncing webspace "' + str(
                        imscpInputData.imscpData['iUsernameDomainIdna']) + '".')

                    # Rsync 00_private of the domain
                    print('\nPlease wait.... Create 00_private dir (00_private/' + str(
                        imscpInputData.imscpData['iUsernameDomainIdna']) + ') for the domain if not exist.')
                    if not os.path.exists('/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                            imscpInputData.imscpData['iUsernameDomainIdna']) + '/'):
                        os.makedirs('/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                            imscpInputData.imscpData['iUsernameDomainIdna']) + '/')

                    print('Syncing 00_private folder from domain "' + str(
                        imscpInputData.imscpData['iUsernameDomainIdna']) + '" :')
                    additionalDomainData = imscpInputData.imscpData['iDomainData'].split("|")
                    additionalDomainData[1].strip()
                    remoteRsyncFolder = '/var/www/virtual/' + firstDomainIdna + '/00_private/'
                    localRsyncFolder = '/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                        imscpInputData.imscpData['iUsernameDomainIdna']) + '/'

                    if imscpSshPublicKey:
                        cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "ssh -i ' + \
                              imscpSshPublicKey + ' -p ' + imscpSshPort + ' -q" --rsync-path="rsync" ' + \
                              imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + \
                              localRsyncFolder
                    else:
                        cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "sshpass -p ' + \
                              imscpRootPassword + ' ssh -p ' + \
                              imscpSshPort + ' -q" --rsync-path="rsync" --exclude={"dovecot.sieve"} ' + \
                              imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + \
                              localRsyncFolder

                    proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    while True:
                        output = proc.stdout.readline().decode('utf-8')
                        if output == '' and proc.poll() is not None:
                            break
                        if '-chk' in str(output):
                            m = re.findall(r'-chk=(\d+)/(\d+)', str(output))
                            total_files = int(m[0][1])
                            progress = (100 * (int(m[0][1]) - int(m[0][0]))) / total_files
                            sys.stdout.write('\rSyncing of 00_private folder of ' + str(
                                imscpInputData.imscpData['iUsernameDomainIdna']) + ' done: ' + str(
                                round(progress, 2)) + '%')
                            sys.stdout.flush()
                            if int(m[0][0]) == 0:
                                break

                    proc.stdout.close()
                    print('\nFinished syncing 00_private folder of domain "' + str(
                        imscpInputData.imscpData['iUsernameDomainIdna']) + '".')
                    os.system(
                        'chown -R ' + keyHelpUsername + ':' + keyHelpUsername + ' /home/users/' + keyHelpUsername + '/')
                    print('System owner for webspace "' + str(
                        imscpInputData.imscpData['iUsernameDomainIdna']) + '". successfully updated.\n')
                    time.sleep(1)
                else:
                    print('\nIgnore syncing from domain "' + str(
                        imscpInputData.imscpData['iUsernameDomainRsync']) + '" !')

                # Rsync i-MSCP sub domains
                for imscpSubDomainsKey, imscpSubDomainsValue in imscpInputData.imscpDomainSubDomains.items():
                    # print(imscpSubDomainsKey, '->', imscpSubDomainsValue)
                    if imscpSubDomainsValue.get('iSubDomainRsync') and imscpSubDomainsValue.get(
                            'iSubDomainIdna') in keyhelpAddData.keyhelpAddedDomains:
                        keyHelpUsername = str(keyhelpInputData.keyhelpData['kusername'].lower())
                        print('Please wait.... Checking whether Keyhelp is ready with folder creation.')
                        loop_starts = time.time()
                        while True:
                            now = time.time()
                            sys.stdout.write(
                                '\rWaiting since {0} seconds for Keyhelp.'.format(int(now - loop_starts)))
                            sys.stdout.flush()
                            time.sleep(1)
                            if os.path.exists('/home/users/' + keyHelpUsername + '/www/' + str(
                                    imscpSubDomainsValue.get('iSubDomainIdna')) + '/'):
                                break
                            seconds = format(int(now - loop_starts))
                            if int(seconds) > 20:
                                os.makedirs('/home/users/' + keyHelpUsername + '/www/' + str(
                                    imscpSubDomainsValue.get('iSubDomainIdna')) + '/')

                        print('Syncing webspace from sub domain "' + str(
                            imscpSubDomainsValue.get('iSubDomainIdna')) + '" :')
                        additionalDomainData = imscpSubDomainsValue.get('iSubDomainData').split("|")
                        additionalDomainData[0].strip()
                        subDomainfolder = additionalDomainData[0].split(".")[0]
                        additionalDomainData[1].strip()
                        remoteRsyncFolder = '/var/www/virtual/' + firstDomainIdna + str(subDomainfolder) + str(
                            additionalDomainData[1]) + '/'
                        localRsyncFolder = '/home/users/' + keyHelpUsername + '/www/' + str(
                            imscpSubDomainsValue.get('iSubDomainIdna')) + '/'

                        if imscpSshPublicKey:
                            cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "ssh -i ' + \
                                  imscpSshPublicKey + ' -p ' + imscpSshPort + ' -q" --rsync-path="rsync" ' + \
                                  imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + localRsyncFolder
                        else:
                            cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "sshpass -p ' + \
                                  imscpRootPassword + ' ssh -p ' + \
                                  imscpSshPort + ' -q" --rsync-path="rsync" --exclude={"dovecot.sieve"} ' + \
                                  imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + localRsyncFolder

                        proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                        while True:
                            output = proc.stdout.readline().decode('utf-8')
                            if output == '' and proc.poll() is not None:
                                break
                            if '-chk' in str(output):
                                m = re.findall(r'-chk=(\d+)/(\d+)', str(output))
                                total_files = int(m[0][1])
                                progress = (100 * (int(m[0][1]) - int(m[0][0]))) / total_files
                                sys.stdout.write('\rSyncing of webspace ' + str(
                                    imscpSubDomainsValue.get('iSubDomainIdna')) + ' done: ' + str(
                                    round(progress, 2)) + '%')
                                sys.stdout.flush()
                                if int(m[0][0]) == 0:
                                    break

                        proc.stdout.close()
                        print('\nFinished syncing webspace "' + str(
                            imscpSubDomainsValue.get('iSubDomainIdna')) + '".')

                        # Rsync 00_private of the sub domain
                        print('\nPlease wait.... Create 00_private dir (00_private/' + str(
                            imscpSubDomainsValue.get('iSubDomainIdna')) + ') for the domain if not exist.')
                        if not os.path.exists('/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                                imscpSubDomainsValue.get('iSubDomainIdna')) + '/'):
                            os.makedirs('/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                                imscpSubDomainsValue.get('iSubDomainIdna')) + '/')

                        print('Syncing 00_private folder from sub domain "' + str(
                            imscpSubDomainsValue.get('iSubDomainIdna')) + '" :')
                        additionalDomainData = imscpSubDomainsValue.get('iSubDomainData').split("|")
                        additionalDomainData[0].strip()
                        subDomainfolder = additionalDomainData[0].split(".")[0]
                        additionalDomainData[1].strip()
                        remoteRsyncFolder = '/var/www/virtual/' + firstDomainIdna + str(
                            subDomainfolder) + '/00_private/'
                        localRsyncFolder = '/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                            imscpSubDomainsValue.get('iSubDomainIdna')) + '/'

                        if imscpSshPublicKey:
                            cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "ssh -i ' + \
                                  imscpSshPublicKey + ' -p ' + imscpSshPort + ' -q" --rsync-path="rsync" ' + \
                                  imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + \
                                  localRsyncFolder
                        else:
                            cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "sshpass -p ' + \
                                  imscpRootPassword + ' ssh -p ' + \
                                  imscpSshPort + ' -q" --rsync-path="rsync" --exclude={"dovecot.sieve"} ' + \
                                  imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + \
                                  localRsyncFolder

                        proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                        while True:
                            output = proc.stdout.readline().decode('utf-8')
                            if output == '' and proc.poll() is not None:
                                break
                            if '-chk' in str(output):
                                m = re.findall(r'-chk=(\d+)/(\d+)', str(output))
                                total_files = int(m[0][1])
                                progress = (100 * (int(m[0][1]) - int(m[0][0]))) / total_files
                                sys.stdout.write('\rSyncing of 00_private folder of ' + str(
                                    imscpSubDomainsValue.get('iSubDomainIdna')) + ' done: ' + str(
                                    round(progress, 2)) + '%')
                                sys.stdout.flush()
                                if int(m[0][0]) == 0:
                                    break

                        proc.stdout.close()
                        print('\nFinished syncing 00_private folder of sub domain "' + str(
                            imscpSubDomainsValue.get('iSubDomainIdna')) + '".')
                        os.system(
                            'chown -R ' + keyHelpUsername + ':' + keyHelpUsername + ' /home/users/' + keyHelpUsername + '/')
                        print('System owner for webspace "' + str(
                            imscpSubDomainsValue.get('iSubDomainIdna')) + '". successfully updated.\n')
                        time.sleep(1)
                    else:
                        print('\nIgnore syncing from sub domain "' + str(
                            imscpSubDomainsValue.get('iSubDomainIdna')) + '" !')

                # Rsync i-MSCP alias domains
                aliasParentDomainIds = []
                for imscpAliasDomainsKey, imscpAliasDomainsValue in imscpInputData.imscpDomainAliases.items():
                    # print(imscpAliasDomainsKey, '->', imscpAliasDomainsValue)
                    aliasParentDomainIds.append(imscpAliasDomainsValue.get('iAliasDomainId'))
                    if imscpAliasDomainsValue.get('iAliasDomainRsync') and imscpAliasDomainsValue.get(
                            'iAliasDomainIdna') in keyhelpAddData.keyhelpAddedDomains:
                        keyHelpUsername = str(keyhelpInputData.keyhelpData['kusername'].lower())
                        print('Please wait.... Checking whether Keyhelp is ready with folder creation.')
                        loop_starts = time.time()
                        while True:
                            now = time.time()
                            sys.stdout.write(
                                '\rWaiting since {0} seconds for Keyhelp.'.format(int(now - loop_starts)))
                            sys.stdout.flush()
                            time.sleep(1)
                            if os.path.exists('/home/users/' + keyHelpUsername + '/www/' + str(
                                    imscpAliasDomainsValue.get('iAliasDomainIdna')) + '/'):
                                break
                            seconds = format(int(now - loop_starts))
                            if int(seconds) > 20:
                                os.makedirs('/home/users/' + keyHelpUsername + '/www/' + str(
                                    imscpAliasDomainsValue.get('iAliasDomainIdna')) + '/')

                        print('Syncing webspace from alias domain "' + str(
                            imscpAliasDomainsValue.get('iAliasDomainIdna')) + '" :')
                        additionalDomainData = imscpAliasDomainsValue.get('iAliasDomainData').split("|")
                        additionalDomainData[0].strip()
                        additionalDomainData[1].strip()
                        remoteRsyncFolder = '/var/www/virtual/' + firstDomainIdna + str(
                            additionalDomainData[0]) + str(
                            additionalDomainData[1]) + '/'
                        localRsyncFolder = '/home/users/' + keyHelpUsername + '/www/' + str(
                            imscpAliasDomainsValue.get('iAliasDomainIdna')) + '/'

                        if imscpSshPublicKey:
                            cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "ssh -i ' + \
                                  imscpSshPublicKey + ' -p ' + imscpSshPort + ' -q" --rsync-path="rsync" ' + \
                                  imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + localRsyncFolder
                        else:
                            cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "sshpass -p ' + \
                                  imscpRootPassword + ' ssh -p ' + \
                                  imscpSshPort + ' -q" --rsync-path="rsync" --exclude={"dovecot.sieve"} ' + \
                                  imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + localRsyncFolder

                        proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                        while True:
                            output = proc.stdout.readline().decode('utf-8')
                            if output == '' and proc.poll() is not None:
                                break
                            if '-chk' in str(output):
                                m = re.findall(r'-chk=(\d+)/(\d+)', str(output))
                                total_files = int(m[0][1])
                                progress = (100 * (int(m[0][1]) - int(m[0][0]))) / total_files
                                sys.stdout.write('\rSyncing of webspace ' + str(
                                    imscpAliasDomainsValue.get('iAliasDomainIdna')) + ' done: ' + str(
                                    round(progress, 2)) + '%')
                                sys.stdout.flush()
                                if int(m[0][0]) == 0:
                                    break

                        proc.stdout.close()
                        print('\nFinished syncing webspace "' + str(
                            imscpAliasDomainsValue.get('iAliasDomainIdna')) + '".')

                        # Rsync 00_private of the alias domain
                        print('\nPlease wait.... Create 00_private dir (00_private/' + str(
                            imscpAliasDomainsValue.get('iAliasDomainIdna')) + ') for the domain if not exist.')
                        if not os.path.exists('/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                                imscpAliasDomainsValue.get('iAliasDomainIdna')) + '/'):
                            os.makedirs('/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                                imscpAliasDomainsValue.get('iAliasDomainIdna')) + '/')

                        print('Syncing 00_private folder from alias domain "' + str(
                            imscpAliasDomainsValue.get('iAliasDomainIdna')) + '" :')
                        additionalDomainData = imscpAliasDomainsValue.get('iAliasDomainData').split("|")
                        additionalDomainData[0].strip()
                        additionalDomainData[1].strip()
                        remoteRsyncFolder = '/var/www/virtual/' + firstDomainIdna + str(
                            additionalDomainData[0]) + '/00_private/'
                        localRsyncFolder = '/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                            imscpAliasDomainsValue.get('iAliasDomainIdna')) + '/'

                        if imscpSshPublicKey:
                            cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "ssh -i ' + \
                                  imscpSshPublicKey + ' -p ' + imscpSshPort + ' -q" --rsync-path="rsync" ' + \
                                  imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + \
                                  localRsyncFolder
                        else:
                            cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "sshpass -p ' + \
                                  imscpRootPassword + ' ssh -p ' + \
                                  imscpSshPort + ' -q" --rsync-path="rsync" --exclude={"dovecot.sieve"} ' + \
                                  imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + \
                                  localRsyncFolder

                        proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                        while True:
                            output = proc.stdout.readline().decode('utf-8')
                            if output == '' and proc.poll() is not None:
                                break
                            if '-chk' in str(output):
                                m = re.findall(r'-chk=(\d+)/(\d+)', str(output))
                                total_files = int(m[0][1])
                                progress = (100 * (int(m[0][1]) - int(m[0][0]))) / total_files
                                sys.stdout.write('\rSyncing of 00_private folder of ' + str(
                                    imscpAliasDomainsValue.get('iAliasDomainIdna')) + ' done: ' + str(
                                    round(progress, 2)) + '%')
                                sys.stdout.flush()
                                if int(m[0][0]) == 0:
                                    break

                        proc.stdout.close()
                        print('\nFinished syncing 00_private folder of alias domain "' + str(
                            imscpAliasDomainsValue.get('iAliasDomainIdna')) + '".')
                        os.system(
                            'chown -R ' + keyHelpUsername + ':' + keyHelpUsername + ' /home/users/' + keyHelpUsername + '/')
                        print('System owner for webspace "' + str(
                            imscpAliasDomainsValue.get('iAliasDomainIdna')) + '". successfully updated.\n')
                        time.sleep(1)
                    else:
                        print('\nIgnore syncing from alias domain "' + str(
                            imscpAliasDomainsValue.get('iAliasDomainIdna')) + '" !')

                # Rsync i-MSCP alias sub domains
                for aliasDomainParentId in aliasParentDomainIds:
                    for imscpAliasSubDomainsKey, imscpAliasSubDomainsValue in imscpInputData.imscpAliasSubDomains[
                        'aliasid-' + aliasDomainParentId].items():
                        # print(imscpAliasSubDomainsKey, '->', imscpAliasSubDomainsValue)
                        if imscpAliasSubDomainsValue.get('iAliasSubDomainRsync') and imscpAliasSubDomainsValue.get(
                                'iAliasSubDomainIdna') in keyhelpAddData.keyhelpAddedDomains:
                            keyHelpUsername = str(keyhelpInputData.keyhelpData['kusername'].lower())
                            print('Please wait.... Checking whether Keyhelp is ready with folder creation.')
                            loop_starts = time.time()
                            while True:
                                now = time.time()
                                sys.stdout.write(
                                    '\rWaiting since {0} seconds for Keyhelp.'.format(int(now - loop_starts)))
                                sys.stdout.flush()
                                time.sleep(1)
                                if os.path.exists('/home/users/' + keyHelpUsername + '/www/' + str(
                                        imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + '/'):
                                    break
                                seconds = format(int(now - loop_starts))
                                if int(seconds) > 20:
                                    os.makedirs('/home/users/' + keyHelpUsername + '/www/' + str(
                                        imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + '/')

                            print('Syncing webspace from alias sub domain "' + str(
                                imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + '" :')
                            additionalDomainData = imscpAliasSubDomainsValue.get('iAliasSubDomainData').split("|")
                            additionalDomainData[0].strip()
                            additionalDomainData[1].strip()
                            remoteRsyncFolder = '/var/www/virtual/' + firstDomainIdna + str(
                                additionalDomainData[0]) + str(
                                additionalDomainData[1]) + '/'
                            localRsyncFolder = '/home/users/' + keyHelpUsername + '/www/' + str(
                                imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + '/'

                            if imscpSshPublicKey:
                                cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "ssh -i ' + \
                                      imscpSshPublicKey + ' -p ' + imscpSshPort + ' -q" --rsync-path="rsync" ' + \
                                      imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + localRsyncFolder
                            else:
                                cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "sshpass -p ' + \
                                      imscpRootPassword + ' ssh -p ' + \
                                      imscpSshPort + ' -q" --rsync-path="rsync" --exclude={"dovecot.sieve"} ' + \
                                      imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + localRsyncFolder

                            proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                            while True:
                                output = proc.stdout.readline().decode('utf-8')
                                if output == '' and proc.poll() is not None:
                                    break
                                if '-chk' in str(output):
                                    m = re.findall(r'-chk=(\d+)/(\d+)', str(output))
                                    total_files = int(m[0][1])
                                    progress = (100 * (int(m[0][1]) - int(m[0][0]))) / total_files
                                    sys.stdout.write('\rSyncing of webspace ' + str(
                                        imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + ' done: ' + str(
                                        round(progress, 2)) + '%')
                                    sys.stdout.flush()
                                    if int(m[0][0]) == 0:
                                        break

                            proc.stdout.close()
                            print('\nFinished syncing webspace "' + str(
                                imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + '".')

                            # Rsync 00_private of the alias domain
                            print('\nPlease wait.... Create 00_private dir (00_private/' + str(
                                imscpAliasSubDomainsValue.get(
                                    'iAliasSubDomainIdna')) + ') for the domain if not exist.')
                            if not os.path.exists('/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                                    imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + '/'):
                                os.makedirs('/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                                    imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + '/')

                            print('Syncing 00_private folder from alias sub domain "' + str(
                                imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + '" :')
                            additionalDomainData = imscpAliasSubDomainsValue.get('iAliasSubDomainData').split("|")
                            additionalDomainData[0].strip()
                            additionalDomainData[1].strip()
                            remoteRsyncFolder = '/var/www/virtual/' + firstDomainIdna + str(
                                additionalDomainData[0]) + '/00_private/'
                            localRsyncFolder = '/home/users/' + keyHelpUsername + '/www/00_private/' + str(
                                imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + '/'

                            if imscpSshPublicKey:
                                cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "ssh -i ' + \
                                      imscpSshPublicKey + ' -p ' + imscpSshPort + ' -q" --rsync-path="rsync" ' + \
                                      imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + localRsyncFolder
                            else:
                                cmd = 'rsync -aHAXSz --delete --info=progress --numeric-ids -e "sshpass -p ' + \
                                      imscpRootPassword + ' ssh -p ' + \
                                      imscpSshPort + ' -q" --rsync-path="rsync" --exclude={"dovecot.sieve"} ' + \
                                      imscpSshUsername + '@' + imscpServerFqdn + ':' + remoteRsyncFolder + ' ' + localRsyncFolder

                            proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                            while True:
                                output = proc.stdout.readline().decode('utf-8')
                                if output == '' and proc.poll() is not None:
                                    break
                                if '-chk' in str(output):
                                    m = re.findall(r'-chk=(\d+)/(\d+)', str(output))
                                    total_files = int(m[0][1])
                                    progress = (100 * (int(m[0][1]) - int(m[0][0]))) / total_files
                                    sys.stdout.write('\rSyncing of 00_private folder of ' + str(
                                        imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + ' done: ' + str(
                                        round(progress, 2)) + '%')
                                    sys.stdout.flush()
                                    if int(m[0][0]) == 0:
                                        break

                            proc.stdout.close()
                            print('\nFinished syncing 00_private folder of alias sub domain "' + str(
                                imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + '".')
                            os.system(
                                'chown -R ' + keyHelpUsername + ':' + keyHelpUsername + ' /home/users/' + keyHelpUsername + '/')
                            print('System owner for webspace "' + str(
                                imscpAliasSubDomainsValue.get(
                                    'iAliasSubDomainIdna')) + '". successfully updated.\n')
                            time.sleep(1)
                        else:
                            print('\nIgnore syncing from alias sub domain "' + str(
                                imscpAliasSubDomainsValue.get('iAliasSubDomainIdna')) + '" !')
                # End migration
                print(
                    '\n\nCongratulations. The migration is done. Check now the logs and make the last manually changes.')
            else:
                print('Migration stopped!')
        else:
            _global_config.write_log('ERROR "' + keyhelpInputData.keyhelpData['kusername'] + '" failed to add.')
            print('ERROR "' + keyhelpInputData.keyhelpData['kusername'] + '" failed to add.\n')
    else:
        print('Migration stopped!')
