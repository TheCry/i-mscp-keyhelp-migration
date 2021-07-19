from distutils.util import strtobool

import json
import mysql.connector
import random
import re
import requests
import string
import time
from mysql.connector import errorcode

import _global_config

_global_config.init()

# General
keyhelpSleeptime = _global_config.keyhelpSleeptime

# KeyHelp
apiServerFqdn = _global_config.apiServerFqdn
apiKey = _global_config.apiKey
apiTimeout = _global_config.apiTimeout
keyhelpMinPasswordLenght = _global_config.keyhelpMinPasswordLenght
apiServerFqdnVerify = _global_config.apiServerFqdnVerify
keyhelpConfigfile = _global_config.keyhelpConfigfile
keyhelpSendloginCredentials = _global_config.keyhelpSendloginCredentials
keyhelpCreateSystemDomain = _global_config.keyhelpCreateSystemDomain
keyhelpUpdatePasswordWithApi = _global_config.keyhelpUpdatePasswordWithApi

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
apiEndpointDns = 'dns'
apiEndpointDirProtection = 'directory-protections'
headers = {
    'X-API-Key': apiKey
}


class KeyhelpGetData:
    def __init__(self):
        self.complete = False
        self.keyhelpData = dict()

    def getServerInformations(self, apiGetData):
        # print(apiGetData['meta']['ip_addresses'])
        self.keyhelpData['kipaddresses'] = apiGetData['meta']['ip_addresses']

    # for ipaddressValue in apiGetData['meta']['ip_addresses']:
    #	print(ipaddressValue)

    def getDnsData(self, kDomainId, kDomainName):
        try:
            responseApi = requests.get(apiUrl + apiEndpointDns + '/' + str(kDomainId), headers=headers,
                                       timeout=apiTimeout, verify=apiServerFqdnVerify)
        except requests.exceptions.HTTPError as errorApi:
            raise SystemExit("An Http Error occurred:" + str(errorApi))
        except requests.exceptions.ConnectionError as errorApi:
            raise SystemExit("An Error Connecting to the API occurred:" + str(errorApi))
        except requests.exceptions.Timeout as errorApi:
            raise SystemExit("A Timeout Error occurred:" + str(errorApi))
        except requests.exceptions.RequestException as errorApi:
            raise SystemExit("An Unknown Error occurred:" + str(errorApi))

        apiGetData = responseApi.json()
        if responseApi.status_code == 200:
            self.keyhelpDomainDnsData = dict()
            print('KeyHelp dns zone for domain "' + kDomainName + '" exists.')
            self.keyhelpDomainDnsData = apiGetData
            return True
        else:
            print("KeyHelp dns zone for domain '" + kDomainName + "' does not exist: Code: %i" % (
                responseApi.status_code))
            return False

    def getServerDatabaseCredentials(self, kConfigfileName):
        try:
            kConfigfile = open(kConfigfileName, 'r')
            keyHelpData = kConfigfile.read()
            keyHelpObj = json.loads(keyHelpData)
            self.keyhelpData['kdatabaseRoot'] = keyHelpObj['database']['root']['username']
            self.keyhelpData['kdatabaseRootPassword'] = keyHelpObj['database']['root']['password']
            _global_config.write_log('Debug KeyHelp informations:\nKeyHelp database root username: ' + self.keyhelpData[
                'kdatabaseRoot'] + '\nKeyHelp database root password: ' + self.keyhelpData[
                                         'kdatabaseRootPassword'] + '\n')

            kConfigfile.close()
            return True
        except IOError:
            print('Error: File "' + kConfigfileName + '" does not exist.')
            return False

    def getAllKeyHelpUsernames(self):
        self.keyhelpUsernames = []
        try:
            responseApi = requests.get(apiUrl + apiEndpointClients + '/', headers=headers,
                                       timeout=apiTimeout, verify=apiServerFqdnVerify)
        except requests.exceptions.HTTPError as errorApi:
            raise SystemExit("An Http Error occurred:" + str(errorApi))
        except requests.exceptions.ConnectionError as errorApi:
            raise SystemExit("An Error Connecting to the API occurred:" + str(errorApi))
        except requests.exceptions.Timeout as errorApi:
            raise SystemExit("A Timeout Error occurred:" + str(errorApi))
        except requests.exceptions.RequestException as errorApi:
            raise SystemExit("An Unknown Error occurred:" + str(errorApi))

        apiGetData = responseApi.json()
        if responseApi.status_code == 200:
            for keyHelpUserData in apiGetData:
                self.keyhelpUsernames.append(keyHelpUserData['username'])

            return True
        else:
            print("KeyHelp clients listing error: Code: %i" % (responseApi.status_code))
            return False

    def getIdKeyhelpUsername(self, kUsername):
        self.keyhelpUserId = ''

        try:
            responseApi = requests.get(apiUrl + apiEndpointClients + '/name/' + kUsername, headers=headers,
                                       timeout=apiTimeout, verify=apiServerFqdnVerify)
        except requests.exceptions.HTTPError as errorApi:
            raise SystemExit("An Http Error occurred:" + str(errorApi))
        except requests.exceptions.ConnectionError as errorApi:
            raise SystemExit("An Error Connecting to the API occurred:" + str(errorApi))
        except requests.exceptions.Timeout as errorApi:
            raise SystemExit("A Timeout Error occurred:" + str(errorApi))
        except requests.exceptions.RequestException as errorApi:
            raise SystemExit("An Unknown Error occurred:" + str(errorApi))

        apiGetData = responseApi.json()
        if responseApi.status_code == 200:
            self.keyhelpUserId = apiGetData['id']
            return True
        else:
            print("KeyHelp clients list error: Code: %i" % (responseApi.status_code))
            return False

    def checkExistKeyhelpUsername(self, kUsername):
        if (len(kUsername) > 0):
            if re.match("^[a-z-]*$", str(kUsername)):
                try:
                    responseApi = requests.get(apiUrl + apiEndpointClients + '/name/' + kUsername, headers=headers,
                                               timeout=apiTimeout, verify=apiServerFqdnVerify)
                except requests.exceptions.HTTPError as errorApi:
                    raise SystemExit("An Http Error occurred:" + str(errorApi))
                except requests.exceptions.ConnectionError as errorApi:
                    raise SystemExit("An Error Connecting to the API occurred:" + str(errorApi))
                except requests.exceptions.Timeout as errorApi:
                    raise SystemExit("A Timeout Error occurred:" + str(errorApi))
                except requests.exceptions.RequestException as errorApi:
                    raise SystemExit("An Unknown Error occurred:" + str(errorApi))

                apiGetData = responseApi.json()
                if responseApi.status_code == 404:
                    self.KeyHelpAdminExists = False
                    self.__checkExistKeyhelpUsernameAsAdmin(kUsername)
                    if not self.KeyHelpAdminExists:
                        _global_config.write_log(
                            'Debug KeyHelp informations:\nKeyHelp panel username: "' + kUsername + '"\n')
                        print('KeyHelp username is ok.')
                        self.keyhelpData['kusername'] = kUsername
                        self.complete = False
                        return True
                    else:
                        print('KeyHelp username "' + kUsername + '" allready exists!')
                        self.complete = False
                        return False
                else:
                    print("KeyHelp username allready exists: Code: %i - %s, Id: %s" % (
                        responseApi.status_code, apiGetData['username'], apiGetData['id']))
                    return False
            else:
                print('Your Keyhelp username contains chars which are not allowed (only: a-z, -)!')
                return False
        else:
            print('Your Keyhelp username is empty!')
            return False

    def __checkExistKeyhelpUsernameAsAdmin(self, kUsername):
        try:
            db_connection = mysql.connector.connect(
                host="localhost",
                user="" + self.keyhelpData['kdatabaseRoot'] + "",
                passwd="" + self.keyhelpData['kdatabaseRootPassword'] + "",
                database="keyhelp"
            )
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with the user name or password")
                exit(1)
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
                exit(1)
            else:
                print(err)
                exit(1)
        else:
            cursor = db_connection.cursor()
            cursor.execute("SELECT username FROM users WHERE is_admin = 1;")
            rows = cursor.fetchall()
            for row in rows:
                if str(kUsername).lower() == str(row[0]).lower():
                    self.KeyHelpAdminExists = True

            db_connection.commit()
            cursor.close()
            db_connection.close()

    def checkExistDefaultHostingplan(self, kDefaultHostingplan):
        try:
            responseApi = requests.get(apiUrl + apiEndpointHostingplans + '/name/' + kDefaultHostingplan,
                                       headers=headers, timeout=apiTimeout, verify=apiServerFqdnVerify)
        except requests.exceptions.HTTPError as errorApi:
            raise SystemExit("An Http Error occurred:" + str(errorApi))
        except requests.exceptions.ConnectionError as errorApi:
            raise SystemExit("An Error Connecting to the API occurred:" + str(errorApi))
        except requests.exceptions.Timeout as errorApi:
            raise SystemExit("A Timeout Error occurred:" + str(errorApi))
        except requests.exceptions.RequestException as errorApi:
            raise SystemExit("An Unknown Error occurred:" + str(errorApi))

        apiGetData = responseApi.json()
        if responseApi.status_code == 200:
            _global_config.write_log(
                'Debug KeyHelp informations:\nDefault hosting plan: "' + kDefaultHostingplan + '"\n')
            print('KeyHelp default hostingplan "' + kDefaultHostingplan + '" exists.\n')
            self.keyhelpData['kdefaulthostingplan'] = kDefaultHostingplan
            self.keyhelpData['kdefaulthostingplanid'] = apiGetData['id']  ###id muss hier eingetragen werden
            return True
        else:
            print("KeyHelp default hostingplan '" + kDefaultHostingplan + "' does not exist: Code: %i" % (
                responseApi.status_code))
            return False

    def checkExistHostingplan(self, kHostingplan):
        try:
            responseApi = requests.get(apiUrl + apiEndpointHostingplans + '/name/' + kHostingplan, headers=headers,
                                       timeout=apiTimeout, verify=apiServerFqdnVerify)
        except requests.exceptions.HTTPError as errorApi:
            raise SystemExit("An Http Error occurred:" + str(errorApi))
        except requests.exceptions.ConnectionError as errorApi:
            raise SystemExit("An Error Connecting to the API occurred:" + str(errorApi))
        except requests.exceptions.Timeout as errorApi:
            raise SystemExit("A Timeout Error occurred:" + str(errorApi))
        except requests.exceptions.RequestException as errorApi:
            raise SystemExit("An Unknown Error occurred:" + str(errorApi))

        apiGetData = responseApi.json()
        if responseApi.status_code == 200:
            print('KeyHelp hostingplan "' + kHostingplan + '" exists.\n')
            self.keyhelpData['khostingplan'] = kHostingplan
            self.keyhelpData['khostingplanid'] = apiGetData['id']  ###id muss hier eingetragen werden
            return True
        else:
            print("KeyHelp hostingplan '" + kHostingplan + "' does not exist: Code: %i" % (responseApi.status_code))
            return False

    def KeyhelpPassword(self, kPassword, kMinPasswordLenght):
        if (len(kPassword) < kMinPasswordLenght):
            print('Your passwword is to small. Min. lenght: ' + str(kMinPasswordLenght))
            return False
        else:
            _global_config.write_log('Debug KeyHelp informations:\nKeyHelp panel password: "' + kPassword + '"\n')
            self.keyhelpData['kpassword'] = kPassword
            self.complete = False
            return True

    def keyhelpCreateRandomPassword(self, kMinPasswordLenght):
        specialChars = string.punctuation
        specialChars = re.sub(r"'", "", specialChars, flags=re.UNICODE)
        specialChars = re.sub(r"\"", "", specialChars, flags=re.UNICODE)
        specialChars = re.sub(r"`", "", specialChars, flags=re.UNICODE)
        passwordCharacters = string.ascii_letters + string.digits + str(specialChars)
        kPassword = ''.join(random.choice(passwordCharacters) for i in range(kMinPasswordLenght))
        _global_config.write_log('Debug KeyHelp informations:\nKeyHelp panel password: "' + kPassword + '"\n')
        self.keyhelpData['kpassword'] = kPassword
        self.complete = False

        return True

    def KeyhelpEmailaddress(self, kEmailaddress):
        emailRegex = '[^@]+@[^@]+\.[^@]+'
        if (re.search(emailRegex, kEmailaddress)):
            _global_config.write_log(
                'Debug KeyHelp informations:\nKeyHelp panel user emailaddress: "' + kEmailaddress + '"\n')
            self.keyhelpData['kemailaddress'] = kEmailaddress
            self.complete = False
            return True
        else:
            print('Your emailaddress is invalid!')
            return False

    def KeyhelpSurname(self, kSurname):
        if (len(kSurname) > 0):
            _global_config.write_log('Debug KeyHelp informations:\nKeyHelp panel user surname: "' + kSurname + '"\n')
            self.keyhelpData['ksurname'] = kSurname
            self.complete = False
            return True
        else:
            print('Your Surname is empty')
            return False

    def KeyhelpName(self, kName):
        if (len(kName) > 0):
            _global_config.write_log('Debug KeyHelp informations:\nKeyHelp panel user name: "' + kName + '"\n')
            self.keyhelpData['kname'] = kName
            self.complete = False
            return True
        else:
            print('Your Name is empty')
            return False

    def KeyhelpHostingplan(self, kHostingplan):
        if (len(kHostingplan) < 1):
            _global_config.write_log(
                'Debug KeyHelp informations:\nUsing hosting plan: "' + self.keyhelpData['kdefaulthostingplan'] + '"\n')
            self.keyhelpData['khostingplan'] = self.keyhelpData['kdefaulthostingplan']
            self.keyhelpData['khostingplanid'] = self.keyhelpData['kdefaulthostingplanid']
            self.complete = True
            return True
        else:
            if self.checkExistHostingplan(kHostingplan):
                _global_config.write_log('Debug KeyHelp informations:\nUsing hosting plan: "' + kHostingplan + '"\n')
                self.complete = True
                return True
            else:
                return False

    def keyhelpDataComplete(self):
        if not self.complete:
            return False
        else:
            return True


class KeyHelpAddDataToServer:
    def __init__(self):
        self.status = False
        self.keyhelpApiReturnData = dict()
        self.keyhelpAddedDbUsernames = []
        self.keyhelpAddedEmailAddresses = []
        self.keyhelpAddedDomains = []
        self.imscpRoundcubeContact2Contactgroup = {}

    def updateKeyHelpDataToApi(self, apiEndPoint, keyHelpData):
        apiJsonData = self.__makeClientsJsonData(keyHelpData, apiEndPoint, updateData=True)
        try:
            responseApi = requests.put(apiUrl + apiEndPoint + '/' + str(keyHelpData['keyhelpDomainId']),
                                       data=apiJsonData,
                                       headers=headers, timeout=apiTimeout, verify=apiServerFqdnVerify)
        except requests.exceptions.HTTPError as errorApi:
            raise SystemExit("An Http Error occurred:" + str(errorApi))
        except requests.exceptions.ConnectionError as errorApi:
            raise SystemExit("An Error Connecting to the API occurred:" + str(errorApi))
        except requests.exceptions.Timeout as errorApi:
            raise SystemExit("A Timeout Error occurred:" + str(errorApi))
        except requests.exceptions.RequestException as errorApi:
            raise SystemExit("An Unknown Error occurred:" + str(errorApi))

        apiPostData = responseApi.json()
        if apiEndPoint == 'domains' and responseApi.status_code == 200:
            _global_config.write_log(
                'KeyHelp domain "' + str(keyHelpData['iSslDomainIdna'] + '" updated successfully'))
            print('Please wait...')
            time.sleep(int(keyhelpSleeptime))
        else:
            _global_config.write_log("KeyHelp API Message: %i - %s, Message %s" % (
                responseApi.status_code, responseApi.reason, apiPostData['message']))
            print("KeyHelp API Message: %i - %s, Message %s" % (
                responseApi.status_code, responseApi.reason, apiPostData['message']))
            self.status = False

    def updateKeyHelpDnsToApi(self, apiEndPoint, keyHelpDnsData, iMscpDnsData, domainId, domainName, kindOfDomain):
        for DnsKey, DnsValue in iMscpDnsData.items():
            if kindOfDomain == 'domain':
                keyHelpDnsData['records']['other'].append(
                    {'host': str(DnsValue.get('iDomainDnsEntry')), 'ttl': str(DnsValue.get('iDomainDnsEntryTTL')),
                     'type': str(DnsValue.get('iDomainType')), 'value': str(DnsValue.get('iDomainText'))})
            elif kindOfDomain == 'domainAlias':
                keyHelpDnsData['records']['other'].append({'host': str(DnsValue.get('iDomainAliasDnsEntry')),
                                                           'ttl': str(DnsValue.get('iDomainAliasDnsEntryTTL')),
                                                           'type': str(DnsValue.get('iDomainAliasType')),
                                                           'value': str(DnsValue.get('iDomainAliasText'))})
        del keyHelpDnsData['is_custom_dns']
        del keyHelpDnsData['is_dns_disabled']
        del keyHelpDnsData['dkim_txt_record']
        apiJsonData = json.dumps(keyHelpDnsData)
        try:
            responseApi = requests.put(apiUrl + apiEndPoint + '/' + str(domainId),
                                       data=apiJsonData,
                                       headers=headers, timeout=apiTimeout, verify=apiServerFqdnVerify)
        except requests.exceptions.HTTPError as errorApi:
            raise SystemExit("An Http Error occurred:" + str(errorApi))
        except requests.exceptions.ConnectionError as errorApi:
            raise SystemExit("An Error Connecting to the API occurred:" + str(errorApi))
        except requests.exceptions.Timeout as errorApi:
            raise SystemExit("A Timeout Error occurred:" + str(errorApi))
        except requests.exceptions.RequestException as errorApi:
            raise SystemExit("An Unknown Error occurred:" + str(errorApi))

        apiPostData = responseApi.json()
        if responseApi.status_code == 200:
            _global_config.write_log(
                'KeyHelp domain dns "' + str(domainName + '" updated successfully'))
            print('Please wait...')
            time.sleep(int(keyhelpSleeptime))
        else:
            _global_config.write_log("KeyHelp API Message: %i - %s, Message %s" % (
                responseApi.status_code, responseApi.reason, apiPostData['message']))
            print("KeyHelp API Message: %i - %s, Message %s" % (
                responseApi.status_code, responseApi.reason, apiPostData['message']))
            self.status = False

    def addKeyHelpDataToApi(self, apiEndPoint, keyHelpData):
        apiJsonData = self.__makeClientsJsonData(keyHelpData, apiEndPoint)
        try:
            responseApi = requests.post(apiUrl + apiEndPoint + '/', data=apiJsonData, headers=headers,
                                        timeout=apiTimeout, verify=apiServerFqdnVerify)
        except requests.exceptions.HTTPError as errorApi:
            raise SystemExit("An Http Error occurred:" + str(errorApi))
        except requests.exceptions.ConnectionError as errorApi:
            raise SystemExit("An Error Connecting to the API occurred:" + str(errorApi))
        except requests.exceptions.Timeout as errorApi:
            raise SystemExit("A Timeout Error occurred:" + str(errorApi))
        except requests.exceptions.RequestException as errorApi:
            raise SystemExit("An Unknown Error occurred:" + str(errorApi))

        try:
            apiPostData = responseApi.json()
        except ValueError:
            print('\nSomething went wrong while making the API request. Try again in 5 seconds!\n')
            time.sleep(int(5))
            try:
                responseApi = requests.post(apiUrl + apiEndPoint + '/', data=apiJsonData, headers=headers,
                                            timeout=apiTimeout, verify=apiServerFqdnVerify)
            except requests.exceptions.HTTPError as errorApi:
                raise SystemExit("An Http Error occurred:" + str(errorApi))
            except requests.exceptions.ConnectionError as errorApi:
                raise SystemExit("An Error Connecting to the API occurred:" + str(errorApi))
            except requests.exceptions.Timeout as errorApi:
                raise SystemExit("A Timeout Error occurred:" + str(errorApi))
            except requests.exceptions.RequestException as errorApi:
                raise SystemExit("An Unknown Error occurred:" + str(errorApi))

            try:
                apiPostData = responseApi.json()
            except ValueError as errorApi:
                print('Second time. Something went wrong while making the API request!')
                raise SystemExit("Error occurred:" + str(errorApi))

        if apiEndPoint == 'clients' and responseApi.status_code == 201:
            self.keyhelpApiReturnData['keyhelpUserId'] = apiPostData['id']
            _global_config.write_log('Debug KeyHelp informations:\nKeyHelp username "' + str(
                keyHelpData['kusername']) + '" added successfully')
            _global_config.write_log('KeyHelp username id: "' + str(self.keyhelpApiReturnData['keyhelpUserId']) + '"')
            self.status = True
        elif apiEndPoint == 'domains' and responseApi.status_code == 201:
            self.keyhelpApiReturnData['keyhelpDomainId'] = apiPostData['id']
            if 'iUsernameDomainIdna' in keyHelpData:
                self.keyhelpAddedDomains.append(keyHelpData['iUsernameDomainIdna'])
                _global_config.write_log(
                    'KeyHelp domain "' + str(keyHelpData['iUsernameDomainIdna']) + '" added successfully')
                _global_config.write_log('KeyHelp domain: "' + str(keyHelpData['iUsernameDomainIdna']) + '"')
                _global_config.write_log(
                    'KeyHelp domain id: "' + str(self.keyhelpApiReturnData['keyhelpDomainId']) + '"')
                self.status = True
            elif 'iAliasDomainIdna' in keyHelpData:
                self.keyhelpAddedDomains.append(keyHelpData['iAliasDomainIdna'])
                _global_config.write_log(
                    'KeyHelp domain "' + str(keyHelpData['iAliasDomainIdna'] + '" added successfully'))
                _global_config.write_log('KeyHelp domain: "' + str(keyHelpData['iAliasDomainIdna']) + '"')
                _global_config.write_log(
                    'KeyHelp domain id: "' + str(self.keyhelpApiReturnData['keyhelpDomainId']) + '"')
                self.status = True
            elif 'iSubDomainIdna' in keyHelpData:
                self.keyhelpAddedDomains.append(keyHelpData['iSubDomainIdna'])
                _global_config.write_log(
                    'KeyHelp sub domain "' + str(keyHelpData['iSubDomainIdna'] + '" added successfully'))
                _global_config.write_log('KeyHelp sub domain: "' + str(keyHelpData['iSubDomainIdna']) + '"')
                _global_config.write_log(
                    'KeyHelp domain id: "' + str(self.keyhelpApiReturnData['keyhelpDomainId']) + '"')
                self.status = True
            elif 'iAliasSubDomainIdna' in keyHelpData:
                self.keyhelpAddedDomains.append(keyHelpData['iAliasSubDomainIdna'])
                _global_config.write_log(
                    'KeyHelp sub domain "' + str(keyHelpData['iAliasSubDomainIdna'] + '" added successfully'))
                _global_config.write_log('KeyHelp sub domain: "' + str(keyHelpData['iAliasSubDomainIdna']) + '"')
                _global_config.write_log(
                    'KeyHelp domain id: "' + str(self.keyhelpApiReturnData['keyhelpDomainId']) + '"')
                self.status = True
            else:
                print('Unknown API action!')

            print('Please wait...')
            time.sleep(int(keyhelpSleeptime))
        elif apiEndPoint == 'emails' and responseApi.status_code == 201:
            _global_config.write_log(
                'EMail address "' + str(keyHelpData['iEmailAddress'] + '" added successfully'))
            if keyHelpData['iEmailMailPassword'] and not keyhelpUpdatePasswordWithApi:
                self.__updateEmailPasswordWithImscpPassword(keyHelpData, apiPostData['id'])
                _global_config.write_log(
                    'EMail address "' + str(keyHelpData['iEmailAddress'] + '" with old i-MSCP password updated'))
            if keyHelpData['emailNeedRsync']:
                self.keyhelpAddedEmailAddresses.append(keyHelpData['iEmailAddress'])
            self.status = True
        elif apiEndPoint == 'databases' and responseApi.status_code == 201:
            self.keyhelpAddedDbUsernames.append(keyHelpData['iDatabaseUsername'])
            _global_config.write_log(
                '\nDatabase "' + str(keyHelpData['iDatabaseName'] + '" added successfully'))
            _global_config.write_log(
                'Database "' + str(
                    keyHelpData['iDatabaseName'] + '" is the new database for the i-MSCP database: ' + keyHelpData[
                        'iOldDatabaseName']))
            _global_config.write_log(
                'Database username for "' + str(
                    keyHelpData['iDatabaseName'] + '": ' + keyHelpData['iDatabaseUsername']))
            _global_config.write_log(
                'Database username "' + str(
                    keyHelpData['iDatabaseUsername'] + '" is the new db user for the i-MSCP db user: ' + keyHelpData[
                        'iOldDatabaseUsername']))
            _global_config.write_log(
                'Database password for "' + str(
                    keyHelpData['iDatabaseUsername'] + '": ' + keyHelpData['iDatabaseUserPassword']))
            _global_config.write_log(
                'Database host for "' + str(
                    keyHelpData['iDatabaseUsername'] + '": ' + keyHelpData['iDatabaseUserHost']) + '\n')
            self.status = True
        elif apiEndPoint == 'ftp-users' and responseApi.status_code == 201:
            _global_config.write_log(
                'FTP user "' + str(keyHelpData['iFtpUsername'] + '" added successfully'))
            if keyHelpData['iFtpUserPassword'] and not keyhelpUpdatePasswordWithApi:
                self.__updateFtpPasswordWithImscpPassword(keyHelpData, apiPostData['id'])
                _global_config.write_log(
                    'FTP user "' + str(keyHelpData['iFtpUsername'] + '" with old i-MSCP password updated'))

            _global_config.write_log('FTP user homedir is now "' + str(keyHelpData['iFtpUserHomeDir'] + '". In i-MSCP '
                                                                                                        'it was: ' +
                                                                       keyHelpData['iOldFtpUserHomeDir']))
        elif apiEndPoint == 'certificates' and responseApi.status_code == 201:
            self.keyhelpApiReturnData['keyhelpSslId'] = apiPostData['id']
            _global_config.write_log(
                'SSL cert for domain "' + str(keyHelpData['iSslDomainIdna'] + '" added successfully'))
            self.status = True
        elif apiEndPoint == 'directory-protections' and responseApi.status_code == 201:
            self.keyhelpApiReturnData['keyhelpDirProtectionId'] = apiPostData['id']
            _global_config.write_log(
                'Directory protection "' + str(keyHelpData['iHtAccessUsername'] + '" added successfully'))
            self.status = True
        else:
            _global_config.write_log("KeyHelp API Message: %i - %s, Message %s" % (
                responseApi.status_code, responseApi.reason, apiPostData['message']))
            print("KeyHelp API Message: %i - %s, Message %s" % (
                responseApi.status_code, responseApi.reason, apiPostData['message']))
            self.status = False

    def __makeClientsJsonData(self, keyHelpData, apiEndPoint, updateData=False):
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
        data = {}
        if apiEndPoint == 'clients':
            data_contact = {}
            data['contact_data'] = {}
            data['username'] = keyHelpData['kusername']
            data['language'] = "de"
            data['email'] = keyHelpData['kemailaddress']
            data['password'] = keyHelpData['kpassword']
            data['notes'] = "User migrated from i-MSCP"
            data['id_hosting_plan'] = keyHelpData['khostingplanid']
            data['is_suspended'] = ''
            data['suspend_on'] = ''
            data['send_login_credentials'] = bool(strtobool(str(keyhelpSendloginCredentials)))
            data['create_system_domain'] = bool(strtobool(str(keyhelpCreateSystemDomain)))
            data_contact['first_name'] = keyHelpData['ksurname']
            data_contact['last_name'] = keyHelpData['kname']
            data_contact['company'] = ''
            data_contact['telephone'] = ''
            data_contact['address'] = ''
            data_contact['city'] = ''
            data_contact['zip'] = ''
            data_contact['state'] = ''
            data_contact['country'] = ''
            data_contact['client_id'] = ''
            data['contact_data'] = data_contact

        if apiEndPoint == 'domains':
            if updateData:
                data_security = {}
                data['security'] = {}
                data_security['id_certificate'] = keyHelpData['keyhelpSslId']
                data_security['force_https'] = bool(strtobool(str('true')))
                data_security['is_hsts'] = bool(strtobool(str(keyHelpData['iSslAllowHsts'])))
                data_security['hsts_max_age'] = keyHelpData['iSslHstsMaxAge']
                data_security['hsts_include'] = bool(strtobool(str(keyHelpData['iSslHstsIncludeSubdomains'])))
                data['security'] = data_security
            else:
                keyHelpDataDomain = ''
                if 'iParentDomainId' in keyHelpData:
                    keyHelpDataParentDomainId = int(keyHelpData['iParentDomainId'])
                else:
                    keyHelpDataParentDomainId = 0

                if 'iUsernameDomainIdna' in keyHelpData:
                    keyHelpDataDomain = keyHelpData['iUsernameDomainIdna']
                    keyHelpAdditionalDomainData = keyHelpData['iDomainData'].split("|")
                    keyHelpAdditionalDomainData[0].strip()
                    keyHelpAdditionalDomainData[1].strip()
                    keyHelpAdditionalDomainData[2].strip()
                    keyHelpData['iDomainUrlMountpoint'] = self.__keyhelpBuildMountpoint(keyHelpAdditionalDomainData[0],
                                                                                        keyHelpAdditionalDomainData[1],
                                                                                        keyHelpDataDomain,
                                                                                        keyHelpData[
                                                                                            'iUsernameDomainIdna'])
                    keyHelpData['iDomainUrlForward'] = keyHelpAdditionalDomainData[2]
                elif 'iAliasDomainIdna' in keyHelpData:
                    keyHelpDataDomain = keyHelpData['iAliasDomainIdna']
                    keyHelpAdditionalDomainData = keyHelpData['iAliasDomainData'].split("|")
                    keyHelpAdditionalDomainData[0].strip()
                    keyHelpAdditionalDomainData[1].strip()
                    keyHelpAdditionalDomainData[2].strip()
                    keyHelpData['iDomainUrlMountpoint'] = self.__keyhelpBuildMountpoint(keyHelpAdditionalDomainData[0],
                                                                                        keyHelpAdditionalDomainData[1],
                                                                                        keyHelpDataDomain,
                                                                                        keyHelpData['iFirstDomainIdna'])
                    keyHelpData['iDomainUrlForward'] = keyHelpAdditionalDomainData[2]
                elif 'iSubDomainIdna' in keyHelpData:
                    keyHelpDataDomain = keyHelpData['iSubDomainIdna']
                    keyHelpAdditionalDomainData = keyHelpData['iSubDomainData'].split("|")
                    keyHelpAdditionalDomainData[0].strip()
                    keyHelpAdditionalDomainData[1].strip()
                    keyHelpAdditionalDomainData[2].strip()
                    keyHelpData['iDomainUrlMountpoint'] = self.__keyhelpBuildMountpoint(keyHelpAdditionalDomainData[0],
                                                                                        keyHelpAdditionalDomainData[1],
                                                                                        keyHelpDataDomain,
                                                                                        keyHelpData['iFirstDomainIdna'])
                    keyHelpData['iDomainUrlForward'] = keyHelpAdditionalDomainData[2]
                elif 'iAliasSubDomainIdna' in keyHelpData:
                    keyHelpDataDomain = keyHelpData['iAliasSubDomainIdna']
                    keyHelpAdditionalDomainData = keyHelpData['iAliasSubDomainData'].split("|")
                    keyHelpAdditionalDomainData[0].strip()
                    keyHelpAdditionalDomainData[1].strip()
                    keyHelpAdditionalDomainData[2].strip()
                    keyHelpData['iDomainUrlMountpoint'] = self.__keyhelpBuildMountpoint(keyHelpAdditionalDomainData[0],
                                                                                        keyHelpAdditionalDomainData[1],
                                                                                        keyHelpDataDomain,
                                                                                        keyHelpData['iFirstDomainIdna'])
                    keyHelpData['iDomainUrlForward'] = keyHelpAdditionalDomainData[2]
                else:
                    print('Fatal Error. No domain name available')
                    exit(1)

                data_target = {}
                data['target'] = {}
                data_security = {}
                data['security'] = {}

                data['id_user'] = int(keyHelpData['addedKeyHelpUserId'])
                data['id_parent_domain'] = keyHelpDataParentDomainId
                data['domain'] = keyHelpDataDomain
                data['php_version'] = ""
                data['is_disabled'] = bool(strtobool(str('false')))
                data['delete_on'] = ''
                data['is_dns_disabled'] = bool(strtobool(str(keyHelpData['keyhelpSetDisableDnsForDomain'])))
                data['is_email_domain'] = bool(strtobool(str('true')))
                data['create_www_subdomain'] = bool(strtobool(str('true')))
                data['create_system_domain'] = bool(strtobool(str(keyhelpCreateSystemDomain)))
                if not keyHelpData['iDomainUrlForward'] == 'no':
                    data_target['target'] = keyHelpData['iDomainUrlForward']
                    data_target['forwarding_type'] = '301'
                else:
                    data_target['target'] = keyHelpData['iDomainUrlMountpoint']
                data['target'] = data_target
                data['security'] = data_security

        if apiEndPoint == 'emails':
            data_aliases = []
            data_forwardings = []
            emailaddressIsCatchall = False

            keyHelpCatchallData = keyHelpData['iEmailCatchall'].split(",")
            if keyHelpData['iEmailAddress'] in keyHelpCatchallData:
                emailaddressIsCatchall = True

            if 'iEmailMailForward' in keyHelpData:
                keyHelpForwardData = keyHelpData['iEmailMailForward'].split(",")
                for emailaddr in keyHelpForwardData:
                    data_forwardings.append(emailaddr)

            data['id_user'] = int(keyHelpData['addedKeyHelpUserId'])
            data['email'] = keyHelpData['iEmailAddress']
            if keyhelpUpdatePasswordWithApi:
                data['password_hash'] = keyHelpData['iEmailMailPassword']
            else:
                data['password'] = keyHelpData['iEmailMailInitialPassword']
            data['description'] = "Email migrated from i-MSCP"
            data['max_size'] = int(keyHelpData['iEmailMailQuota'])
            data['catch_all'] = bool(strtobool(str(emailaddressIsCatchall)))
            data['store_forwarded_emails'] = bool(strtobool(str(keyHelpData['emailStoreForward'])))
            data['aliases'] = data_aliases
            data['forwardings'] = data_forwardings

        if apiEndPoint == 'databases':
            data_remote_hosts = []

            if 'iDatabaseUserHost' in keyHelpData:
                if keyHelpData['iDatabaseUserHost'] != 'localhost':
                    keyHelpRemoteAccessData = keyHelpData['iDatabaseUserHost'].split(",")
                    for ipaddr in keyHelpRemoteAccessData:
                        data_remote_hosts.append(ipaddr)

            data['id_user'] = int(keyHelpData['addedKeyHelpUserId'])
            data['database_name'] = keyHelpData['iDatabaseName']
            data['database_username'] = keyHelpData['iDatabaseUsername']
            data['password'] = keyHelpData['iDatabaseUserPassword']
            data['description'] = "Database migrated from i-MSCP"
            data['remote_hosts'] = data_remote_hosts

            # print(str(data)+'\n')

        if apiEndPoint == 'ftp-users':
            data['id_user'] = int(keyHelpData['addedKeyHelpUserId'])
            data['username'] = keyHelpData['iFtpUsername']
            data['description'] = "FTP user migrated from i-MSCP"
            data['home_directory'] = '/www/' + keyHelpData['iFtpUserHomeDir']
            if keyhelpUpdatePasswordWithApi:
                data['password_hash'] = keyHelpData['iFtpInitialPassword']
            else:
                data['password'] = keyHelpData['iFtpInitialPassword']

        if apiEndPoint == 'certificates':
            data['id_user'] = int(keyHelpData['addedKeyHelpUserId'])
            data['name'] = 'Import from i-MSCP: ' + keyHelpData['iSslDomainIdna']
            data['private_key'] = keyHelpData['iSslPrivateKey']
            data['certificate'] = keyHelpData['iSslCertificate']
            data['ca_certificate'] = keyHelpData['iSslCaBundle']

        if apiEndPoint == 'directory-protections':
            data['id_user'] = int(keyHelpData['addedKeyHelpUserId'])
            data['path'] = keyHelpData['iHtAccessPath']
            data['auth_name'] = keyHelpData['iHtAccessAuthName']
            data['username'] = keyHelpData['iHtAccessUsername']
            data['password_hash'] = keyHelpData['iHtAccessPassword']

        jsonData = json.dumps(data)

        return jsonData

    def addHtAccessUsersFromImscp(self, keyHelpData):
        try:
            db_connection = mysql.connector.connect(
                host="localhost",
                user="" + keyHelpData['kdatabaseRoot'] + "",
                passwd="" + keyHelpData['kdatabaseRootPassword'] + "",
                database="keyhelp"
            )
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with the user name or password")
                exit(1)
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
                exit(1)
            else:
                print(err)
                exit(1)
        else:
            cursor = db_connection.cursor()
            cursor.execute("INSERT INTO directory_protections (id_user, path, auth_name, username, password) VALUES ('" + str(
                keyHelpData['addedKeyHelpUserId']) + "', '" + str(keyHelpData['iHtAccessPath']) + "', '" + str(
                keyHelpData['iHtAccessAuthName']) + "', '" + str(keyHelpData['iHtAccessUsername']) + "', '" + str(
                keyHelpData['iHtAccessPassword']) + "');")

            db_connection.commit()
            cursor.close()
            db_connection.close()

    def __updateEmailPasswordWithImscpPassword(self, keyHelpData, addedEmailId):
        try:
            db_connection = mysql.connector.connect(
                host="localhost",
                user="" + keyHelpData['kdatabaseRoot'] + "",
                passwd="" + keyHelpData['kdatabaseRootPassword'] + "",
                database="keyhelp"
            )
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with the user name or password")
                exit(1)
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
                exit(1)
            else:
                print(err)
                exit(1)
        else:
            cursor = db_connection.cursor()
            cursor.execute(
                "UPDATE mail_users SET password = '" + str(keyHelpData['iEmailMailPassword']) + "' WHERE id = '" + str(
                    addedEmailId) + "';")

            db_connection.commit()
            cursor.close()
            db_connection.close()

    def __updateFtpPasswordWithImscpPassword(self, keyHelpData, addedFtpUserId):
        try:
            db_connection = mysql.connector.connect(
                host="localhost",
                user="" + keyHelpData['kdatabaseRoot'] + "",
                passwd="" + keyHelpData['kdatabaseRootPassword'] + "",
                database="keyhelp"
            )
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with the user name or password")
                exit(1)
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
                exit(1)
            else:
                print(err)
                exit(1)
        else:
            cursor = db_connection.cursor()
            cursor.execute("UPDATE ftp_users SET password = '" + str(
                keyHelpData['iFtpUserPassword']) + "' WHERE id = '" + str(addedFtpUserId) + "';")

            db_connection.commit()
            cursor.close()
            db_connection.close()

    def addRoundcubeContactUsers(self, roundcubeAddData):
        try:
            db_connection = mysql.connector.connect(
                host="localhost",
                user="" + roundcubeAddData['kdatabaseRoot'] + "",
                passwd="" + roundcubeAddData['kdatabaseRootPassword'] + "",
                database="roundcube"
            )
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with the user name or password")
                exit(1)
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
                exit(1)
            else:
                print(err)
                exit(1)
        else:
            cursor = db_connection.cursor()
            try:
                ignore = False
                cursor.execute(
                    "INSERT INTO users (username, mail_host, created, language, preferences) VALUES ('" + str(
                        roundcubeAddData['rUsername']) + "', '" + str(roundcubeAddData['rMailHost']) + "', '" + str(
                        roundcubeAddData['rCreated']) + "', '" + str(roundcubeAddData['rLanguage']) + "', '" + str(
                        roundcubeAddData['rPreferences']) + "');")

                db_connection.commit()
                rlastInserId = cursor.lastrowid
            except (mysql.connector.Error) as err:
                ignore = True
                # print(err)
                print('Error: The email address "' + roundcubeAddData[
                    'rUsername'] + '" allready exists in the roundcube table "users"! Ignoring all contacts of this '
                                   'email address.')
            cursor.close()
            db_connection.close()

            if not ignore:
                self.imscpRoundcubeContact2Contactgroup = roundcubeAddData['imscpRoundcubeContact2Contactgroup']
                if bool(roundcubeAddData['imscpRoundcubeIdentities']):
                    for rcuIdentityKey, rcuIdentityValue in roundcubeAddData['imscpRoundcubeIdentities'].items():
                        if roundcubeAddData['rUserId'] == rcuIdentityValue.get('rUserId'):
                            roundcubeIdentityAddData = {}
                            roundcubeIdentityAddData['kdatabaseRoot'] = roundcubeAddData['kdatabaseRoot']
                            roundcubeIdentityAddData['kdatabaseRootPassword'] = roundcubeAddData[
                                'kdatabaseRootPassword']
                            roundcubeIdentityAddData['identity_id'] = rcuIdentityValue.get('rContactId')
                            roundcubeIdentityAddData['user_id'] = int(rlastInserId)
                            roundcubeIdentityAddData['changed'] = rcuIdentityValue.get('rChanged')
                            roundcubeIdentityAddData['del'] = rcuIdentityValue.get('rDel')
                            roundcubeIdentityAddData['standard'] = rcuIdentityValue.get('rStandard')
                            roundcubeIdentityAddData['name'] = rcuIdentityValue.get('rName')
                            roundcubeIdentityAddData['organization'] = rcuIdentityValue.get('rOrganization')
                            roundcubeIdentityAddData['email'] = rcuIdentityValue.get('rEmail')
                            roundcubeIdentityAddData['reply-to'] = rcuIdentityValue.get('rReplyTo')
                            roundcubeIdentityAddData['bcc'] = rcuIdentityValue.get('rBcc')
                            roundcubeIdentityAddData['signature'] = rcuIdentityValue.get('rSignature')
                            roundcubeIdentityAddData['html_signature'] = rcuIdentityValue.get('rHtmlSignature')

                            self.__addRoundcubeIdentities(roundcubeIdentityAddData)

                if bool(roundcubeAddData['imscpRoundcubeContacts']):
                    for rcuContactKey, rcuContactValue in roundcubeAddData['imscpRoundcubeContacts'].items():
                        if roundcubeAddData['rUserId'] == rcuContactValue.get('rUserId'):
                            lastContactInsertId = 0
                            roundcubeContactAddData = {}
                            roundcubeContactAddData['kdatabaseRoot'] = roundcubeAddData['kdatabaseRoot']
                            roundcubeContactAddData['kdatabaseRootPassword'] = roundcubeAddData['kdatabaseRootPassword']
                            roundcubeContactAddData['contact_id'] = rcuContactValue.get('rContactId')
                            roundcubeContactAddData['changed'] = rcuContactValue.get('rChanged')
                            roundcubeContactAddData['del'] = rcuContactValue.get('rDel')
                            roundcubeContactAddData['name'] = rcuContactValue.get('rName')
                            roundcubeContactAddData['email'] = rcuContactValue.get('rEmail')
                            roundcubeContactAddData['firstname'] = rcuContactValue.get('rFirstname')
                            roundcubeContactAddData['surname'] = rcuContactValue.get('rSurname')
                            roundcubeContactAddData['vcard'] = rcuContactValue.get('rVcard')
                            roundcubeContactAddData['words'] = rcuContactValue.get('rWords')
                            roundcubeContactAddData['user_id'] = int(rlastInserId)

                            lastContactInsertId = self.__addRoundcubeContacts(roundcubeContactAddData)
                            if bool(self.imscpRoundcubeContact2Contactgroup):
                                self.__changeIdsofContact2ContactGroup(rcuContactValue.get('rContactId'),
                                                                       lastContactInsertId, 'contact')

                if bool(roundcubeAddData['imscpRoundcubeContactgroups']):
                    for rcuContactGroupKey, rcuContactGroupValue in roundcubeAddData[
                        'imscpRoundcubeContactgroups'].items():
                        if roundcubeAddData['rUserId'] == rcuContactGroupValue.get('rUserId'):
                            lastContactGroupInsertId = 0
                            roundcubeContactGroupAddData = {}
                            roundcubeContactGroupAddData['kdatabaseRoot'] = roundcubeAddData['kdatabaseRoot']
                            roundcubeContactGroupAddData['kdatabaseRootPassword'] = roundcubeAddData[
                                'kdatabaseRootPassword']
                            roundcubeContactGroupAddData['user_id'] = int(rlastInserId)
                            roundcubeContactGroupAddData['changed'] = rcuContactGroupValue.get('rChanged')
                            roundcubeContactGroupAddData['del'] = rcuContactGroupValue.get('rDel')
                            roundcubeContactGroupAddData['name'] = rcuContactGroupValue.get('rName')

                            lastContactGroupInsertId = self.__addRoundcubeContactGroups(roundcubeContactGroupAddData)
                            if bool(self.imscpRoundcubeContact2Contactgroup):
                                self.__changeIdsofContact2ContactGroup(rcuContactGroupValue.get('rContactGroupId'),
                                                                       lastContactGroupInsertId, 'group')

    def __addRoundcubeIdentities(self, roundcubeIdentityAddData):
        try:
            db_connection = mysql.connector.connect(
                host="localhost",
                user="" + roundcubeIdentityAddData['kdatabaseRoot'] + "",
                passwd="" + roundcubeIdentityAddData['kdatabaseRootPassword'] + "",
                database="roundcube"
            )
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with the user name or password")
                exit(1)
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
                exit(1)
            else:
                print(err)
                exit(1)
        else:
            cursor = db_connection.cursor()
            try:
                cursor.execute(
                    "INSERT INTO identities (`user_id`, `changed`,`del`, `standard`, `name`, `organization`, `email`, `reply-to`, `bcc`, `signature`, `html_signature`) VALUES ('" + str(
                        roundcubeIdentityAddData['user_id']) + "', '" + str(
                        roundcubeIdentityAddData['changed']) + "', '" + str(
                        roundcubeIdentityAddData['del']) + "', '" + str(
                        roundcubeIdentityAddData['standard']) + "', '" + str(
                        roundcubeIdentityAddData['name']) + "', '" + str(
                        roundcubeIdentityAddData['organization']) + "', '" + str(
                        roundcubeIdentityAddData['email']) + "', '" + str(
                        roundcubeIdentityAddData['reply-to']) + "', '" + str(
                        roundcubeIdentityAddData['bcc']) + "', '" + str(
                        roundcubeIdentityAddData['signature']) + "', '" + str(
                        roundcubeIdentityAddData['html_signature']) + "');")

                db_connection.commit()
            except (mysql.connector.Error) as err:
                # print(err)
                print('Error: An error occurred while adding the e-mail signature for "' + roundcubeIdentityAddData[
                    'email'] + '".')

            cursor.close()
            db_connection.close()

    def __addRoundcubeContacts(self, roundcubeContactAddData):
        try:
            db_connection = mysql.connector.connect(
                host="localhost",
                user="" + roundcubeContactAddData['kdatabaseRoot'] + "",
                passwd="" + roundcubeContactAddData['kdatabaseRootPassword'] + "",
                database="roundcube"
            )
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with the user name or password")
                exit(1)
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
                exit(1)
            else:
                print(err)
                exit(1)
        else:
            cursor = db_connection.cursor()
            cursor.execute(
                "INSERT INTO contacts (changed, del, name, email, firstname, surname, vcard, words, user_id) VALUES ('" + str(
                    roundcubeContactAddData['changed']) + "', '" + str(roundcubeContactAddData['del']) + "', '" + str(
                    roundcubeContactAddData['name']) + "', '" + str(roundcubeContactAddData['email']) + "', '" + str(
                    roundcubeContactAddData['firstname']) + "', '" + str(
                    roundcubeContactAddData['surname']) + "', '" + str(roundcubeContactAddData['vcard']) + "', '" + str(
                    roundcubeContactAddData['words']) + "', '" + str(roundcubeContactAddData['user_id']) + "');")

            db_connection.commit()
            lastInsertId = cursor.lastrowid
            cursor.close()
            db_connection.close()

            return lastInsertId

    def __addRoundcubeContactGroups(self, roundcubeContactGroupAddData):
        try:
            db_connection = mysql.connector.connect(
                host="localhost",
                user="" + roundcubeContactGroupAddData['kdatabaseRoot'] + "",
                passwd="" + roundcubeContactGroupAddData['kdatabaseRootPassword'] + "",
                database="roundcube"
            )
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with the user name or password")
                exit(1)
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
                exit(1)
            else:
                print(err)
                exit(1)
        else:
            cursor = db_connection.cursor()
            cursor.execute("INSERT INTO contactgroups (user_id, changed, del, name) VALUES ('" + str(
                roundcubeContactGroupAddData['user_id']) + "', '" + str(
                roundcubeContactGroupAddData['changed']) + "', '" + str(
                roundcubeContactGroupAddData['del']) + "', '" + str(roundcubeContactGroupAddData['name']) + "');")

            db_connection.commit()
            lastInsertId = cursor.lastrowid
            cursor.close()
            db_connection.close()

            return lastInsertId

    def addRoundcubeContact2Groups(self, roundcubeContact2ContactGroupAddData):
        try:
            db_connection = mysql.connector.connect(
                host="localhost",
                user="" + roundcubeContact2ContactGroupAddData['kdatabaseRoot'] + "",
                passwd="" + roundcubeContact2ContactGroupAddData['kdatabaseRootPassword'] + "",
                database="roundcube"
            )
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with the user name or password")
                exit(1)
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
                exit(1)
            else:
                print(err)
                exit(1)
        else:
            cursor = db_connection.cursor()
            try:
                ignore = False
                cursor.execute("INSERT INTO contactgroupmembers (contactgroup_id, contact_id, created) VALUES ('" + str(
                    roundcubeContact2ContactGroupAddData['contactgroup_id']) + "', '" + str(
                    roundcubeContact2ContactGroupAddData['contact_id']) + "', '" + str(
                    roundcubeContact2ContactGroupAddData['created']) + "');")

                db_connection.commit()
            except (mysql.connector.Error) as err:
                ignore = True
                # print(err)

            if ignore:
                print('Ignoring entry for "contactgroupmembers" because of a previously occurred error!')

            cursor.close()
            db_connection.close()

    def __changeIdsofContact2ContactGroup(self, idToChange, newId, idColumn):
        for i in self.imscpRoundcubeContact2Contactgroup.keys():
            if idColumn == 'contact':
                if self.imscpRoundcubeContact2Contactgroup[i]['rContactId'] == idToChange:
                    self.imscpRoundcubeContact2Contactgroup[i]['rContactId'] = newId
            if idColumn == 'group':
                if self.imscpRoundcubeContact2Contactgroup[i]['rContactGroupId'] == idToChange:
                    self.imscpRoundcubeContact2Contactgroup[i]['rContactGroupId'] = newId

    def keyhelpCreateRandomEmailPassword(self, kMinPasswordLenght):
        specialChars = string.punctuation
        specialChars = re.sub(r"'", "", specialChars, flags=re.UNICODE)
        specialChars = re.sub(r"\"", "", specialChars, flags=re.UNICODE)
        specialChars = re.sub(r"`", "", specialChars, flags=re.UNICODE)
        passwordCharacters = string.ascii_letters + string.digits + str(specialChars)
        emailPassword = ''.join(random.choice(passwordCharacters) for i in range(kMinPasswordLenght))

        return emailPassword

    def keyhelpCreateRandomFtpPassword(self, kMinPasswordLenght):
        specialChars = string.punctuation
        specialChars = re.sub(r"'", "", specialChars, flags=re.UNICODE)
        specialChars = re.sub(r"\"", "", specialChars, flags=re.UNICODE)
        specialChars = re.sub(r"`", "", specialChars, flags=re.UNICODE)
        passwordCharacters = string.ascii_letters + string.digits + str(specialChars)
        ftpPassword = ''.join(random.choice(passwordCharacters) for i in range(kMinPasswordLenght))

        return ftpPassword

    def keyhelpCreateRandomDatabaseUserPassword(self, kMinPasswordLenght):
        specialChars = string.punctuation
        specialChars = re.sub(r"'", "", specialChars, flags=re.UNICODE)
        specialChars = re.sub(r"\"", "", specialChars, flags=re.UNICODE)
        specialChars = re.sub(r"`", "", specialChars, flags=re.UNICODE)
        passwordCharacters = string.ascii_letters + string.digits + str(specialChars)
        emailPassword = ''.join(random.choice(passwordCharacters) for i in range(kMinPasswordLenght))

        return emailPassword

    def __keyhelpBuildMountpoint(self, iMountpoint, iHtdocFolder, kDomainName, iFirstDomainName):
        if len(str(iMountpoint)) == 1:
            iHtdocFolder = re.sub(r"/htdocs", "", str(iHtdocFolder), flags=re.UNICODE)
            print('Mountpoint for ' + kDomainName + ': ' + str(iFirstDomainName) + str(iHtdocFolder))
            return str(iFirstDomainName) + str(iHtdocFolder)
        else:
            iMountPointFolderData = iMountpoint.split("/")
            iHtdocFolder = re.sub(r"/htdocs", "", str(iHtdocFolder), flags=re.UNICODE)
            if len(iMountPointFolderData) == 2:
                print('Mountpoint for ' + kDomainName + ': ' + str(iMountPointFolderData[1]) + str(iHtdocFolder))
                return str(iMountPointFolderData[1]) + str(iHtdocFolder)
            elif len(iMountPointFolderData) == 3:
                print('Mountpoint for ' + kDomainName + ': ' + str(iMountPointFolderData[2]) + '.' + str(
                    iMountPointFolderData[1]) + str(iHtdocFolder))
                return str(iMountPointFolderData[2]) + '.' + str(iMountPointFolderData[1]) + str(iHtdocFolder)
            else:
                return str(kDomainName) + str(iHtdocFolder)
