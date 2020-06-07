import requests, time, json, re, configparser, io, os, sys, idna, paramiko, mysql.connector
from distutils.util import strtobool
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, SSHException
from mysql.connector import errorcode

import _global_config

_global_config.init()

#### General ####
showDebug = _global_config.showDebug

#### i-MSCP ####
imscpServerFqdn = _global_config.imscpServerFqdn
imscpSshUsername = _global_config.imscpSshUsername
imscpSshPort = _global_config.imscpSshPort
imscpSshTimeout = _global_config.imscpSshTimeout
imscpRootPassword = _global_config.imscpRootPassword
imscpSshPublicKey = _global_config.imscpSshPublicKey
imscpDbDumpFolder = _global_config.imscpDbDumpFolder


class imscpGetData:
    def __init__(self):
        self.complete = False
        self.imscpData = {}
        self.imscpDomainAliases = {}
        self.imscpDomainSubDomains = {}
        self.imscpAliasSubDomains = {}
        self.imscpDomainEmailAddressNormalCatchAll = {}
        self.imscpDomainEmailAddressNormal = {}
        self.imscpDomainEmailAddressNormalForward = {}
        self.imscpDomainEmailAddressForward = {}
        self.imscpDomainSubEmailAddressNormalCatchAll = {}
        self.imscpDomainSubEmailAddressNormal = {}
        self.imscpDomainSubEmailAddressNormalForward = {}
        self.imscpDomainSubEmailAddressForward = {}
        self.imscpAliasEmailAddressNormalCatchAll = {}
        self.imscpAliasEmailAddressNormal = {}
        self.imscpAliasEmailAddressNormalForward = {}
        self.imscpAliasEmailAddressForward = {}
        self.imscpAliasSubEmailAddressNormalCatchAll = {}
        self.imscpAliasSubEmailAddressNormal = {}
        self.imscpAliasSubEmailAddressNormalForward = {}
        self.imscpAliasSubEmailAddressForward = {}
        self.imscpDomainDatabaseNames = {}
        self.imscpDomainDatabaseUsernames = {}
        self.imscpFtpUserNames = {}

    def getImscpMySqlCredentials(self, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        # Get MySQL Credential
        stdin, stdout, stderr = client.exec_command('cat /etc/mysql/conf.d/imscp.cnf')
        iConfigFileData = ''
        for line in stdout:
            line = line.replace('"', '')
            iConfigFileData += str(line)

        iConfigData = io.StringIO(iConfigFileData)
        iconfig = configparser.ConfigParser()
        iconfig.read_file(iConfigData)

        iconfig['client']['host'].strip()
        iconfig['client']['port'].strip()
        iconfig['client']['user'].strip()
        iconfig['client']['password'].strip()

        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        # Get MySQL Credential
        stdin, stdout, stderr = client.exec_command('grep DATABASE_NAME /etc/imscp/imscp.conf')

        for line in stdout:
            line = line.replace('"', '')
            line = line.replace('\n', '')
            imscpDatabase = line.split(" = ")
            imscpDatabase[1].strip()

        _global_config.write_log('Debug i-MSCP MySQL informations:')
        _global_config.write_log('i-MSCP MySQL-Host: ' + iconfig['client']['host'])
        _global_config.write_log('i-MSCP MySQL-Port: ' + iconfig['client']['port'])
        _global_config.write_log('i-MSCP MySQL-User: ' + iconfig['client']['user'])
        _global_config.write_log('i-MSCP MySQL-Password: ' + iconfig['client']['password'])
        _global_config.write_log('i-MSCP Database: ' + imscpDatabase[1] + '\n')
        if showDebug:
            print('\nDebug i-MSCP MySQL informations:')
            print('i-MSCP MySQL-Host: ' + iconfig['client']['host'])
            print('i-MSCP MySQL-Port: ' + iconfig['client']['port'])
            print('i-MSCP MySQL-User: ' + iconfig['client']['user'])
            print('i-MSCP MySQL-Password: ' + iconfig['client']['password'])
            print('i-MSCP Database: ' + imscpDatabase[1] + '\n')

        self.imscpData['imysqlhost'] = iconfig['client']['host']
        self.imscpData['imysqlport'] = iconfig['client']['port']
        self.imscpData['imysqluser'] = iconfig['client']['user']
        self.imscpData['imysqlpassword'] = iconfig['client']['password']
        self.imscpData['imysqldatabase'] = imscpDatabase[1]

        self.complete = False

        return True

    def getImscpUserWebData(self, iUsername, client):
        if (len(iUsername) > 0):
            iUsernameIdna = idna.encode(iUsername).decode('utf-8')
            if imscpSshPublicKey:
                client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                               key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
            else:
                client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                               password=imscpRootPassword, timeout=imscpSshTimeout)

            stdin, stdout, stderr = client.exec_command(
                'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
                self.imscpData['imysqluser'] + ' -p' + self.imscpData[
                    'imysqlpassword'] + ' -e "SELECT domain_id, domain_name, domain_admin_id, document_root, url_forward FROM ' +
                self.imscpData[
                    'imysqldatabase'] + '.domain WHERE domain_name = \'' + iUsernameIdna + '\' AND domain_status = \'ok\'"')
            i = 0
            dataLine = ''
            for line in stdout:
                if i > 0:
                    dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
                    dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
                i += 1

            if i > 0:
                imscpUsernameData = dataLine.split("|")
                imscpUsernameData[0].strip()
                imscpUsernameData[1].strip()
                imscpUsernameData[2].strip()
                imscpUsernameData[3].strip()
                imscpUsernameData[4].strip()
                self.imscpData['iUsernameDomainId'] = imscpUsernameData[0]
                self.imscpData['iUsernameDomain'] = iUsername
                self.imscpData['iUsernameDomainIdna'] = imscpUsernameData[1]
                self.imscpData['iUsernameDomainAdminId'] = imscpUsernameData[2]
                self.imscpData['iDomainData'] = imscpUsernameData[1] + '|' + imscpUsernameData[3] + '|' + \
                                                imscpUsernameData[4]

                _global_config.write_log('Debug i-MSCP informations:\nYour Domain: "' + iUsername + '"')
                _global_config.write_log('Your Domain IDN converted: "' + iUsernameIdna + '"\n')
                if showDebug:
                    print('\nDebug i-MSCP informations:\nYour Domain: "' + iUsername + '"')
                    print('Your Domain IDN converted: "' + iUsernameIdna + '"\n')

                print('\nFound domain: ' + iUsername)
                print('Get i-MSCP sub domain data')
                self.__getImscpSubDomains(self.imscpData['iUsernameDomainId'], self.imscpData['iUsernameDomain'],
                                          self.imscpData['iUsernameDomainIdna'], client)
                print('Get i-MSCP alias domain data')
                self.__getImscpAliasDomains(self.imscpData['iUsernameDomainId'], self.imscpData['iUsernameDomain'],
                                            self.imscpData['iUsernameDomainIdna'], client)
                print('Get i-MSCP domain emailaddress data')
                self.__getImscpDomainEmailaddresses(self.imscpData['iUsernameDomainId'],
                                                    self.imscpData['iUsernameDomain'],
                                                    self.imscpData['iUsernameDomainIdna'], client)
                print('Get i-MSCP database data')
                self.__getImscpDomainDatabases(self.imscpData['iUsernameDomainId'], self.imscpData['iUsernameDomain'],
                                               self.imscpData['iUsernameDomainIdna'], client)
                print('Get i-MSCP FTP user data')
                self.__getImscpFtpUsers(self.imscpData['iUsernameDomainIdna'], self.imscpData['iUsernameDomainAdminId'],
                                        client)

                self.complete = True
                return True
            else:
                print('Your i-MSCP username does not exist!')
                return False
        else:
            print('Your i-MSCP username is empty!')
            return False

    def __getImscpSubDomains(self, iUsernameDomainId, iUsernameDomain, iUsernameDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' + self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT subdomain_id, subdomain_name, subdomain_mount, subdomain_document_root, subdomain_url_forward FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.subdomain WHERE domain_id = \'' + iUsernameDomainId + '\' AND subdomain_status = \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpDomainSubDomains = {}
        for line in stdout:
            if i > 0:
                dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
                dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
                imscpSubDomainData = dataLine.split("|")
                imscpSubDomainData[0].strip()
                imscpSubDomainData[1].strip()
                imscpSubDomainData[2].strip()
                imscpSubDomainData[3].strip()
                imscpSubDomainData[4].strip()

                index = int(imscpSubDomainData[0])

                self.imscpDomainSubDomains[index] = {}
                self.imscpDomainSubDomains[index]['iSubDomainId'] = imscpSubDomainData[0]
                self.imscpDomainSubDomains[index]['iSubDomain'] = imscpSubDomainData[1] + '.' + iUsernameDomainIdna
                self.imscpDomainSubDomains[index]['iSubDomainIdna'] = idna.encode(
                    imscpSubDomainData[1] + '.' + iUsernameDomain).decode('utf-8')
                if str(imscpSubDomainData[2]) == '/' + str(imscpSubDomainData[1]):
                    imscpSubDomainData[2] = imscpSubDomainData[2] + '.' + str(iUsernameDomainIdna)
                self.imscpDomainSubDomains[index]['iSubDomainData'] = imscpSubDomainData[2] + '|' + imscpSubDomainData[
                    3] + '|' + imscpSubDomainData[4]

                _global_config.write_log(
                    'Debug i-MSCP informations sub domains:\nSub domain "' + self.imscpDomainSubDomains[index][
                        'iSubDomain'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')
                if showDebug:
                    print('Debug i-MSCP informations sub domains:\nSub domain "' + self.imscpDomainSubDomains[index][
                        'iSubDomain'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

                self.__getImscpSubDomainEmailaddresses(iUsernameDomainId,
                                                       self.imscpDomainSubDomains[index]['iSubDomainId'],
                                                       self.imscpDomainSubDomains[index]['iSubDomain'],
                                                       self.imscpDomainSubDomains[index]['iSubDomainIdna'], client)

                _global_config.write_log(
                    '======================= End data for sub domain "' + self.imscpDomainSubDomains[index][
                        'iSubDomain'] + '" =======================\n\n\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations sub domains:\nNo sub domains found for the i-MSCP domain "' + iUsernameDomain + '"\n')
            if showDebug:
                print(
                    'Debug i-MSCP informations sub domains:\nNo sub domains found for the i-MSCP domain "' + iUsernameDomain + '"\n')

    def __getImscpAliasDomains(self, iUsernameDomainId, iUsernameDomain, iUsernameDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' + self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT alias_id, alias_name, alias_mount, alias_document_root, url_forward FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.domain_aliasses WHERE domain_id = \'' + iUsernameDomainId + '\' AND alias_status = \'ok\'"')
        i = 0

        dataLine = ''
        self.imscpDomainAliases = {}
        for line in stdout:
            if i > 0:
                dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
                dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
                imscpAliasDomainData = dataLine.split("|")
                imscpAliasDomainData[0].strip()
                imscpAliasDomainData[1].strip()
                imscpAliasDomainData[2].strip()
                imscpAliasDomainData[3].strip()
                imscpAliasDomainData[4].strip()

                index = int(imscpAliasDomainData[0])

                self.imscpDomainAliases[index] = {}
                self.imscpDomainAliases[index]['iAliasDomainId'] = imscpAliasDomainData[0]
                self.imscpDomainAliases[index]['iAliasDomain'] = imscpAliasDomainData[1]
                self.imscpDomainAliases[index]['iAliasDomainIdna'] = idna.encode(imscpAliasDomainData[1]).decode(
                    'utf-8')
                self.imscpDomainAliases[index]['iAliasDomainData'] = imscpAliasDomainData[2] + '|' + \
                                                                     imscpAliasDomainData[3] + '|' + \
                                                                     imscpAliasDomainData[4]

                _global_config.write_log(
                    'Debug i-MSCP informations alias domains:\nAlias domain "' + self.imscpDomainAliases[index][
                        'iAliasDomain'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')
                if showDebug:
                    print('Debug i-MSCP informations alias domains:\nAlias domain "' + self.imscpDomainAliases[index][
                        'iAliasDomain'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

                self.__getImscpAliasSubDomains(self.imscpDomainAliases[index]['iAliasDomainId'],
                                               self.imscpDomainAliases[index]['iAliasDomain'],
                                               self.imscpDomainAliases[index]['iAliasDomainIdna'], client)
                self.__getImscpAliasEmailaddresses(iUsernameDomainId, self.imscpDomainAliases[index]['iAliasDomainId'],
                                                   self.imscpDomainAliases[index]['iAliasDomain'],
                                                   self.imscpDomainAliases[index]['iAliasDomainIdna'], client)

                _global_config.write_log(
                    '======================= End data for alias domain "' + self.imscpDomainAliases[index][
                        'iAliasDomain'] + '" =======================\n\n\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations alias domains:\nNo alias domains found for the i-MSCP domain "' + iUsernameDomain + '"\n')
            if showDebug:
                print(
                    'Debug i-MSCP informations alias domains:\nNo alias domains found for the i-MSCP domain "' + iUsernameDomain + '"\n')

    def __getImscpFtpUsers(self, iUsernameDomain, iUsernameDomainAdminId, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, \
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' + self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData['imysqlpassword'] + ' -e "SELECT userid, passwd, homedir FROM ' +
            self.imscpData['imysqldatabase'] + '.ftp_users WHERE admin_id = \'' + iUsernameDomainAdminId + '\'"')
        i = 0
        dataLine = ''
        self.imscpFtpUserNames = {}
        for line in stdout:
            if i > 0:
                dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
                dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
                imscpDomainFtpUserData = dataLine.split("|")
                imscpDomainFtpUserData[0].strip()
                imscpDomainFtpUserData[1].strip()
                imscpDomainFtpUserData[2].strip()

                index = i

                self.imscpFtpUserNames[index] = {}
                self.imscpFtpUserNames[index]['iFtpUsername'] = imscpDomainFtpUserData[0]
                self.imscpFtpUserNames[index]['iFtpUserPassword'] = imscpDomainFtpUserData[1]
                self.imscpFtpUserNames[index]['iFtpUserHomeDir'] = imscpDomainFtpUserData[2]

                _global_config.write_log(
                    'Debug i-MSCP informations FTP users:\nFTP user "' + self.imscpFtpUserNames[index][
                        'iFtpUsername'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')
                if showDebug:
                    print('Debug i-MSCP informations FTP users:\nFTP user "' + self.imscpFtpUserNames[index][
                        'iFtpUsername'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations FTP users:\nNo FTP user found for the i-MSCP domain "' + iUsernameDomain + '"\n')
            if showDebug:
                print(
                    'Debug i-MSCP informations FTP users:\nNo FTP user found for the i-MSCP domain "' + iUsernameDomain + '"\n')
        else:
            _global_config.write_log(
                '======================= End data for FTP users "' + iUsernameDomain + '" =======================\n\n\n')

    def __getImscpDomainDatabases(self, iUsernameDomainId, iUsernameDomain, iUsernameDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, \
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' + self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData['imysqlpassword'] + ' -e "SELECT sqld_id, sqld_name FROM ' +
            self.imscpData['imysqldatabase'] + '.sql_database WHERE domain_id = \'' + iUsernameDomainId + '\'"')
        i = 0
        dataLine = ''
        self.imscpDomainDatabaseNames = {}
        for line in stdout:
            if i > 0:
                dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
                dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
                imscpDomainDatabaseData = dataLine.split("|")
                imscpDomainDatabaseData[0].strip()
                imscpDomainDatabaseData[1].strip()

                index = int(imscpDomainDatabaseData[0])

                self.imscpDomainDatabaseNames[index] = {}
                self.imscpDomainDatabaseNames[index]['iDatabaseId'] = imscpDomainDatabaseData[0]
                self.imscpDomainDatabaseNames[index]['iDatabaseName'] = imscpDomainDatabaseData[1]

                _global_config.write_log(
                    'Debug i-MSCP informations database:\nDatabase "' + self.imscpDomainDatabaseNames[index][
                        'iDatabaseName'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')
                if showDebug:
                    print('Debug i-MSCP informations database:\nDatabase "' + self.imscpDomainDatabaseNames[index][
                        'iDatabaseName'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

                self.__getImscpDomainDatabaseUsers(iUsernameDomainId, iUsernameDomain,
                                                   self.imscpDomainDatabaseNames[index]['iDatabaseId'],
                                                   self.imscpDomainDatabaseNames[index]['iDatabaseName'], client)

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations database:\nNo database found for the i-MSCP domain "' + iUsernameDomain + '"\n')
            if showDebug:
                print(
                    'Debug i-MSCP informations database:\nNo database found for the i-MSCP domain "' + iUsernameDomain + '"\n')
        else:
            _global_config.write_log(
                '======================= End data for database "' + iUsernameDomain + '" =======================\n\n\n')

    def __getImscpDomainDatabaseUsers(self, iUsernameDomainId, iUsernameDomain, iDatabaseId, iDatabaseName, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' + self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT sqlu_id, sqld_id, sqlu_name, sqlu_host FROM ' + self.imscpData[
                'imysqldatabase'] + '.sql_user WHERE sqld_id = \'' + iDatabaseId + '\'"')
        i = 0
        dataLine = ''
        for line in stdout:
            if i > 0:
                dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
                dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
                imscpDomainDatabaseUsernameData = dataLine.split("|")
                imscpDomainDatabaseUsernameData[0].strip()
                imscpDomainDatabaseUsernameData[1].strip()
                imscpDomainDatabaseUsernameData[2].strip()
                imscpDomainDatabaseUsernameData[3].strip()

                index = int(imscpDomainDatabaseUsernameData[0])

                self.imscpDomainDatabaseUsernames[index] = {}
                self.imscpDomainDatabaseUsernames[index]['iDatabaseUserId'] = imscpDomainDatabaseUsernameData[0]
                self.imscpDomainDatabaseUsernames[index]['iDatabaseId'] = imscpDomainDatabaseUsernameData[1]
                self.imscpDomainDatabaseUsernames[index]['iDatabaseUsername'] = imscpDomainDatabaseUsernameData[2]
                self.imscpDomainDatabaseUsernames[index]['iDatabaseUserHost'] = imscpDomainDatabaseUsernameData[3]

                _global_config.write_log('Debug i-MSCP informations database users:\nDatabase username "' +
                                         self.imscpDomainDatabaseUsernames[index][
                                             'iDatabaseUsername'] + '" found for the i-MSCP database "' + iDatabaseName + '""(domain: ' + iUsernameDomain + ')\n')
                if showDebug:
                    print('Debug i-MSCP informations database:\nDatabase username "' +
                          self.imscpDomainDatabaseUsernames[index][
                              'iDatabaseUsername'] + '" found for the i-MSCP database "' + iDatabaseName + '" (domain: ' + iUsernameDomain + ')\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations database users :\nNo database users found for the database "' +
                self.imscpDomainDatabaseUsernames[index]['iDatabaseUsername'] + '"\n')
            if showDebug:
                print('Debug i-MSCP informations database users:\nNo database users found for the database "' +
                      self.imscpDomainDatabaseUsernames[index]['iDatabaseUsername'] + '"\n')
        else:
            _global_config.write_log(
                '======================= End data for database users - "' + iDatabaseName + '" - Domain "' + iUsernameDomain + '" =======================\n\n\n')

    def __getImscpAliasSubDomains(self, iAliasDomainid, iAliasDomain, iAliasDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' + self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT subdomain_alias_id, subdomain_alias_name, subdomain_alias_mount, subdomain_alias_document_root, subdomain_alias_url_forward FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.subdomain_alias WHERE alias_id = \'' + iAliasDomainid + '\' AND subdomain_alias_status = \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpAliasSubDomains['aliasid-' + iAliasDomainid] = {}
        for line in stdout:
            if i > 0:
                dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
                dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
                imscpAliasSubDomainData = dataLine.split("|")
                imscpAliasSubDomainData[0].strip()
                imscpAliasSubDomainData[1].strip()
                imscpAliasSubDomainData[2].strip()
                imscpAliasSubDomainData[3].strip()
                imscpAliasSubDomainData[4].strip()

                index = int(imscpAliasSubDomainData[0])

                self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index] = {}
                self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomainId'] = \
                    imscpAliasSubDomainData[0]
                self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomain'] = \
                    imscpAliasSubDomainData[1] + '.' + iAliasDomainIdna
                self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomainIdna'] = idna.encode(
                    imscpAliasSubDomainData[1] + '.' + iAliasDomain).decode('utf-8')
                self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomainData'] = \
                    imscpAliasSubDomainData[2] + '|' + imscpAliasSubDomainData[3] + '|' + imscpAliasSubDomainData[4]

                _global_config.write_log('Debug i-MSCP informations alias sub domains:\nAlias sub domain "' +
                                         self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index][
                                             'iAliasSubDomain'] + '" found for the i-MSCP alias domain "' + iAliasDomain + '"\n')
                if showDebug:
                    print('Debug i-MSCP informations alias sub domains:\nAlias sub domain "' +
                          self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index][
                              'iAliasSubDomain'] + '" found for the i-MSCP alias domain "' + iAliasDomain + '"\n')

                self.__getImscpAliasSubEmailaddresses(iAliasDomainid,
                                                      self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index][
                                                          'iAliasSubDomainId'],
                                                      self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index][
                                                          'iAliasSubDomain'],
                                                      self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index][
                                                          'iAliasSubDomainIdna'], client)

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations alias sub domains:\nNo alias sub domains found for the i-MSCP alias domain "' + iAliasDomain + '"\n')
            if showDebug:
                print(
                    'Debug i-MSCP informations alias sub domains:\nNo alias sub domains found for the i-MSCP alias domain "' + iAliasDomain + '"\n')

    def __getImscpDomainEmailaddresses(self, iUsernameDomainId, iUsernameDomain, iUsernameDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' + self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT mail_id, mail_acc, mail_pass, mail_forward, mail_type, sub_id, quota, mail_addr FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.mail_users WHERE domain_id = \'' + iUsernameDomainId + '\' AND sub_id = \'0\' AND mail_type LIKE \'normal%\' AND status = \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpDomainEmailAddressNormalCatchAll = {}
        self.imscpDomainEmailAddressNormal = {}
        self.imscpDomainEmailAddressNormalForward = {}
        self.imscpDomainEmailAddressForward = {}
        for line in stdout:
            if i > 0:
                dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
                dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
                imscpEmailDomainData = dataLine.split("|")
                imscpEmailDomainData[0].strip()
                imscpEmailDomainData[1].strip()
                imscpEmailDomainData[2].strip()
                imscpEmailDomainData[3].strip()
                imscpEmailDomainData[4].strip()
                imscpEmailDomainData[5].strip()
                imscpEmailDomainData[6].strip()
                imscpEmailDomainData[7].strip()

                index = int(imscpEmailDomainData[0])

                # Remove rounds=5000$ from i-MSCP password
                imscpEmailDomainData[2] = re.sub("rounds=5000\$", "", imscpEmailDomainData[2], flags=re.UNICODE)

                if imscpEmailDomainData[4] == 'normal_catchall':
                    self.imscpDomainEmailAddressNormalCatchAll[index] = {}
                    self.imscpDomainEmailAddressNormalCatchAll[index]['iEmailMailId'] = imscpEmailDomainData[0]
                    self.imscpDomainEmailAddressNormalCatchAll[index]['iEmailAddress'] = imscpEmailDomainData[1]
                    _global_config.write_log('Debug i-MSCP informations catchall emails domain:\nEmailadress "' +
                                             self.imscpDomainEmailAddressNormalCatchAll[index][
                                                 'iEmailAddress'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails domain:\nEmailadress "' +
                              self.imscpDomainEmailAddressNormal[index][
                                  'iEmailAddress'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

                if imscpEmailDomainData[4] == 'normal_mail':
                    self.imscpDomainEmailAddressNormal[index] = {}
                    self.imscpDomainEmailAddressNormal[index]['iEmailMailId'] = imscpEmailDomainData[0]
                    self.imscpDomainEmailAddressNormal[index]['iEmailMailPassword'] = imscpEmailDomainData[2]
                    self.imscpDomainEmailAddressNormal[index]['iEmailMailForward'] = imscpEmailDomainData[3]
                    self.imscpDomainEmailAddressNormal[index]['iEmailMailType'] = imscpEmailDomainData[4]
                    self.imscpDomainEmailAddressNormal[index]['iEmailMailQuota'] = imscpEmailDomainData[6]
                    self.imscpDomainEmailAddressNormal[index]['iEmailAddress'] = imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails domain:\nEmailadress "' +
                                             self.imscpDomainEmailAddressNormal[index][
                                                 'iEmailAddress'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails domain:\nEmailadress "' +
                              self.imscpDomainEmailAddressNormal[index][
                                  'iEmailAddress'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

                if imscpEmailDomainData[4] == 'normal_mail,normal_forward':
                    self.imscpDomainEmailAddressNormalForward[index] = {}
                    self.imscpDomainEmailAddressNormalForward[index]['iEmailMailId'] = imscpEmailDomainData[0]
                    self.imscpDomainEmailAddressNormalForward[index]['iEmailMailPassword'] = imscpEmailDomainData[2]
                    self.imscpDomainEmailAddressNormalForward[index]['iEmailMailForward'] = imscpEmailDomainData[3]
                    self.imscpDomainEmailAddressNormalForward[index]['iEmailMailType'] = imscpEmailDomainData[4]
                    self.imscpDomainEmailAddressNormalForward[index]['iEmailMailQuota'] = imscpEmailDomainData[6]
                    self.imscpDomainEmailAddressNormalForward[index]['iEmailAddress'] = imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails domain:\nEmailadress "' +
                                             self.imscpDomainEmailAddressNormalForward[index][
                                                 'iEmailAddress'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails domain:\nEmailadress "' +
                              self.imscpDomainEmailAddressNormalForward[index][
                                  'iEmailAddress'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

                if imscpEmailDomainData[4] == 'normal_forward':
                    self.imscpDomainEmailAddressForward[index] = {}
                    self.imscpDomainEmailAddressForward[index]['iEmailMailId'] = imscpEmailDomainData[0]
                    self.imscpDomainEmailAddressForward[index]['iEmailMailPassword'] = imscpEmailDomainData[2]
                    self.imscpDomainEmailAddressForward[index]['iEmailMailForward'] = imscpEmailDomainData[3]
                    self.imscpDomainEmailAddressForward[index]['iEmailMailType'] = imscpEmailDomainData[4]
                    self.imscpDomainEmailAddressForward[index]['iEmailMailQuota'] = imscpEmailDomainData[6]
                    self.imscpDomainEmailAddressForward[index]['iEmailAddress'] = imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails domain:\nEmailadress "' +
                                             self.imscpDomainEmailAddressForward[index][
                                                 'iEmailAddress'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails domain:\nEmailadress "' +
                              self.imscpDomainEmailAddressForward[index][
                                  'iEmailAddress'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations emails domain:\nNo emails found for the i-MSCP domain "' + iUsernameDomain + '"\n')
            if showDebug:
                print(
                    'Debug i-MSCP informations emails domain:\nNo emails found for the i-MSCP domain "' + iUsernameDomain + '"\n')
        else:
            _global_config.write_log(
                '======================= End data for email data "' + iUsernameDomain + '" =======================\n\n\n')

    def __getImscpSubDomainEmailaddresses(self, iUsernameDomainId, iSubDomainId, iSubDomain, iSubDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' + self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT mail_id, mail_acc, mail_pass, mail_forward, mail_type, sub_id, quota, mail_addr FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.mail_users WHERE domain_id = \'' + iUsernameDomainId + '\' AND sub_id = \'' + iSubDomainId + '\' AND mail_type LIKE \'subdom%\'  AND status = \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpDomainSubEmailAddressNormalCatchAll['subid-' + iSubDomainId] = {}
        self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId] = {}
        self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId] = {}
        self.imscpDomainSubEmailAddressForward['subid-' + iSubDomainId] = {}
        for line in stdout:
            if i > 0:
                dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
                dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
                imscpEmailDomainData = dataLine.split("|")
                imscpEmailDomainData[0].strip()
                imscpEmailDomainData[1].strip()
                imscpEmailDomainData[2].strip()
                imscpEmailDomainData[3].strip()
                imscpEmailDomainData[4].strip()
                imscpEmailDomainData[5].strip()
                imscpEmailDomainData[6].strip()
                imscpEmailDomainData[7].strip()

                index = int(imscpEmailDomainData[0])

                # Remove rounds=5000$ from i-MSCP password
                imscpEmailDomainData[2] = re.sub("rounds=5000\$", "", imscpEmailDomainData[2], flags=re.UNICODE)

                if imscpEmailDomainData[4] == 'subdom_catchall':
                    self.imscpDomainSubEmailAddressNormalCatchAll['subid-' + iSubDomainId][index] = {}
                    self.imscpDomainSubEmailAddressNormalCatchAll['subid-' + iSubDomainId][index]['iEmailMailId'] = \
                    imscpEmailDomainData[0]
                    self.imscpDomainSubEmailAddressNormalCatchAll['subid-' + iSubDomainId][index]['iEmailAddress'] = \
                    imscpEmailDomainData[1]
                    _global_config.write_log('Debug i-MSCP informations catchall emails sub domain:\nEmailadress "' +
                                             self.imscpDomainSubEmailAddressNormalCatchAll['subid-' + iSubDomainId][
                                                 index][
                                                 'iEmailAddress'] + '" found for the i-MSCP sub domain "' + iSubDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails sub domain:\nEmailadress "' +
                              self.imscpDomainSubEmailAddressNormal[index][
                                  'iEmailAddress'] + '" found for the i-MSCP sub domain "' + iSubDomain + '"\n')

                if imscpEmailDomainData[4] == 'subdom_mail':
                    self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId][index] = {}
                    self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId][index]['iEmailMailId'] = \
                    imscpEmailDomainData[0]
                    self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId][index]['iEmailMailPassword'] = \
                    imscpEmailDomainData[2]
                    self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId][index]['iEmailMailForward'] = \
                    imscpEmailDomainData[3]
                    self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId][index]['iEmailMailType'] = \
                    imscpEmailDomainData[4]
                    self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId][index]['iEmailMailQuota'] = \
                    imscpEmailDomainData[6]
                    self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId][index]['iEmailAddress'] = \
                    imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails sub domain:\nEmailadress "' +
                                             self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId][index][
                                                 'iEmailAddress'] + '" found for the i-MSCP sub domain "' + iSubDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails sub domain:\nEmailadress "' +
                              self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId][index][
                                  'iEmailAddress'] + '" found for the i-MSCP sub domain "' + iSubDomain + '"\n')

                if imscpEmailDomainData[4] == 'subdom_mail,subdom_forward':
                    self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId][index] = {}
                    self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId][index]['iEmailMailId'] = \
                    imscpEmailDomainData[0]
                    self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId][index]['iEmailMailPassword'] = \
                    imscpEmailDomainData[2]
                    self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId][index]['iEmailMailForward'] = \
                    imscpEmailDomainData[3]
                    self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId][index]['iEmailMailType'] = \
                    imscpEmailDomainData[4]
                    self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId][index]['iEmailMailQuota'] = \
                    imscpEmailDomainData[6]
                    self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId][index]['iEmailAddress'] = \
                    imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails sub domain:\nEmailadress "' +
                                             self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId][
                                                 index][
                                                 'iEmailAddress'] + '" found for the i-MSCP sub domain "' + iSubDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails sub domain:\nEmailadress "' +
                              self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId][index][
                                  'iEmailAddress'] + '" found for the i-MSCP sub domain "' + iSubDomain + '"\n')

                if imscpEmailDomainData[4] == 'subdom_forward':
                    self.imscpDomainSubEmailAddressForward['subid-' + iSubDomainId][index] = {}
                    self.imscpDomainSubEmailAddressForward['subid-' + iSubDomainId][index]['iEmailMailId'] = \
                    imscpEmailDomainData[0]
                    self.imscpDomainSubEmailAddressForward['subid-' + iSubDomainId][index]['iEmailMailPassword'] = \
                    imscpEmailDomainData[2]
                    self.imscpDomainSubEmailAddressForward['subid-' + iSubDomainId][index]['iEmailMailForward'] = \
                    imscpEmailDomainData[3]
                    self.imscpDomainSubEmailAddressForward['subid-' + iSubDomainId][index]['iEmailMailType'] = \
                    imscpEmailDomainData[4]
                    self.imscpDomainSubEmailAddressForward['subid-' + iSubDomainId][index]['iEmailMailQuota'] = \
                    imscpEmailDomainData[6]
                    self.imscpDomainSubEmailAddressForward['subid-' + iSubDomainId][index]['iEmailAddress'] = \
                    imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails sub domain:\nEmailadress "' +
                                             self.imscpDomainSubEmailAddressForward['subid-' + iSubDomainId][index][
                                                 'iEmailAddress'] + '" found for the i-MSCP sub domain "' + iSubDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails sub domain:\nEmailadress "' +
                              self.imscpDomainSubEmailAddressForward['subid-' + iSubDomainId][index][
                                  'iEmailAddress'] + '" found for the i-MSCP sub domain "' + iSubDomain + '"\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations emails sub domain:\nNo emails found for the i-MSCP sub domain "' + iSubDomain + '"\n')
            if showDebug:
                print(
                    'Debug i-MSCP informations emails sub domain:\nNo emails found for the i-MSCP sub domain "' + iSubDomain + '"\n')

    def __getImscpAliasEmailaddresses(self, iUsernameDomainId, iAliasDomainid, iAliasDomain, iAliasDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' + self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT mail_id, mail_acc, mail_pass, mail_forward, mail_type, sub_id, quota, mail_addr FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.mail_users WHERE domain_id = \'' + iUsernameDomainId + '\' AND sub_id = \'' + iAliasDomainid + '\' AND mail_type LIKE \'alias%\' AND status = \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpAliasEmailAddressNormalCatchAll['aliasid-' + iAliasDomainid] = {}
        self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid] = {}
        self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid] = {}
        self.imscpAliasEmailAddressForward['aliasid-' + iAliasDomainid] = {}
        for line in stdout:
            if i > 0:
                dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
                dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
                imscpEmailDomainData = dataLine.split("|")
                imscpEmailDomainData[0].strip()
                imscpEmailDomainData[1].strip()
                imscpEmailDomainData[2].strip()
                imscpEmailDomainData[3].strip()
                imscpEmailDomainData[4].strip()
                imscpEmailDomainData[5].strip()
                imscpEmailDomainData[6].strip()
                imscpEmailDomainData[7].strip()

                index = int(imscpEmailDomainData[0])

                # Remove rounds=5000$ from i-MSCP password
                imscpEmailDomainData[2] = re.sub("rounds=5000\$", "", imscpEmailDomainData[1], flags=re.UNICODE)

                if imscpEmailDomainData[4] == 'alias_catchall':
                    self.imscpAliasEmailAddressNormalCatchAll['aliasid-' + iAliasDomainid][index] = {}
                    self.imscpAliasEmailAddressNormalCatchAll['aliasid-' + iAliasDomainid][index]['iEmailMailId'] = \
                        imscpEmailDomainData[0]
                    self.imscpAliasEmailAddressNormalCatchAll['aliasid-' + iAliasDomainid][index]['iEmailAddress'] = \
                        imscpEmailDomainData[1]
                    _global_config.write_log('Debug i-MSCP informations catchall emails alias domain:\nEmailadress "' +
                                             self.imscpAliasEmailAddressNormalCatchAll['aliasid-' + iAliasDomainid][
                                                 index][
                                                 'iEmailAddress'] + '" found for the i-MSCP alias domain "' + iAliasDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations catchall emails alias domain:\nEmailadress "' +
                              self.imscpAliasEmailAddressNormalCatchAll['aliasid-' + iAliasDomainid][index][
                                  'iEmailAddress'] + '" found for the i-MSCP alias domain "' + iAliasDomain + '"\n')

                if imscpEmailDomainData[4] == 'alias_mail':
                    self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid][index] = {}
                    self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid][index]['iEmailMailId'] = \
                        imscpEmailDomainData[0]
                    self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid][index]['iEmailMailPassword'] = \
                        imscpEmailDomainData[2]
                    self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid][index]['iEmailMailForward'] = \
                        imscpEmailDomainData[3]
                    self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid][index]['iEmailMailType'] = \
                        imscpEmailDomainData[4]
                    self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid][index]['iEmailMailQuota'] = \
                        imscpEmailDomainData[6]
                    self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid][index]['iEmailAddress'] = \
                        imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails alias domain:\nEmailadress "' +
                                             self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid][index][
                                                 'iEmailAddress'] + '" found for the i-MSCP alias domain "' + iAliasDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails alias domain:\nEmailadress "' +
                              self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid][index][
                                  'iEmailAddress'] + '" found for the i-MSCP alias domain "' + iAliasDomain + '"\n')

                if imscpEmailDomainData[4] == 'alias_mail,alias_forward':
                    self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][index] = {}
                    self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][index]['iEmailMailId'] = \
                        imscpEmailDomainData[0]
                    self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][index]['iEmailMailPassword'] = \
                        imscpEmailDomainData[3]
                    self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][index]['iEmailMailForward'] = \
                        imscpEmailDomainData[3]
                    self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][index]['iEmailMailType'] = \
                        imscpEmailDomainData[4]
                    self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][index]['iEmailMailQuota'] = \
                        imscpEmailDomainData[6]
                    self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][index]['iEmailAddress'] = \
                        imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails alias domain:\nEmailadress "' +
                                             self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][
                                                 index][
                                                 'iEmailAddress'] + '" found for the i-MSCP alias domain "' + iAliasDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails alias domain:\nEmailadress "' +
                              self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][index][
                                  'iEmailAddress'] + '" found for the i-MSCP alias domain "' + iAliasDomain + '"\n')

                if imscpEmailDomainData[4] == 'alias_forward':
                    self.imscpAliasEmailAddressForward['aliasid-' + iAliasDomainid][index] = {}
                    self.imscpAliasEmailAddressForward['aliasid-' + iAliasDomainid][index]['iEmailMailId'] = \
                        imscpEmailDomainData[0]
                    self.imscpAliasEmailAddressForward['aliasid-' + iAliasDomainid][index]['iEmailMailPassword'] = \
                        imscpEmailDomainData[2]
                    self.imscpAliasEmailAddressForward['aliasid-' + iAliasDomainid][index]['iEmailMailForward'] = \
                        imscpEmailDomainData[3]
                    self.imscpAliasEmailAddressForward['aliasid-' + iAliasDomainid][index]['iEmailMailType'] = \
                        imscpEmailDomainData[4]
                    self.imscpAliasEmailAddressForward['aliasid-' + iAliasDomainid][index]['iEmailMailQuota'] = \
                        imscpEmailDomainData[6]
                    self.imscpAliasEmailAddressForward['aliasid-' + iAliasDomainid][index]['iEmailAddress'] = \
                        imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails alias domain:\nEmailadress "' +
                                             self.imscpAliasEmailAddressForward['aliasid-' + iAliasDomainid][index][
                                                 'iEmailAddress'] + '" found for the i-MSCP alias domain "' + iAliasDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails alias domain:\nEmailadress "' +
                              self.imscpAliasEmailAddressForward['aliasid-' + iAliasDomainid][index][
                                  'iEmailAddress'] + '" found for the i-MSCP alias domain "' + iAliasDomain + '"\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations emails alias domain:\nNo emails found for the i-MSCP alias domain "' + iAliasDomain + '"\n')
            if showDebug:
                print(
                    'Debug i-MSCP informations emails alias domain:\nNo emails found for the i-MSCP alias domain "' + iAliasDomain + '"\n')

    def __getImscpAliasSubEmailaddresses(self, iAliasDomainid, iAliasSubDomainId, iAliasSubDomain, iAliasSubDomainIdna,
                                         client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' + self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT mail_id, mail_acc, mail_acc, mail_pass, mail_forward, mail_type, sub_id, quota, mail_addr FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.mail_users WHERE domain_id = \'' + iAliasDomainid + '\' AND sub_id = \'' + iAliasSubDomainId + '\' AND mail_type LIKE \'alssub%\' AND status = \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpAliasSubEmailAddressNormalCatchAll['subid-' + iAliasSubDomainId] = {}
        self.imscpAliasSubEmailAddressNormal['subid-' + iAliasSubDomainId] = {}
        self.imscpAliasSubEmailAddressNormalForward['subid-' + iAliasSubDomainId] = {}
        self.imscpAliasSubEmailAddressForward['subid-' + iAliasSubDomainId] = {}
        for line in stdout:
            if i > 0:
                dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
                dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
                imscpEmailDomainData = dataLine.split("|")
                imscpEmailDomainData[0].strip()
                imscpEmailDomainData[1].strip()
                imscpEmailDomainData[2].strip()
                imscpEmailDomainData[3].strip()
                imscpEmailDomainData[4].strip()
                imscpEmailDomainData[5].strip()
                imscpEmailDomainData[6].strip()
                imscpEmailDomainData[7].strip()

                index = int(imscpEmailDomainData[0])

                # Remove rounds=5000$ from i-MSCP password
                imscpEmailDomainData[2] = re.sub("rounds=5000\$", "", imscpEmailDomainData[1], flags=re.UNICODE)

                if imscpEmailDomainData[4] == 'alssub_catchall':
                    self.imscpAliasSubEmailAddressNormalCatchAll['subid-' + iAliasSubDomainId][index] = {}
                    self.imscpAliasSubEmailAddressNormalCatchAll['subid-' + iAliasSubDomainId][index]['iEmailMailId'] = \
                        imscpEmailDomainData[0]
                    self.imscpAliasSubEmailAddressNormalCatchAll['subid-' + iAliasSubDomainId][index]['iEmailAddress'] = \
                        imscpEmailDomainData[1]
                    _global_config.write_log(
                        'Debug i-MSCP informations catchall emails alias sub domain:\nEmailadress "' +
                        self.imscpAliasSubEmailAddressNormalCatchAll['subid-' + iAliasSubDomainId][index][
                            'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations catchall emails alias sub domain:\nEmailadress "' +
                              self.imscpAliasSubEmailAddressNormalCatchAll['subid-' + iAliasSubDomainId][index][
                                  'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')

                if imscpEmailDomainData[4] == 'alssub_mail':
                    self.imscpAliasSubEmailAddressNormal['subid-' + iAliasSubDomainId][index] = {}
                    self.imscpAliasSubEmailAddressNormal['subid-' + iAliasSubDomainId][index]['iEmailMailId'] = \
                        imscpEmailDomainData[0]
                    self.imscpAliasSubEmailAddressNormal['subid-' + iAliasSubDomainId][index]['iEmailMailPassword'] = \
                        imscpEmailDomainData[2]
                    self.imscpAliasSubEmailAddressNormal['subid-' + iAliasSubDomainId][index]['iEmailMailForward'] = \
                        imscpEmailDomainData[3]
                    self.imscpAliasSubEmailAddressNormal['subid-' + iAliasSubDomainId][index]['iEmailMailType'] = \
                        imscpEmailDomainData[4]
                    self.imscpAliasSubEmailAddressNormal['subid-' + iAliasSubDomainId][index]['iEmailMailQuota'] = \
                        imscpEmailDomainData[6]
                    self.imscpAliasSubEmailAddressNormal['subid-' + iAliasSubDomainId][index]['iEmailAddress'] = \
                        imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails alias sub domain:\nEmailadress "' +
                                             self.imscpAliasSubEmailAddressNormal['subid-' + iAliasSubDomainId][index][
                                                 'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails alias sub domain:\nEmailadress "' +
                              self.imscpAliasSubEmailAddressNormal['subid-' + iAliasSubDomainId][index][
                                  'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')

                if imscpEmailDomainData[4] == 'alssub_mail,alssub_forward':
                    self.imscpAliasSubEmailAddressNormalForward['subid-' + iAliasSubDomainId][index] = {}
                    self.imscpAliasSubEmailAddressNormalForward['subid-' + iAliasSubDomainId][index]['iEmailMailId'] = \
                        imscpEmailDomainData[0]
                    self.imscpAliasSubEmailAddressNormalForward['subid-' + iAliasSubDomainId][index][
                        'iEmailMailPassword'] = imscpEmailDomainData[2]
                    self.imscpAliasSubEmailAddressNormalForward['subid-' + iAliasSubDomainId][index][
                        'iEmailMailForward'] = imscpEmailDomainData[3]
                    self.imscpAliasSubEmailAddressNormalForward['subid-' + iAliasSubDomainId][index]['iEmailMailType'] = \
                        imscpEmailDomainData[4]
                    self.imscpAliasSubEmailAddressNormalForward['subid-' + iAliasSubDomainId][index][
                        'iEmailMailQuota'] = \
                        imscpEmailDomainData[6]
                    self.imscpAliasSubEmailAddressNormalForward['subid-' + iAliasSubDomainId][index]['iEmailAddress'] = \
                        imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails alias sub domain:\nEmailadress "' +
                                             self.imscpAliasSubEmailAddressNormalForward['subid-' + iAliasSubDomainId][
                                                 index][
                                                 'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails alias sub domain:\nEmailadress "' +
                              self.imscpAliasSubEmailAddressNormalForward['subid-' + iAliasSubDomainId][index][
                                  'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')

                if imscpEmailDomainData[4] == 'alssub_forward':
                    self.imscpAliasSubEmailAddressForward['subid-' + iAliasSubDomainId][index] = {}
                    self.imscpAliasSubEmailAddressForward['subid-' + iAliasSubDomainId][index]['iEmailMailId'] = \
                        imscpEmailDomainData[0]
                    self.imscpAliasSubEmailAddressForward['subid-' + iAliasSubDomainId][index]['iEmailMailPassword'] = \
                        imscpEmailDomainData[2]
                    self.imscpAliasSubEmailAddressForward['subid-' + iAliasSubDomainId][index]['iEmailMailForward'] = \
                        imscpEmailDomainData[3]
                    self.imscpAliasSubEmailAddressForward['subid-' + iAliasSubDomainId][index]['iEmailMailType'] = \
                        imscpEmailDomainData[4]
                    self.imscpAliasSubEmailAddressForward['subid-' + iAliasSubDomainId][index]['iEmailMailQuota'] = \
                        imscpEmailDomainData[6]
                    self.imscpAliasSubEmailAddressForward['subid-' + iAliasSubDomainId][index]['iEmailAddress'] = \
                        imscpEmailDomainData[7]
                    _global_config.write_log('Debug i-MSCP informations emails alias sub domain:\nEmailadress "' +
                                             self.imscpAliasSubEmailAddressForward['subid-' + iAliasSubDomainId][index][
                                                 'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')
                    if showDebug:
                        print('Debug i-MSCP informations emails alias sub domain:\nEmailadress "' +
                              self.imscpAliasSubEmailAddressForward['subid-' + iAliasSubDomainId][index][
                                  'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations emails alias sub domain:\nNo emails found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')
            if showDebug:
                print(
                    'Debug i-MSCP informations emails alias sub domain:\nNo emails found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')

    def imscpDataComplete(self):
        if not self.complete:
            return False
        else:
            return True
