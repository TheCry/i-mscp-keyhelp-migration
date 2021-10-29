import base64
import configparser
import idna
import io
import re

import _global_config

_global_config.init()

# i-MSCP
imscpServerFqdn = _global_config.imscpServerFqdn
imscpSshUsername = _global_config.imscpSshUsername
imscpSshPort = _global_config.imscpSshPort
imscpSshTimeout = _global_config.imscpSshTimeout
imscpRootPassword = _global_config.imscpRootPassword
imscpRoundcubeContactImport = _global_config.imscpRoundcubeContactImport
imscpMysqlVersion5_7 = _global_config.imscpMysqlVersion5_7
imscpSshPublicKey = _global_config.imscpSshPublicKey
imscpDbDumpFolder = _global_config.imscpDbDumpFolder
keyhelpUpdatePasswordWithApi = _global_config.keyhelpUpdatePasswordWithApi


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
        self.imscpSslCerts = {}
        self.imscpDomainHtAcccessUsers = {}
        self.imscpDnsEntries = {}
        self.imscpDnsAliasEntries = {}

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

        self.imscpData['imysqlhost'] = iconfig['client']['host']
        self.imscpData['imysqlport'] = iconfig['client']['port']
        self.imscpData['imysqluser'] = iconfig['client']['user']
        self.imscpData['imysqlpassword'] = iconfig['client']['password']
        self.imscpData['imysqldatabase'] = imscpDatabase[1]

        self.complete = False

        return True

    def getImscpUserWebData(self, iUsername, client):
        if (len(iUsername) > 0):
            iUsernameIdna = idna.encode(iUsername.lower()).decode('utf-8')
            if imscpSshPublicKey:
                client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                               key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
            else:
                client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                               password=imscpRootPassword, timeout=imscpSshTimeout)

            stdin, stdout, stderr = client.exec_command(
                'mysql -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
                self.imscpData['imysqluser'] + ' -p' + self.imscpData[
                    'imysqlpassword'] + ' -e "SELECT domain_id, domain_name, domain_admin_id, document_root, '
                                        'url_forward FROM ' +
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
                self.imscpData['iUsernameDomainRsync'] = True
                self.imscpData['iUsernameDomainId'] = imscpUsernameData[0]
                self.imscpData['iUsernameDomain'] = iUsername
                self.imscpData['iUsernameDomainIdna'] = imscpUsernameData[1]
                self.imscpData['iUsernameDomainAdminId'] = imscpUsernameData[2]
                self.imscpData['iDomainData'] = imscpUsernameData[1] + '|' + imscpUsernameData[3] + '|' + \
                                                imscpUsernameData[4]

                _global_config.write_log('Debug i-MSCP informations:\nYour Domain: "' + iUsername + '"')
                _global_config.write_log('Your Domain IDN converted: "' + iUsernameIdna + '"\n')

                print('\nFound domain: ' + iUsername)

                if imscpRoundcubeContactImport:
                    self.imscpRoundcubeUsers = {}
                    self.imscpRoundcubeIdentities = {}
                    self.imscpRoundcubeContacts = {}
                    self.imscpRoundcubeContactgroups = {}
                    self.imscpRoundcubeContact2Contactgroup = {}

                print('Get i-MSCP domain dns data')
                self.__getImscpDomainDns(self.imscpData['iUsernameDomainId'], self.imscpData['iUsernameDomainIdna'],
                                         client)
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
                self.__getImscpSslCert(self.imscpData['iUsernameDomainId'], self.imscpData['iUsernameDomainIdna'],
                                       'dmn', client)
                print('Get i-MSCP HtAccess user data')
                self.__getImscpHtAccessUsers(self.imscpData['iUsernameDomainId'], self.imscpData['iUsernameDomain'],
                                             self.imscpData['iUsernameDomainIdna'], client)

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
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT subdomain_id, subdomain_name, subdomain_mount, '
                                    'subdomain_document_root, subdomain_url_forward FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.subdomain WHERE domain_id = \'' + iUsernameDomainId + '\' AND subdomain_status = \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpDomainSubDomains = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpSubDomainData = dataLine.split("|")
            imscpSubDomainData[0].strip()
            imscpSubDomainData[1].strip()
            imscpSubDomainData[2].strip()
            imscpSubDomainData[3].strip()
            imscpSubDomainData[4].strip()

            index = int(imscpSubDomainData[0])

            self.imscpDomainSubDomains[index] = {}
            if imscpSubDomainData[1] in imscpSubDomainData[2] and imscpSubDomainData[4] == 'no':
                self.imscpDomainSubDomains[index]['iSubDomainRsync'] = True
            else:
                self.imscpDomainSubDomains[index]['iSubDomainRsync'] = False

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

            self.__getImscpSubDomainEmailaddresses(iUsernameDomainId,
                                                   self.imscpDomainSubDomains[index]['iSubDomainId'],
                                                   self.imscpDomainSubDomains[index]['iSubDomain'],
                                                   self.imscpDomainSubDomains[index]['iSubDomainIdna'], client)
            self.__getImscpSslCert(self.imscpDomainSubDomains[index]['iSubDomainId'],
                                   self.imscpDomainSubDomains[index]['iSubDomainIdna'], 'sub', client)

            _global_config.write_log(
                '======================= End data for sub domain "' + self.imscpDomainSubDomains[index][
                    'iSubDomain'] + '" =======================\n\n\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations sub domains:\nNo sub domains found for the i-MSCP domain "' + iUsernameDomain + '"\n')

    def __getImscpAliasDomains(self, iUsernameDomainId, iUsernameDomain, iUsernameDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT alias_id, alias_name, alias_mount, alias_document_root, url_forward '
                                    'FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.domain_aliasses WHERE domain_id = \'' + iUsernameDomainId + '\' AND alias_status = \'ok\'"')
        i = 0

        dataLine = ''
        self.imscpDomainAliases = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpAliasDomainData = dataLine.split("|")
            imscpAliasDomainData[0].strip()
            imscpAliasDomainData[1].strip()
            imscpAliasDomainData[2].strip()
            imscpAliasDomainData[3].strip()
            imscpAliasDomainData[4].strip()

            index = int(imscpAliasDomainData[0])

            self.imscpDomainAliases[index] = {}
            if imscpAliasDomainData[1] in imscpAliasDomainData[2] and imscpAliasDomainData[4] == 'no':
                self.imscpDomainAliases[index]['iAliasDomainRsync'] = True
            else:
                self.imscpDomainAliases[index]['iAliasDomainRsync'] = False

            self.imscpDomainAliases[index]['iAliasDomainId'] = imscpAliasDomainData[0]
            self.imscpDomainAliases[index]['iAliasDomain'] = imscpAliasDomainData[1]
            self.imscpDomainAliases[index]['iAliasDomainIdna'] = idna.encode(imscpAliasDomainData[1]).decode(
                'utf-8')
            self.imscpDomainAliases[index]['iAliasDomainData'] = imscpAliasDomainData[2] + '|' + \
                                                                 imscpAliasDomainData[3] + '|' + \
                                                                 imscpAliasDomainData[4]
            self.__getImscpSslCert(self.imscpDomainAliases[index]['iAliasDomainId'],
                                   self.imscpDomainAliases[index]['iAliasDomainIdna'], 'als', client)

            _global_config.write_log(
                'Debug i-MSCP informations alias domains:\nAlias domain "' + self.imscpDomainAliases[index][
                    'iAliasDomain'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

            self.__getImscpDomainAliasDns(iUsernameDomainId, self.imscpDomainAliases[index]['iAliasDomainId'],
                                          self.imscpDomainAliases[index]['iAliasDomainIdna'], client)
            self.__getImscpAliasSubDomains(iUsernameDomainId, self.imscpDomainAliases[index]['iAliasDomainId'],
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

    def __getImscpFtpUsers(self, iUsernameDomain, iUsernameDomainAdminId, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, \
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT userid, REPLACE(passwd , \'\\\'\', \'-!!!-\'), homedir FROM ' +
            self.imscpData['imysqldatabase'] + '.ftp_users WHERE admin_id = \'' + iUsernameDomainAdminId + '\'"')
        i = 0
        dataLine = ''
        self.imscpFtpUserNames = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|||", line, flags=re.UNICODE)
            imscpDomainFtpUserData = dataLine.split("|||")
            imscpDomainFtpUserData[0].strip()
            imscpDomainFtpUserData[1].strip()
            imscpDomainFtpUserData[2].strip()

            imscpDomainFtpUserData[1] = re.sub(r"-!!!-", "\\\'", imscpDomainFtpUserData[1], flags=re.UNICODE)

            index = i

            self.imscpFtpUserNames[index] = {}
            self.imscpFtpUserNames[index]['iFtpUsername'] = imscpDomainFtpUserData[0]
            self.imscpFtpUserNames[index]['iFtpUserPassword'] = imscpDomainFtpUserData[1]
            self.imscpFtpUserNames[index]['iFtpUserHomeDir'] = imscpDomainFtpUserData[2]

            _global_config.write_log(
                'Debug i-MSCP informations FTP users:\nFTP user "' + self.imscpFtpUserNames[index][
                    'iFtpUsername'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations FTP users:\nNo FTP user found for the i-MSCP domain "' + iUsernameDomain + '"\n')
        else:
            _global_config.write_log(
                '======================= End data for FTP users "' + iUsernameDomain + '" =======================\n\n\n')

    def __getImscpSslCert(self, iDomainId, iDomainName, iDomainType, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, \
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData['imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT cert_id, TO_BASE64(private_key), TO_BASE64(certificate), IF(ca_bundle '
                                    'IS NULL or ca_bundle = \'\', \'empty\', TO_BASE64(ca_bundle)), allow_hsts, hsts_max_age, '
                                    'hsts_include_subdomains FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.ssl_certs WHERE domain_id = \'' + iDomainId + '\' AND domain_type = \'' + iDomainType + '\' AND status = \'ok\'"')

        i = 0
        dataLine = ''

        if iDomainType == 'dmn':
            self.imscpSslCerts['domainid-' + iDomainId] = {}
        if iDomainType == 'sub':
            self.imscpSslCerts['subid-' + iDomainId] = {}
        if iDomainType == 'als':
            self.imscpSslCerts['aliasid-' + iDomainId] = {}
        if iDomainType == 'alssub':
            self.imscpSslCerts['aliassubid-' + iDomainId] = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpSslData = dataLine.split("|")
            imscpSslData[0].strip()
            imscpSslData[1].strip()
            imscpSslData[1] = re.sub(r"\\n", "", imscpSslData[1], flags=re.UNICODE)
            imscpSslData[2].strip()
            imscpSslData[2] = re.sub(r"\\n", "", imscpSslData[2], flags=re.UNICODE)
            imscpSslData[3].strip()
            imscpSslData[3] = re.sub(r"\\n", "", imscpSslData[3], flags=re.UNICODE)
            imscpSslData[4].strip()
            imscpSslData[5].strip()
            imscpSslData[6].strip()

            index = int(imscpSslData[0])

            if iDomainType == 'dmn':
                self.imscpSslCerts['domainid-' + iDomainId][index] = {}
                self.imscpSslCerts['domainid-' + iDomainId][index]['iSslId'] = imscpSslData[0]
                self.imscpSslCerts['domainid-' + iDomainId][index]['iSslPrivateKey'] = str(base64.b64decode(
                    imscpSslData[1] + "==").decode('utf-8'))
                self.imscpSslCerts['domainid-' + iDomainId][index]['iSslCertificate'] = str(base64.b64decode(
                    imscpSslData[2] + "==").decode('utf-8'))
                if imscpSslData[3] != 'empty':
                    self.imscpSslCerts['domainid-' + iDomainId][index]['iSslCaBundle'] = str(base64.b64decode(
                        imscpSslData[3] + "==").decode('utf-8'))
                else:
                    self.imscpSslCerts['domainid-' + iDomainId][index]['iSslCaBundle'] = ''
                self.imscpSslCerts['domainid-' + iDomainId][index]['iSslAllowHsts'] = imscpSslData[4]
                self.imscpSslCerts['domainid-' + iDomainId][index]['iSslHstsMaxAge'] = imscpSslData[5]
                self.imscpSslCerts['domainid-' + iDomainId][index]['iSslHstsIncludeSubdomains'] = imscpSslData[6]

                # print(str(self.imscpSslCerts['domainid-' + iDomainId][index]['iSslPrivateKey'].decode('utf-8')))
                # print(str(self.imscpSslCerts['domainid-' + iDomainId][index]['iSslCertificate'].decode('utf-8')))
                # print(str(self.imscpSslCerts['domainid-' + iDomainId][index]['iSslCaBundle'].decode('utf-8')))
            if iDomainType == 'sub':
                self.imscpSslCerts['subid-' + iDomainId][index] = {}
                self.imscpSslCerts['subid-' + iDomainId][index]['iSslId'] = imscpSslData[0]
                self.imscpSslCerts['subid-' + iDomainId][index]['iSslPrivateKey'] = str(base64.b64decode(
                    imscpSslData[1] + "==").decode('utf-8'))
                self.imscpSslCerts['subid-' + iDomainId][index]['iSslCertificate'] = str(base64.b64decode(
                    imscpSslData[2] + "==").decode('utf-8'))
                if imscpSslData[3] != 'empty':
                    self.imscpSslCerts['subid-' + iDomainId][index]['iSslCaBundle'] = str(base64.b64decode(
                        imscpSslData[3] + "==").decode('utf-8'))
                else:
                    self.imscpSslCerts['subid-' + iDomainId][index]['iSslCaBundle'] = ''
                self.imscpSslCerts['subid-' + iDomainId][index]['iSslAllowHsts'] = imscpSslData[4]
                self.imscpSslCerts['subid-' + iDomainId][index]['iSslHstsMaxAge'] = imscpSslData[5]
                self.imscpSslCerts['subid-' + iDomainId][index]['iSslHstsIncludeSubdomains'] = imscpSslData[6]

                # print(str(self.imscpSslCerts['subid-' + iDomainId][index]['iSslPrivateKey']))
                # print(str(self.imscpSslCerts['subid-' + iDomainId][index]['iSslCertificate']))
                # print(str(self.imscpSslCerts['subid-' + iDomainId][index]['iSslCaBundle']))
            if iDomainType == 'als':
                self.imscpSslCerts['aliasid-' + iDomainId][index] = {}
                self.imscpSslCerts['aliasid-' + iDomainId][index]['iSslId'] = imscpSslData[0]
                self.imscpSslCerts['aliasid-' + iDomainId][index]['iSslPrivateKey'] = str(base64.b64decode(
                    imscpSslData[1] + "==").decode('utf-8'))
                self.imscpSslCerts['aliasid-' + iDomainId][index]['iSslCertificate'] = str(base64.b64decode(
                    imscpSslData[2] + "==").decode('utf-8'))
                if imscpSslData[3] != 'empty':
                    self.imscpSslCerts['aliasid-' + iDomainId][index]['iSslCaBundle'] = str(base64.b64decode(
                        imscpSslData[3] + "==").decode('utf-8'))
                else:
                    self.imscpSslCerts['aliasid-' + iDomainId][index]['iSslCaBundle'] = ''
                self.imscpSslCerts['aliasid-' + iDomainId][index]['iSslAllowHsts'] = imscpSslData[4]
                self.imscpSslCerts['aliasid-' + iDomainId][index]['iSslHstsMaxAge'] = imscpSslData[5]
                self.imscpSslCerts['aliasid-' + iDomainId][index]['iSslHstsIncludeSubdomains'] = imscpSslData[6]

                # print(str(self.imscpSslCerts['aliasid-' + iDomainId][index]['iSslPrivateKey'].decode('utf-8')))
                # print(str(self.imscpSslCerts['aliasid-' + iDomainId][index]['iSslCertificate'].decode('utf-8')))
                # print(str(self.imscpSslCerts['aliasid-' + iDomainId][index]['iSslCaBundle'].decode('utf-8')))
            if iDomainType == 'alssub':
                self.imscpSslCerts['aliassubid-' + iDomainId][index] = {}
                self.imscpSslCerts['aliassubid-' + iDomainId][index]['iSslId'] = imscpSslData[0]
                self.imscpSslCerts['aliassubid-' + iDomainId][index]['iSslPrivateKey'] = str(base64.b64decode(
                    imscpSslData[1] + "==").decode('utf-8'))
                self.imscpSslCerts['aliassubid-' + iDomainId][index]['iSslCertificate'] = str(base64.b64decode(
                    imscpSslData[2] + "==").decode('utf-8'))
                if imscpSslData[3] != 'empty':
                    self.imscpSslCerts['aliassubid-' + iDomainId][index]['iSslCaBundle'] = str(base64.b64decode(
                        imscpSslData[3] + "==").decode('utf-8'))
                else:
                    self.imscpSslCerts['aliassubid-' + iDomainId][index]['iSslCaBundle'] = ''
                self.imscpSslCerts['aliassubid-' + iDomainId][index]['iSslAllowHsts'] = imscpSslData[4]
                self.imscpSslCerts['aliassubid-' + iDomainId][index]['iSslHstsMaxAge'] = imscpSslData[5]
                self.imscpSslCerts['aliassubid-' + iDomainId][index]['iSslHstsIncludeSubdomains'] = imscpSslData[6]

                # print(str(self.imscpSslCerts['aliassubid-' + iDomainId][index]['iSslPrivateKey'].decode('utf-8')))
                # print(str(self.imscpSslCerts['aliassubid-' + iDomainId][index]['iSslCertificate'].decode('utf-8')))
                # print(str(self.imscpSslCerts['aliassubid-' + iDomainId][index]['iSslCaBundle'].decode('utf-8')))

            _global_config.write_log(
                'Debug i-MSCP informations SSL certs:\nSSL cert found for the i-MSCP domain "' + iDomainName + '"\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations SSL Certs:\nNo SSL cert found for the i-MSCP domain "' + iDomainName + '"\n')
        else:
            _global_config.write_log(
                '======================= End data for SSL certs "' + iDomainName + '" =======================\n\n\n')

    def __getImscpHtAccessUsers(self, iUsernameDomainId, iUsernameDomain, iUsernameDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, \
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData['imysqlpassword'] + ' -e "SELECT id, uname, upass FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.htaccess_users WHERE dmn_id = \'' + iUsernameDomainId + '\' AND uname != \'' + iUsernameDomainIdna + '\'"')
        i = 0
        dataLine = ''
        self.imscpDomainHtAcccessUsers = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpDomainHtAccessData = dataLine.split("|")
            imscpDomainHtAccessData[0].strip()
            imscpDomainHtAccessData[1].strip()
            imscpDomainHtAccessData[2].strip()

            index = int(imscpDomainHtAccessData[0])

            self.imscpDomainHtAcccessUsers[index] = {}
            self.imscpDomainHtAcccessUsers[index]['iHtAccessId'] = imscpDomainHtAccessData[0]
            self.imscpDomainHtAcccessUsers[index]['iHtAccessUsername'] = imscpDomainHtAccessData[1]
            self.imscpDomainHtAcccessUsers[index]['iHtAccessPassword'] = imscpDomainHtAccessData[2]

            _global_config.write_log(
                'Debug i-MSCP informations HTACCESS:\nHTACCESS user "' + self.imscpDomainHtAcccessUsers[index][
                    'iHtAccessUsername'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations HTACCESS:\nNo HTACCESS users found for the i-MSCP domain "' + iUsernameDomain + '"\n')
        else:
            _global_config.write_log(
                '======================= End data for HTACCESS users "' + iUsernameDomain + '" =======================\n\n\n')

    def __getImscpDomainDns(self, iUsernameDomainId, iUsernameDomain, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, \
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData['imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT domain_dns_id, domain_dns, domain_type, domain_text FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.domain_dns WHERE domain_id = \'' + iUsernameDomainId + '\' AND owned_by = '
                                                                                             '\'custom_dns_feature\' '
                                                                                             'AND alias_id = \'0\' '
                                                                                             'AND domain_dns_status = '
                                                                                             '\'ok\'"')
        i = 0
        dataLine = ''
        self.imscpDnsEntries = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpDnsEntriesDataArray = dataLine.split("|")
            j = 0
            imscpDnsEntriesData = []
            for dnsLine in imscpDnsEntriesDataArray:
                if j < 3:
                    imscpDnsEntriesData.append(dnsLine.strip())
                else:
                    if 3 < len(imscpDnsEntriesData):
                        imscpDnsEntriesData[3] = imscpDnsEntriesData[3] + ' ' + dnsLine.strip()
                    else:
                        imscpDnsEntriesData.append(dnsLine.strip())

                j += 1

            index = int(imscpDnsEntriesData[0])

            dataLineDns = re.sub(r"\\t", "|", imscpDnsEntriesData[1], flags=re.UNICODE)
            DomainDnsEntriesData = dataLineDns.split("|")
            DomainDnsEntriesData[0] = DomainDnsEntriesData[0].replace(iUsernameDomain, '')

            self.imscpDnsEntries[index] = {}
            self.imscpDnsEntries[index]['iDomainDnsId'] = imscpDnsEntriesData[0].rstrip()
            self.imscpDnsEntries[index]['iDomainDns'] = imscpDnsEntriesData[1].rstrip()
            self.imscpDnsEntries[index]['iDomainDnsEntry'] = DomainDnsEntriesData[0].rstrip('.')
            self.imscpDnsEntries[index]['iDomainDnsEntryTTL'] = DomainDnsEntriesData[1].rstrip()
            self.imscpDnsEntries[index]['iDomainDns'] = imscpDnsEntriesData[1].rstrip()
            self.imscpDnsEntries[index]['iDomainType'] = imscpDnsEntriesData[2].rstrip()
            self.imscpDnsEntries[index]['iDomainText'] = imscpDnsEntriesData[3].rstrip()

            _global_config.write_log(
                'Debug i-MSCP informations domain dns:\nDNS "' + self.imscpDnsEntries[index][
                    'iDomainDnsEntry'] + '" found for the i-MSCP domain "' + iUsernameDomain + '"\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations domain dns:\nNo dns entry found for the i-MSCP domain "' + iUsernameDomain + '"\n')
        else:
            _global_config.write_log(
                '======================= End data for domain dns "' + iUsernameDomain + '" =======================\n\n\n')

    def __getImscpDomainAliasDns(self, iUsernameDomainId, iAliasDomainid, iAliasDomain, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, \
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData['imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT domain_dns_id, domain_dns, domain_type, domain_text FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.domain_dns WHERE domain_id = \'' + iUsernameDomainId + '\' AND owned_by = '
                                                                                             '\'custom_dns_feature\' '
                                                                                             'AND alias_id = \'' + iAliasDomainid + '\' '
                                                                                                                                    'AND domain_dns_status = '
                                                                                                                                    '\'ok\'"')
        i = 0
        dataLine = ''
        self.imscpDnsAliasEntries['aliasid-' + iAliasDomainid] = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpDnsEntriesDataArray = dataLine.split("|")
            j = 0
            imscpAliasDnsEntriesData = []
            for dnsLine in imscpDnsEntriesDataArray:
                if j < 3:
                    imscpAliasDnsEntriesData.append(dnsLine.strip())
                else:
                    if 3 < len(imscpAliasDnsEntriesData):
                        imscpAliasDnsEntriesData[3] = imscpAliasDnsEntriesData[3] + ' ' + dnsLine.strip()
                    else:
                        imscpAliasDnsEntriesData.append(dnsLine.strip())

                j += 1

            index = int(imscpAliasDnsEntriesData[0])

            dataLineAliasDns = re.sub(r"\\t", "|", imscpAliasDnsEntriesData[1], flags=re.UNICODE)
            DomainAliasDnsEntriesData = dataLineAliasDns.split("|")
            DomainAliasDnsEntriesData[0] = DomainAliasDnsEntriesData[0].replace(iAliasDomain, '')

            self.imscpDnsAliasEntries['aliasid-' + iAliasDomainid][index] = {}
            self.imscpDnsAliasEntries['aliasid-' + iAliasDomainid][index]['iDomainAliasDnsId'] = \
                imscpAliasDnsEntriesData[0].rstrip()
            self.imscpDnsAliasEntries['aliasid-' + iAliasDomainid][index]['iDomainAliasDns'] = imscpAliasDnsEntriesData[
                1].rstrip()
            self.imscpDnsAliasEntries['aliasid-' + iAliasDomainid][index]['iDomainAliasDnsEntry'] = \
                DomainAliasDnsEntriesData[0].rstrip('.')
            self.imscpDnsAliasEntries['aliasid-' + iAliasDomainid][index]['iDomainAliasDnsEntryTTL'] = \
                DomainAliasDnsEntriesData[1].rstrip()
            self.imscpDnsAliasEntries['aliasid-' + iAliasDomainid][index]['iDomainAliasDns'] = imscpAliasDnsEntriesData[
                1].rstrip()
            self.imscpDnsAliasEntries['aliasid-' + iAliasDomainid][index]['iDomainAliasType'] = \
                imscpAliasDnsEntriesData[2].rstrip()
            self.imscpDnsAliasEntries['aliasid-' + iAliasDomainid][index]['iDomainAliasText'] = \
                imscpAliasDnsEntriesData[3].rstrip()

            _global_config.write_log('Debug i-MSCP informations domain alias dns:\nDNS "' +
                                     self.imscpDnsAliasEntries['aliasid-' + iAliasDomainid][index][
                                         'iDomainAliasDnsEntry'] + '" found for the i-MSCP domain alias "' + iAliasDomain + '"\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations domain alias dns:\nNo dns entry found for the i-MSCP domain alias "' + iAliasDomain + '"\n')
        else:
            _global_config.write_log(
                '======================= End data for domain alias dns "' + iAliasDomain + '" =======================\n\n\n')

    def __getImscpDomainDatabases(self, iUsernameDomainId, iUsernameDomain, iUsernameDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, \
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData['imysqlpassword'] + ' -e "SELECT sqld_id, sqld_name FROM ' +
            self.imscpData['imysqldatabase'] + '.sql_database WHERE domain_id = \'' + iUsernameDomainId + '\'"')
        i = 0
        dataLine = ''
        self.imscpDomainDatabaseNames = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
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

            self.__getImscpDomainDatabaseUsers(iUsernameDomainId, iUsernameDomain,
                                               self.imscpDomainDatabaseNames[index]['iDatabaseId'],
                                               self.imscpDomainDatabaseNames[index]['iDatabaseName'], client)

            i += 1

        if i == 0:
            _global_config.write_log(
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
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT sqlu_id, sqld_id, sqlu_name, sqlu_host FROM ' + self.imscpData[
                'imysqldatabase'] + '.sql_user WHERE sqld_id = \'' + iDatabaseId + '\'"')
        i = 0
        dataLine = ''
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
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

            if keyhelpUpdatePasswordWithApi:
                self.imscpDomainDatabaseUsernames[index][
                    'iDatabasePasswordHash'] = self.__getImscpDatabaseUserPasswordHash(
                    imscpDomainDatabaseUsernameData[2],
                    imscpDomainDatabaseUsernameData[3], client)
            else:
                self.imscpDomainDatabaseUsernames[index]['iDatabasePasswordHash'] = 'N/A'

            _global_config.write_log('Debug i-MSCP informations database users:\nDatabase username "' +
                                     self.imscpDomainDatabaseUsernames[index][
                                         'iDatabaseUsername'] + '" found for the i-MSCP database "' + iDatabaseName + '""(domain: ' + iUsernameDomain + ')\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations database users :\nNo database users found for the database "' +
                iDatabaseName + '"\n')
        else:
            _global_config.write_log(
                '======================= End data for database users - "' + iDatabaseName + '" - Domain "' + iUsernameDomain + '" =======================\n\n\n')

    def __getImscpDatabaseUserPasswordHash(self, iDatabaseUsername, iDatabaseUserHost, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        if imscpMysqlVersion5_7:
            stdin, stdout, stderr = client.exec_command(
                'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
                self.imscpData[
                    'imysqluser'] + ' -p' + self.imscpData[
                    'imysqlpassword'] + ' -e "SHOW CREATE USER \'' + iDatabaseUsername + '\'@\'' + iDatabaseUserHost + '\'"')
        else:
            stdin, stdout, stderr = client.exec_command(
                'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
                self.imscpData[
                    'imysqluser'] + ' -p' + self.imscpData[
                    'imysqlpassword'] + ' -e "SHOW GRANTS FOR \'' + iDatabaseUsername + '\'@\'' + iDatabaseUserHost + '\'"')
        i = 0
        dataLine = ''
        iDatabasePasswordHash = 'N/A'
        for line in stdout:
            if imscpMysqlVersion5_7:
                if i == 1:
                    dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            else:
                if i == 0:
                    dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            #print(dataLine)
            i += 1
        if dataLine:
            imscpDomainDatabaseUsernamePasswordData = dataLine.split("|")
            if imscpMysqlVersion5_7:
                iDatabasePasswordHash = imscpDomainDatabaseUsernamePasswordData[7].strip()
            else:
                try:
                    iDatabasePasswordHash = imscpDomainDatabaseUsernamePasswordData[9].strip()
                except IndexError:
                    raise SystemExit(
                        "A MySQL query Error occurred: It seems on i-MSCP is MySQL version >= 5.7 installed. Set "
                        "'imscpMysqlVersion5_7' to true in the migration-config.cfg.")
            # Remove single quotes
            iDatabasePasswordHash = iDatabasePasswordHash[1:]
            iDatabasePasswordHash = iDatabasePasswordHash[:-1]

        if iDatabasePasswordHash == 'N/A':
            _global_config.write_log(
                'Debug i-MSCP informations database user password :\nNo password found for the user "' + iDatabaseUsername + '@' + iDatabaseUserHost + '"\n')
        else:
            _global_config.write_log(
                'Debug i-MSCP informations database user password:\nDatabase username password found for user "' + iDatabaseUsername + '@' + iDatabaseUserHost + '"\n')
            _global_config.write_log(
                '======================= End data for database user password for user - "' + iDatabaseUsername + '" =======================\n\n\n')

        return iDatabasePasswordHash

    def __getImscpAliasSubDomains(self, iUsernameDomainId, iAliasDomainid, iAliasDomain, iAliasDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT subdomain_alias_id, subdomain_alias_name, subdomain_alias_mount, '
                                    'subdomain_alias_document_root, subdomain_alias_url_forward FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.subdomain_alias WHERE alias_id = \'' + iAliasDomainid + '\' AND '
                                                                                              'subdomain_alias_status'
                                                                                              ' = \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpAliasSubDomains['aliasid-' + iAliasDomainid] = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpAliasSubDomainData = dataLine.split("|")
            imscpAliasSubDomainData[0].strip()
            imscpAliasSubDomainData[1].strip()
            imscpAliasSubDomainData[2].strip()
            imscpAliasSubDomainData[3].strip()
            imscpAliasSubDomainData[4].strip()

            index = int(imscpAliasSubDomainData[0])

            self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index] = {}
            if imscpAliasSubDomainData[1] in imscpAliasSubDomainData[2] and imscpAliasSubDomainData[4] == 'no':
                self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomainRsync'] = True
            else:
                self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomainRsync'] = False

            self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomainId'] = \
                imscpAliasSubDomainData[0]
            self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomain'] = \
                imscpAliasSubDomainData[1] + '.' + iAliasDomainIdna
            self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomainIdna'] = idna.encode(
                imscpAliasSubDomainData[1] + '.' + iAliasDomain).decode('utf-8')
            self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomainData'] = \
                imscpAliasSubDomainData[2] + '|' + imscpAliasSubDomainData[3] + '|' + imscpAliasSubDomainData[4]
            self.__getImscpSslCert(
                self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomainId'],
                self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index]['iAliasSubDomain'], 'alssub', client)

            _global_config.write_log('Debug i-MSCP informations alias sub domains:\nAlias sub domain "' +
                                     self.imscpAliasSubDomains['aliasid-' + iAliasDomainid][index][
                                         'iAliasSubDomain'] + '" found for the i-MSCP alias domain "' + iAliasDomain + '"\n')

            self.__getImscpAliasSubEmailaddresses(iUsernameDomainId,
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

    def __getImscpDomainEmailaddresses(self, iUsernameDomainId, iUsernameDomain, iUsernameDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT mail_id, mail_acc, mail_pass, mail_forward, mail_type, sub_id, quota, '
                                    'mail_addr FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.mail_users WHERE domain_id = \'' + iUsernameDomainId + '\' AND sub_id = \'0\' '
                                                                                             'AND mail_type LIKE '
                                                                                             '\'normal%\' AND status '
                                                                                             '= \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpDomainEmailAddressNormalCatchAll = {}
        self.imscpDomainEmailAddressNormal = {}
        self.imscpDomainEmailAddressNormalForward = {}
        self.imscpDomainEmailAddressForward = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
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

                if imscpRoundcubeContactImport:
                    print('Get i-MSCP roundcube domain email contact data')
                    self.__getImscpRoundcubeUsers(client, self.imscpDomainEmailAddressNormal[index]['iEmailAddress'])

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

                if imscpRoundcubeContactImport:
                    print('Get i-MSCP roundcube domain email contact data')
                    self.__getImscpRoundcubeUsers(client,
                                                  self.imscpDomainEmailAddressNormalForward[index]['iEmailAddress'])

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

            i += 1

        if i == 0:
            _global_config.write_log(
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
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData['imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT mail_id, mail_acc, mail_pass, mail_forward, mail_type, sub_id, quota, '
                                    'mail_addr FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.mail_users WHERE domain_id = \'' + iUsernameDomainId + '\' AND sub_id = \'' + iSubDomainId + '\' AND mail_type LIKE \'subdom%\'  AND status = \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpDomainSubEmailAddressNormalCatchAll['subid-' + iSubDomainId] = {}
        self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId] = {}
        self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId] = {}
        self.imscpDomainSubEmailAddressForward['subid-' + iSubDomainId] = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
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

                if imscpRoundcubeContactImport:
                    print('Get i-MSCP roundcube sub domain email contact data')
                    self.__getImscpRoundcubeUsers(client,
                                                  self.imscpDomainSubEmailAddressNormal['subid-' + iSubDomainId][index][
                                                      'iEmailAddress'])

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

                if imscpRoundcubeContactImport:
                    print('Get i-MSCP roundcube sub domain email contact data')
                    self.__getImscpRoundcubeUsers(client,
                                                  self.imscpDomainSubEmailAddressNormalForward['subid-' + iSubDomainId][
                                                      index]['iEmailAddress'])

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

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations emails sub domain:\nNo emails found for the i-MSCP sub domain "' + iSubDomain + '"\n')

    def __getImscpAliasEmailaddresses(self, iUsernameDomainId, iAliasDomainid, iAliasDomain, iAliasDomainIdna, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT mail_id, mail_acc, mail_pass, mail_forward, mail_type, sub_id, quota, '
                                    'mail_addr FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.mail_users WHERE domain_id = \'' + iUsernameDomainId + '\' AND sub_id = \'' + iAliasDomainid + '\' AND mail_type LIKE \'alias%\' AND status = \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpAliasEmailAddressNormalCatchAll['aliasid-' + iAliasDomainid] = {}
        self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid] = {}
        self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid] = {}
        self.imscpAliasEmailAddressForward['aliasid-' + iAliasDomainid] = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
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

                if imscpRoundcubeContactImport:
                    print('Get i-MSCP roundcube alias domain email contact data')
                    self.__getImscpRoundcubeUsers(client,
                                                  self.imscpAliasEmailAddressNormal['aliasid-' + iAliasDomainid][index][
                                                      'iEmailAddress'])

            if imscpEmailDomainData[4] == 'alias_mail,alias_forward':
                self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][index] = {}
                self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][index]['iEmailMailId'] = \
                    imscpEmailDomainData[0]
                self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][index]['iEmailMailPassword'] = \
                    imscpEmailDomainData[2]
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

                if imscpRoundcubeContactImport:
                    print('Get i-MSCP roundcube alias domain email contact data')
                    self.__getImscpRoundcubeUsers(client,
                                                  self.imscpAliasEmailAddressNormalForward['aliasid-' + iAliasDomainid][
                                                      index]['iEmailAddress'])

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

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations emails alias domain:\nNo emails found for the i-MSCP alias domain "' + iAliasDomain + '"\n')

    def __getImscpAliasSubEmailaddresses(self, iDomainid, iAliasSubDomainId, iAliasSubDomain, iAliasSubDomainIdna,
                                         client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT mail_id, mail_acc, mail_pass, mail_forward, mail_type, '
                                    'sub_id, quota, mail_addr FROM ' +
            self.imscpData[
                'imysqldatabase'] + '.mail_users WHERE domain_id = \'' + iDomainid + '\' AND sub_id = \'' + iAliasSubDomainId + '\' AND mail_type LIKE \'alssub%\' AND status = \'ok\'"')
        i = 0
        dataLine = ''
        self.imscpAliasSubEmailAddressNormalCatchAll['aliassubid-' + iAliasSubDomainId] = {}
        self.imscpAliasSubEmailAddressNormal['aliassubid-' + iAliasSubDomainId] = {}
        self.imscpAliasSubEmailAddressNormalForward['aliassubid-' + iAliasSubDomainId] = {}
        self.imscpAliasSubEmailAddressForward['aliassubid-' + iAliasSubDomainId] = {}
        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
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

            if imscpEmailDomainData[4] == 'alssub_catchall':
                self.imscpAliasSubEmailAddressNormalCatchAll['aliassubid-' + iAliasSubDomainId][index] = {}
                self.imscpAliasSubEmailAddressNormalCatchAll['aliassubid-' + iAliasSubDomainId][index]['iEmailMailId'] = \
                    imscpEmailDomainData[0]
                self.imscpAliasSubEmailAddressNormalCatchAll['aliassubid-' + iAliasSubDomainId][index][
                    'iEmailAddress'] = \
                    imscpEmailDomainData[1]
                _global_config.write_log(
                    'Debug i-MSCP informations catchall emails alias sub domain:\nEmailadress "' +
                    self.imscpAliasSubEmailAddressNormalCatchAll['aliassubid-' + iAliasSubDomainId][index][
                        'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')

            if imscpEmailDomainData[4] == 'alssub_mail':
                self.imscpAliasSubEmailAddressNormal['aliassubid-' + iAliasSubDomainId][index] = {}
                self.imscpAliasSubEmailAddressNormal['aliassubid-' + iAliasSubDomainId][index]['iEmailMailId'] = \
                    imscpEmailDomainData[0]
                self.imscpAliasSubEmailAddressNormal['aliassubid-' + iAliasSubDomainId][index]['iEmailMailPassword'] = \
                    imscpEmailDomainData[2]
                self.imscpAliasSubEmailAddressNormal['aliassubid-' + iAliasSubDomainId][index]['iEmailMailForward'] = \
                    imscpEmailDomainData[3]
                self.imscpAliasSubEmailAddressNormal['aliassubid-' + iAliasSubDomainId][index]['iEmailMailType'] = \
                    imscpEmailDomainData[4]
                self.imscpAliasSubEmailAddressNormal['aliassubid-' + iAliasSubDomainId][index]['iEmailMailQuota'] = \
                    imscpEmailDomainData[6]
                self.imscpAliasSubEmailAddressNormal['aliassubid-' + iAliasSubDomainId][index]['iEmailAddress'] = \
                    imscpEmailDomainData[7]
                _global_config.write_log('Debug i-MSCP informations emails alias sub domain:\nEmailadress "' +
                                         self.imscpAliasSubEmailAddressNormal['aliassubid-' + iAliasSubDomainId][index][
                                             'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')

                if imscpRoundcubeContactImport:
                    print('Get i-MSCP roundcube alias sub domain email contact data')
                    self.__getImscpRoundcubeUsers(client, self.imscpAliasSubEmailAddressNormal[
                        'aliassubid-' + iAliasSubDomainId][index]['iEmailAddress'])

            if imscpEmailDomainData[4] == 'alssub_mail,alssub_forward':
                self.imscpAliasSubEmailAddressNormalForward['aliassubid-' + iAliasSubDomainId][index] = {}
                self.imscpAliasSubEmailAddressNormalForward['aliassubid-' + iAliasSubDomainId][index]['iEmailMailId'] = \
                    imscpEmailDomainData[0]
                self.imscpAliasSubEmailAddressNormalForward['aliassubid-' + iAliasSubDomainId][index][
                    'iEmailMailPassword'] = imscpEmailDomainData[2]
                self.imscpAliasSubEmailAddressNormalForward['aliassubid-' + iAliasSubDomainId][index][
                    'iEmailMailForward'] = imscpEmailDomainData[3]
                self.imscpAliasSubEmailAddressNormalForward['aliassubid-' + iAliasSubDomainId][index][
                    'iEmailMailType'] = \
                    imscpEmailDomainData[4]
                self.imscpAliasSubEmailAddressNormalForward['aliassubid-' + iAliasSubDomainId][index][
                    'iEmailMailQuota'] = \
                    imscpEmailDomainData[6]
                self.imscpAliasSubEmailAddressNormalForward['aliassubid-' + iAliasSubDomainId][index]['iEmailAddress'] = \
                    imscpEmailDomainData[7]
                _global_config.write_log('Debug i-MSCP informations emails alias sub domain:\nEmailadress "' +
                                         self.imscpAliasSubEmailAddressNormalForward['aliassubid-' + iAliasSubDomainId][
                                             index][
                                             'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')

                if imscpRoundcubeContactImport:
                    print('Get i-MSCP roundcube alias sub domain email contact data')
                    self.__getImscpRoundcubeUsers(client, self.imscpAliasSubEmailAddressNormalForward[
                        'aliassubid-' + iAliasSubDomainId][index]['iEmailAddress'])

            if imscpEmailDomainData[4] == 'alssub_forward':
                self.imscpAliasSubEmailAddressForward['aliassubid-' + iAliasSubDomainId][index] = {}
                self.imscpAliasSubEmailAddressForward['aliassubid-' + iAliasSubDomainId][index]['iEmailMailId'] = \
                    imscpEmailDomainData[0]
                self.imscpAliasSubEmailAddressForward['aliassubid-' + iAliasSubDomainId][index]['iEmailMailPassword'] = \
                    imscpEmailDomainData[2]
                self.imscpAliasSubEmailAddressForward['aliassubid-' + iAliasSubDomainId][index]['iEmailMailForward'] = \
                    imscpEmailDomainData[3]
                self.imscpAliasSubEmailAddressForward['aliassubid-' + iAliasSubDomainId][index]['iEmailMailType'] = \
                    imscpEmailDomainData[4]
                self.imscpAliasSubEmailAddressForward['aliassubid-' + iAliasSubDomainId][index]['iEmailMailQuota'] = \
                    imscpEmailDomainData[6]
                self.imscpAliasSubEmailAddressForward['aliassubid-' + iAliasSubDomainId][index]['iEmailAddress'] = \
                    imscpEmailDomainData[7]
                _global_config.write_log('Debug i-MSCP informations emails alias sub domain:\nEmailadress "' +
                                         self.imscpAliasSubEmailAddressForward['aliassubid-' + iAliasSubDomainId][
                                             index][
                                             'iEmailAddress'] + '" found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')

            i += 1

        if i == 0:
            _global_config.write_log(
                'Debug i-MSCP informations emails alias sub domain:\nNo emails found for the i-MSCP alias sub domain "' + iAliasSubDomain + '"\n')

    def __getImscpRoundcubeUsers(self, client, rEmailaddress):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT user_id, username, mail_host, REPLACE(created , \' \', \'!!!\'), '
                                    'REPLACE(last_login , \' \', \'!!!\'), IF(failed_login = \'\', \'empty\', REPLACE(failed_login , \' \', \'!!!\')), '
                                    'IF(failed_login_counter = \'\', \'empty\', failed_login_counter), language, preferences FROM ' +
            self.imscpData[
                'imysqldatabase'] + '_roundcube.users WHERE username = \'' + rEmailaddress + '\'"')
        i = 0
        dataLine = ''

        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpRoundcubeUserData = dataLine.split("|")
            imscpRoundcubeUserData[0].strip()
            imscpRoundcubeUserData[1].strip()
            imscpRoundcubeUserData[2].strip()
            imscpRoundcubeUserData[3].strip()
            imscpRoundcubeUserData[4].strip()
            imscpRoundcubeUserData[5].strip()
            imscpRoundcubeUserData[6].strip()
            imscpRoundcubeUserData[7].strip()
            imscpRoundcubeUserData[8].strip()

            index = int(imscpRoundcubeUserData[0])

            imscpRoundcubeUserData[3] = re.sub(r"!!!", " ", imscpRoundcubeUserData[3], flags=re.UNICODE)
            imscpRoundcubeUserData[4] = re.sub(r"!!!", " ", imscpRoundcubeUserData[4], flags=re.UNICODE)
            imscpRoundcubeUserData[5] = re.sub(r"!!!", " ", imscpRoundcubeUserData[5], flags=re.UNICODE)

            imscpRoundcubeUserData[5] = re.sub(r"empty", "", imscpRoundcubeUserData[5], flags=re.UNICODE)
            imscpRoundcubeUserData[6] = re.sub(r"empty", "", imscpRoundcubeUserData[6], flags=re.UNICODE)

            self.imscpRoundcubeUsers[index] = {}

            imscpRoundcubeUserData[2] = re.sub(r"localhost", "127.0.0.1", imscpRoundcubeUserData[2], flags=re.UNICODE)

            self.imscpRoundcubeUsers[index]['rUserId'] = imscpRoundcubeUserData[0]
            self.imscpRoundcubeUsers[index]['rUsername'] = imscpRoundcubeUserData[1]
            self.imscpRoundcubeUsers[index]['rMailHost'] = imscpRoundcubeUserData[2]
            self.imscpRoundcubeUsers[index]['rCreated'] = imscpRoundcubeUserData[3]
            self.imscpRoundcubeUsers[index]['rLastLogin'] = imscpRoundcubeUserData[4]
            self.imscpRoundcubeUsers[index]['rFailedLogin'] = imscpRoundcubeUserData[5]
            self.imscpRoundcubeUsers[index]['rFailedLoginCounter'] = imscpRoundcubeUserData[6]
            self.imscpRoundcubeUsers[index]['rLanguage'] = imscpRoundcubeUserData[7]
            self.imscpRoundcubeUsers[index]['rPreferences'] = imscpRoundcubeUserData[8]

            _global_config.write_log(
                'Debug i-MSCP informations roundcube users:\nRoundcube user "' + self.imscpRoundcubeUsers[index][
                    'rUsername'] + '" found.\n')

            self.__getImscpRoundcubeIdentities(self.imscpRoundcubeUsers[index]['rUserId'], client)
            self.__getImscpRoundcubeContacts(self.imscpRoundcubeUsers[index]['rUserId'], client)
            self.__getImscpRoundcubeContactgroups(self.imscpRoundcubeUsers[index]['rUserId'], client)

            _global_config.write_log(
                '======================= End data for roundcube users =======================\n\n\n')

            i += 1

    def __getImscpRoundcubeIdentities(self, rUserId, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -r -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData['imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT identity_id, user_id, REPLACE(changed , \' \', \'--!!!--\'), del, '
                                    'standard, IF(name = \'\', \'empty\', REPLACE(name , \' \', \'--!!!--\')), IF(organization = \'\', \'empty\', REPLACE(organization , \' \', \'--!!!--\')), email, IF(\'reply-to\' = \'\', \'reply-to\', \'empty\'), '
                                    'IF(bcc = \'\', \'empty\', bcc), IF(signature = \'\', \'empty\', REPLACE(REPLACE(REPLACE(signature , \'\n\', \'-!!-\'), \'\r\', \'_!!_\'), \'\ \', \'--!!!--\')), '
                                    'html_signature FROM ' +
            self.imscpData['imysqldatabase'] + '_roundcube.identities WHERE user_id = \'' + rUserId + '\'"')
        i = 0
        dataLine = ''

        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpRoundcubeIdentityData = dataLine.split("|")
            imscpRoundcubeIdentityData[0].strip()
            imscpRoundcubeIdentityData[1].strip()
            imscpRoundcubeIdentityData[2].strip()
            imscpRoundcubeIdentityData[3].strip()
            imscpRoundcubeIdentityData[4].strip()
            imscpRoundcubeIdentityData[5].strip()
            imscpRoundcubeIdentityData[6].strip()
            imscpRoundcubeIdentityData[7].strip()
            imscpRoundcubeIdentityData[8].strip()
            imscpRoundcubeIdentityData[9].strip()
            imscpRoundcubeIdentityData[10].strip()
            imscpRoundcubeIdentityData[11].strip()

            index = int(imscpRoundcubeIdentityData[0])

            self.imscpRoundcubeIdentities[index] = {}
            imscpRoundcubeIdentityData[2] = re.sub(r"--!!!--", " ", imscpRoundcubeIdentityData[2], flags=re.UNICODE)
            imscpRoundcubeIdentityData[5] = re.sub(r"--!!!--", " ", imscpRoundcubeIdentityData[5], flags=re.UNICODE)
            imscpRoundcubeIdentityData[6] = re.sub(r"--!!!--", " ", imscpRoundcubeIdentityData[6], flags=re.UNICODE)
            imscpRoundcubeIdentityData[10] = re.sub(r"-!!-", "\n", imscpRoundcubeIdentityData[10], flags=re.UNICODE)
            imscpRoundcubeIdentityData[10] = re.sub(r"_!!_", "\r", imscpRoundcubeIdentityData[10], flags=re.UNICODE)
            imscpRoundcubeIdentityData[10] = re.sub(r"!!!", " ", imscpRoundcubeIdentityData[10], flags=re.UNICODE)

            imscpRoundcubeIdentityData[5] = re.sub(r"empty", "", imscpRoundcubeIdentityData[5], flags=re.UNICODE)
            imscpRoundcubeIdentityData[6] = re.sub(r"empty", "", imscpRoundcubeIdentityData[6], flags=re.UNICODE)
            imscpRoundcubeIdentityData[8] = re.sub(r"empty", "", imscpRoundcubeIdentityData[8], flags=re.UNICODE)
            imscpRoundcubeIdentityData[9] = re.sub(r"empty", "", imscpRoundcubeIdentityData[9], flags=re.UNICODE)
            imscpRoundcubeIdentityData[10] = re.sub(r"empty", "", imscpRoundcubeIdentityData[10], flags=re.UNICODE)

            self.imscpRoundcubeIdentities[index]['rIdentityId'] = imscpRoundcubeIdentityData[0]
            self.imscpRoundcubeIdentities[index]['rUserId'] = imscpRoundcubeIdentityData[1]
            self.imscpRoundcubeIdentities[index]['rChanged'] = imscpRoundcubeIdentityData[2]
            self.imscpRoundcubeIdentities[index]['rDel'] = imscpRoundcubeIdentityData[3]
            self.imscpRoundcubeIdentities[index]['rStandard'] = imscpRoundcubeIdentityData[4]
            self.imscpRoundcubeIdentities[index]['rName'] = imscpRoundcubeIdentityData[5]
            self.imscpRoundcubeIdentities[index]['rOrganization'] = imscpRoundcubeIdentityData[6]
            self.imscpRoundcubeIdentities[index]['rEmail'] = imscpRoundcubeIdentityData[7]
            self.imscpRoundcubeIdentities[index]['rReplyTo'] = imscpRoundcubeIdentityData[8]
            self.imscpRoundcubeIdentities[index]['rBcc'] = imscpRoundcubeIdentityData[9]
            self.imscpRoundcubeIdentities[index]['rSignature'] = imscpRoundcubeIdentityData[10]
            self.imscpRoundcubeIdentities[index]['rHtmlSignature'] = imscpRoundcubeIdentityData[11]

            _global_config.write_log('Debug i-MSCP informations roundcube identities:\nRoundcube identity "' +
                                     self.imscpRoundcubeIdentities[index]['rName'] + '" found.\n')

            _global_config.write_log(
                '======================= End data for roundcube identities =======================\n\n\n')

            i += 1

    def __getImscpRoundcubeContacts(self, rUserId, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -r -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT contact_id, REPLACE(changed , \' \', \'!!!\'), del, IF(name = \'\', '
                                    '\'empty\', REPLACE(name , \' \', \'!!!\')), email, IF(firstname = \'\', \'empty\', REPLACE(firstname '
                                    ', \' \', \'!!!\')), IF(surname = \'\', \'empty\', REPLACE(surname , \' \', \'!!!\')), '
                                    'REPLACE(REPLACE(REPLACE(vcard , \'\n\', \'---\'), \'\r\', \'___\'), \'\ \', '
                                    '\'!!!\'), REPLACE(words , \' \', \'!!!\'), user_id FROM ' +
            self.imscpData[
                'imysqldatabase'] + '_roundcube.contacts WHERE user_id = \'' + rUserId + '\'"')
        i = 0
        dataLine = ''

        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpRoundcubeContactData = dataLine.split("|")
            imscpRoundcubeContactData[0].strip()
            imscpRoundcubeContactData[1].strip()
            imscpRoundcubeContactData[2].strip()
            imscpRoundcubeContactData[3].strip()
            imscpRoundcubeContactData[4].strip()
            imscpRoundcubeContactData[5].strip()
            imscpRoundcubeContactData[6].strip()
            imscpRoundcubeContactData[7].strip()
            imscpRoundcubeContactData[8].strip()
            imscpRoundcubeContactData[9].strip()

            index = int(imscpRoundcubeContactData[0])

            self.imscpRoundcubeContacts[index] = {}
            imscpRoundcubeContactData[1] = re.sub(r"!!!", " ", imscpRoundcubeContactData[1], flags=re.UNICODE)
            imscpRoundcubeContactData[3] = re.sub(r"!!!", " ", imscpRoundcubeContactData[3], flags=re.UNICODE)
            imscpRoundcubeContactData[5] = re.sub(r"!!!", " ", imscpRoundcubeContactData[5], flags=re.UNICODE)
            imscpRoundcubeContactData[6] = re.sub(r"!!!", " ", imscpRoundcubeContactData[6], flags=re.UNICODE)
            imscpRoundcubeContactData[8] = re.sub(r"!!!", " ", imscpRoundcubeContactData[8], flags=re.UNICODE)
            imscpRoundcubeContactData[7] = re.sub(r"---", "\n", imscpRoundcubeContactData[7], flags=re.UNICODE)
            imscpRoundcubeContactData[7] = re.sub(r"___", "\r", imscpRoundcubeContactData[7], flags=re.UNICODE)
            imscpRoundcubeContactData[7] = re.sub(r"!!!", " ", imscpRoundcubeContactData[7], flags=re.UNICODE)

            imscpRoundcubeContactData[3] = re.sub(r"empty", "", imscpRoundcubeContactData[3], flags=re.UNICODE)
            imscpRoundcubeContactData[5] = re.sub(r"empty", "", imscpRoundcubeContactData[5], flags=re.UNICODE)
            imscpRoundcubeContactData[6] = re.sub(r"empty", "", imscpRoundcubeContactData[6], flags=re.UNICODE)

            self.imscpRoundcubeContacts[index]['rContactId'] = imscpRoundcubeContactData[0]
            self.imscpRoundcubeContacts[index]['rChanged'] = imscpRoundcubeContactData[1]
            self.imscpRoundcubeContacts[index]['rDel'] = imscpRoundcubeContactData[2]
            self.imscpRoundcubeContacts[index]['rName'] = imscpRoundcubeContactData[3]
            self.imscpRoundcubeContacts[index]['rEmail'] = imscpRoundcubeContactData[4]
            self.imscpRoundcubeContacts[index]['rFirstname'] = imscpRoundcubeContactData[5]
            self.imscpRoundcubeContacts[index]['rSurname'] = imscpRoundcubeContactData[6]
            self.imscpRoundcubeContacts[index]['rVcard'] = imscpRoundcubeContactData[7]
            self.imscpRoundcubeContacts[index]['rWords'] = imscpRoundcubeContactData[8]
            self.imscpRoundcubeContacts[index]['rUserId'] = imscpRoundcubeContactData[9]

            _global_config.write_log('Debug i-MSCP informations roundcube contact:\nRoundcube contact "' +
                                     self.imscpRoundcubeContacts[index]['rEmail'] + '" found.\n')

            _global_config.write_log(
                '======================= End data for roundcube contacts =======================\n\n\n')

            i += 1

    def __getImscpRoundcubeContactgroups(self, rUserId, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -r -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT contactgroup_id, user_id, REPLACE(changed , \' \', \'!!!\'), del, '
                                    'REPLACE(name , \' \', \'!!!\') FROM ' +
            self.imscpData[
                'imysqldatabase'] + '_roundcube.contactgroups WHERE user_id = \'' + rUserId + '\'"')
        i = 0
        dataLine = ''

        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpRoundcubeContactGroupData = dataLine.split("|")
            imscpRoundcubeContactGroupData[0].strip()
            imscpRoundcubeContactGroupData[1].strip()
            imscpRoundcubeContactGroupData[2].strip()
            imscpRoundcubeContactGroupData[3].strip()
            imscpRoundcubeContactGroupData[4].strip()

            index = int(imscpRoundcubeContactGroupData[0])

            imscpRoundcubeContactGroupData[2] = re.sub(r"!!!", " ", imscpRoundcubeContactGroupData[2], flags=re.UNICODE)
            imscpRoundcubeContactGroupData[4] = re.sub(r"!!!", " ", imscpRoundcubeContactGroupData[4], flags=re.UNICODE)

            self.imscpRoundcubeContactgroups[index] = {}

            self.imscpRoundcubeContactgroups[index]['rContactGroupId'] = imscpRoundcubeContactGroupData[0]
            self.imscpRoundcubeContactgroups[index]['rUserId'] = imscpRoundcubeContactGroupData[1]
            self.imscpRoundcubeContactgroups[index]['rChanged'] = imscpRoundcubeContactGroupData[2]
            self.imscpRoundcubeContactgroups[index]['rDel'] = imscpRoundcubeContactGroupData[3]
            self.imscpRoundcubeContactgroups[index]['rName'] = imscpRoundcubeContactGroupData[4]

            _global_config.write_log('Debug i-MSCP informations roundcube contact group:\nRoundcube contact "' +
                                     self.imscpRoundcubeContactgroups[index]['rName'] + '" found.\n')

            self.__getImscpRoundcubeContact2Contactgroup(self.imscpRoundcubeContactgroups[index]['rContactGroupId'],
                                                         client)

            _global_config.write_log(
                '======================= End data for roundcube contact groups =======================\n\n\n')

            i += 1

    def __getImscpRoundcubeContact2Contactgroup(self, rContactGroupId, client):
        if imscpSshPublicKey:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername,
                           key_filename=imscpSshPublicKey, timeout=imscpSshTimeout)
        else:
            client.connect(imscpServerFqdn, port=imscpSshPort, username=imscpSshUsername, password=imscpRootPassword,
                           timeout=imscpSshTimeout)

        stdin, stdout, stderr = client.exec_command(
            'mysql -s -h' + self.imscpData['imysqlhost'] + ' -P' + self.imscpData['imysqlport'] + ' -u' +
            self.imscpData[
                'imysqluser'] + ' -p' + self.imscpData[
                'imysqlpassword'] + ' -e "SELECT contactgroup_id, contact_id, REPLACE(created , \' \', \'!!!\') FROM ' +
            self.imscpData[
                'imysqldatabase'] + '_roundcube.contactgroupmembers WHERE contactgroup_id = \'' + rContactGroupId + '\'"')
        i = 0
        dataLine = ''

        for line in stdout:
            # dataLine = re.sub("^\s+|\s+$", "", line, flags=re.UNICODE)
            dataLine = re.sub(r"\s+", "|", line, flags=re.UNICODE)
            imscpRoundcubeContactGroup2ContactData = dataLine.split("|")
            imscpRoundcubeContactGroup2ContactData[0].strip()
            imscpRoundcubeContactGroup2ContactData[1].strip()
            imscpRoundcubeContactGroup2ContactData[2].strip()

            imscpRoundcubeContactGroup2ContactData[2] = re.sub(r"!!!", " ", imscpRoundcubeContactGroup2ContactData[2],
                                                               flags=re.UNICODE)
            self.imscpRoundcubeContact2Contactgroup[str(i) + '-g-' + imscpRoundcubeContactGroup2ContactData[0] + '-c-' +
                                                    imscpRoundcubeContactGroup2ContactData[1]] = {}

            self.imscpRoundcubeContact2Contactgroup[str(i) + '-g-' + imscpRoundcubeContactGroup2ContactData[0] + '-c-' +
                                                    imscpRoundcubeContactGroup2ContactData[1]]['rContactGroupId'] = \
                imscpRoundcubeContactGroup2ContactData[0]
            self.imscpRoundcubeContact2Contactgroup[str(i) + '-g-' + imscpRoundcubeContactGroup2ContactData[0] + '-c-' +
                                                    imscpRoundcubeContactGroup2ContactData[1]]['rContactId'] = \
                imscpRoundcubeContactGroup2ContactData[1]
            self.imscpRoundcubeContact2Contactgroup[str(i) + '-g-' + imscpRoundcubeContactGroup2ContactData[0] + '-c-' +
                                                    imscpRoundcubeContactGroup2ContactData[1]]['rCreated'] = \
            imscpRoundcubeContactGroup2ContactData[2]

            _global_config.write_log(
                '======================= End data for roundcube contact groups to contact =======================\n\n\n')

            i += 1

    def imscpDataComplete(self):
        if not self.complete:
            return False
        else:
            return True
