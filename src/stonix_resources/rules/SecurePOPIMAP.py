###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
# produced under U.S. Government contract DE-AC52-06NA25396 for Los Alamos    #
# National Laboratory (LANL), which is operated by Los Alamos National        #
# Security, LLC for the U.S. Department of Energy. The U.S. Government has    #
# rights to use, reproduce, and distribute this software.  NEITHER THE        #
# GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY, LLC MAKES ANY WARRANTY,        #
# EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.  #
# If software is modified to produce derivative works, such modified software #
# should be clearly marked, so as not to confuse it with the version          #
# available from LANL.                                                        #
#                                                                             #
# Additionally, this program is free software; you can redistribute it and/or #
# modify it under the terms of the GNU General Public License as published by #
# the Free Software Foundation; either version 2 of the License, or (at your  #
# option) any later version. Accordingly, this program is distributed in the  #
# hope that it will be useful, but WITHOUT ANY WARRANTY; without even the     #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    #
# See the GNU General Public License for more details.                        #
#                                                                             #
###############################################################################
'''
Created on Nov 9, 2015

@author: Breen Malmberg
'''

from __future__ import absolute_import

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..ServiceHelper import ServiceHelper
from ..CommandHelper import CommandHelper
from ..stonixutilityfunctions import iterate

import os
import re
import traceback


class SecurePOPIMAP(Rule):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 141
        self.rulename = 'SecurePOPIMAP'
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.applicable = {'type': 'black',
                           'family': ['darwin']}
        self.guidance = ['NSA(3.17)', 'cce-4384-4', '3887-7', '4530-2', '4547-6', '4552-6', '4371-1', '4410-7']

        data1 = 'bool'
        key1 = 'DISABLEPOPIMAP'
        instructions1 = 'To prevent POP/IMAP services from being disabled entirely, set the value of DisablePOPIMAP to False.'
        default1 = True
        self.disableci = self.initCi(data1, key1, instructions1, default1)

        data2 = 'bool'
        key2 = 'SECUREPOPIMAP'
        instructions2 = 'To securely configure POP/IMAP services, set the value of SecurePOPIMAP to True.'
        default2 = False
        self.secureci = self.initCi(data2, key2, instructions2, default2)

        data3 = 'string'
        key3 = 'RequireProtocols'
        instructions3 = 'If this system will be operating as a mail server, fill in the required/used protocols below. Please use a space-delimited list. Valid entries are limited to: imap, imaps, pop3, pop3s'
        default3 = ''
        self.reqprotocols = self.initCi(data3, key3, instructions3, default3)

        self.localization()

    def localization(self):
        '''
        determine which type of OS we are running on and set up class variables accordingly

        @return: void
        @author: Breen Malmberg
        '''

        self.initobjs()

        self.setcommon()

        if self.pkgh.manager not in ['apt-get', 'yum', 'zypper', 'dnf']:
            self.logger.log(LogPriority.DEBUG, "Could not identify OS type or OS not supported!")

        if self.pkgh.manager == 'apt-get':
            self.setdebian()
        if self.pkgh.manager == 'yum':
            self.setredhat()
        if self.pkgh.manager == 'dnf':
            self.setredhat()
        if self.pkgh.manager == 'zypper':
            self.setsuse()

        pass

    def initobjs(self):
        '''
        initialize objects needed/used by other methods within this class

        @return: void
        @author: Breen Malmberg
        '''

        try:

            # if you add class variables here, be sure to also add
            # checks for them, in the checkinitobjs() method
            self.pkgh = Pkghelper(self.logger, self.environ)
            self.svch = ServiceHelper(self.environ, self.logger)
            self.cmdh = CommandHelper(self.logger)
            self.debian = False
            self.suse = False
            self.redhat = False
            self.pkgdict = {}
            self.confpathdict = {}
            self.servicename = ''
            self.osdetected = False

        except Exception:
            raise

    def setcommon(self):
        '''
        set variables which are common to all platforms
        @return: void
        @author: Breen Malmberg
        '''

        self.detailedresults = ""

        self.reqprots = ""

        self.protocollist = ['imap', 'imaps', 'pop3', 'pop3s']

    def setdebian(self):
        '''
        set debian specific variables
        @return: void
        @author: Breen Malmberg
        '''

        self.debian = True
        self.osdetected = True
        self.pkgdict = {'dovecot-core': False,
                        'dovecot-pop3d': False,
                        'dovecot-imapd': False}

        # the following dictionary is of the format:
        # {configfilepath1: {partialmatch1: fullreplacement1,
        #                    partialmatch2: fullreplacement2},
        # configfilepath2: {partialmatch1: fullreplacement1,
        #                    partialmatch2: fullreplacement2}
        # }
        self.confpathdict = {'/etc/dovecot/dovecot.conf': {'protocols =': 'protocols = ' + str(self.reqprots) + '\n',
                                       'disable_plaintext_auth =': 'disable_plaintext_auth = yes\n',
                                       'login_process_per_connection =': 'login_process_per_connection = yes\n',
                                       'mail_drop_priv_before_exec =': 'mail_drop_priv_before_exec = yes\n',
                                       'login_trusted_networks =': '#login_trusted_networks =\n'}}
        self.servicename = 'dovecot'

    def setredhat(self):
        '''
        set redhat sepcific variables
        @return: void
        @author: Breen Malmberg
        '''

        self.redhat = True
        self.osdetected = True
        self.pkgdict = {'dovecot': False}

        # the following dictionary is of the format:
        # {configfilepath1: {partialmatch1: fullreplacement1,
        #                    partialmatch2: fullreplacement2},
        # configfilepath2: {partialmatch1: fullreplacement1,
        #                    partialmatch2: fullreplacement2}
        # }
        self.confpathdict = {'/etc/dovecot/dovecot.conf': {'protocols =': 'protocols = ' + str(self.reqprots) + '\n',
                                       'disable_plaintext_auth =': 'disable_plaintext_auth = yes\n',
                                       'login_process_per_connection =': 'login_process_per_connection = yes\n',
                                       'mail_drop_priv_before_exec =': 'mail_drop_priv_before_exec = yes\n',
                                       'login_trusted_networks =': '#login_trusted_networks =\n'}}
        self.servicename = 'dovecot'

    def setsuse(self):
        '''
        set suse specific variables
        @return: void
        @author: Breen Malmberg
        '''

        self.suse = True
        self.osdetected = True
        self.pkgdict = {'dovecot': False}

        # the following dictionary is of the format:
        # {configfilepath1: {partialmatch1: fullreplacement1,
        #                    partialmatch2: fullreplacement2},
        # configfilepath2: {partialmatch1: fullreplacement1,
        #                    partialmatch2: fullreplacement2}
        # }
        self.confpathdict = {'/etc/dovecot/dovecot.conf': {'protocols =': 'protocols = ' + str(self.reqprots) + '\n',
                                       'disable_plaintext_auth =': 'disable_plaintext_auth = yes\n',
                                       'login_process_per_connection =': 'login_process_per_connection = yes\n',
                                       'mail_drop_priv_before_exec =': 'mail_drop_priv_before_exec = yes\n',
                                       'login_trusted_networks =': '#login_trusted_networks =\n'}}
        self.servicename = 'dovecot'

    def getFileContents(self, filepath):
        '''
        '''

        filecontents = []

        try:

            if not isinstance(filepath, basestring):
                self.logger.log(LogPriority.DEBUG, "Parameter filepath must be of type: basestring")
            if not filepath:
                self.logger.log(LogPriority.DEBUG, "Parameter filepath must not be blank")

            if not os.path.exists(filepath):
                self.logger.log(LogPriority.DEBUG, "Specified filepath not found")
            else:
                f = open(filepath, 'r')
                filecontents = f.readlines()
                f.close()

            if not filecontents:
                self.logger.log(LogPriority.DEBUG, "Specified file had no contents")

        except Exception:
            raise
        return filecontents

    def searchContents(self, regex, contents):
        '''
        '''

        retval = False

        try:

            if not isinstance(regex, basestring):
                self.logger.log(LogPriority.DEBUG, "Parameter regex must be of type: basestring")
                retval = False
                return retval
            if not isinstance(contents, list):
                self.logger.log(LogPriority.DEBUG, "Parameter contents must be of type: list")
                retval = False
                return retval

            if not regex:
                self.logger.log(LogPriority.DEBUG, "regex must not be blank")
                retval = False
                return retval
            if not contents:
                self.logger.log(LogPriority.DEBUG, "contents must not be blank")
                retval = False
                return retval

            for line in contents:
                if re.search(regex, line):
                    retval = True

        except Exception:
            raise
        return retval

    def fixContents(self, fixdict, filepath, contents):
        '''
        '''

        retval = True

        if not isinstance(fixdict, dict):
            self.logger.log(LogPriority.DEBUG, "Parameter fixdict must be of type: dict")
            retval = False
            return retval
        if not isinstance(filepath, basestring):
            self.logger.log(LogPriority.DEBUG, "Parameter filepath must be of type: basestring")
            retval = False
            return retval
        if not isinstance(contents, list):
            self.logger.log(LogPriority.DEBUG, "Parameter contents must be of type: list")
            retval = False
            return retval

        if not fixdict:
            self.logger.log(LogPriority.DEBUG, "Parameter fixdict must not be empty")
            retval = False
            return retval
        if not filepath:
            self.logger.log(LogPriority.DEBUG, "Parameter filepath must not be blank")
            retval = False
            return retval
        if not contents:
            self.logger.log(LogPriority.DEBUG, "Parameter contents must not be empty")
            retval = False
            return retval

        contentdict = {}
        for item in fixdict:
            contentdict[item] = False

        tempfilepath = filepath + '.stonixtmp'

        for line in contents:
            for partialmatch in fixdict:
                if re.search(partialmatch, line):
                    contents = [c.replace(line, fixdict[partialmatch]) for c in contents]
                    contentdict[partialmatch] = True

        for item in contentdict:
            if not contentdict[item]:
                contents.append('\n' + fixdict[item])

        tf = open(tempfilepath, 'w')
        tf.writelines(contents)
        tf.close()

        event = {'eventtype': 'conf',
                 'filepath': filepath}
        myid = iterate(self.iditerator, self.rulenumber)

        self.statechglogger.recordchgevent(myid, event)
        self.statechglogger.recordfilechange(filepath, tempfilepath, myid)

        os.rename(tempfilepath, filepath)

    def report(self):
        '''
        return true if all check actions report compliant
        return false if one or more check actions reports not compliant

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.compliant = True
        self.detailedresults = ''
        self.logger.log(LogPriority.DEBUG, "Entering SecurePOPIMAP.report()...")

        try:

            self.reqprots = self.reqprotocols.getcurrvalue()

            if self.suse:
                self.setsuse()
            if self.debian:
                self.setdebian()
            if self.redhat:
                self.setredhat()

            self.logger.log(LogPriority.DEBUG, "Checking init objects...")
            if not self.checkinitobjs():
                self.logger.log(LogPriority.DEBUG, 'One or more class properties were not initialized or set correctly.')
                self.rulesuccess = False
                self.compliant = False
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant
            self.logger.log(LogPriority.DEBUG, "Finished checking init objects. all were OK")

            # disable stuff
            if self.disableci.getcurrvalue():
                self.logger.log(LogPriority.DEBUG, "The disable POP/IMAP option is set. Checking if POP/IMAP is disabled...")
                self.logger.log(LogPriority.DEBUG, "Checking for running service...")
                if not self.checksvc():
                    self.compliant = False
                    self.detailedresults += "\nRule is not compliant because: The " + str(self.servicename) + " service is either running or enabled."
                self.logger.log(LogPriority.DEBUG, "Service check finished.")

                self.logger.log(LogPriority.DEBUG, "Checking packages...")
                if not self.checkpkgs(False):
                    self.compliant = False
                    self.detailedresults += "\nRule is not compliant because one or more of the packages is still installed."
                self.logger.log(LogPriority.DEBUG, "Package check finished.")

            # secure stuff
            elif self.secureci.getcurrvalue():
                self.logger.log(LogPriority.DEBUG, "The secure POP/IMAP option is set. Checking if POP/IMAP is secured...")
                if not self.reqprots:
                    self.detailedresults += '\nRequired protocols were not specified. Cannot securely configure POP/IMAP without them.'
                    self.compliant = False
                slist = self.reqprots.split()
                if slist:
                    for prot in slist:
                        if prot.strip() != '' and prot.strip() not in self.protocollist:
                            self.detailedresults += "\nRule is not compliant because: The specified protocol: " + str(prot) + " is not a valid protocol."
                            self.compliant = False
                else:
                    self.detailedresults += '\nUnable to read protocol list. Please use a space-delimited list when specifying your required protocols.'
                self.logger.log(LogPriority.DEBUG, "The secure POP/IMAP option is set. Checking if POP/IMAP is secured...")
                if self.checkpkgs(True):
                    self.logger.log(LogPriority.DEBUG, "Required packages are installed.")
                    self.logger.log(LogPriority.DEBUG, " Checking file configuration...")
                    if not self.checkconfig():
                        self.compliant = False
                    self.logger.log(LogPriority.DEBUG, "File configuration check finished.")
                else:
                    self.logger.log(LogPriority.DEBUG, "One or more required packages are not installed.")
                    self.compliant = False
                    self.detailedresults += "\nRule is not compliant because one or more of the required packages are not installed."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def checkinitobjs(self):
        '''
        validate each class property and object to be used in this class before it is used
        return True if each object is properly assigned/initialized
        return False if not

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            if not self.pkgh:
                retval = False
                self.logger.log(LogPriority.DEBUG, "The package helper object was not initialized correctly")
            if not self.svch:
                retval = False
                self.logger.log(LogPriority.DEBUG, "The service helper object was not initialized correctly")
            if not self.cmdh:
                retval = False
                self.logger.log(LogPriority.DEBUG, "The command helper object was not initialized correctly")
            if not self.osdetected:
                retval = False
                self.logger.log(LogPriority.DEBUG, "Unable to determine OS type or package manager")
            if not self.servicename:
                retval = False
                self.logger.log(LogPriority.DEBUG, "servicename variable was not set")
            if not self.pkgdict:
                retval = False
                self.logger.log(LogPriority.DEBUG, "pgkdict variable was not set")
            if not self.confpathdict:
                retval = False
                self.logger.log(LogPriority.DEBUG, "confpathdict variable was not set")

        except AttributeError:
            retval = False
            self.logger.log(LogPriority.DEBUG, "One or more of the class variables are undefined")
            return retval
        return retval

    def checksvc(self):
        '''
        check to see if the dovecot service is enabled or running
        return False if it is either running or enabled
        if the service is neither running nor enabled, return True

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        enabled = False
        running = False

        try:

            if self.svch.auditservice(self.servicename):
                enabled = True
                self.detailedresults += '\nThe ' + str(self.servicename) + ' service is still enabled'
            if enabled:
                self.detailedresults += "\nThere are service(s) which need to be disabled"
            if self.svch.isrunning(self.servicename):
                running = False
                self.detailedresults += '\nThe ' + str(self.servicename) + ' service is still running'
            if running:
                self.detailedresults += "\nThere are service(s) which need to be stopped"

            if enabled | running:
                retval = False

        except Exception:
            raise
        return retval

    def checkpkgs(self, desired):
        '''
        check compliance of packages portion of rule

        if desired, check if all required packages are installed:
            True if yes, False if no

        if not desired, check if any packages are installed:
            True if no, False if yes

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            if not desired:
                for pkg in self.pkgdict:
                    if self.pkgh.check(pkg):
                        self.pkgdict[pkg] = True
                        retval = False
            else:
                for pkg in self.pkgdict:
                    if not self.pkgh.check(pkg):
                        self.pkgdict[pkg] = False
                        retval = False

        except Exception:
            raise
        return retval

    def checkconfig(self):
        '''
        verify configuration state of file(s)

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        contents = []

        try:

            for path in self.confpathdict:
                contents = self.getFileContents(path)
                if contents:
                    for confitem in self.confpathdict[path]:
                        if not self.searchContents(str(self.confpathdict[path][confitem]), contents):
                            retval = False
                            self.detailedresults += "\nRequired configuration option: " + str(self.confpathdict[path][confitem]) + " was not found in file: " + str(path)

                else:
                    self.logger.log(LogPriority.DEBUG, "Unable to check contents of file: " + str(path))

                if retval:
                    self.detailedresults += "\nAll required configuration options have been found in file: " + str(path)

            if retval:
                self.detailedresults += "\nAll required configuration options have been found in all required configuration files"

        except Exception:
            raise
        return retval

    def fix(self):
        '''
        run each fix action and get the success results of each one
        return True if all fix actions succeeded
        return False if not

        @return: fixsuccess
        @rtype: bool
        @author: Breen Malmberg
        '''

        fixsuccess = True
        self.detailedresults = ''
        self.iditerator = 0

        try:

            if self.disableci.getcurrvalue():
                self.detailedresults += '\nYou have selected the DisablePOPIMAP option. It will now be disabled/removed from this system.'
                if not self.turnoffsvc():
                    fixsuccess = False
                if not self.removePackages():
                    fixsuccess = False
            elif self.secureci.getcurrvalue():
                self.detailedresults += '\nYou have selected the SecurePOPIMAP option. It will now be installed (if it is not already installed) and then securely configured.'
                if not self.installPackages():
                    fixsuccess = False
                if not self.configurefiles():
                    fixsuccess = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixsuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixsuccess

    def turnoffsvc(self):
        '''
        disable dovecot service if it is enabled
        return True if dovecot service was successfully disabled or is not enabled
        return False if otherwise

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Attempting to disable service: " + str(self.servicename))

        retval = True

        try:

            self.svch.disableservice(self.servicename)

            if self.svch.auditservice(self.servicename):
                retval = False
                self.logger.log(LogPriority.DEBUG, "Service is still enabled after executing disableservice!")

            if self.svch.isrunning(self.servicename):
                retval = False
                self.logger.log(LogPriority.DEBUG, "Service is still running after executing disableservice!")

            if retval:
                self.logger.log(LogPriority.DEBUG, "Successfully disabled service: " + str(self.servicename))
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to disable service: " + str(self.servicename))

        except Exception:
            raise
        return retval

    def removePackages(self):
        '''
        Remove all packages in self.pkgdict, which are currently installed
        return True if all installed packages were successfully removed
        return False if not

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            for pkg in self.pkgdict:
                if self.pkgdict[pkg]:
                    if not self.pkgh.remove(pkg):
                        retval = False
                        self.detailedresults += '\nFailed to remove package: ' + str(pkg)
                    else:
                        self.pkgdict[pkg] = False

            if not retval:
                self.logger.log(LogPriority.DEBUG, "Failed to remove packages")
            else:
                self.logger.log(LogPriority.DEBUG, "Successfully removed all packages")

        except Exception:
            raise
        return retval

    def configurefiles(self):
        '''
        set the correct configuration options within the dovecot configuration file(s)

        @return: void
        @author: Breen Malmberg
        '''

        try:

            for path in self.confpathdict:
                contents = self.getFileContents(path)
                self.fixContents(self.confpathdict[path], path, contents)

        except Exception:
            raise

    def installPackages(self):
        '''
        install all necessary dovecot packages

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        self.logger.log(LogPriority.DEBUG, "Attempting to install all necessary packages...")

        try:

            for pkg in self.pkgdict:
                if not self.pkgdict[pkg]:
                    if not self.pkgh.install(pkg):
                        retval = False
                        self.detailedresults += '\nFailed to install package ' + str(pkg)
                        self.logger.log(LogPriority.DEBUG, "Failed to install package: " + str(pkg))

            if not retval:
                self.logger.log(LogPriority.DEBUG, "Failed to install one or more required packages. Please check your connection to the network and ensure that your package repositories are correctly configured.")
            else:
                self.logger.log(LogPriority.DEBUG, "Successfully installed all required packages")

        except Exception:
            raise
        return retval
