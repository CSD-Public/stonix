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
Created on May 22, 2013

Enable logging for all attempted access and ftp commands,
restrict the set of users allowed to access ftp and set the default umask for
ftp users.

@author: bemalmbe
@change: 04/21/2014 dkennel Updated CI invocation, removed bug where second
copy of Environment was instantiated, fixed bug where CI was not referenced in
the Fix method.
@change: 2014/08/26 Multiple bugs on RHEL 7 fixed.
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/04/26 ekkehard Results Formatting
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..CommandHelper import CommandHelper
from ..stonixutilityfunctions import iterate


class SecureFTP(Rule):
    '''
    Enable logging for all attempted access and ftp commands, restrict the set
of users allowed to access ftp and set the default umask for ftp users.
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
        self.rulenumber = 32
        self.rulename = 'SecureFTP'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.detailedresults = 'The SecureFTP rule has not yet been run'
        self.compliant = True
        self.guidance = ['CIS', 'CCE 4678-9', 'CCE 4695-3', 'CCE 4510-4',
                         'CCE 4157-4', 'CCE 4677-1', 'CCE 4179-8',
                         'CCE 4589-8', 'CCE 4113-7', 'CCE 4739-9',
                         'CCE 4135-0', 'CCE 3768-9', 'CCE 3782-0',
                         'CCE 4347-1', 'CCE 4497-4', 'CCE 4834-8',
                         'CCE 4549-2', 'CCE 4554-2', 'CCE 4443-8']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}

        # init CI(s)
        datatype = 'bool'
        key = 'SECUREFTP'
        instructions = 'To prevent the secure configuration of FTPD, set ' + \
        'the value of SecureFTP to False'
        default = True
        self.SecureFTP = self.initCi(datatype, key, instructions, default)

        datatype2 = 'bool'
        key2 = 'ALLOWLOCALFTP'
        instructions2 = 'To allow local FTP account access, set the value of AllowLocalFTP to True. (Not Recommended. Use SSH or SCP instead)'
        default2 = False
        self.AllowLocalFTP = self.initCi(datatype2, key2, instructions2, default2)

        datatype3 = 'list'
        key3 = 'ALLOWUSERSLIST'
        instructions3 = '(Only use this if you set AllowLocalFTP to True) Enter single-space-delimited list of user account names to allow access to FTP.'
        default3 = []
        self.AllowUsersList = self.initCi(datatype3, key3, instructions3, default3)

        # set up class variables
        self.logoptions = ['xferlog_std_format=NO', 'log_ftp_protocol=YES']

        self.denyftpoptions = ['local_enable=NO', 'local_umask=0777',
                               'anonymous_enable=NO']

        self.allowftpoptions = ['userlist_enable=YES',
                                'userlist_file=/etc/vsftp.ftpusers',
                                'userlist_deny=NO', 'local_umask=0022',
                                'local_enable=YES', 'write_enable=YES']

        self.conffile = '/etc/vsftpd/vsftpd.conf'
        self.conffilelocations = ['/etc/vsftpd.conf', '/etc/vsftpd/vsftpd.conf']
        for location in self.conffilelocations:
            if os.path.exists(location):
                self.conffile = location

        self.packages = ['vsftpd']

        self.blockusers = ['root', 'daemon', 'bin', 'sys', 'adm', 'lp', 'uucp',
                           'nuucp', 'smmsp', 'listen', 'nobody', 'noaccess',
                           'nobody4', 'gdm', 'webservd']

        self.usersfile = '/etc/vsftpd/ftpusers'
        self.usersfilelocations = ['/etc/vsftpd/vsftpd.ftpusers',
                                   '/etc/vsftpd.ftpusers',
                                   '/etc/vsftpd/ftpusers', '/etc/ftpusers']
        for location in self.usersfilelocations:
            if os.path.exists(location):
                self.usersfile = location

###############################################################################
    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return bool
        @author bemalmbe
        '''

        # defaults
        self.detailedresults = ''
        self.distro = ''
        self.ftpdinstalled = False
        self.allowftpusers = self.AllowUsersList.getcurrvalue()

        try:

            # init helper objects
            self.cmhelper = CommandHelper(self.logger)

            # run report functions
            if self.environ.getosfamily() == 'darwin':
                self.compliant = self.reportMac()
            else:
                # only init the pkghelper object if the os is not darwin-based
                self.pkghelper = Pkghelper(self.logger, self.environ)
                for package in self.packages:
                    if self.pkghelper.check(package):
                        self.ftpdinstalled = True
                        self.distro = package
                if not self.ftpdinstalled:
                    self.detailedresults += '\nftpd not installed. nothing to do.'
                    self.compliant = True
                    return self.compliant
                self.compliant = self.reportLinux()

        except IOError:
            self.detailedresults += '\n' + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################
    def reportMac(self):
        '''
        method to determine compliance status of only mac os x systems

        @return: bool
        @author: bemalmbe
        '''

        # defaults
        compliant = True
        macftpdconffile = '/etc/ftpd.conf'
        macftpdconffilelocations = ['/etc/ftpd.conf', '/private/etc/ftpd.conf']
        for location in macftpdconffilelocations:
            if os.path.exists(location):
                macftpdconffile = location

        try:

            macoptionslist = ['umask all 077', 'upload all off',
                              'modify all off']

            if os.path.exists(macftpdconffile):
                f = open(macftpdconffile, 'r')
                contentlines = f.readlines()
                f.close()

                for option in macoptionslist:
                    if not self.searchList(option, contentlines):
                        compliant = False
                if not compliant:
                    self.detailedresults += '\nFTPD configuration file is missing a required configuration line.'
            else:
                compliant = False
                self.detailedresults += '\nFTPD configuration file is missing.'

            # check if the ftp daemon is configured to be disabled
            self.cmhelper.executeCommand('defaults read /System/Library/LaunchDaemons/ftp.plist Disabled')
            if not self.cmhelper.findInOutput('1'):
                compliant = False
                self.detailedresults += '\nFTPD is not disabled in ftp.plist.'

            # check if the ftp daemon is loaded/running
            self.cmhelper.executeCommand('launchctl list | grep ftp')
            output = self.cmhelper.getOutput()
            if 'com.apple.ftpd' in output:
                compliant = False
                self.detailedresults += '\nFTP daemon is currently running/loaded.'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise
        return compliant

###############################################################################
    def reportLinux(self):
        '''
        '''

        # defaults
        compliant = True

        try:

            # check if ftpd conf file exists
            if not os.path.exists(self.conffile):
                self.detailedresults += '\nFTPD installed, but unable to locate configuration file.'
                compliant = False
            else:
                # check configuration directives in ftpd conf file
                if not self.checkFTPDConfig():
                    self.detailedresults += '\nFTPD configuration is incorrect.'
                    compliant = False
            # check if ftp users file exists
            if not os.path.exists(self.usersfile):
                self.detailedresults += '\nFTPD installed, but unable to locate users file.'
                compliant = False
            else:
                # check ftpd users file values
                if not self.checkFTPUsers():
                    self.detailedresults += '\nFTPD users file is missing users.'
                    compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise
        return compliant

###############################################################################
    def checkFTPDConfig(self):
        '''
        '''

        # defaults
        retval = True

        try:

            f = open(self.conffile, 'r')
            contentlines = f.readlines()
            f.close()

            # check for log options
            for option in self.logoptions:
                if not self.searchList(option, contentlines):
                    retval = False

            # if allow local ftp is set, check to make sure allow ftp options are
            # set and that deny ftp options are not set
            if self.AllowLocalFTP.getcurrvalue():

                for option in self.allowftpoptions:
                    if not self.searchList(option, contentlines):
                        retval = False
                for option in self.denyftpoptions:
                    if self.searchList(option, contentlines):
                        retval = False
            # if allow local ftp is not set, check that the reverse is true
            else:

                for option in self.denyftpoptions:
                    if not self.searchList(option, contentlines):
                        retval = False
                for option in self.allowftpoptions:
                    if self.searchList(option, contentlines):
                        retval = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise
        return retval

###############################################################################
    def checkFTPUsers(self):
        '''
        '''

        # defaults
        retval = True

        f = open(self.usersfile, 'r')
        contentlines = f.readlines()
        f.close()

        if self.AllowLocalFTP.getcurrvalue():

            for user in self.AllowUsersList.getcurrvalue():
                if not self.searchList(user, contentlines):
                    retval = False
            for user in self.blockusers:
                if self.searchList(user, contentlines):
                    retval = False
        else:

            for user in self.blockusers:
                if not self.searchList(user, contentlines):
                    retval = False

        return retval

###############################################################################
    def fix(self):
        '''
        if the ftp configuration file does not contain the secure configuration
        options listed in self.confoptions, then add them to the file.
        self.rulesuccess will be updated if the rule does not succeed.

        @author bemalmbe
        '''

        # defaults
        self.detailedresults = ''
        self.iditerator = 0

        try:

            if self.SecureFTP.getcurrvalue():

                # disable ftpd in mac os x 10.9
                if self.environ.getosfamily() == 'darwin':
                    self.fixMac()
                else:
                    self.fixLinux()

            else:

                self.detailedresults += '\nSecureFTP not enabled. Nothing will be done.'

            if self.detailedresults:
                self.logger.log(LogPriority.INFO, self.detailedresults)

        except IOError:
            self.detailedresults += '\n' + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, ['SecureFTP.fix ',
                                               self.detailedresults])
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += '\n' + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, ['SecureFTP.fix ',
                                                self.detailedresults])
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################
    def fixLinux(self):
        '''
        '''

        try:

            self.configureFTPD()
            self.configureFTPUsers()

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise

###############################################################################
    def fixMac(self):
        '''
        '''

        macoptionslist = ['umask all 077',
                        'upload all off',
                        'modify all off']
        macftpdconffile = '/etc/ftpd.conf'

        contentlines = ['####### THIS SECTION ADDED BY STONIX #######\n']

        try:

            for option in macoptionslist:
                contentlines.append(option + '\n')

            f = open(macftpdconffile, 'w')
            f.writelines(contentlines)
            f.close()

            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype': 'creation',
                     'filepath': macftpdconffile}

            self.statechglogger.recordchgevent(myid, event)

            os.chmod(macftpdconffile, 0644)
            os.chown(macftpdconffile, 0, 0)

            undocmd = ''
            if os.path.exists('/System/Library/LaunchDaemons/ftp.plist'):
                f = open('/System/Library/LaunchDaemons/ftp.plist', 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('Disabled = 1;', line):
                        undocmd = 'defaults write /System/Library/LaunchDaemons/ftp.plist Disabled -bool true'
                    elif re.search('Disabled = 0;', line):
                        undocmd = 'defaults write /System/Library/LaunchDaemons/ftp.plist Disabled -bool false'

            if not undocmd:
                undocmd = 'defaults delete /System/Library/LaunchDaemons/ftp.plist Disabled'

            undocmd2 = ''
            self.cmhelper.executeCommand('launchctl list | grep ftp')
            if self.cmhelper.findInOutput('com.apple.ftpd'):
                undocmd2 = 'launchctl load -w /System/Library/LaunchDaemons/ftp.plist'

            try:

                self.cmhelper.executeCommand('defaults write /System/Library/LaunchDaemons/ftp.plist Disabled -bool true')

            except OSError:
                self.detailedresults += '\nfixmac() - One or more issued commands failed'
                undocmd = ''

            try:

                self.cmhelper.executeCommand('launchctl unload -w /System/Library/LaunchDaemons/ftp.plist')

            except OSError:
                self.detailedresults += '\nfixmac() - One or more issued commands failed'
                undocmd2 = ''

            if undocmd:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'commandstring',
                         'command': undocmd}

                self.statechglogger.recordchgevent(myid, event)

            if undocmd2:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'commandstring',
                         'command': undocmd2}

                self.statechglogger.recordchgevent(myid, event)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise

###############################################################################
    def configureFTPD(self):
        '''
        '''

        # defaults
        tmpfile = self.conffile + '.stonixtmp'

        try:

            if not os.path.exists(self.conffile):
                f = open(self.conffile, 'w')
                f.close()

            f = open(self.conffile, 'r')
            contentlines = f.readlines()
            f.close()

            for option in self.logoptions:
                if not self.searchList(option, contentlines):
                    contentlines.append('\n' + option)

            if self.AllowLocalFTP.getcurrvalue():

                for line in contentlines:
                    sline = line.strip()
                    if self.searchList(sline, self.denyftpoptions):
                        contentlines = [c.replace(line, '\n') for c in contentlines]

                for option in self.allowftpoptions:
                    if not self.searchList(option, contentlines):
                        contentlines.append('\n' + option)

            else:

                for line in contentlines:
                    sline = line.strip()
                    if self.searchList(sline, self.allowftpoptions):
                        contentlines = [c.replace(line, '\n') for c in contentlines]

                for option in self.denyftpoptions:
                    if not self.searchList(option, contentlines):
                        contentlines.append('\n' + option)

            tf = open(tmpfile, 'w')
            tf.writelines(contentlines)
            tf.close()

            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)

            event = {'eventtype': 'conf',
                     'filepath': self.conffile}

            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(tmpfile, self.conffile, myid)

            os.rename(tmpfile, self.conffile)
            os.chmod(self.conffile, 0600)
            os.chown(self.conffile, 0, 0)

        except Exception:
            raise

###############################################################################
    def configureFTPUsers(self):
        '''
        '''

        # defaults
        tmpusersfile = self.usersfile + '.stonixtmp'

        if not os.path.exists(self.usersfile):
            f = open(self.usersfile, 'w')
            f.close()

        f = open(self.usersfile, 'r')
        contentlines = f.readlines()
        f.close()

        if self.AllowLocalFTP.getcurrvalue():

            for line in contentlines:
                sline = line.strip()
                if self.searchList(sline, self.blockusers):
                    contentlines = [c.replace(line, '\n') for c in contentlines]

            for user in self.AllowUsersList.getcurrvalue():
                if not self.searchList(user, contentlines):
                    contentlines.append('\n' + user)

        else:

            for line in contentlines:
                sline = line.strip()
                if  not self.searchList(sline, self.blockusers):
                    contentlines = [c.replace(line, '\n') for c in contentlines]

            for user in self.blockusers:
                if not self.searchList(user, contentlines):
                    contentlines.append('\n' + user)

        tf = open(tmpusersfile, 'w')
        tf.writelines(contentlines)
        tf.close()

        self.iditerator += 1
        myid = iterate(self.iditerator, self.rulenumber)
        event = {'eventtype': 'conf',
                 'filepath': self.conffile}

        self.statechglogger.recordchgevent(myid, event)
        self.statechglogger.recordfilechange(tmpusersfile, self.usersfile, myid)

        os.rename(tmpusersfile, self.usersfile)
        os.chmod(self.usersfile, 0600)
        os.chown(self.usersfile, 0, 0)

###############################################################################
    def searchList(self, searchterm, searchlist):
        '''
        '''

        # defaults
        retval = False

        try:

            for line in searchlist:
                if not re.search('^#', line):
                    if re.search(re.escape(searchterm), line):
                        retval = True

        except Exception:
            raise

        return retval
