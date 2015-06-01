'''
###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
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

Created on Mar 2, 2015

This rule will check the default owners and access permissions for all system
packages and their associated files as well as the file contents.

@author: bemalmbe
'''

from __future__ import absolute_import

import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class VerifySysFilePerms(Rule):
    '''
    This rule will check the default owners and access permissions for all
    system packages and their associated files as well as the file contents.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 227
        self.rulename = 'VerifySysFilePerms'
        self.compliant = True
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = True
        self.helptext = 'This rule will check the default owners and ' + \
        'access permissions for all system packages and their associated ' + \
        'files as well as the file contents.'
        self.guidance = ['']

        datatype = 'bool'
        key = 'VerifySysFilePerms'
        instructions = 'To disable this rule, set the value of ' + \
        'VerifySysFilePerms to False'
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.isApplicableWhiteList = [{"0": "darwin",
                                       "1": "Mac OS X",
                                       "2": ["10.9", "10.10"]}]
        self.isApplicableBlackList = [{"0": "darwin",
                                       "1": "Mac OS X",
                                       "2": ["10.0", "10.1", "10.2", "10.3",
                                             "10.4", "10.5", "10.6", "10.7",
                                             "10.8"]}]
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.10']}}

        self.findsysvol = '/usr/sbin/bless --info --getBoot'
        self.hasrun = False

    def report(self):
        '''

        @return: bool
        @author: bemalmbe
        '''

        # defaults
        self.detailedresults = ""
        self.compliant = True
        self.cmdhelper = CommandHelper(self.logger)
        self.sysvol = ''

        try:

            self.cmdhelper.executeCommand(self.findsysvol)
            errout = self.cmdhelper.getErrorString()
            if not errout:
                self.sysvol = self.cmdhelper.getOutputString()
            wrongperms = []

            if errout:
                if re.search('Can\'t access "efi-boot-device" NVRAM variable', errout):
                    self.detailedresults += '\nIt appears this system was not properly blessed. This requires a manual fix.'
                    self.compliant = False
                self.compliant = False
                self.detailedresults += '\nThere was an error retrieving the boot partition'

            # check for the presence of required utilities on the system
            # if either is not found, log and return false
            if not os.path.exists('/usr/sbin/bless'):
                self.detailedresults += '\nA required utility, bless, could not be found. Aborting...'
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                self.compliant = False
                return self.compliant
            elif not os.path.exists('/usr/sbin/diskutil'):
                self.detailedresults += '\nA required utility, diskutil, could not be found. Aborting...'
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                self.compliant = False
                return self.compliant

            # run verify perms command and get output
            self.cmdhelper.executeCommand('/usr/sbin/diskutil verifyPermissions ' + str(self.sysvol))
            outputlist = self.cmdhelper.getOutput()
            errout = self.cmdhelper.getErrorString()
            if errout:
                self.compliant = False
                self.detailedresults += '\nThere was an error verifying the system file permissions'
            for line in outputlist:
                if re.search('differs on', line) or re.search('differ on', line):
                    wrongperms.append(line)

            # if any incorrect permissions or ownership found, return false
            if wrongperms:
                self.compliant = False
                if self.hasrun:
                    self.detailedresults += '\nThe disk utility for Mac OS X has been run, but there are files which were unable to be reverted to their intended permissions state(s). This is due to an issue with a mismatch in the package receipts database originally configured for this system, as compared to the current versions of the files on this system. This sometimes occurs when a system has been upgraded from a long-deprecated version of Mac OS to a more current one. This is an issue which Apple needs to fix before this rule can succeed on such systems.'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''

        @return: bool
        @author: bemalmbe
        '''

        # defaults
        self.detailedresults = ""
        success = True
        self.iditerator = 0

        try:

            if not self.sysvol:
                self.detailedresults += '\nNo boot disk could be found! Aborting...'
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                success = False
                return success

            self.cmdhelper.executeCommand('/usr/sbin/diskutil repairPermissions ' + str(self.sysvol))
            errout = self.cmdhelper.getErrorString()
            if errout and not re.search('SUID file', errout):
                success = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        self.hasrun = True
        return success

    def undo(self):
        '''

        @author: bemalmbe
        '''

        self.detailedresults += '\nThere is no undo function for this rule'
        self.logger.log(LogPriority.INFO, self.detailedresults)
