###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was  #
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
Created on Mar 2, 2015

This rule will check the default owners and access permissions for all system
packages and their associated files as well as the file contents.

@author: Breen Malmberg
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
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
        self.sethelptext()
        self.guidance = ['']

        datatype = 'bool'
        key = 'VERIFYSYSFILEPERMS'
        instructions = 'To disable this rule, set the value of ' + \
        'VerifySysFilePerms to False'
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        # this rule does not apply to sierra because mac completely removed the
        # ability to check and fix disk permissions, via command line,
        # in os x 10.12 and later
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.11', 'r', '10.11.10']}}

        self.findsysvol = '/usr/sbin/bless --info --getBoot'
        self.hasrun = False

    def report(self):
        '''

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        '''

        # defaults
        self.detailedresults = ""
        self.compliant = True
        self.cmdhelper = CommandHelper(self.logger)
        self.sysvol = ''

        try:

            if re.search("10.11", self.environ.getosver()):
                self.compliant = self.reportCapitan()
            else:

                if not os.path.exists('/usr/sbin/bless'):
                    self.detailedresults += '\nA required utility, bless, could not be found. Aborting...'
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    self.compliant = False
                    self.formatDetailedResults("report", self.compliant, self.detailedresults)
                    return self.compliant

                self.cmdhelper.executeCommand(self.findsysvol)
                retcode = self.cmdhelper.getReturnCode()
                if retcode == 0:
                    self.sysvol = self.cmdhelper.getOutputString()
                wrongperms = []

                if retcode != 0:
                    errout = self.cmdhelper.getErrorString()
                    if re.search('Can\'t access "efi-boot-device" NVRAM variable', errout):
                        self.detailedresults += '\nIt appears this system was not properly blessed. This requires a manual fix.'
                    self.compliant = False
                    self.detailedresults += '\nThere was an error retrieving the boot partition'
                    self.formatDetailedResults("report", self.compliant, self.detailedresults)
                    return self.compliant

                # check for the presence of required utilities on the system
                # if either is not found, log and return false
                if not os.path.exists('/usr/sbin/diskutil'):
                    self.detailedresults += '\nA required utility, diskutil, could not be found. Aborting...'
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    self.compliant = False
                    self.formatDetailedResults("report", self.compliant, self.detailedresults)
                    return self.compliant

                # run verify perms command and get output
                self.cmdhelper.executeCommand('/usr/sbin/diskutil verifyPermissions ' + str(self.sysvol))
                outputlist = self.cmdhelper.getOutput()
                retcode = self.cmdhelper.getReturnCode()
                errout = self.cmdhelper.getErrorString()
                if retcode != 0:
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
                    else:
                        self.detailedresults += '\nFiles with incorrect permissions and/or ownership have been found.'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportCapitan(self):
        '''
        run report actions specific to mac os x el capitan

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        reportcommand = '/usr/libexec/repair_packages --verify --standard-pkgs'

        try:

            if not os.path.exists('/usr/libexec/repair_packages'):
                retval = False
                self.detailedresults += '\nA required utility /usr/libexec/repair_packages was not found. System File verification was not performed.'
                return retval
            self.cmdhelper.executeCommand(reportcommand)
            errout = self.cmdhelper.getErrorString()
            retcode = self.cmdhelper.getReturnCode()
            output = self.cmdhelper.getOutput()
            if retcode != 0:
                retval = False
                self.detailedresults += '\nThere was an error running command repair_packages --verify'
                self.logger.log(LogPriority.DEBUG, errout)
            if output:
                for line in output:
                    if re.search('differ', line, re.IGNORECASE):
                        # added the following line to essentially white list a file
                        # that there is currently a bug with, in mac os x
                        # there is currently nothing we can do about this, so we will
                        # ignore the file, to prevent the rule from being ncaf every
                        # time on mac os x. a bug has been filed with apple as of 1/31/2017
                        if re.search("Applications\/Safari\.app\/Contents\/Resources\/Safari\.help\/Contents\/Resources\/index\.html", line, re.IGNORECASE):
                            continue
                        else:
                            retval = False
                            self.detailedresults += '\n' + str(line) + '\n'

        except Exception:
            raise
        return retval

    def fix(self):
        '''

        @return: success
        @rtype: bool
        @author: Breen Malmberg
        '''

        # defaults
        self.detailedresults = ""
        success = True

        try:

            if not self.ci.getcurrvalue():
                self.detailedresults += '\nThe option for this rule was not enabled. Nothing was done.'
                return success

            if re.search("10.11", self.environ.getosver()):
                success = self.fixCapitan()
            else:

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
        self.formatDetailedResults("fix", success, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        self.hasrun = True
        return success

    def fixCapitan(self):
        '''
        run fix actions specific to mac os x el capitan

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        success = True
        fixcommand = '/usr/libexec/repair_packages --repair --standard-pkgs --volume /'

        try:

            if not os.path.exists('/usr/libexec/repair_packages'):
                success = False
                self.detailedresults += '\nA required utility repair_packages was not found. No fix actions were performed.'
                return success
            self.cmdhelper.executeCommand(fixcommand)
            retcode = self.cmdhelper.getReturnCode()
            errout = self.cmdhelper.getErrorString()
            if retcode != 0:
                success = False
                self.detailedresults += '\nThere was an error running command repair_packages --repair'
                self.logger.log(LogPriority.DEBUG, errout)
        except Exception:
            raise
        return success

    def undo(self):
        '''

        @author: Breen Malmberg
        '''

        self.detailedresults += '\nThere is no undo function for this rule'
        self.logger.log(LogPriority.INFO, self.detailedresults)
