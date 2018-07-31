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
Created on 2015/08/04
Verify package integrity, correct permissions
@author: Eric Ball
@change: 2015/08/04 eball - Original implementation
@change: 2015/08/24 eball - Improve output, remove .pyc files from output
@change: 2016/04/20 eball - Per RHEL 7 STIG, added a fix to automate correction
    of file permissions
@change: 2018/07/30 Breen Malmberg - re-wrote the report and fix methods entirely
'''

from __future__ import absolute_import

import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class InstalledSoftwareVerification(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 230
        self.rulename = 'InstalledSoftwareVerification'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = True
        self.guidance = ['NSA 2.1.3.2', 'CCE 14931-0',
                         'CCE-RHEL7-CCE-TBD 2.1.3.2.1']
        self.applicable = {'type': 'white',
                           'os': {'Red Hat Enterprise Linux': ['6.0', '+'],
                                  'CentOS Linux': ['7.0', '+']}}

        datatype = 'bool'
        key = 'FIXPERMISSIONS'
        instructions = 'If set to True, this rule will fix the permissions \
of the package for any file which has a permission deviation from the vendor \
default.'
        default = True
        self.fixPermsCi = self.initCi(datatype, key, instructions, default)
        self.sethelptext()

    def getInstalledPackages(self):
        '''
        return a list of installed packages (as reported
        by rpm database)

        @return:installedpackages
        @rtype: list
        @author: Breen Malmberg
        '''

        installedpackages = []

        listinstalledcmd = "rpm -qa"

        self.ch.executeCommand(listinstalledcmd)
        outputlist = self.ch.getOutput()
        retcode = self.ch.getReturnCode()
        if retcode == 0:
            installedpackages = outputlist
        else:
            errmsg = self.ch.getErrorString()
            self.logger.log(LogPriority.DEBUG, errmsg)

        return installedpackages

    def report(self):
        '''
        Compile a list of files not conforming to rpm package database permissions (Mode)
        report non-compliant if any are found
        else report compliant

        @return: self.compliant
        @rtype: bool
        @author: Eric Ball
        @author: Breen Malmberg
        @change: Breen Malmberg - 07/30/2018 - complete re-write of method
        '''

        self.detailedresults = ""
        self.compliant = True
        self.ch = CommandHelper(self.logger)
        reportcmd = "rpm -V --nosignature --nolinkto --nofiledigest --nosize --nomtime --nordev --nocaps "
        self.badpermfiles = []
        self.badpermpkgs = {}
        self.badgroupfiles = []
        self.badownerfiles = []
        self.badhashfiles = []

        try:

            self.logger.log(LogPriority.DEBUG, "Searching for files with incorrect permissions...")

            installedpkgs = self.getInstalledPackages()

            for pkg in installedpkgs:
                self.ch.executeCommand(reportcmd + pkg)
                outputlist = self.ch.getOutput()
                self.badpermpkgs[pkg] = []
                for line in outputlist:
                    # search for bad permissions
                    if re.search("^.*(\.+M|M\.+)", line, re.IGNORECASE):
                        sline = line.split()
                        self.badpermpkgs[pkg].append(sline[1])
                        self.badpermfiles.append(sline[1])
                    # search for bad group ownership
                    if re.search("^.*(\.+G|G\.+)", line, re.IGNORECASE):
                        sline = line.split()
                        self.badgroupfiles.append(sline[1])
                    # search for bad ownership (user)
                    if re.search("^.*(\.+U|U\.+)", line, re.IGNORECASE):
                        sline = line.split()
                        self.badownerfiles.append(sline[1])
                    # search for bad md5 hash
                    if re.search("^.*(\.+5|5\.+)", line, re.IGNORECASE):
                        sline = line.split()
                        self.badhashfiles.append(sline[1])

            if self.badpermfiles:
                self.compliant = False
                self.detailedresults += "\nThe following package files have incorrect permissions:\n" + "\n".join(self.badpermfiles)
            if self.badgroupfiles:
                self.compliant = False
                self.detailedresults += "\n\nThe following package files have bad group ownership:\n" + "\n".join(self.badgroupfiles)
            if self.badownerfiles:
                self.compliant = False
                self.detailedresults += "\n\nThe following package files have bad ownership:\n" + "\n".join(self.badownerfiles)
            if self.badhashfiles:
                self.compliant = False
                self.detailedresults += "\n\nThe following package files have bad MD5 checksums:\n" + "\n".join(self.badhashfiles)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = self.detailedresults + traceback.format_exc()
            self.compliant = False
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def fix(self):
        '''
        The fix method changes permissions to the package defaults.

        @return: self.rulesuccess
        @rtype: bool
        @author: Eric Ball
        @author: Breen Malmberg
        @change: Breen Malmberg - 07/30/2018 - re-write of entire method
        '''

        self.detailedresults = ""
        self.rulesuccess = True
        fixcmd = "rpm --setperms "

        try:

            if not self.fixPermsCi.getcurrvalue():
                return self.rulesuccess

            for pkg in self.badpermpkgs:
                if self.badpermpkgs[pkg]:
                    self.ch.executeCommand(fixcmd + pkg)
                    retcode = self.ch.getReturnCode()
                    if retcode != 0:
                        self.rulesuccess = False

            self.detailedresults += "\n\nPlease note that we will not attempt to fix ownership, group ownership, or bad md5 checksums. For suggestions on what to do if files are found with these issues, please see the rule's help text."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
