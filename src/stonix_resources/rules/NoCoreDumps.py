###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
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
Created on Nov 21, 2012

@author: Derek Walker
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 02/14/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 Dave Kennel Replaced old-style CI invocation
@change: 2014/07/29 Dave Kennel Rule was setting Linux permissions to mode 600
which conflicted with DisableIPV6 and NoCoreDumps which expected 644.
@change: 2015/04/15 Dave Kennel updated for new isApplicable
@change: 2016/09/09 Eric Ball Refactored reports and fixes to remove file creation
    from reports.
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/01/30 Derek Walker - combined linux sub methods into one method.
    updated fixLinux method to set permissions in correct order so that
    events for permission corrections are actually recorded to harmonize
    with unit test.
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''

from __future__ import absolute_import

from ..CommandHelper import CommandHelper
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix

import os
import traceback
import re


class NoCoreDumps(Rule):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''

        :param config:
        :param environ:
        :param logger:
        :param statechglogger:
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 49
        self.rulename = "NoCoreDumps"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.guidance = ["NSA 2.2.4.2"]
        self.applicable = {'type': 'white',
                           'family': ['linux'],
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}

        datatype = 'bool'
        key = 'NOCOREDUMPS'
        instructions = "To prevent the disabling of core dumps on your system, set the value of NOCOREDUMPS to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.sethelptext()
        self.initObjs()
        self.determineOS()

    def determineOS(self):
        '''

        :return:
        '''

        self.os = "unknown"

        if self.environ.getosfamily() == "linux":
            self.os = "linux"
        else:
            if self.environ.getostype() == "Mac OS X":
                self.os = "mac"

    def initObjs(self):
        '''

        :return:
        '''

        self.ch = CommandHelper(self.logger)

    def report(self):
        '''
        Main parent report method that calls the sub report methods report1
        and report2

        @author: Derek Walker
        @return: self.compliant
        @rtype: bool
        @change: Breen Malmberg - 1/10/2017 - doc string edit; return var init;
                minor refactor
        '''

        self.detailedresults = ""
        self.compliant = True

        try:

            if self.os == "linux":
                if not self.reportLinux():
                    self.compliant = False
            elif self.os == "mac":
                if not self.reportMac():
                    self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportMac(self):
        '''
        run report actions for mac systems

        @return: compliant
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 1/10/2017 - added doc string; default return var init;
                try/except; logging; minor refactor
        '''

        self.logger.log(LogPriority.DEBUG, "System has been detected as Mac OS X, running reportMac()...")
        compliant = True

        try:

            self.ch.executeCommand("/usr/bin/launchctl limit core")
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                self.detailedresults += "\nFailed to run launchctl command to get current value of core dumps configuration"
                errmsg = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, errmsg)
            else:
                output = self.ch.getOutputString()
                if output:
                    if not re.search("0", output):
                        compliant = False
                else:
                    compliant = False

        except Exception:
            raise
        return compliant

    def reportLinux(self):
        '''
        Sub report method 1 that searches the /etc/security/limits.conf file
        for the following line "* hard core 0"

        @return: bool
        '''

        compliant = True

        try:

            if not self.check_security_limits():
                compliant = False

            if not self.check_sysctl():
                compliant = False

            if not self.check_profile():
                compliant = False

        except Exception:
            raise
        return compliant

    def check_profile(self):
        '''

        :return:
        '''

        compliant = True

        kvtype = "conf"
        if os.path.exists("/etc/profile.d"):
            path = "/etc/profile.d/stonix_no_core_dumps.sh"
        else:
            path = "/etc/profile"
        tmppath = path + ".stonixtmp"
        opts = {"ulimit -S -c": "0"}
        intent = "present"
        delimiter = "space"
        self.profile_editor = KVEditorStonix(self.statechglogger, self.logger,
                                            kvtype, path, tmppath, opts,
                                            intent, delimiter)
        if not self.profile_editor.report():
            compliant = False
            self.detailedresults += "\nCorrect configuration line not found in " + path + ":\nulimit -S -c 0"

        return compliant

    def check_sysctl(self):
        '''

        :return:
        '''

        compliant = True

        self.ch.executeCommand("/sbin/sysctl fs.suid_dumpable")
        retcode = self.ch.getReturnCode()

        if retcode != 0:
            self.detailedresults += "\nFailed to get value of core dumps configuration with sysctl command"
            errmsg = self.ch.getErrorString()
            self.logger.log(LogPriority.DEBUG, errmsg)
        else:
            output = self.ch.getOutputString()
            if output.strip() != "fs.suid_dumpable = 0":
                compliant = False
                self.detailedresults += "\nCore dumps are currently enabled"

        return compliant

    def check_security_limits(self):
        '''

        :return:
        '''

        compliant = True

        kvtype = "conf"
        path = "/etc/security/limits.conf"
        tmppath = path + ".stonixtmp"
        opts = {"* hard core": "0"}
        intent = "present"
        delimiter = "space"

        self.seclimits_editor = KVEditorStonix(self.statechglogger, self.logger,
                                            kvtype, path, tmppath, opts,
                                            intent, delimiter)
        if not self.seclimits_editor.report():
            compliant = False
            self.detailedresults += "\nCorrect configuration line not found in " + path + ":\n*    hard    core    0"

        return compliant

    def fix(self):
        '''
        parent fix method which calls os-specific private fix methods

        @author: Derek Walker
        @return: bool
        '''

        self.iditerator = 0
        self.detailedresults = ""
        self.rulesuccess = True

        try:

            if not self.ci.getcurrvalue():
                return

            #clear out event history so only the latest fix is recorded
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.os == "linux":
                if not self.fixLinux():
                    self.rulesuccess = False

            elif self.os == "mac":
                if not self.fixMac():
                    self.rulesuccess = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def fixLinux(self):
        '''
        Sub fix method 1 that opens the /etc/security/limits.conf file and a
        adds the following line: "* hard core 0"

        @return: bool
        '''

        success = True

        try:

            if not self.fix_security_limits():
                success = False

            if not self.fix_sysctl():
                success = False

            if not self.fix_profile():
                success = False

        except Exception:
            raise
        return success

    def fix_sysctl(self):
        '''

        :return:
        '''

        success = True

        self.logger.log(LogPriority.DEBUG, "Configuring /etc/sysctl fs.suid_dumpable directive")
        self.ch.executeCommand("/sbin/sysctl -w fs.suid_dumpable=0")
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            success = False
            self.detailedresults += "\nFailed to set core dumps variable suid_dumpable to 0"
            errmsg = self.ch.getErrorString()
            self.logger.log(LogPriority.DEBUG, errmsg)
        else:
            self.logger.log(LogPriority.DEBUG, "Re-reading sysctl configuration from files")
            self.ch.executeCommand("/sbin/sysctl -p")
            retcode2 = self.ch.getReturnCode()
            if retcode2 != 0:
                success = False
                self.detailedresults += "\nFailed to load new sysctl configuration from config file"
                errmsg2 = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, errmsg2)
        return success

    def fix_security_limits(self):
        '''

        :return:
        '''

        success = True

        self.logger.log(LogPriority.DEBUG, "Configuring /etc/security/limits.conf core directive")

        if not self.seclimits_editor.fix():
            success = False
        else:
            if not self.seclimits_editor.commit():
                success = False

        return success

    def fix_profile(self):
        '''

        :return:
        '''

        success = True

        self.logger.log(LogPriority.DEBUG, "Configuring /etc/profile ulimit directive")

        if not self.profile_editor.fix():
            success = False
        else:
            if not self.profile_editor.commit():
                success = False

        return success

    def fixMac(self):
        '''
        run fix actions for Mac  OS X systems

        @return: success
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 1/10/2017 - added doc string; default return var init;
                try/except; fixed command being used to restart sysctl on mac; logging
        '''

        self.logger.log(LogPriority.DEBUG, "System detected as Mac OS X. Running fixMac()...")
        success = True

        try:

            self.logger.log(LogPriority.DEBUG, "Configuring launchctl limit core directive")
            self.ch.executeCommand("/usr/bin/launchctl limit core 0 0")
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                success = False
                errmsg = self.ch.getErrorString()
                self.detailedresults += "\nFailed to run launchctl command to configure core dumps"
                self.logger.log(LogPriority.DEBUG, errmsg)

        except Exception:
            raise
        return success
