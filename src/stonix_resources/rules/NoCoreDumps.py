###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
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
from ..stonixutilityfunctions import iterate, readFile, checkPerms, createFile, setPerms, writeFile, resetsecon

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
        self.ch = CommandHelper(self.logger)
        self.sethelptext()

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
            if self.environ.getosfamily() == "linux":
                if not self.reportLinux():
                    self.compliant = False
            elif self.environ.getostype()== "mac":
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
        return compliant

    def reportLinux(self):
        '''
        Sub report method 1 that searches the /etc/security/limits.conf file
        for the following line "* hard core 0"

        @return: bool
        '''

        compliant = True
        if not self.check_security_limits():
            compliant = False

        if not self.check_sysctl():
            compliant = False

        if not self.check_profile():
            compliant = False
        return compliant

    def check_security_limits(self):
        '''

        :return:
        '''

        compliant = True
        path1 = "/etc/security/limits.conf"
        lookfor1 = "(^\*)\s+hard\s+core\s+0?"
        if os.path.exists(path1):
            if not checkPerms(path1, [0, 0, 0o644], self.logger):
                self.detailedresults += "Permissions incorrect on " + path1 + "\n"
                compliant = False
            contents = readFile(path1, self.logger)
            if contents:
                found = False
                for line in contents:
                    if re.search(lookfor1, line.strip()):
                        found = True
                if not found:
                    self.detailedresults += "Correct configuration line * hard core 0 " + \
                        "not found in /etc/security/limits.conf\n"
                    compliant = False
        else:
            self.detailedresults += path1 + " file doesn't exist\n"
        return compliant

    def check_sysctl(self):
        '''

        :return:
        '''

        compliant = True

        self.ch.executeCommand("/sbin/sysctl fs.suid_dumpable")
        retcode = self.ch.getReturnCode()

        if retcode != 0:
            self.detailedresults += "Failed to get value of core dumps configuration with sysctl command\n"
            errmsg = self.ch.getErrorString()
            self.logger.log(LogPriority.DEBUG, errmsg)
            compliant = False
        else:
            output = self.ch.getOutputString()
            if output.strip() != "fs.suid_dumpable = 0":
                compliant = False
                self.detailedresults += "Core dumps are currently enabled\n"
        return compliant

    def check_profile(self):
        '''

        :return:
        '''

        compliant = True
        profile = ""
        if os.path.exists("/etc/profile.d"):
            profile = "/etc/profile.d/stonix_no_core_dumps.sh"
            if not os.path.exists(profile):
                profile = ""
        elif os.path.exists("/etc/profile"):
            profile = "/etc/profile"
        if profile:
            contents = readFile(profile, self.logger)
            tempstring = ""
            found = False
            for line in contents:
                if re.search("^ulimit\s+\-S\s+\-c\s+1", line.strip()):
                    found = True
            if not found:
                compliant = False
                self.detailedresults += "Didn't find the line ulimit -S -c 1 " + \
                    "in user's profile\n"
        else:
            compliant = False
            self.detailedresults += "User profile file doesn't exist\n"
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

            if self.environ.getosfamily() == "linux":
                if not self.fixLinux():
                    self.rulesuccess = False

            elif self.environ.getostype() == "mac":
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
        @return: bool
        '''

        success = True
        if not self.fix_security_limits():
            success = False

        if not self.fix_sysctl():
            success = False

        if not self.fix_profile():
            success = False
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
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                command = "/sbin/sysctl -w fs.suid_dumpable=1"
                event = {"eventtype": "commandstring",
                         "command": command}
                self.statechglogger.recordchgevent(myid, event)
        return success

    def fix_security_limits(self):
        '''

        :return:
        '''

        success = True
        path1 = "/etc/security/limits.conf"
        lookfor1 = "(^\*)\s+hard\s+core\s+0?"
        created = False
        if not os.path.exists(path1):
            if not createFile(path1, self.logger):
                success = False
                self.detailedresults += "Unable to create " + path1 + " file\n"
            else:
                created = True
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": "path1"}
                self.statechglogger.recordchgevent(myid, event)
        if os.path.exists(path1):
            if not checkPerms(path1, [0, 0, 0o644], self.logger):
                if not created:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(path1, [0, 0, 0o644], self.logger, self.statechglogger, myid):
                        success = False
                        self.detailedresults += "Unable to correct permissions on " + path1 + "\n"
            contents = readFile(path1, self.logger)
            found = False
            tempstring = ""
            if contents:
                for line in contents:
                    if re.search(lookfor1, line.strip()):
                        found = True
                    else:
                        tempstring += line
            else:
                found = False
            if not found:
                tempstring += "* hard core 0\n"
                tempfile = path1 + ".tmp"
                if not writeFile(tempfile, tempstring, self.logger):
                    success = False
                    self.detailedresults += "Unable to write contents to " + path1 + "\n"
                else:
                    if not created:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "conf",
                                 "filepath": path1}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(path1, tempfile, myid)
                    os.rename(tempfile, path1)
                    setPerms(path1, [0, 0, 0o644], self.logger)
                    resetsecon(path1)
        return success

    def fix_profile(self):
        '''

        :return:
        '''

        success = True
        created = True
        lookfor = "^ulimit\s+\-S\s+\-c\s+1"
        if os.path.exists("/etc/profile.d"):
            profile = "/etc/profile.d/stonix_no_core_dumps.sh"
            if not os.path.exists(profile):
                if not createFile(profile, self.logger):
                    success = False
                    self.detailedresults += "Unable to create " + profile + "\n"
                else:
                    created = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": profile}
                    self.statechglogger.recordchgevent(myid, event)
            if os.path.exists(profile):
                if not checkPerms(profile, [0, 0, 0o755], self.logger):
                    if not created:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(profile, [0, 0, 0o755], self.logger, self.statechglogger, myid):
                            success = False
                            self.detailedresults += "Unable to correct permissions on " + profile + "\n"
                contents = readFile(profile, self.logger)
                found = False
                tempstring = ""
                if contents:
                    for line in contents:
                        if re.search(lookfor, line.strip()):
                            found = True
                        else:
                            tempstring += line
                else:
                    found = False
                if not found:
                    tempstring += "ulimit -S -c 1\n"
                    tempfile = profile + ".tmp"
                    if not writeFile(tempfile, tempstring, self.logger):
                        success = False
                        self.detailedresults += "Unable to write contents to " + profile + "\n"
                    else:
                        if not created:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "conf",
                                     "filepath": profile}
                            self.statechglogger.recordchgevent(myid, event)
                            self.statechglogger.recordfilechange(profile, tempfile, myid)
                        os.rename(tempfile, profile)
                        setPerms(profile, [0, 0, 0o755], self.logger)
                        resetsecon(profile)
        elif os.path.exists("/etc/profile"):
            profile = "/etc/profile"
            if not checkPerms(profile, [0, 0, 0o755], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(profile, [0, 0, 0o755], self.logger, self.statechglogger, myid):
                    success = False
                    self.detailedresults += "Unable to correct permissions on " + profile + "\n"
            contents = readFile(profile, self.logger)
            found = False
            tempstring = ""
            if contents:
                for line in contents:
                    if re.search(lookfor, line.strip()):
                        found = True
                    else:
                        tempstring += line
            else:
                found = False
            if not found:
                tempstring += "ulimit -S -c 1\n"
                tempfile = profile + ".tmp"
                if not writeFile(tempfile, tempstring, self.logger):
                    success = False
                    self.detailedresults += "Unable to write contents to " + profile + "\n"
                else:
                    if not created:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "conf",
                                 "filepath": profile}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(profile, tempfile, myid)
                    os.rename(tempfile, profile)
                    setPerms(profile, [0, 0, 0o755], self.logger)
                    resetsecon(profile)
        else:
            profile = "/etc/profile"
            if not createFile(profile, self.logger):
                success = False
                self.detailedresults += "Unable not create " + profile + "\n"
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": profile}
                self.statechglogger.recordchgevent(myid, event)
                tempstring = "ulimit -S -c 1\n"
                tempfile = profile + ".tmp"
                if not writeFile(tempfile, tempstring, self.logger):
                    success = False
                    self.detailedresults += "Unable to write contents to /etc/profile\n"
                else:
                    os.rename(tempfile, profile)
                    setPerms(profile, [0, 0, 0o755], self.logger)
                    resetsecon(profile)

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
        self.logger.log(LogPriority.DEBUG, "Configuring launchctl limit core directive")
        self.ch.executeCommand("/usr/bin/launchctl limit core 0 0")
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            success = False
            errmsg = self.ch.getErrorString()
            self.detailedresults += "\nFailed to run launchctl command to configure core dumps"
            self.logger.log(LogPriority.DEBUG, errmsg)
        return success
