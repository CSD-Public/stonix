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
'''
Created on Nov 21, 2012

@author: dwalker
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 02/14/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel Replaced old-style CI invocation
@change: 2014/07/29 dkennel Rule was setting Linux permissions to mode 600
which conflicted with DisableIPV6 and NoCoreDumps which expected 644.
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2016/09/09 eball Refactored reports and fixes to remove file creation
    from reports.
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import writeFile, readFile, setPerms, checkPerms
from ..stonixutilityfunctions import iterate, resetsecon, createFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix
from subprocess import call
import os
import traceback
import re


class NoCoreDumps(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 49
        self.rulename = "NoCoreDumps"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rule disables the ability of the system to " + \
            "produce core dump images.  A reboot is required or Mac OS X " + \
            "for this rule to take effect."
        self.guidance = ["NSA 2.2.4.2"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}

        datatype = 'bool'
        key = 'NOCOREDUMPS'
        instructions = "To disable this rule set the value of NOCOREDUMPS " + \
            "to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.iditerator = 0
        self.created1 = False
        self.created2 = False

###############################################################################

    def report(self):
        '''Main parent report method that calls the sub report methods report1
        and report2
        @author: dwalker
        @return: bool
        '''
        try:
            self.detailedresults = ""
            self.rulesuccess = True
            osfam = self.environ.getosfamily()
            if osfam == "linux":
                compliant1 = self.reportLinux1()
                compliant2 = self.reportLinux2()
                if not compliant1 or not compliant2:
                    self.compliant = False
                else:
                    self.compliant = True
            elif osfam == "freebsd" or self.environ.getostype() == "Mac OS X":
                self.compliant = self.reportFreebsdMac()
            elif osfam == "solaris":
                self.compliant = self.reportSolaris()
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def reportFreebsdMac(self):
        # there may be a more update way to do this using launchctl
        self.detailedresults = ""
        lookfor = {'kern.coredump': "0"}
        if self.environ.getostype() == "Mac OS X":
            path = "/private/etc/sysctl.conf"
            tmpPath = "/private/etc/sysctl.conf.tmp"
            perms = [0, 0, 0o600]
        else:
            path = "/etc/sysctl.conf"
            tmpPath = "/etc/sysctl.conf.tmp"
            perms = [0, 0, 0o644]
        kvtype = "conf"
        intent = "present"
        compliant = True
        if not os.path.exists(path):
            compliant = False
            self.detailedresults += path + " does not exist\n"
        else:
            if not checkPerms(path, perms, self.logger):
                self.detailedresults += "Permissions incorrect on " + path + \
                    "\n"
                compliant = False
            self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                         kvtype, path, tmpPath, lookfor,
                                         intent, "closedeq")
            if not self.editor.report():
                self.detailedresults += "Correct contents were not found in " + \
                    path + " file\n"
                compliant = False
        return compliant

###############################################################################

    def reportLinux1(self):
        '''Sub report method 1 that searches the /etc/security/limits.conf file
        for the following line "* hard core 0"
        @return: bool
        '''
        match = False
        lookfor = "(^\*)(\s)* hard core 0?"
        path = "/etc/security/limits.conf"
        compliant = True
        if not os.path.exists(path):
            compliant = False
            self.detailedresults += path + " does not exist\n"
        else:
            if not checkPerms(path, [0, 0, 0o644], self.logger):
                compliant = False
                self.detailedresults += "Permissions incorrect on " + path + \
                    "\n"
            contents = readFile(path, self.logger)
            if not contents:
                return False
            for line in contents:
                if re.match(lookfor, line):
                    match = True
                    break
        if match and compliant:
            return True
        else:
            return False

###############################################################################

    def reportLinux2(self):
        '''Sub report method 2 that searches the /etc/sysctl.conf file
        for the following line "fs.suid_dumpable = 0"
        @return: bool
        '''
        lookfor = {"fs.suid_dumpable": "0"}
        path = "/etc/sysctl.conf"
        tmpPath = "/etc/sysctl.conf.tmp"
        kvtype = "conf"
        intent = "present"
        compliant = True
        if not os.path.exists(path):
            compliant = False
            self.detailedresults += path + " does not exist\n"
        else:
            if not checkPerms(path, [0, 0, 0o644], self.logger):
                compliant = False
                self.detailedresults += "Permissions incorrect on " + path + \
                    "\n"
            self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                         kvtype, path, tmpPath, lookfor,
                                         intent, "openeq")
            if not self.editor.report():
                compliant = False
                self.detailedresults += "Correct contents were not found in " + \
                    path + " file\n"
        return compliant

###############################################################################

    def reportSolaris(self):
        lookfor = {'COREADM_GLOB_CONTENT': 'all'}
        path = "/etc/coreadm.conf"
        tmpPath = "/etc/coreadm.conf.tmp"
        kvtype = "conf"
        intent = "present"
        compliant = True
        if not os.path.exists(path):
            compliant = False
            self.detailedresults += path + " does not exist\n"
        else:
            if not checkPerms(path, [0, 0, 0o644], self.logger):
                compliant = False
                self.detailedresults += "Permissions incorrect on " + path + \
                    "\n"
            self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                         kvtype, path, tmpPath, lookfor,
                                         intent, "closedeq")
            if not self.editor.report():
                compliant = False
                self.detailedresults += "Correct contents were not found in " + \
                    path + " file\n"
        return compliant

###############################################################################

    def fix(self):
        '''Main parent fix method that calls the sub fix methods fix1
        and fix2
        @author: dwalker
        @return: bool
        '''
        try:
            if not self.ci.getcurrvalue():
                return
            success = True
            self.detailedresults = ""

            #clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            osfam = self.environ.getosfamily()
            if osfam == "linux":
                if self.fixLinux1() and self.fixLinux2():
                    retval = call(["/sbin/sysctl", "-p"],
                                  stdout=None,
                                  stderr=None, shell=False)
                    if retval != 0:
                        self.detailedresults += "Unable to restart sysctl"
                        self.logger.log(LogPriority.DEBUG,
                                        self.detailedresults)
                        success = False
                else:
                    success = False
            elif osfam == 'freebsd' or self.environ.getostype() == "Mac OS X":
                success = self.fixFreebsdMac()
            elif osfam == 'solaris':
                success = self.fixSolaris()
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################

    def fixLinux1(self):
        '''Sub fix method 1 that opens the /etc/security/limits.conf file and a
        adds the following line: "* hard core 0"
        @return: bool
        '''
        path = "/etc/security/limits.conf"
        lookfor = "(^\*)(\s)* hard core 0?"
        tempstring = ""
        success, found = True, False

        if not os.path.exists(path):
            createFile(path, self.logger)
            self.created1 = True
            setPerms(path, [0, 0, 0o644], self.logger)

        contents = readFile(path, self.logger)
        for line in contents:
            if re.match(lookfor, line):
                found = True
                tempstring += line
            else:
                tempstring += line
        if not found:
            tempstring += "* hard core 0 \n"

        tmpfile = path + ".tmp"
        if not writeFile(tmpfile, tempstring, self.logger):
            self.rulesuccess = False
            return False
        if self.created1:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": path}
            self.statechglogger.recordchgevent(myid, event)
            os.rename(tmpfile, path)
        elif tempstring != "".join(contents):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype': "conf",
                     'filepath': path}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(path, tmpfile, myid)
            os.rename(tmpfile, path)
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            setPerms(path, [0, 0, 0o644], self.logger, self.statechglogger,
                     myid)
        resetsecon(path)
        return success

###############################################################################

    def fixLinux2(self):
        '''Sub fix method 2 that searches the /etc/sysctl.conf file
        for the following line "fs.suid_dumpable = 0"
        @return: bool
        '''
        path = "/etc/sysctl.conf"
        success = True

        if not os.path.exists(path):
            createFile(path, self.logger)
            self.created2 = True
            setPerms(path, [0, 0, 0o644], self.logger)
            self.reportLinux2()  # Set up KVEditor

        if self.created2:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": path}
            self.statechglogger.recordchgevent(myid, event)
        if self.editor.fixables or self.editor.removeables:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.editor.setEventID(myid)
            if not self.editor.fix():
                self.rulesuccess = False
                return False
            elif not self.editor.commit():
                self.rulesuccess = False
                return False
            elif not checkPerms(path, [0, 0, 0o644], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(path, [0, 0, 0o644], self.logger,
                                self.statechglogger, myid):
                    self.rulesuccess = False
                    return False
        resetsecon(path)
        return success

###############################################################################

    def fixFreebsdMac(self):
        if self.environ.getostype() == "Mac OS X":
            path = "/private/etc/sysctl.conf"
            perms = [0, 0, 0o600]
        else:
            path = "/etc/sysctl.conf"
            perms = [0, 0, 0o644]
        success = True

        if not os.path.exists(path):
            createFile(path, self.logger)
            self.created1 = True
            setPerms(path, perms, self.logger)
            self.reportFreebsdMac()  # Set up KVEditor

        if self.created1:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": path}
            self.statechglogger.recordchgevent(myid, event)
        if self.editor.fixables or self.editor.removeables:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.editor.setEventID(myid)
            if not self.editor.fix():
                self.rulesuccess = False
                return False
            elif not self.editor.commit():
                self.rulesuccess = False
                return False
            elif not checkPerms(path, perms, self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(path, perms, self.logger,
                                self.statechglogger, myid):
                    self.rulesuccess = False
                    return False
        resetsecon(path)
        if self.environ.getostype() != "Mac OS X":
            cmd = "/sbin/sysctl"
            retval = call([cmd, "-p"], stdout=None, stderr=None, shell=False)
            if retval != 0:
                self.detailedresults = "Unable to restart sysctl"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                success = False
        return success

###############################################################################

    def fixSolaris(self):
        path = "/etc/coreadm.conf"
        success = True

        if not os.path.exists(path):
            createFile(path, self.logger)
            self.created1 = True
            setPerms(path, [0, 0, 0o644], self.logger)
            self.reportSolaris()  # Set up KVEditor

        if self.created1:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": path}
            self.statechglogger.recordchgevent(myid, event)
        if self.editor.fixables or self.editor.removeables:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.editor.setEventID(myid)
            if not self.editor.fix():
                self.rulesuccess = False
                return False
            elif not self.editor.commit():
                self.rulesuccess = False
                return False
            elif not checkPerms(path, [0, 0, 0o644], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(path, [0, 0, 0o644], self.logger,
                                self.statechglogger, myid):
                    self.rulesuccess = False
                    return False
        resetsecon(path)
        retval = call(["/usr/bin/coreadm", "-u"], stdout=None, stderr=None,
                      shell=False)
        if retval != 0:
            self.detailedresults = "Unable to restart coreadm"
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
            success = False
        return success
