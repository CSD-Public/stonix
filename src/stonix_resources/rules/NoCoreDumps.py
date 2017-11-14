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
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
'''
from __future__ import absolute_import
from ..CommandHelper import CommandHelper
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
        self.guidance = ["NSA 2.2.4.2"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']}}

        datatype = 'bool'
        key = 'NOCOREDUMPS'
        instructions = "To disable this rule set the value of NOCOREDUMPS " + \
            "to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.iditerator = 0
        self.created1 = False
        self.created2 = False
        self.sethelptext()

###############################################################################

    def report(self):
        '''
        Main parent report method that calls the sub report methods report1
        and report2

        @author: dwalker
        @return: self.compliant
        @rtype: bool
        @change: Breen Malmberg - 1/10/2017 - doc string edit; return var init;
                minor refactor
        '''

        self.detailedresults = ""
        self.compliant = True

        try:

            osfam = self.environ.getosfamily()
            ostype = self.environ.getostype()

            if osfam == "linux":
                if not self.reportLinux1():
                    self.compliant = False
                if not self.reportLinux2():
                    self.compliant = False

            if osfam == "freebsd":
                if not self.reportFreebsdMac():
                    self.compliant = False

            if ostype == "Mac OS X":
                if not self.reportFreebsdMac():
                    self.compliant = False

            if osfam == "solaris":
                if not self.reportSolaris():
                    self.compliant = False

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
        '''
        run report actions for freebsd and mac systems

        @return: compliant
        @rtype: bool
        @author: dwalker
        @change: Breen Malmberg - 1/10/2017 - added doc string; default return var init;
                try/except; logging; minor refactor
        '''

        self.logger.log(LogPriority.DEBUG, "System has been detected as either freebsd or mac, running reportFreebsdMac()...")
        compliant = True
        lookfor = {'kern.coredump': "0"}

        try:

            if self.environ.getostype() == "Mac OS X":
                path = "/private/etc/sysctl.conf"
                tmpPath = path + ".tmp"
                perms = [0, 0, 0o600]
            else:
                path = "/etc/sysctl.conf"
                tmpPath = path + ".tmp"
                perms = [0, 0, 0o644]
            kvtype = "conf"
            intent = "present"
    
            if not os.path.exists(path):
                compliant = False
                self.detailedresults += "File path: " + str(path) + " does not exist\n"
            else:
                if not checkPerms(path, perms, self.logger):
                    self.detailedresults += "Permissions incorrect on " + str(path) + "\n"
                    compliant = False
                self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                             kvtype, path, tmpPath, lookfor,
                                             intent, "closedeq")
                if not self.editor.report():
                    self.detailedresults += "Correct contents were not found in " + \
                        path + " file\n"
                    compliant = False

        except Exception:
            raise

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
                    ch = CommandHelper(self.logger)
                    cmd = ["/sbin/sysctl", "-p"]
                    ch.executeCommand(cmd)
                    retval = int(ch.getReturnCode())
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
        '''
        run fix actions for freebsd and mac systems

        @return: success
        @rtype: bool
        @author: dwalker
        @change: Breen Malmberg - 1/10/2017 - added doc string; default return var init;
                try/except; fixed command being used to restart sysctl on mac; logging
        '''

        self.logger.log(LogPriority.DEBUG, "System detected as either freebsd or mac. Running fixFreebsdMac()...")
        success = True

        try:

            self.cmdhelper = CommandHelper(self.logger)

            if self.environ.getostype() == "Mac OS X":
                path = "/private/etc/sysctl.conf"
                perms = [0, 0, 0o600]
            else:
                path = "/etc/sysctl.conf"
                perms = [0, 0, 0o644]
    
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
                if not self.created1:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor.setEventID(myid)
                if not self.editor.fix():
                    success = False
                    self.logger.log(LogPriority.DEBUG, "kveditor fix() failed.\n")
                    return success
                elif not self.editor.commit():
                    success = False
                    self.logger.log(LogPriority.DEBUG, "kveditor commit() failed.\n")
                    return success
            if not checkPerms(path, perms, self.logger):
                self.logger.log(LogPriority.DEBUG, "Fixing permissions and ownership on file: " + str(path) + "\n")
                if not self.created1:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(path, perms, self.logger,
                                    self.statechglogger, myid):
                        success = False
                        self.logger.log(LogPriority.DEBUG, "setPerms() failed.\n")
                        return success
                else:
                    if not setPerms(path, perms, self.logger):
                        success = False
                        self.logger.log(LogPriority.DEBUG, "setPerms() failed.\n")
                        return success

            # restart/reload the sysctl with the updated values
            if self.environ.getostype() != "Mac OS X":
                cmdbase = "/usr/sbin/sysctl"
                sysctlcmd = cmdbase + " -a"
                self.cmdhelper.executeCommand(sysctlcmd)
                retcode = self.cmdhelper.getReturnCode()
                if retcode != 0:
                    errmsg = self.cmdhelper.getErrorString()
                    self.detailedresults += "Unable to restart sysctl"
                    self.logger.log(LogPriority.DEBUG, "Unable to restart sysctl.\n" + errmsg)
                    success = False

        except Exception:
            raise

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
