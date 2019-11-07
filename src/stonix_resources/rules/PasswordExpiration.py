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
Created on Jun 17, 2013

@author: dwalker
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 02/16/2014 ekkehard Blacklisted Darwin
@change: 04/18/2014 dkennel Replaced old-style CI invocation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@note: May need to be passed to Ekkehard or Roy for Mac portion
@note: No OS X Implementation blacklisted darwin
@change: 2015/04/16 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2016/06/20 eball 35 days for account expire, removed chk/fixPam
@change: 2016/12/7 dwalker changed min number of days value from 7 to 1
'''

from stonixutilityfunctions import iterate, writeFile, readFile, resetsecon
from stonixutilityfunctions import checkPerms, setPerms, createFile
from stonixutilityfunctions import getUserGroupName, getOctalPerms
from rule import Rule
from logdispatcher import LogPriority
from KVEditorStonix import KVEditorStonix
from CommandHelper import CommandHelper
from pkghelper import Pkghelper
from subprocess import Popen, PIPE
from time import strftime
import traceback
import re
import os
import shutil
import stat


class PasswordExpiration(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 42
        self.rulename = "PasswordExpiration"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.iditerator = 0
        self.guidance = ["2.3.1.7"]
        self.applicable = {'type': 'black', 'family': ['darwin']}
        self.universal = "#The following lines were added by stonix\n"
        datatype = 'bool'
        key = 'PASSWORDEXPIRATION'
        instructions = "To disable this rule set the value of " + \
            "PASSWORDEXPIRATION to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.libusercreate = False
        self.libuserinstall = False
        self.useraddcreate = False
        self.logindefcreate = False
        self.fixable, self.shadow = True, True
        self.editor1, self.editor2 = "", ""
        self.fixusers = []

###############################################################################

    def report(self):
        try:
            self.detailedresults = ""
            self.ch = CommandHelper(self.logger)
            self.lockedpwds = '^\*LK\*|^!|^\*|^x$'
            if self.environ.getosfamily() == "linux":
                self.ph = Pkghelper(self.logger, self.environ)
                self.specs = {"PASS_MAX_DAYS": "180",
                              "PASS_MIN_DAYS": "1",
                              "PASS_MIN_LEN": "8",
                              "PASS_WARN_AGE": "28"}
                if self.ph.manager in ("apt-get", "zypper"):
                    # apt-get systems do not set min length in the same file
                    # as other systems(login.defs)
                    del self.specs["PASS_MIN_LEN"]

                self.shadowfile = "/etc/shadow"
                self.logdeffile = "/etc/login.defs"
                self.useraddfile = "/etc/default/useradd"
                self.libuserfile = "/etc/libuser.conf"
                self.compliant = self.reportLinux()
            elif self.environ.getosfamily() == "solaris":
                self.specs = {"PASSLENGTH": "8",
                              "MINWEEKS": "1",
                              "MAXWEEKS": "26",
                              "WARNWEEKS": "4"}
                self.shadowfile = "/etc/shadow"
                self.logdeffile = "/etc/default/passwd"
                self.compliant = self.reportSolaris()
            elif self.environ.getosfamily() == "freebsd":
                self.specs = {"warnpassword": "28d",
                              "minpasswordlen": "8",
                              "passwordtime": "180d"}
                self.shadowfile = "/etc/master.passwd"
                self.loginfile = "/etc/login.conf"
                self.compliant = self.reportFreebsd()
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

    def reportLinux(self):
        compliant1 = self.checklogindefs()
        compliant2 = self.chkShadow()
        compliant3 = self.chkUserAdd()
        compliant4 = self.checklibuser()
        if compliant1 and compliant2 and compliant3 and compliant4:
            return True
        else:
            return False

###############################################################################

    def reportSolaris(self):
        compliant1 = self.checklogindefs()
        compliant2 = self.chkShadow()
        if compliant1 and compliant2:
            return True
        else:
            return False

###############################################################################

    def reportFreebsd(self, specs):
        compliant1 = self.chkPasswd()
        compliant2 = self.chkLogin(specs)
        if compliant1 and compliant2:
            return True
        else:
            return False

###############################################################################

    def checklogindefs(self):
        '''report method for various distros of linux and solaris'''
        compliant = True
        debug = ""
        if not os.path.exists(self.logdeffile):
            compliant = False
            self.detailedresults += self.logdeffile + " file does not exist\n"
        elif not checkPerms(self.logdeffile, [0, 0, 0o644], self.logger):
            compliant = False
            self.detailedresults += self.logdeffile + " does not have " + \
                "the correct permissions. Expected 644, found " + \
                str(getOctalPerms(self.logdeffile)) + ".\n"
        tmpfile = self.logdeffile + ".tmp"
        self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                      "conf", self.logdeffile, tmpfile,
                                      self.specs, "present", "space")
        if not self.editor1.report():
            self.detailedresults += self.logdeffile + " does not " + \
                "contain the correct contents\n"
            debug = self.logdeffile + " doesn't contain the correct " + \
                "contents\n"
            self.logger.log(LogPriority.DEBUG, debug)
            compliant = False

        return compliant

###############################################################################

    def chkShadow(self):
        debug = ""
        compliant = True
        if os.path.exists(self.shadowfile):
            if self.ph.manager == "apt-get":
                statdata = os.stat(self.shadowfile)
                mode = stat.S_IMODE(statdata.st_mode)
                retval = getUserGroupName(self.shadowfile)
                if retval[0] != "root" or retval[1] != "shadow":
                    compliant = False
                    self.detailedresults += self.shadowfile + " ownership " + \
                        "is not correct (either owner is not root, or " + \
                        "group is not shadow).\n"
                if mode != 0o640:
                    compliant = False
                    self.detailedresults += self.shadowfile + " does not have " + \
                        "the correct permissions. Expected 640, found " + \
                        str(getOctalPerms(self.shadowfile)) + ".\n"
            elif not checkPerms(self.shadowfile, [0, 0, 0o400], self.logger) and \
                 not checkPerms(self.shadowfile, [0, 0, 0], self.logger):
                compliant = False
                self.detailedresults += self.shadowfile + " does not have " + \
                    "the correct permissions. Expected 400 or 0, found " + \
                    str(getOctalPerms(self.shadowfile)) + ".\n"
            contents = readFile(self.shadowfile, self.logger)
            if self.environ.getosfamily() == "solaris" or \
               self.environ.getosfamily() == "linux":
                if self.environ.getosfamily() == "linux":
                    whichid = "/usr/bin/id"
                elif self.environ.getosfamily() == "solaris":
                    whichid = "/usr/xpg4/bin/id"
                for line in contents:
                    badacct = False
                    debug = ""
                    if re.search("^\#", line) or re.match("^\s*$", line):
                        continue
                    if re.search(":", line):
                        field = line.split(":")
                        cmd = [whichid, "-u", field[0]]
                        self.ch.executeCommand(cmd)
                        output = self.ch.getOutputString().strip()
                        error = self.ch.getError()
                        if error:
                            continue
                        if output:
                            if output.isdigit():
                                uid = int(output)
                            else:
                                uid = 100
                        else:
                            continue
                        try:
                            if uid >= 500 and not re.search(self.lockedpwds,
                                                            field[1]):
                                for i in [3, 4, 5, 6]:
                                    if field[i]:
                                        val = field[i]
                                        if val.isdigit():
                                            field[i] = int(field[i])
                                        elif i == 6:
                                            field[i] = 99
                                        else:
                                            field[i] = 0
                                    elif i == 6:
                                        field[i] = 99
                                    else:
                                        field[i] = 0
                                if field[3] != 1 or field[3] == "":
                                    compliant = False
                                    self.detailedresults += "Shadow file: " + \
                                        "Minimum age is not equal to 1\n"
                                    badacct = True
                                if field[4] > 180 or field[4] == "":
                                    compliant = False
                                    self.detailedresults += "Shadow file: " + \
                                        "Expiration is not 180 or less\n"
                                    badacct = True
                                if field[5] != 28 or field[5] == "":
                                    compliant = False
                                    self.detailedresults += "Shadow file: " + \
                                        "Password expiration warnings are " + \
                                        "not set to 28 days\n"
                                    badacct = True
                                if field[6] != 35 or field[6] == "":
                                    compliant = False
                                    self.detailedresults += "Shadow file: " + \
                                        "Account lock is not set to 35 days\n"
                                    badacct = True
                        except IndexError:
                            compliant = False
                            debug = traceback.format_exc()
                            debug += ' Index out of range\n'
                            badacct = True
                        if debug:
                            self.logger.log(LogPriority.DEBUG, debug)
                    if badacct:
                        self.fixusers.append(field[0])
            if self.environ.getosfamily() == 'freebsd':
                for line in contents:
                    debug = ""
                    if re.search("^\#", line) or re.match('^\s*$', line):
                        continue
                    if re.search(':', line):
                        field = line.split(':')
                        message = Popen(['/usr/bin/id', '-u', field[0]],
                                        stderr=PIPE, stdout=PIPE, shell=False)
                        uid = message.stdout.readline()
                        uid = uid.strip()
                        message.stdout.close()
                        if uid.isdigit():
                            uid = int(uid)
                        else:
                            uid = 100
                        try:
                            if uid >= 500 and not re.search(self.lockedpwds,
                                                            field[1]):
                                for i in [5, 6]:
                                    if field[i]:
                                        val = field[i]
                                        if not val.isdigit():
                                            field[i] = 0
                                    else:
                                        field[i] = 0

                                if int(field[5]) > 180 or field[5] == "":
                                    self.shadow = False
                                    compliant = False
                                    debug += "expiration is not 180 or less"
                                if int(field[6]) != 1 or field[6] == "":
                                    self.shadow = False
                                    compliant = False
                                    debug += "Account lock is not set to 1"
                        except IndexError:
                            self.shadow = False
                            compliant = False
                            debug = traceback.format_exc()
                            debug += ' Index out of range'
                            self.logger.log(LogPriority.DEBUG, debug)
                        if debug:
                            self.logger.log(LogPriority.DEBUG, debug)
        else:
            self.detailedresults += self.shadowfile + " does not exist\n"
            compliant = False
        debug = "chkShadow method is returning " + str(compliant) + \
            " compliance\n"
        self.logger.log(LogPriority.DEBUG, debug)
        return compliant

###############################################################################

    def chkUserAdd(self):
        compliant = True
        debug = ""
        if not os.path.exists(self.useraddfile):
            self.detailedresults += self.useraddfile + " file does not exist\n"
            compliant = False
        else:
            if not checkPerms(self.useraddfile, [0, 0, 0o600], self.logger):
                compliant = False
                self.detailedresults += self.useraddfile + " does not have " + \
                    "the correct permissions. Expected 600, found " + \
                    str(getOctalPerms(self.useraddfile)) + ".\n"
            contents = readFile(self.useraddfile, self.logger)
            found = False
            valcorrect = True
            for line in contents:
                if re.search("^\#", line) or re.match('^\s*$', line):
                    continue
                if re.search('^INACTIVE', line.strip()) and re.search('=',
                                                                      line):
                    found = True
                    temp = line.split('=')
                    if int(temp[1].strip()) <= -1 or int(temp[1].strip()) > 35:
                        valcorrect = False
                        break
            if not found:
                compliant = False
                self.detailedresults += "INACTIVE key was not found in " + \
                    self.useraddfile + "\n"
            if found and not valcorrect:
                compliant = False
                self.detailedresults += "INACTIVE key was found in " + \
                    self.useraddfile + ", but value is incorrect\n"
        debug += "chkUserAdd method is returning " + str(compliant) + \
            " compliance\n"
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return compliant

###############################################################################

    def checklibuser(self):
        '''Private method to check the password hash algorithm settings in
        libuser.conf.
        @author: dwalker


        :returns: bool

        '''
        compliant = True
        '''check if libuser is intalled'''
        if not self.ph.check("libuser"):
            '''if not, check if available'''
            if self.ph.checkAvailable("libuser"):
                self.detailedresults += "libuser available but not installed\n"
                return False
            else:
                '''not available, not a problem'''
                return True
        '''create a kveditor for file if it exists, if not, we do it in
        the setlibuser method inside the fix'''
        if os.path.exists(self.libuserfile):
            data = {"userdefaults": {"LU_SHADOWMAX": "",
                                     "LU_SHADOWMIN": "",
                                     "LU_SHADOWWARNING": "",
                                     "LU_UIDNUMBER": "",
                                     "LU_SHADOWINACTIVE": "",
                                     "LU_SHADOWEXPIRE": ""}}
            datatype = "tagconf"
            intent = "notpresent"
            tmppath = self.libuserfile + ".tmp"
            self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                          datatype, self.libuserfile,
                                          tmppath, data, intent, "openeq")
            if not self.editor2.report():
                debug = "/etc/libuser.conf doesn't contain the correct " + \
                    "contents\n"
                self.detailedresults += "/etc/libuser.conf doesn't " + \
                    "contain the correct contents\n"
                self.logger.log(LogPriority.DEBUG, debug)
                compliant = False
            if not checkPerms(self.libuserfile, [0, 0, 0o644], self.logger):
                self.detailedresults += "Permissions are incorrect on " + \
                    self.libuserfile + "\n"
                compliant = False
        else:
            self.detailedresults += "Libuser installed but libuser " + \
                "file doesn't exist\n"
            compliant = False
        return compliant


###############################################################################

    def chkLogin(self):
        compliant = True
        if os.path.exists(self.loginfile):
            if not checkPerms(self.loginfile, [0, 0, 0o644], self.logger):
                compliant = False
                self.detailedresults += self.libuserfile + " does not have " + \
                    "the correct permissions. Expected 644, found " + \
                    str(getOctalPerms(self.libuserfile)) + ".\n"
            contents = readFile(self.loginfile, self.logger)
            iterator1 = 0
            for line in contents:
                if re.search("^#", line) or re.match('^\s*$', line):
                    iterator1 += 1
                elif re.search('^default:\\\\$', line.strip()):
                    found = True
                    temp = contents[iterator1 + 1:]
                    length2 = len(temp) - 1
                    iterator2 = 0
                    for line2 in temp:
                        if re.search('^[^:][^:]*:\\\\$', line2):
                            contents2 = temp[:iterator2]
                            break
                        elif iterator2 < length2:
                            iterator2 += 1
                        elif iterator2 == length2:
                            contents2 = temp[:iterator2]
                    break
                else:
                    iterator1 += 1
            if contents2:
                for key in self.Fspecs:
                    found = False
                    for line in contents2:
                        if re.search("^#", line) or re.match('^\s*$', line):
                            continue
                        elif re.search('^:' + key, line.strip()):
                            if re.search('=', line):
                                temp = line.split('=')
                                if re.search(str(self.Fspecs[key]) +
                                             '(:\\\\|:|\\\\|\s)',
                                             temp[1]):
                                    found = True
                                    continue
                                else:
                                    found = False
                                    break
                    if not found:
                        compliant = False
            return compliant
        else:
            self.detailedresults += self.loginfile + "does not exist. " + \
                "Please note that the fix for this rule will not attempt " + \
                "to create this file.\n"
            compliant = False
        debug = "chkLogin method is returning " + (compliant) + " compliance\n"
        self.logger.log(LogPriority.DEBUG, debug)
        return compliant

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""

            # clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.environ.getosfamily() == "linux":
                self.rulesuccess = self.fixLinux()
            if self.environ.getosfamily() == "solaris":
                self.rulesuccess = self.fixSolaris()
            if self.environ.getosfamily() == "freebsd":
                self.rulesuccess = self.fixFreebsd()
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################

    def fixLinux(self):
        success1 = self.fixLogDef(self.specs)
        success2 = self.fixShadow()
        success3 = self.fixUserAdd()
        success4 = self.setlibuser()
        if success1 and success2 and success3 and success4:
            return True
        else:
            return False

###############################################################################

    def fixSolaris(self):
        success1 = self.fixLogDef()
        success2 = self.fixShadow()
        if success1 and success2:
            return True
        else:
            return False

###############################################################################

    def fixFreebsd(self):
        success1 = self.fixPasswd()
        success2 = self.fixLogin()
        if success1 and success2:
            return True
        else:
            return False

###############################################################################

    def fixLogDef(self, specs):
        success = True
        debug = ""
        if not os.path.exists(self.logdeffile):
            if createFile(self.logdeffile, self.logger):
                self.logindefcreate = True
                setPerms(self.logdeffile, [0, 0, 0o644], self.logger)
                tmpfile = self.logdeffile + ".tmp"
                self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", self.logdeffile, tmpfile,
                                              specs, "present", "space")
            else:
                self.detailedresults += "Was not able to create " + \
                    self.logdeffile + " file\n"
                success = False
        if self.logindefcreate:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": self.logdeffile}
            self.statechglogger.recordchgevent(myid, event)
        elif not checkPerms(self.logdeffile, [0, 0, 0o644], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(self.logdeffile, [0, 0, 0o644], self.logger,
                            self.statechglogger, myid):
                debug += "permissions not correct on: " + \
                    self.logdeffile + "\n"
                success = False
        if self.editor1.fixables or self.editor1.removeables:
            if not self.logindefcreate:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.editor1.setEventID(myid)
            if not self.editor1.fix():
                debug += "fixLogDef editor.fix did not complete successfully\n"
                success = False
            elif not self.editor1.commit():
                debug += "fixLogDef editor.commit did not complete successfully\n"
                success = False
            os.chown(self.logdeffile, 0, 0)
            os.chmod(self.logdeffile, 0o644)
            resetsecon(self.logdeffile)
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return success

###############################################################################

    def fixShadow(self):
        success = True
        if not os.path.exists(self.shadowfile):
            self.detailedresults += self.shadowfile + "does not exist. \
Will not perform fix on shadow file\n"
            return False
        if self.fixusers:
            contents = readFile(self.shadowfile, self.logger)

            if self.ph.manager == "apt-get":
                perms = [0, 42, 0o640]
            else:
                perms = [0, 0, 0o400]
            if not checkPerms(self.shadowfile, perms, self.logger) and \
               not checkPerms(self.shadowfile, [0, 0, 0], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                setPerms(self.shadowfile, perms, self.logger,
                         self.statechglogger, myid)

            tmpdate = strftime("%Y%m%d")
            tmpdate = list(tmpdate)
            date = tmpdate[0] + tmpdate[1] + tmpdate[2] + tmpdate[3] + "-" + \
                tmpdate[4] + tmpdate[5] + "-" + tmpdate[6] + tmpdate[7]
            for user in self.fixusers:
                cmd = ["chage", "-d", date, "-m", "1", "-M", "180", "-W", "28",
                       "-I", "35", user]
                self.ch.executeCommand(cmd)

            # We have to do some gymnastics here, because chage writes directly
            # to /etc/shadow, but statechglogger expects the new contents to
            # be in a temp file.
            newContents = readFile(self.shadowfile, self.logger)
            shadowTmp = "/tmp/shadow.stonixtmp"
            createFile(shadowTmp, self.logger)
            writeFile(shadowTmp, "".join(newContents) + "\n", self.logger)
            writeFile(self.shadowfile, "".join(contents) + "\n", self.logger)
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype': 'conf',
                     'filepath': self.shadowfile}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(self.shadowfile, shadowTmp,
                                                 myid)
            shutil.move(shadowTmp, self.shadowfile)
            os.chmod(self.shadowfile, perms[2])
            os.chown(self.shadowfile, perms[0], perms[1])
            resetsecon(self.shadowfile)
        return success

###############################################################################

    def fixUserAdd(self):
        success = True
        if not os.path.exists(self.useraddfile):
            if createFile(self.useraddfile, self.logger):
                self.useraddcreate = True
                setPerms(self.useraddfile, [0, 0, 0o600], self.logger)
            else:
                self.detailedresults += self.useraddfile + \
                    " could not be created\n"
                success = False
        if self.useraddcreate:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": self.useraddfile}
            self.statechglogger.recordchgevent(myid, event)

        if not checkPerms(self.useraddfile, [0, 0, 0o600], self.logger):
            if not self.useraddcreate:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.useraddfile, [0, 0, 0o600],
                                self.logger, self.statechglogger, myid):
                    self.detailedresults += "Could not set permissions on " + \
                        self.useraddfile
                    success = False
        tempstring = ""
        contents = readFile(self.useraddfile, self.logger)
        found = False
        for line in contents:
            if re.search("^\#", line) or re.match('^\s*$', line):
                tempstring += line
                continue
            if re.search("^INACTIVE", line.strip()):
                if re.search("=", line):
                    temp = line.split("=")
                    if int(temp[1].strip()) <= -1 or \
                       int(temp[1].strip()) > 35:
                        continue
                    else:
                        found = True
                        tempstring += line
                else:
                    continue
            elif re.search("^" + self.universal, line.strip()):
                continue
            else:
                tempstring += line
        if not found:
            tempstring += "INACTIVE=35\n"
        tmpfile = self.useraddfile + ".tmp"
        if not writeFile(tmpfile, tempstring, self.logger):
            return False
        if not self.useraddcreate:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype': 'conf',
                     'filepath': self.useraddfile}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(self.useraddfile, tmpfile,
                                                 myid)
        shutil.move(tmpfile, self.useraddfile)
        os.chown(self.useraddfile, 0, 0)
        os.chmod(self.useraddfile, 0o600)
        resetsecon(self.useraddfile)
        return success

###############################################################################

    def setlibuser(self):
        success = True
        debug = ""
        created = False
        data = {"userdefaults": {"LU_SHADOWMAX": "",
                                 "LU_SHADOWMIN": "",
                                 "LU_SHADOWWARNING": "",
                                 "LU_UIDNUMBER": "",
                                 "LU_SHADOWINACTIVE": "",
                                 "LU_SHADOWEXPIRE": ""}}
        '''check if installed'''
        if not self.ph.check("libuser"):
            '''if not installed, check if available'''
            if self.ph.checkAvailable("libuser"):
                '''if available, install it'''
                if not self.ph.install("libuser"):
                    self.detailedresults += "Unable to install libuser\n"
                    return False
                else:
                    '''since we're just now installing it we know we now
                    need to create the kveditor'''
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    comm = self.ph.getRemove()
                    event = {"eventtype": "commandstring",
                             "command": comm}
                    self.statechglogger.recordchgevent(myid, event)
                    datatype = "tagconf"
                    intent = "notpresent"
                    tmppath = self.libuserfile + ".tmp"
                    self.editor2 = KVEditorStonix(self.statechglogger,
                                                  self.logger, datatype,
                                                  self.libuserfile, tmppath,
                                                  data, intent, "openeq")
                    self.editor2.report()
            else:
                return True
        if not os.path.exists(self.libuserfile):
            if not createFile(self.libuserfile, self.logger):
                self.detailedresults += "Unable to create libuser file\n"
                debug = "Unable to create the libuser file\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
            created = True
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": self.libuserfile}
            self.statechglogger.recordchgevent(myid, event)
            tmppath = self.libuserfile + ".tmp"
            self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                          "tagconf", self.libuserfile,
                                          tmppath, data,
                                          "notpresent", "openeq")
            self.editor2.report()
        if not checkPerms(self.libuserfile, [0, 0, 0o644], self.logger):
            if not created:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.libuserfile, [0, 0, 0o644],
                                self.logger, self.statechglogger, myid):
                    self.detailedresults += "Could not set permissions on " + \
                        self.libuserfile
                    success = False
            elif not setPerms(self.libuserfile, [0, 0, 0o644], self.logger):
                success = False
                self.detailedresults += "Unable to set the " + \
                        "permissions on " + self.libuserfile + "\n"
        if self.editor2.removeables:
            if not created:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.editor2.setEventID(myid)
            if self.editor2.fix():
                if self.editor2.commit():
                    debug += "/etc/libuser.conf has been corrected\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    os.chown(self.libuserfile, 0, 0)
                    os.chmod(self.libuserfile, 0o644)
                    resetsecon(self.libuserfile)
                else:
                    self.detailedresults += "/etc/libuser.conf " + \
                        "couldn't be corrected\n"
                    success = False
            else:
                self.detailedresults += "/etc/libuser.conf couldn't " + \
                    "be corrected\n"
                success = False
        return success

###############################################################################

    def fixLogin(self):
        success = True
        tempstring = ""
        debug = ""
        if not os.path.exists(self.loginfile):
            self.detailedresults = self.loginfile + "does not exist. \
Will not perform fix on useradd file\n"
            return False
        if not checkPerms(self.loginfile, [0, 0, 0o644], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(self.loginfile, [0, 0, 0o644], self.logger,
                            self.statechglogger, myid):
                success = False
        contents = readFile(self.loginfile, self.logger)
        iterator1 = 0
        for line in contents:
            if re.search("^#", line) or re.match('^\s*$', line):
                iterator1 += 1
            elif re.search('^default:\\\\$', line.strip()):
                contents1 = contents[:iterator1 + 1]
                temp = contents[iterator1 + 1:]
                length2 = len(temp) - 1
                iterator2 = 0
                for line2 in temp:
                    if re.search('^[^:][^:]*:\\\\$', line2):
                        contents3 = temp[iterator2:]
                        contents2 = temp[:iterator2]
                        break
                    elif iterator2 < length2:
                        iterator2 += 1
                    elif iterator2 == length2:
                        contents2 = temp[:iterator2]
                break
            else:
                iterator1 += 1
        if contents2:
            for key in self.Fspecs:
                iterator = 0
                found = False
                for line in contents2:
                    if re.search("^#", line) or re.match('^\s*$', line):
                        iterator += 1
                        continue
                    elif re.search('^:' + key, line.strip()):
                        if re.search('=', line):
                            temp = line.split('=')
                            if re.search(str(self.Fspecs[key]) +
                                         '(:\\\\|:|\\\\|\s)',
                                         temp[1]):
                                iterator += 1
                                found = True
                            else:
                                contents2.pop(iterator)
                    else:
                        iterator += 1
                if not found:
                    contents2.append('\t' + key + '=' + str(self.Fspecs[key]) +
                                     ':\\\\\n')
        final = []
        for line in contents1:
            final.append(line)
        for line in contents2:
            final.append(line)
        for line in contents3:
            final.append(line)
        for line in final:
            tempstring += line
        debug += "tempstring to be written to: " + self.loginfile + "\n"
        self.logger.log(LogPriority.DEBUG, debug)
        tmpfile = self.loginfile + ".tmp"
        if writeFile(tmpfile, tempstring, self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype': 'conf',
                     'filepath': self.loginfile}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(self.loginfile, tmpfile, myid)
            shutil.move(tmpfile, self.loginfile)
            os.chown(self.loginfile, 0, 0)
            os.chmod(self.loginfile, 0o644)
            resetsecon(self.loginfile)
        else:
            success = False
        return success
