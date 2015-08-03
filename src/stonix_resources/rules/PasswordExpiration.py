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
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, writeFile, readFile, resetsecon, getUserGroupName
from ..stonixutilityfunctions import checkPerms, setPerms, createFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix
from ..CommandHelper import CommandHelper
from ..pkghelper import Pkghelper
from time import strftime
from subprocess import Popen, PIPE
import traceback
import re
import os
import stat


class PasswordExpiration(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 42
        self.rulename = "PasswordExpiration"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rule configures the password configuration " + \
        "for each entry in the shadow file and any other files that " + \
        "pertain to pw expiration, length, warning time, etc.  ***For " + \
        "solaris, please be aware, that there is no undo for the content " + \
        "change of the shadow file but there will be a permissions change " + \
        "undo if the permissions were originally incorrect"
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
        self.libusercreate, self.libuserinstall, self.useraddcreate, self.logindefcreate = False, False, False, False
        self.fixable, self.shadow = True, True
        self.editor1, self.editor2 = "", ""
        self.fixusers = []

###############################################################################

    def report(self):
        try:
            self.detailedresults = ""
            self.ch = CommandHelper(self.logger)
            self.lockedpwds = '^\*LK\*|^!|^\*|^x$'
            self.libuseritems = {"userdefaults": {"LU_SHADOWMAX": "",
                                                  "LU_SHADOWMIN": "",
                                                  "LU_SHADOWWARNING": "",
                                                  "LU_UIDNUMBER": "",
                                                  "LU_SHADOWINACTIVE": "",
                                                  "LU_SHADOWEXPIRE": ""}}
            if self.environ.getosfamily() == "linux":
                self.ph = Pkghelper(self.logger, self.environ)
                self.specs = {"PASS_MAX_DAYS": "180",
                              "PASS_MIN_DAYS": "7",
                              "PASS_MIN_LEN": "8",
                              "PASS_WARN_AGE": "28"}
                if self.ph.manager == "apt-get":
                    #apt-get systems don't set min length in the same file
                    #as other systems(login.defs)
                    del self.specs["PASS_MIN_LEN"]

                self.shadowfile = "/etc/shadow"
                self.logdeffile = "/etc/login.defs"
                self.useraddfile = "/etc/default/useradd"
                if self.ph.manager == "apt-get":
                    self.libuser = "python-libuser"
                else:
                    self.libuser = "libuser"
                if self.ph.manager == "zypper":
                    self.libuserfile = "/var/lib/YaST2/users_first_stage.ycp"
                else:
                    self.libuserfile = "/etc/libuser.conf"
                self.pamfile = "/etc/pam.d/common-password"
                self.compliant = self.reportLinux(self.specs)
            elif self.environ.getosfamily() == "solaris":
                self.specs = {"PASSLENGTH": "8",
                              "MINWEEKS": "1",
                              "MAXWEEKS": "26",
                              "WARNWEEKS": "4"}
                self.shadowfile = "/etc/shadow"
                self.logdeffile = "/etc/default/passwd"
                self.compliant = self.reportSolaris(self.specs)
            elif self.environ.getosfamily() == "freebsd":
                self.specs = {#'warnexpire':'28d',
                              "warnpassword": "28d",
                              "minpasswordlen": "8",
                              "passwordtime": "180d"}
                self.shadowfile = "/etc/master.passwd"
                self.loginfile = "/etc/login.conf"
                self.compliant = self.reportFreebsd(self.specs)
            if self.compliant:
                self.detailedresults += "PasswordExpiration report has " + \
                    "been run and the system is compliant\n"
            else:
                self.detailedresults += "PasswordExpiration report has " + \
                    "been run and the system is not compliant\n"
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

    def reportLinux(self, specs):
        compliant1 = self.chkLogDef(specs)
        compliant2 = self.chkShadow()
        compliant3 = self.chkUserAdd()
        compliant4 = self.chkLibUsers()
        if self.ph.manager == "apt-get":
            compliant5 = self.chkPam()
        else:
            compliant5 = True
        if compliant1 and compliant2 and compliant3 and compliant4 and compliant5:
            return True
        else:
            return False

###############################################################################

    def reportSolaris(self, specs):
        compliant1 = self.chkLogDef(specs)
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

    def chkLogDef(self, specs):
        '''report method for various distros of linux and solaris'''
        compliant = True
        debug = ""
        if not os.path.exists(self.logdeffile):
            if createFile(self.logdeffile, self.logger):
                self.logindefcreate = True
                setPerms(self.logdeffile, [0, 0, 420], self.logger)
                tmpfile = self.logdeffile + ".tmp"
                self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", self.logdeffile, tmpfile,
                                              specs, "present", "space")
                if not self.editor1.report():
                    debug += self.logdeffile + " doesn't contain the " + \
                        "correct contents\n"
                    compliant = False
            else:
                self.detailedresults += "Wasn't able to create " + \
                    self.logdeffile + " file\n"
                compliant = False
        else:
            if not checkPerms(self.logdeffile, [0, 0, 420], self.logger):
                compliant = False
            tmpfile = self.logdeffile + ".tmp"
            self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                          "conf", self.logdeffile, tmpfile,
                                          specs, "present", "space")
            if not self.editor1.report():
                debug += "chkLogDef editor.report is not compliant\n"
                compliant = False
        debug += "chkLogDef method is returning " + str(compliant) + \
            " compliance\n"
        self.logger.log(LogPriority.DEBUG, debug)
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
                if mode != 416:
                    compliant = False
            elif not checkPerms(self.shadowfile, [0, 0, 256], self.logger) and \
                not checkPerms(self.shadowfile, [0, 0, 0], self.logger):
                compliant = False
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
                            if uid >= 500 and not re.search(self.lockedpwds, field[1]):
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
                                if field[3] < 7 or field[3] == "":
                                    compliant = False
                                    debug += "field 4 not equal to 7 in shadow\n"
                                    badacct = True
                                if field[4] > 180 or field[4] == "":
                                    compliant = False
                                    debug += "expiration is not 180 or less\n"
                                    badacct = True
                                if field[5] < 28 or field[5] == "":
                                    compliant = False
                                    debug += "warnings not set to 28 days\n"
                                    badacct = True
                                if field[6] > 7 or field[6] == "":
                                    compliant = False
                                    debug += "Account lock is not set to 7\n"
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
                            if uid >= 500 and not re.search(self.lockedpwds, field[1]):
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
                                if int(field[6]) > 7 or field[6] == "":
                                    self.shadow = False
                                    compliant = False
                                    debug += "Account lock is not set to 7"
                        except IndexError:
                            self.shadow = False
                            compliant = False
                            debug = traceback.format_exc()
                            debug += ' Index out of range'
                            self.logger.log(LogPriority.DEBUG, debug)
                        if debug:
                            self.logger.log(LogPriority.DEBUG, debug)
        else:
            self.detailedresults += self.shadowfile + " doesn't exist\n"
            compliant = False
        debug = "chkShadow method is returning " + str(compliant) + " compliance\n"
        self.logger.log(LogPriority.DEBUG, debug)
        return compliant

###############################################################################

    def chkUserAdd(self):
        compliant = True
        debug = ""
        if not os.path.exists(self.useraddfile):
            if createFile(self.useraddfile, self.logger):
                self.useraddcreate = True
                setPerms(self.useraddfile, [0, 0, 384], self.logger)
            else:
                debug += self.useraddfile + " couldn't be created\n"
                compliant = False
        else:
            if not checkPerms(self.useraddfile, [0, 0, 384], self.logger):
                compliant = False
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
                debug += "INACTIVE key was not found in or" + \
                    self.useraddfile + "\n"
            if found and not valcorrect:
                compliant = False
                debug += "INACTIVE key was found but value is incorrect\n"
        debug += "chkUserAdd method is returning " + str(compliant) + \
            " compliance\n"
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return compliant

###############################################################################

    def chkLibUsers(self):
        compliant = True
        debug = ""
        if re.search("Debian", self.environ.getostype()) or self.ph.manager == "zypper":
            return True
        if not self.ph.check(self.libuser):
            debug += "libuser not installed\n"
            self.detailedresults += "libuser not installed\n"
            compliant = False

        if os.path.exists(self.libuserfile):

            #check permissions on /etc/libuser.conf
            if not checkPerms(self.libuserfile, [0, 0, 420], self.logger):
                self.detailedresults += "permissions incorrect on " + \
                    self.libuserfile + "\n"
                debug += "permissions incorrect on " + self.libuserfile
                compliant = False
            tmpfile = self.libuserfile + ".tmp"
            #create the libuser configuration file editor
            self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                          "tagconf", self.libuserfile, tmpfile,
                                          self.libuseritems, "notpresent",
                                          "openeq")
            #check the contents of /etc/libuser.conf
            if not self.editor2.report():
                self.detailedresults += self.libuserfile + " doesn't " + \
                    "contain the correct contents\n"
                debug += self.libuserfile + " doesn't contain the correct " + \
                    "contents\n"
                compliant = False
        else:
            self.detailedresults += self.libuserfile + " doesn't exist\n"
            debug += self.libuserfile + " doesn't exist\n"
            compliant = False
        debug += "chkLibUsers method is returning " + str(compliant) + \
            " compliance\n"
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return compliant

###############################################################################

    def chkLogin(self):
        compliant = True
        if os.path.exists(self.loginfile):
            if not checkPerms(self.loginfile, [0, 0, 420], self.logger):
                compliant = False
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
                                if re.search(str(self.Fspecs[key]) + '(:\\\\|:|\\\\|\s)', temp[1]):
                                    found = True
                                    continue
                                else:
                                    found = False
                                    break
                    if not found:
                        compliant = False
            return compliant
        else:
            self.detailedresults += self.loginfile + "doesn't exist\n"
            compliant = False
        debug = "chkLogin method is returning " + (compliant) + " compliance\n"
        self.logger.log(LogPriority.DEBUG, debug)
        return compliant
    
###############################################################################

    def chkPam(self):
        compliant = True
        debug = ""
        contents = readFile(self.pamfile, self.logger)
        if not contents:
            msg = "Required pam file is blank.  This is a major problem\n"
            self.logger.log(LogPriority.DEBUG, msg)
            return False
        found = False
        for line in contents:
            if re.match("^password", line) and re.search("pam_unix.so", line):
                found = True
                break
        if found:
            found2 = False
            line = re.sub("\s+", " ", line)
            line = line.strip()
            temp = line.split()
            for item in temp:
                if re.search("minlen=", item):
                    length = item.split("=")
                    try:
                        if length[1] == "8":
                            found2 = True
                    except IndexError:
                        raise ("No value after = sign after minlen\n")
            if not found2:
                compliant = False
        else:
            compliant = False
            debug = "Didn't find the password line containing pam_unix.so\n"
        debug += "chkPam method is returning " + str(compliant) + " compliance\n"
        self.logger.log(LogPriority.DEBUG, debug)
        return compliant
    
###############################################################################

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""
            
            #clear out event history so only the latest fix is recorded
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
        success1 = self.fixLogDef()
        success2 = self.fixShadow()
        success3 = self.fixUserAdd()
        success4 = self.fixLibUsers()
        if self.ph.manager == "apt-get":
            success5 = self.fixPam()
        else:
            success5 = True
        if success1 and success2 and success3 and success4 and success5:
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

    def fixLogDef(self):
        success = True
        debug = ""
        if self.logindefcreate:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype":"creation",
                     "filepath": self.edior1.getPath()}
            self.statechglogger.recordchgevent(myid, event)
        if not checkPerms(self.logdeffile, [0, 0, 420], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(self.logdeffile, [0, 0, 420], self.logger,
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
            os.chmod(self.logdeffile, 420)
            resetsecon(self.logdeffile)
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return success
    
###############################################################################

    def fixShadow(self):
        success = True
        debug = ""
        date = ""
        contents = readFile(self.shadowfile, self.logger)
        if not os.path.exists(self.shadowfile) or not contents:
            self.detailedresults += self.shadowfile + "doesn't exist. \
Will not perform fix on shadow file\n"
            return False
        if self.ph.manager == "apt-get":
            statdata = os.stat(self.shadowfile)
            owner = statdata.st_uid
            group = statdata.st_gid
            mode = stat.S_IMODE(statdata.st_mode)
            retval = getUserGroupName(self.shadowfile)
            if retval[0] != "root" or retval[1] != "shadow" or mode != 416:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'perm',
                         'startstate': [owner, group, mode],
                         'endstate': [0, 42, 416],
                         'filepath': self.shadowfile}
                self.statechglogger.recordchgevent(myid, event)
                os.chown(self.shadowfile, 0, 42)
                os.chmod(self.shadowfile, 416)
        elif not checkPerms(self.shadowfile, [0, 0, 256], self.logger) and \
            not checkPerms(self.shadowfile, [0, 0, 0], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(self.shadowfile, [0, 0, 256], self.logger,
                                                    self.statechglogger, myid):
                debug = "unable to set permisssions on " + self.shadowfile + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                success = False
        tmpdate = strftime("%Y%m%d")
        tmpdate = list(tmpdate)
        date += tmpdate[0] + tmpdate[1] + tmpdate[2] + tmpdate[3] + "-" + \
        tmpdate[4] + tmpdate[5] + "-" + tmpdate[6] + tmpdate[7]
        if self.fixusers:
            for item in self.fixusers:
                cmd = ["chage", "-d", date, "-m", "7", "-M", "180", "-W", "28", "-I", "7", item]
                self.ch.executeCommand(cmd)
        #put in sections for bsd and solaris which both use passwd command
        return success

###############################################################################

    def fixUserAdd(self):
        success = True
        if not os.path.exists(self.useraddfile):
            self.detailedresults = self.useraddfile + "doesn't exist. \
Will not perform fix on useradd file\n"
            success = False
        else:
            if self.useraddcreate:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": self.useraddfile}
                self.statechglogger.recordchgevent(myid, event)

            if not checkPerms(self.useraddfile, [0, 0, 384], self.logger):
                if not self.useraddcreate:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.useraddfile, [0, 0, 384], self.logger,
                                    self.statechglogger, myid):
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
                        if int(temp[1].strip()) <= -1 or int(temp[1].strip()) > 35:
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
            os.rename(tmpfile, self.useraddfile)
            os.chown(self.useraddfile, 0, 0)
            os.chmod(self.useraddfile, 384)
            resetsecon(self.useraddfile)
        return success

###############################################################################

    def fixLibUsers(self):
        success = True
        debug = ""
        created = False
        if re.search("Debian", self.environ.getostype()) or self.ph.manager == "zypper":
            return True
        if not self.ph.check(self.libuser):
            if self.ph.checkAvailable(self.libuser):
                if not self.ph.install(self.libuser):
                    self.detailedresults += "Unable to install libuser\n"
                    return False
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    commandstring = self.ph.getRemove() + self.libuser
                    event = {"eventtype": "commandstring",
                             "command": commandstring}
                    self.statechglogger.recordchgevent(myid, event)
            else:
                self.detailedresults += "There is no libuser package " + \
                    "available for install on this platform\n"
                return False
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
        if os.path.exists(self.libuserfile):
            if not self.editor2:
                tpath = self.libuserfile + ".tmp"
                self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                              "tagconf", self.libuserfile,
                                              tpath, self.libuseritems,
                                              "notpresent", "openeq")
                self.editor2.report()
            if not checkPerms(self.libuserfile, [0, 0, 420], self.logger):
                if not created:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.libuserfile, [0, 0, 420],
                                    self.logger, self.stchlogger, myid):
                        success = False
                else:
                    if not setPerms(self.libuserfile, [0, 0, 420],
                                    self.logger):
                        success = False

            if self.editor2.fixables or self.editor2.removeables:
                if not created:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor2.setEventID(myid)
                if not self.editor2.fix():
                    debug += "Editor2.fix did not complete successfully\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                elif not self.editor2.commit():
                    debug += "Editor2.commit did not complete successfully\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
            os.chown(self.libuserfile, 0, 0)
            os.chmod(self.libuserfile, 420)
            resetsecon(self.libuserfile)
        return success

###############################################################################

    def fixLogin(self):
        success = True
        tempstring = ""
        debug = ""
        if not os.path.exists(self.loginfile):
            self.detailedresults = self.loginfile + "doesn't exist. \
Will not perform fix on useradd file\n"
            return False
        if not checkPerms(self.loginfile, [0, 0, 420], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(self.loginfile, [0, 0, 420], self.logger,
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
                            if re.search(str(self.Fspecs[key]) + '(:\\\\|:|\\\\|\s)', temp[1]):
                                iterator += 1
                                found = True
                            else:
                                contents2.pop(iterator)
                    else:
                        iterator += 1
                if not found:
                    contents2.append('\t' + key + '=' + str(self.Fspecs[key]) + ':\\\\\n')
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
            event = {'eventtype':'conf',
                     'filepath':self.loginfile}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(self.loginfile, tmpfile, myid)
            os.rename(tmpfile, self.loginfile)
            os.chown(self.loginfile, 0, 0)
            os.chmod(self.loginfile, 420)
            resetsecon(self.loginfile)
        else:
            success = False
        return success
    
###############################################################################

    def fixPam(self):
        '''
        fixes pam for debian based systems only
        @author: dwalker
        @return: bool
        '''
        success = True
        contents = readFile(self.pamfile, self.logger)
        if not contents:
            self.detailedresults += "Required pam file is blank.  This is " + \
            "a major problem\n"
            return False
        tempstring = ""
        for line in contents:
            if re.match("^password", line) and re.search("pam_unix.so", line):
                line = re.sub("\s+", " ", line)
                line = line.strip()
                temp = line.split()
                found = False
                for item in temp:
                    if re.search("minlen=", item):
                        found = True
                        length = item.split("=")
                        try:
                            if length[1] == "8":
                                found = True
                            else:
                                line = re.sub("minlen=.*[^\s]", "minlen=8", line)
                        except IndexError:
                            line = re.sub("minlen=.*[^\s]", "minlen=8", line)
                if not found:
                    line += " minlen=8\n"
                tempstring += line
            else:
                tempstring += line
        tmpfile = self.pamfile + ".tmp"
        if writeFile(tmpfile, tempstring, self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype':'conf',
                     'filepath':self.pamfile}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(self.pamfile, tmpfile, myid)
            os.rename(tmpfile, self.pamfile)
            os.chown(self.pamfile, 0, 0)
            os.chmod(self.pamfile, 420)
            resetsecon(self.pamfile)
        else:
            success = False
        return success