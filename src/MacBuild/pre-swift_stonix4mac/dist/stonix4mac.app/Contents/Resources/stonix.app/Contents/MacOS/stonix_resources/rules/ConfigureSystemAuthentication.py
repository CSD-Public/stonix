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
Created on Sep 11, 2013

@author: dwalker
@change: 2014/04/18 dkennel Implemented new style CI in place of old style.
@change: 2014/12/15 dkennel replaced print statement with logger debug call.
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2015/10/22 eball Rebased code in several spots for readability, and to
    correct logic errors (e.g. unreachable code, unused vars)
@change: 2016/01/25 eball - Changed pw policies to meet RHEL 7 STIG and
    CNSSI standards
'''
from __future__ import absolute_import

import os
import re
from subprocess import call
import traceback
from ..KVEditorStonix import KVEditorStonix
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..rule import Rule
from ..stonixutilityfunctions import iterate, setPerms, checkPerms, readFile, \
    writeFile, resetsecon, createFile


class ConfigureSystemAuthentication(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 57
        self.rulename = "ConfigureSystemAuthentication"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = """This rule configures the PAM stack for password \
requirements and failed login attempts. It also ensures the system uses \
SHA512 encryption.
There are three configuration items. Two of these \
configuration involve configuring PAM, PASSWORDREQ and PASSWORDFAIL. Please \
be advised, due to the complexity and sensitivity of PAM, portions of the PAM \
files that these two CIs configure will be completely overwritten, therefore \
if you have configured PAM with other modules, you may want to avoid enabling \
these two items and configure them by hand. Also, if on a yum-based package \
manager system such as Red Hat, Fedora, or CentOS, both PAM files have to \
receive the same contents. Due to this, no undo events will be recorded for \
the first two configuration items. However, backups will be made in the \
/etc/pam.d directory to restore them back to the way before the rule was run. \
Run these rules at your own risk. If your system uses portage for a package \
manager (i.e. Gentoo), you will need to do fix manually for all files except \
for the login.defs file"""
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd']}
        datatype = "bool"
        key = "CONFIGSYSAUTH"
        instructions = "To disable this rule, set the value of " + \
            "CONFIGSYSAUTH to False."
        default = True
        self.ci1 = self.initCi(datatype, key, instructions, default)

        datatype = "bool"
        key = "PASSWORDREQ"
        instructions = "To not configure password requirements, set " + \
            "PASSWORDREQ to False. This configuration item will configure " + \
            "PAM's password requirements when changing to a new password."
        default = True
        self.ci2 = self.initCi(datatype, key, instructions, default)

        datatype = "bool"
        key = "PASSWORDFAIL"
        instructions = "To not configure password fail locking, set " + \
            "PASSWORDFAIL to False. This configuration item will " + \
            "configure PAM's failed login attempts mechanism using either " + \
            "faillock or tally2."
        default = True
        self.ci3 = self.initCi(datatype, key, instructions, default)

        datatype = "bool"
        key = "PWHASHING"
        instructions = "To not set the hashing algorithm, set " + \
            "PWHASHING to False. This configuration item will configure " + \
            "libuser and/or login.defs, which specifies the hashing " + \
            "algorithm to use."
        default = True
        self.ci4 = self.initCi(datatype, key, instructions, default)

        self.guidance = ["NSA 2.3.3.1,", "NSA 2.3.3.2"]
        self.iditerator = 0
        self.created = False

    def report(self):
        '''
        ConfigureSystemAuthentication() report method to report if system
        is compliant with authentication and password settings
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''
        try:
            self.detailedresults = ""
            if self.environ.getosfamily() == "linux":
                self.compliant = self.reportLinux()
            elif self.environ.getosfamily() == "solaris":
                self.compliant = self.reportSolaris()
            elif self.environ.getosfamily() == "freebsd":
                self.compliant = self.reportFreebsd()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.compliant
###############################################################################

    def reportLinux(self):
        '''Linux specific submethod for linux distributions.
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''
        self.logindefs = "/etc/login.defs"
        debug = ""
        compliant = True
        self.editor1, self.editor2 = "", ""
        self.pwqeditor = ""
        self.ph = Pkghelper(self.logger, self.environ)
        self.pamsha512present = True
        if self.ph.manager == "apt-get":
            self.pam = "/etc/pam.d/common-password"
            self.pam2 = "/etc/pam.d/common-auth"
            self.cracklib = "libpam-cracklib"
            self.quality = "libpam-pwquality"
            self.libuserfile = "/etc/libuser.conf"
        elif self.ph.manager == "zypper":
            self.pam = "/etc/pam.d/common-password-pc"
            self.pam2 = "/etc/pam.d/common-auth-pc"
            self.cracklib = "cracklib"
            self.quality = "pam_pwquality"
            self.libuserfile = "/var/lib/YaST2/users_first_stage.ycp"
        else:
            self.pam = "/etc/pam.d/password-auth-ac"
            self.pam2 = "/etc/pam.d/system-auth-ac"
            self.cracklib = "cracklib"
            self.quality = "libpwquality"
            self.libuserfile = "/etc/libuser.conf"
        quality = "quality"
        cracklib = "cracklib"

        # This section to configure password regulations ######################
        if self.ph.manager == "apt-get":
            # for apt-get systems, pwquality doesn't work
            # we will use cracklib until pwquality is fixed
            if not self.chkpassword(cracklib):
                debug = "chkpassword() is not compliant\n"
                self.logger.log(LogPriority.DEBUG, debug)
                self.detailedresults += "Cracklib is not configured\n"
                compliant = False
        elif self.ph.check(self.quality):
            if not self.chkpassword(quality):
                debug = "chkpassword() is not compliant\n"
                self.logger.log(LogPriority.DEBUG, debug)
                self.detailedresults += "pwquality is not configured\n"
                compliant = False
        elif not self.ph.checkAvailable(self.quality):
            if self.ph.check(self.cracklib):
                if not self.chkpassword(cracklib):
                    debug = "chkpassword() is not compliant\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    self.detailedresults += "Cracklib is not configured\n"
                    compliant = False
            elif not self.ph.checkAvailable(self.cracklib):
                debug = "There is no password checking program " + \
                    "installed nor available on this system\n"
                self.logger.log(LogPriority.DEBUG, debug)
                self.detailedresults += "There is no password checking " + \
                    "program installed nor available for your system\n"
                compliant = False
            # cracklib is not installed but available for install
            else:
                debug = "cracklib not installed but is available\n"
                self.logger.log(LogPriority.DEBUG, debug)
                self.detailedresults += "This system will use cracklib " + \
                    "password checking program but is not installed.  " + \
                    "Will install and be configured when fix is run\n"
                compliant = False
        # pwquality is not installed but available for install
        else:
            debug = "pwquality not installed but is available\n"
            self.logger.log(LogPriority.DEBUG, debug)
            self.detailedresults += "This system will use pwquality " + \
                    "password checking program but is not installed.  " + \
                    "Will install and be configured when fix is run\n"
            compliant = False
        #######################################################################

        # check if pam file has correct contents for screen lock out
        if not self.chklockout():
            if self.ph.manager == "zypper":
                self.detailedresults += "zypper based systems do not have " + \
                    "a lockout program\n"
            else:
                debug = "Account locking configuration is incorrect\n"
                self.logger.log(LogPriority.DEBUG, debug)
                compliant = False

        # check if libuser file is present, if so check its contents
        if os.path.exists(self.libuserfile):
            if not self.chklibuserhash():
                debug = "chklibuserhash() is not compliant\n"
                self.logger.log(LogPriority.DEBUG, debug)
                compliant = False
        # check if the /etc/login.defs file has correct contents
        if not self.chkdefspasshash():
            debug = "chkdefspasshash() is not compliant\n"
            self.logger.log(LogPriority.DEBUG, debug)
            compliant = False
        return compliant

###############################################################################

    def reportSolaris(self):
        compliant = True
        self.pam = "/etc/pam.conf"
        self.config = readFile(self.pam, self.logger)
        if self.config:
            if not checkPerms(self.pam, [0, 0, 420], self.logger):
                compliant = False
            if os.path.exists("/usr/lib/security/pam_passwdqc.so"):
                if not self.chkpasswdqcCracklib():
                    compliant = False
        else:
            compliant = False
        if not self.chklockout():
            compliant = False
        if not self.chkpolicy():
            compliant = False
        return compliant

###############################################################################

    def reportFreebsd(self):
        '''no pam_tally2.so or pam_cracklib.so  available for freebsd'''
        compliant = True
        self.logindefs = "/etc/login.conf"
        self.pam = "/etc/pam.d/passwd"
        self.config = readFile(self.pam, self.logger)
        if self.config:
            if not checkPerms(self.pam2, [0, 0, 420], self.logger):
                compliant = False
            if self.chkpasswdqcinstall():
                if not self.chkpasswdqcCracklib():
                    compliant = False
            if not self.chkpampasshash():
                compliant = False
        if not self.chkdefspasshash():
            compliant = False
        return compliant

###############################################################################

    def fix(self):
        '''
        ConfigureSystemAuthentication.fix() method to fix the system to be
        compliant with authentication and password settings
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if fix is successful, False if it isn't
        '''
        try:
            if not self.ci1.getcurrvalue():
                return
            # delete past state change records from previous fix
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.environ.getosfamily() == "linux":
                self.rulesuccess = self.fixLinux()
            elif self.environ.getosfamily() == "freebsd":
                self.rulesuccess = self.fixFreebsd()
            elif self.environ.getosfamily() == "solaris":
                self.rulesuccess = self.fixSolaris()
            elif self.environ.getosfamily() == "darwin":
                self.rulesuccess = self.fixMac()
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
        '''
        Linux specific submethod to correct linux distributions.  If your
        system is portage based, i.e. gentoo, you will need to do a manual
        fix for everything except the login.defs file
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if fix is successful, False if it isn't
        '''

        success = True
        debug = ""
        self.detailedresults = ""
        usingcracklib, usingquality = False, False
        if self.ph.manager == "apt-get":
            isDebian = True
        else:
            isDebian = False
        createFile(self.pam + ".backup", self.logger)
        createFile(self.pam2 + ".backup", self.logger)
        if self.ci2.getcurrvalue():
            if self.ph.check(self.quality) and not isDebian:
                usingquality = True
            elif self.ph.checkAvailable(self.quality) and not isDebian:
                if not self.ph.install(self.quality):
                    debug = "Wasn't able to install pwquality, unable to " + \
                        "continue with the rest of the rule\n"
                    self.detailedresults += debug
                    self.logger.log(LogPriority.DEBUG, debug)
                    return False
                else:
                    usingquality = True
            elif self.ph.check(self.cracklib):
                usingcracklib = True
            elif self.ph.checkAvailable(self.cracklib):
                if not self.ph.install(self.cracklib):
                    debug = "Wasn't able to install cracklib, unable " + \
                        "to continue with the rest of the rule\n"
                    self.detailedresults += debug
                    self.logger.log(LogPriority.DEBUG, debug)
                    return False
                else:
                    usingcracklib = True
            else:
                debug = "There are no preferred password enforcement " + \
                    "pam modules available to install on this system.  " + \
                    "Unable to proceed with configuration\n"
                self.detailedresults += debug
                self.logger.log(LogPriority.DEBUG, debug)
                success = False

            if usingquality:
                package = "quality"
            elif usingcracklib:
                package = "cracklib"
            else:
                error = "Could not find pwquality/cracklib pam " + \
                    "module. Fix failed."
                self.logger.log(LogPriority.ERROR, error)
                self.detailedresults += error + "\n"
                return False
            if not self.setpassword(package):
                self.detailedresults += "Unable to set the pam password " + \
                    " authority\n"
                success = False
        if self.ci3.getcurrvalue():
            if self.ph.manager != "zypper": 
                if not self.chklockout():
                    if not self.setlockout():
                        self.detailedresults += "Unable to set the pam " + \
                            "lockout authority\n"
                        success = False
        if self.ci4.getcurrvalue():
            if not os.path.exists(self.libuserfile):
                if not self.pamsha512present:
                    if self.ph.checkAvailable("libuser"):
                        if self.ph.install("libuser"):
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            comm  = self.ph.getRemove()
                            event = {"eventtype": "commandstring",
                                     "command": comm}
                            self.statechglogger.recordchgevent(myid, event)
                            
            elif not self.chklibuserhash():
                if not self.setlibhash():
                    debug = "setlibhash() failed\n"
                    self.detailedresults += "Unable to configure " + \
                        "/etc/libuser.conf\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
            if not self.chkdefspasshash():
                if not self.setdefpasshash():
                    debug = "setdefpasshash() failed\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    self.detailedresults += "Unable to configure " + \
                        "/etc/login.defs file\n"
                    success = False
        return success

###############################################################################

    def fixSolaris(self):
        changed = False
        success = True
        if self.config:
            if not checkPerms(self.pam, [0, 0, 420], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.pam, [0, 0, 420], self.logger,
                                self.statechglogger, myid):
                    return False
            if not self.chkpasswdqc():
                if self.setpasswdqc():
                    changed = True
                else:
                    success = False
        if changed:
            tempstring = ""
            for line in self.config:
                tempstring += line
            tmpfile = self.pam + ".tmp"
            if writeFile(tmpfile, tempstring, self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': self.pam}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(self.pam, tmpfile, myid)
                os.rename(tmpfile, self.pam)
                os.chown(self.pam, 0, 0)
                os.chmod(self.pam, 420)
                resetsecon(self.pam)
            else:
                success = False

        path = "/etc/default/login"
        if os.path.exists(path):
            if not checkPerms(path, [0, 0, 292], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(path, [0, 0, 292], self.logger,
                                self.statechglogger, myid):
                    success = False
        if self.editor1.fixables:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.editor1.setEventID(myid)
            if not self.editor1.fix():
                success = False
            elif not self.editor1.commit():
                success = False
            os.chown(path, 0, 0)
            os.chmod(path, 292)
            resetsecon(path)
        if not self.fixPolicy():
            success = False
        return success

###############################################################################

    def fixFreebsd(self):
        changed = False
        success = True
        if self.config:
            if not checkPerms(self.pam, [0, 0, 420], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.pam, [0, 0, 420], self.logger,
                                self.statechglogger, myid):
                    success = False
            if not self.chklockout():
                if os.path.exists('/lib/security/pam_faillock.so'):
                    if self.setlockout6():
                        changed = True
                    else:
                        success = False
                else:
                    if self.setlockout5():
                        changed = True
                    else:
                        success = False
                tempstring = ""
                for line in self.config:
                    tempstring += line
                tmpfile = self.pam + ".tmp"
                if writeFile(tmpfile, tempstring, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'conf',
                             'filepath': self.pam}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.pam, tmpfile,
                                                         myid)
                    os.rename(tmpfile, self.pam)
                    os.chown(self.pam, 0, 0)
                    os.chmod(self.pam, 420)
                    resetsecon(self.pam)
                else:
                    success = False
        if self.config2:
            changed = False
            self.config = self.config2
            if not checkPerms(self.pam2, [0, 0, 420], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.pam2, [0, 0, 420], self.logger,
                                self.statechglogger, myid):
                    success = False
            if not self.chkpasswdqc():
                if self.setpasswdqc():
                    changed = True
                else:
                    success = False
            if not self.chkpampasshash():
                if self.setpampasshash():
                    changed = True
                else:
                    success = False
            if changed:
                tempstring = ""
                for line in self.config:
                    tempstring += line
                tmpfile = self.pam2 + ".tmp"
                if writeFile(tmpfile, tempstring, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'conf',
                             'filepath': self.pam2}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.pam2, tmpfile,
                                                         myid)
                    os.rename(tmpfile, self.pam2)
                    os.chown(self.pam2, 0, 0)
                    os.chmod(self.pam2, 420)
                    resetsecon(self.pam2)
                else:
                    success = False
        if not self.chkdefspasshash():
            if not self.fixLogin():
                success = False
        return success

###############################################################################       
    
    def chkpassword(self, package):
        '''Private method to check for the presence of the correct
        pwquality/cracklib directives. In this method we want
        the pwquality/cracklib line to be the first line to appear of the
        password type and the pam_unix.so line to be right after.
        @author: dwalker
        @return: bool
        '''
        compliant = False
        regex2 = r"^password[ \t]+sufficient[ \t]+pam_unix.so sha512 shadow " + \
            "try_first_pass use_authtok remember=5"
        if package == "quality":
            compliant1 = self.chkpwquality()
            regex1 = r"^password[ \t]+requisite[ \t]+pam_pwquality.so " + \
                "minlen=14 minclass=4 difok=7 dcredit=0 ucredit=0 " + \
                "lcredit=0 ocredit=0 retry=3"
            compliant2 = self.chkPwCheck(regex1, regex2, package)
            if compliant1 and compliant2:
                compliant = True
        elif package == "cracklib":
            regex1 = r"^password[ \t]+requisite[ \t]+pam_cracklib.so " + \
                "minlen=14 minclass=4 difok=7 dcredit=0 ucredit=0 " + \
                "lcredit=0 ocredit=0 retry=3"
            compliant = self.chkPwCheck(regex1, regex2, package)
        return compliant

###############################################################################
    
    def chkpwquality(self):
        compliant = True
        pwqfile = "/etc/security/pwquality.conf"
        if os.path.exists(pwqfile):
            tmpfile = pwqfile + ".tmp"
            data = {"difok": "4",
                    "minlen": "14",
                    "dcredit" : "-1",
                    "ucredit": "-1",
                    "lcredit": "-1",
                    "ocredit": "-1",
                    "maxrepeat": "3",
                    "minclass": "3"}
            self.pwqeditor = KVEditorStonix(self.statechglogger, self.logger,
                                            "conf", pwqfile, tmpfile, data,
                                            "present", "openeq")
            if not self.pwqeditor.report():
                compliant = False
                self.detailedresults += "Not all correct contents were " + \
                    "found in " + pwqfile + "\n"
        else:
            compliant = False
            self.detailedresults += "System is using pwquality and " + \
                "crucial file /etc/security/pwquality doesn't exist\n"
        return compliant
    
###############################################################################

    def chkPwCheck(self, regex1, regex2, package):
        compliant = True
        pamfiles = []
        if self.ph.manager == "yum":
            pamfiles.append(self.pam)
            pamfiles.append(self.pam2)
        else:
            pamfiles.append(self.pam)
        for pam in pamfiles:
            if os.path.exists(pam):
                if not checkPerms(pam, [0, 0, 420], self.logger):
                    self.detailedresults += "permissions aren't correct " + \
                        "on " + pam + "\n"
                    compliant = False
            else:
                self.detailedresults += pam + " does not exist.  Due to " + \
                    "the complexity of pam, stonix will not attempt to " + \
                    "create this file\n"
                self.pamsha512present = False
                return False
        if self.ph.manager == "solaris":
            config = self.config
            if not config:
                return False
            for line in config:
                if re.search("^#", line) or re.match("^\s*$", line):
                    continue
                if re.match("^other[ \t]password", line):
                    if re.search("pam_dhkeys.so.1", line):
                        pamunixso = True
                    elif re.search("pam_passwdqc.so", line):
                        if re.search("other[ \t]password[ \t]requisite[ \t]" +
                                     "/usr/lib/security/pam_passwdqc.so[ \t]" +
                                     "min=disabled,disabled,16,12,8", line):
                            if pamunixso:
                                compliant = True
                                break
                            else:
                                compliant = False
                                break
                        else:
                            compliant = False
                            break
        else:
            if self.ph.manager == "portage":
                self.detailedresults = package + " can't be configured " + \
                    "for gentoo"
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return True
            for pam in pamfiles:
                tmpconfig1, tmpconfig2 = [], []
                found = False
                if not os.path.exists(pam):
                    self.detailedresults += "Pam file required to configure " + \
                        package + " does not exist\n"
                    return False
                config = readFile(pam, self.logger)
                # if the file is blank just add the two required lines
                if not config:
                    self.detailedresults += "pam file required to " + \
                        "configure" + package + " is blank.  Will not " + \
                        "attempt to configure this file\n"
                    return False
                # Find lines that start with password, which will be in a
                # block. Copy all lines that start with password, are comments,
                # or blank, until we find a line that doesn't start with any of
                # those.
                for line in config:
                    if re.search("^password", line):
                        tmpconfig1.append(line)
                        found = True
                    elif re.search(r"^#|^\s*$", line) and found:
                        tmpconfig1.append(line)
                    elif found:
                        break
                if not len(tmpconfig1) >= 2:
                    self.detailedresults += pam + " file has incorrect " + \
                        "format\n"
                    compliant = False
                else:
                    for line in tmpconfig1:
                        if re.search("^password", line):
                            tmpconfig2.append(line)
                    if not re.search(regex1, tmpconfig2[0].strip()):
                        self.detailedresults += 'Could not match "' + regex1 + \
                            '" to the first password line in ' + pam + "\n"
                        compliant = False
                    if not re.search(regex2, tmpconfig2[1].strip()):
                        self.detailedresults += 'Could not match "' + regex2 + \
                            '" to the second password line in ' + pam + "\n"
                        compliant = False
        return compliant

###############################################################################

    def chklockout(self):
        '''Systemauth.__chklockout() Private method to check the account lock
        out settings that should be enforced via pam_tally2. There are two
        potential styles of lockout, the old style setup by STOR 4.0 and the
        new style setup by STOR 4.1. Either version is valid.'''
        # the first auth line should be the pam_tally2.so line
        if self.ph.manager == "solaris":
            compliant = True
            path = "/etc/default/login"
            if os.path.exists(path):
                if not checkPerms(path, [0, 0, 292], self.logger):
                    self.detailedresults += "permissions are incorrect " + \
                        "for " + path + " file\n"
                    compliant = False
                data = {"RETRIES": "5"}
                tmppath = path + ".tmp"
                self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", path, tmppath, data,
                                              "present", "closedeq")
                if not self.editor1.report():
                    self.detailedresults += "Didn't find the correct " + \
                        "contents inside " + path + "file\n"
                    compliant = False
                return compliant
            else:
                self.detailedresults += path + " doesn't exist\n"
                return False
        elif self.ph.manager == "portage":
            return True
        else:
            compliant = False
            if self.ph.manager in ["zypper", "apt-get"]:
                compliant = self.chkPamtally2()
            else:
                compliant = self.chkPamfaillock()
            return compliant
###############################################################################

    def chkPamtally2(self):
        '''
        This sub method is only for zypper systems i.e. novell, opensuse etc.
        Other systems will use pam_faillock
        @author: dwalker
        @return: bool
        '''
        pamfiles = []
        compliant = True
        if self.ph.manager == "yum":
            pamfiles.append(self.pam)
            pamfiles.append(self.pam2)
        else:
            pamfiles.append(self.pam2)
        for pam in pamfiles:
            if os.path.exists(pam):
                if not checkPerms(pam, [0, 0, 420], self.logger):
                    self.detailedresults += "permissions are incorrect " + \
                        "on " + pam + " file\n"
                    compliant = False
            else:
                self.detailedresults += pam + " does not exist.  Due to " + \
                    "the complexity of pam, stonix will not attempt to " + \
                    "create this file\n"
                return False
        regex1 = r"^auth[ \t]+required[ \t]+pam_env.so"
        regex2 = r"^auth[ \t]+required[ \t]+pam_tally2.so deny=5 " + \
            "unlock_time=600 onerr=fail"
        for pam in pamfiles:
            tmpconfig1, tmpconfig2 = [], []
            found = False
            if not os.path.exists(pam):
                self.detailedresults += "Pam file required to configure " + \
                    "pamtally2 does not exist\n"
                return False
            config = readFile(pam, self.logger)
            # if the file is blank just add the two required lines
            if not config:
                self.detailedresults += "pam file required to configure " + \
                    "pamtally2 is blank.  Will not attempt to configure " + \
                    "this file"
                return False
            # Find lines that start with auth, which will be in a block. Copy
            # all lines that start with auth, are comments, or blank, until we
            # find a line that doesn't start with any of those.
            for line in config:
                if re.search("^auth", line):
                    tmpconfig1.append(line)
                    found = True
                elif re.search(r"^#|^\s*$", line) and found:
                    tmpconfig1.append(line)
                elif found:
                    break
            if not len(tmpconfig1) >= 2:
                self.detailedresults += pam + " file is in bad format\n"
                compliant = False
            else:
                for line in tmpconfig1:
                    if re.search("^auth", line):
                        tmpconfig2.append(line)
                if not re.search(regex1, tmpconfig2[0].strip()):
                    self.detailedresults += 'Could not match "' + regex1 + \
                        '" to the first auth line in ' + pam + "\n"
                    compliant = False
                if not re.search(regex2, tmpconfig2[1].strip()):
                    self.detailedresults += 'Could not match "' + regex2 + \
                        '" to the second auth line in ' + pam + "\n"
                    compliant = False
        return compliant

###############################################################################

    def chkPamfaillock(self):
        compliant = True
        pamfiles = []
        if self.ph.manager == "yum":
            pamfiles.append(self.pam)
            pamfiles.append(self.pam2)
        else:
            pamfiles.append(self.pam2)
        for pam in pamfiles:
            if os.path.exists(pam):
                if not checkPerms(pam, [0, 0, 420], self.logger):
                    compliant = False
            else:
                self.detailedresults += pam + " does not exist.  Due to " + \
                    "the complexity of pam stonix will not attempt to " + \
                    "create this file\n"
                return False
        regex1 = "^auth[ \t]+required[ \t]+pam_env.so\n" + \
            "auth[ \t]+required[ \t]+pam_faillock.so preauth silent audit " + \
            "deny=5 unlock_time=900 fail_interval=900\n" + \
            ".*auth[ \t]+sufficient[ \t]+pam_unix.so try_first_pass\n" + \
            ".*auth[ \t]+requisite[ \t]+pam_succeed_if.so uid >= 500 quiet\n" + \
            ".*auth[ \t]+sufficient[ \t]+pam_krb5.so use_first_pass\n" + \
            ".*auth[ \t]+\[default=die\][ \t]+pam_faillock.so authfail audit deny=5 unlock_time=900 fail_interval=900\n" + \
            ".*auth[ \t]+required[ \t]+pam_deny.so"
        regex2 = r"^account[ \t]+required[ \t]+pam_faillock.so"
        for pam in pamfiles:
            tmpconfig1, tmpconfig2 = [], []
            tmpstring = ""
            found = False
            config = readFile(pam, self.logger)
            if not config:
                self.detailedresults += "pam file required to configure " + \
                    "faillock is blank.  Will not attempt to configure " + \
                    "this file\n"
                return False
            # Find lines that start with auth, which will be in a block. Copy
            # all lines that start with auth, are comments, or blank, until we
            # find a line that doesn't start with any of those.
            for line in config:
                if re.search("^auth", line):
                    tmpconfig1.append(line)
                    found = True
                elif re.search(r"^#|^\s*$", line) and found:
                    tmpconfig1.append(line)
                elif found:
                    break
            if not len(tmpconfig1) >= 2:
                compliant = False
            else:
                for line in tmpconfig1:
                    if re.search("^auth", line):
                        tmpconfig2.append(line)
                for line in tmpconfig2:
                    tmpstring += line
                # Doing re.search with re.S flag, to include newlines in '.'
                if not re.search(regex1, tmpstring, re.S):
                    self.detailedresults += "Didn't find the correct " + \
                        "contents for faillock inside " + pam + " file\n"
                    compliant = False
            config = readFile(pam, self.logger)
            accountfound = False
            # for the account section of the pam file, the first line should
            # be the pam_faillock.so line
            for line in config:
                if re.search("^account", line):
                    accountfound = True
                    if not re.search(regex2, line.strip()):
                        self.detailedresults += 'Could not match "' + regex2 + \
                            '" to the first account line in ' + pam + "\n"
                        compliant = False
                    break
            if not accountfound:
                compliant = False
        return compliant

###############################################################################

    def chkdefspasshash(self):
        '''Method to check the password
        hash algorithm settings in login.defs.'''
        compliant = True
        debug = ""
        if os.path.exists(self.logindefs):
            if not checkPerms(self.logindefs, [0, 0, 420], self.logger):
                self.detailedresults += "Permissions incorrect for " + \
                    self.logindefs + " file\n"
                compliant = False
        if self.ph.manager == "freebsd":
            contents = readFile(self.logindefs, self.logger)
            if not contents:
                return False
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
                found = False
                for line in contents2:
                    if re.search("^#", line) or re.match('^\s*$', line):
                        continue
                    elif re.search("^:passwd_format", line.strip()):
                        if re.search('=', line):
                            temp = line.split('=')
                            if re.search(str("sha512") + "(:\\\\|:|\\\\|\s)",
                                         temp[1]):
                                found = True
                                continue
                            else:
                                found = False
                                break
                if not found:
                    debug += "Did not find the SHA512 line in " + \
                        "/etc/login.defs\n"
                    compliant = False
            return compliant
        else:
            data = {"MD5_CRYPT_ENAB": "no",
                    "ENCRYPT_METHOD": "SHA512",
                    "PASS_MAX_DAYS": "180",
                    "PASS_MIN_DAYS": "1",
                    "PASS_WARN_AGE": "7"}
            datatype = "conf"
            intent = "present"
            tmppath = self.logindefs + ".tmp"
            self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                          datatype, self.logindefs, tmppath,
                                          data, intent, "space")
            if not self.editor2.report():
                debug = self.logindefs + " doesn't contain the correct " + \
                    "contents\n"
                self.detailedresults += self.logindefs + " doesn't contain " + \
                    "the correct contents\n"
                self.logger.log(LogPriority.DEBUG, debug)
                compliant = False
        return compliant
###############################################################################

    def chklibuserhash(self):
        '''Systemauth.__chklibuserhash() Private method to check the password
        hash algorithm settings in libuser.conf.
        @author: dwalker
        @return: bool'''
        compliant = True
        if self.ph.manager in ["yum", "apt-get"]:
            data = {"defaults": {"crypt_style": "sha512"}}
            datatype = "tagconf"
            intent = "present"
            tmppath = self.libuserfile + ".tmp"
            self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                          datatype, self.libuserfile,
                                          tmppath, data, intent, "openeq")
            if not self.editor1.report():
                debug = "/etc/libuser.conf doesn't contain the correct " + \
                    "contents\n"
                self.detailedresults += "/etc/libuser.conf doesn't " + \
                    "contain the correct contents\n"
                self.logger.log(LogPriority.DEBUG, debug)
                compliant = False
            if not checkPerms(self.libuserfile, [0, 0, 420], self.logger):
                self.detailedresults += "Permissions are incorrect on " + \
                    self.libuserfile + "\n"
                compliant = False
        elif self.ph.manager == "zypper":
            contents = readFile(self.libuserfile, self.logger)
            if not contents:
                self.detailedresults += self.libuserfile + " is blank\n"
                return False
            for line in contents:
                if re.match("^\"encryption_method\"", line.strip()):
                    if re.search(":", line):
                        temp = line.split(":")
                        if temp[1].strip() != "\"sha512\"":
                            compliant = False
                            break
            if not checkPerms(self.libuserfile, [0, 0, 420], self.logger):
                self.detailedresults += "Permissions are incorrect on " + \
                    self.libuserfile + "\n"
                compliant = False
        return compliant

###############################################################################

    def chkpolicy(self):
        compliant = True
        path = "/etc/security/policy.conf"
        tmppath = path + ".tmp"
        data = {"CRYPT_DEFAULT": "6",
                "LOCK_AFTER_RETRIES": "YES"}
        if not os.path.exists(path):
            self.detailedresults += path + " doesn't exist\n"
            return False
        self.editor2 = KVEditorStonix(self.statechglogger, self.logger, "conf",
                                      path, tmppath, data, "present",
                                      "closedeq")
        if not checkPerms(path, [0, 0, 420], self.logger):
            self.detailedresults += "permissions are incorrect on " + path + \
                "\n"
            compliant = False
        if not self.editor2.report():
            self.detailedresults += path + " doesn't contain the correct " + \
                "contents\n"
            compliant = False
        return compliant

###############################################################################

    def fixPolicy(self):
        path = "/etc/security/policy.conf"
        if not checkPerms(path, [0, 0, 420], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(path, [0, 0, 420], self.logger,
                            self.statechglogger, myid):
                return False
        if self.editor2.fixables:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.editor2.setEventID(myid)
            if not self.editor2.fix():
                return False
            elif not self.editor2.commit():
                return False
            os.chown(path, 0, 0)
            os.chmod(path, 420)
            resetsecon(path)
        return True

###############################################################################

    def fixLogin(self):
        # only for freebsd
        tempstring = ""
        if os.path.exists(self.logindefs):
            if not checkPerms(self.logindefs, [0, 0, 416], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.logindefs, [0, 0, 416], self.logger,
                                self.statechglogger, myid):
                    return False
            contents = readFile(self.logindefs, self.logger)
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
                iterator = 0
                for line in contents2:
                    if re.search("^#", line) or re.match('^\s*$', line):
                        iterator += 1
                        continue
                    elif re.search("^:passwd_format", line.strip()):
                        if re.search('=', line):
                            temp = line.split('=')
                            if not re.search(str("sha512") +
                                             '(:\\\\|:|\\\\|\s)',
                                             temp[1]):
                                iterator += 1
                                contents2.pop(iterator)
                    else:
                        iterator += 1
                contents2.append('\t' + ":passwd_format=sha512" + ':\\\n')
            final = []
            for line in contents1:
                final.append(line)
            for line in contents2:
                final.append(line)
            for line in contents3:
                final.append(line)
        for line in final:
            tempstring += line
        tmpfile = self.logindefs + ".tmp"
        if writeFile(tmpfile, tempstring, self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype': 'conf',
                     'filepath': self.logindefs}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(self.logindefs, tmpfile, myid)
            os.rename(tmpfile, self.logindefs)
            os.chown(self.logindefs, 0, 0)
            if self.ph.manager == "freebsd":
                os.chmod(self.logindefs, 420)
            else:
                os.chmod(self.logindefs, 416)
            resetsecon(self.logindefs)
            retval = call(["/usr/bin/cap_mkdb", "/etc/login.conf"],
                          stdout=None, shell=False)
            if retval == 0:
                return True
            else:
                return False
        else:
            return False

###############################################################################

    def setpassword(self, package):
        success = False
        regex2 = "^password[ \t]+sufficient[ \t]+pam_unix.so sha512 shadow " + \
            "try_first_pass use_authtok remember=5"
        data2 = "password\tsufficient\tpam_unix.so sha512 shadow " + \
            "try_first_pass use_authtok remember=5\n"
        if package == "quality":
            success1 = self.setpwquality()
            regex1 = "^password[ \t]+requisite[ \t]+pam_pwquality.so " + \
                "minlen=14 minclass=4 difok=7 dcredit=0 ucredit=0 lcredit=0 " \
                + "ocredit=0 retry=3"
            data1 = "password\trequisite\tpam_pwquality.so minlen=14 " + \
                "minclass=4 difok=7 dcredit=0 ucredit=0 lcredit=0 " + \
                "ocredit=0 retry=3\n"
            success2 = self.setPwCheck(regex1, regex2, data1, data2, package)
            if success1 and success2:
                success = True
        elif package == "cracklib":
            regex1 = "^password[ \t]+requisite[ \t]+pam_cracklib.so " + \
                "minlen=14 minclass=4 difok=7 dcredit=0 ucredit=0 lcredit=0 " \
                + "ocredit=0 retry=3"
            data1 = "password\trequisite\tpam_cracklib.so minlen=14 " + \
                "minclass=4 difok=7 dcredit=0 ucredit=0 lcredit=0 " + \
                "ocredit=0 retry=3\n"
            success = self.setPwCheck(regex1, regex2, data1, data2, package)
        return success
###############################################################################

    def setpwquality(self):
        success = True
        created = False
        if not self.pwqeditor:
            pwqfile = "/etc/security/pwquality.conf"
            if not os.path.exists(pwqfile):
                createFile(pwqfile, self.logger)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'creation',
                         'filepath': pwqfile}
                self.statechglogger.recordchgevent(myid, event)
                created = True
            tmpfile = pwqfile + ".tmp"
            data = {"difok": "4",
                    "minlen": "14",
                    "dcredit" : "-1",
                    "ucredit": "-1",
                    "lcredit": "-1",
                    "ocredit": "-1",
                    "maxrepeat": "3",
                    "minclass": "3"}
            self.pwqeditor = KVEditorStonix(self.statechglogger, self.logger,
                                            "conf", pwqfile, tmpfile, data,
                                            "present", "openeq")
            self.pwqeditor.report()
        if self.pwqeditor.fixables:
            if self.pwqeditor.fix():
                if not created:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.pwqeditor.setEventID(myid)
                if not self.pwqeditor.commit():
                    success = False
                    self.detailedresults += "Unable to correct " + pwqfile + "\n"
            else:
                success = False
                self.detailedresults += "Unable to correct " + pwqfile + "\n"
        return success
                        
    def setPwCheck(self, regex1, regex2, data1, data2, package):
        '''Private method to set the pwquality/cracklib directive in
        password-auth or common-password. retval is a list of two items.
        retval[0] will change from False to True, if anything in the file is
        changed, but retval[1] will always be True for success of the method
        @author: dwalker
        @return: list'''

        pamfiles = []
        success = True
        # for yum systems, changes need to be made to both pam files to work
        if self.ph.manager == "yum":
            pamfiles.append(self.pam)
            pamfiles.append(self.pam2)
        else:
            pamfiles.append(self.pam)
        for pam in pamfiles:
            if os.path.exists(pam):
                if not checkPerms(pam, [0, 0, 420], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(pam, [0, 0, 420], self.logger,
                                    "", self.statechglogger, myid):
                        self.detailedresults += "Unable to set " + \
                            "permissions on " + pam + " file\n"
                        success = False
            else:
                self.detailedresults += pam + " does not exist. Due to " + \
                    "the complexity of PAM, STONIX will not attempt to " + \
                    "create this file\n"
                return False
        newconfig = []

        for pam in pamfiles:
            changed = False
            tmpconfig1, tmpconfig2 = [], []
            newconfig = []
            if not os.path.exists(pam):
                self.detailedresults += "Pam file required to configure " + \
                    package + "does not exist\n"
                return False
            config = readFile(pam, self.logger)

            # if the file is blank just add the two required lines
            if not config:
                self.detailedresults += "Pam file required to configure " + \
                    "pwquality/cracklib is blank.  Will not attempt to " + \
                    "configure this file\n"
                return False
            for line in config:
                if re.search("^password", line.strip()):
                    tmpconfig2.append(line)
                else:
                    tmpconfig1.append(line)
            if not len(tmpconfig2) >= 2:
                tmpconfig2 = []
                tmpconfig2.append(data1)
                tmpconfig2.append(data2)
                changed = True
            else:
                if not re.search(regex1, tmpconfig2[0].strip()):
                    tmpconfig2[0] = data1
                    changed = True
                if not re.search(regex2, tmpconfig2[1].strip()):
                    tmpconfig2[1] = data2
                    changed = True

            if changed:
                for item in tmpconfig1:
                    newconfig.append(item)
                for item in tmpconfig2:
                    newconfig.append(item)
                tempstring = ""
                for line in newconfig:
                    tempstring += line
                tmpfile = pam + ".tmp"
                if writeFile(tmpfile, tempstring, self.logger):
                    if self.ph.manager != "yum":
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {'eventtype': 'conf',
                                 'filepath': pam}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(pam, tmpfile,
                                                             myid)
                        os.rename(tmpfile, pam)
                        os.chown(pam, 0, 0)
                        os.chmod(pam, 420)
                        resetsecon(pam)
                    else:
                        os.rename(tmpfile, pam)
                        os.chown(pam, 0, 0)
                        os.chmod(pam, 420)
                        resetsecon(pam)
                else:
                    self.detailedresults += "unable to write changes to: " + \
                        pam + "\n"
                    success = False
        return success
###############################################################################

    def setlibhash(self):
        '''
        Method to check if libuser is installed and the contents of libuser
        file.
        @author: dwalker
        @return: bool
        '''

        if self.ph.manager in ["apt-get", "yum"]:
            if os.path.exists(self.libuserfile):
                if self.editor1.fixables:
                    if not self.created:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.editor1.setEventID(myid)
                    if self.editor1.fix():
                        if self.editor1.commit():
                            debug = "/etc/libuser.conf has been corrected\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            os.chown(self.libuserfile, 0, 0)
                            os.chmod(self.libuserfile, 420)
                            resetsecon(self.libuserfile)
                        else:
                            self.detailedresults += "/etc/libuser.conf " + \
                                "couldn't be corrected\n"
                            return False
                    else:
                        self.detailedresults += "/etc/libuser.conf couldn't " + \
                            "be corrected\n"
                        return False
        else:
            if self.ph.manager == "zypper":
                if os.path.exists(self.libuserfile):
                    contents = readFile(self.libuserfile, self.logger)
                    tempstring = ""
                    found = False
                    for line in contents:
                        if re.search("^#", line) or re.match('^\s*$', line):
                            tempstring += line
                        elif re.search("^\"encryption_method\"", line.strip()):
                            if re.search(":", line):
                                temp = line.split(":")
                                if temp[1] == "sha512":
                                    found = True
                                    tempstring += line
                                else:
                                    found = False
                            else:
                                continue
                        else:
                            tempstring += line
                    if not found:
                        line = "\"encryption_method\" : \"sha512\"\n"
                        tempstring += line
                    tmpfile = self.libuserfile + ".tmp"
                    if writeFile(tmpfile, tempstring, self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {'eventtype': 'conf',
                                 'filepath': self.libuserfile}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(self.libuserfile,
                                                             tmpfile, myid)
                        os.rename(tmpfile, self.libuserfile)
                        os.chown(self.libuserfile, 0, 0)
                        os.chmod(self.libuserfile, 420)
                        resetsecon(self.libuserfile)
        return True
###############################################################################

    def setlockout(self):
        if self.ph.manager == "portage":
            return True
        elif self.ph.manager == "zypper":
            self.detailedresults += "zypper based systems do not contain " + \
                "a pam lockout module\n"
            return True
        elif self.ph.manager == "apt-get":
            success = self.setPamtally2()
        else:
            success = self.setFaillock()
        return success
###############################################################################

    def setFaillock(self):
        '''Private method to set the account lockout configuration.
        using pam_faillock
        @author: dwalker
        @return: bool
        '''

        pamfiles = []
        success = True
        debug = ""
        if self.ph.manager == "yum":
            pamfiles.append(self.pam)
            pamfiles.append(self.pam2)
        else:
            pamfiles.append(self.pam2)
        for pam in pamfiles:
            if os.path.exists(pam):
                if not checkPerms(pam, [0, 0, 420], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(pam, [0, 0, 420], self.logger,
                                    "", self.statechglogger, myid):
                        self.detailedresults += "Unable to set permissions " + \
                            "on " + pam + "\n"
                        success = False
            else:
                self.detailedresults += pam + " does not exist.  Due to " + \
                    "the complexity of pam stonix will not attempt to create " + \
                    "this file\n"
                return False
        regex1 = "^auth[ \t]+required[ \t]+pam_env.so\n" + \
            "auth[ \t]+required[ \t]+pam_faillock.so preauth silent audit " + \
            "deny=5 unlock_time=900 fail_interval=900\n" + \
            ".*auth[ \t]+sufficient[ \t]+pam_unix.so try_first_pass\n" + \
            ".*auth[ \t]+requisite[ \t]+pam_succeed_if.so uid >= 500 quiet\n" + \
            ".*auth[ \t]+sufficient[ \t]+pam_krb5.so use_first_pass\n" + \
            ".*auth[ \t]+\[default=die\][ \t]+pam_faillock.so authfail audit deny=5 unlock_time=900 fail_interval=900\n" + \
            ".*auth[ \t]+required[ \t]+pam_deny.so"
        regex2 = "^account[ \t]+required[ \t]+pam_faillock.so"
        data1 = """auth\trequired\tpam_env.so
auth\trequired\tpam_faillock.so preauth silent audit deny=5 unlock_time=900 fail_interval=900
auth\tsufficient\tpam_unix.so try_first_pass
auth\trequisite\tpam_succeed_if.so uid >= 500 quiet
auth\tsufficient\tpam_krb5.so use_first_pass
auth\t[default=die]\tpam_faillock.so authfail audit deny=5 unlock_time=900 fail_interval=900
auth\trequired\tpam_deny.so
"""
        data2 = "account\trequired\tpam_faillock.so\n"
        for pam in pamfiles:
            changed1, changed2 = False, False
            newconfig = []
            tmpconfig1, tmpconfig2, tmpconfig3 = "", "", ""
            if not os.path.exists(pam):
                debug += pam + " is required to configure " + \
                    "pam_faillock, but does not exist\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
            config = readFile(pam, self.logger)
            # if the file is blank don't do anything
            if not config:
                debug += pam + "is required to configure faillock, but is " + \
                    "blank. Will not attempt to configure this file\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
            foundAuth = False
            foundAcc = False
            for line in config:
                if re.search("^auth", line) or (re.search("^#", line) and
                                                foundAuth):
                    tmpconfig1 += line
                    foundAuth = True
                    foundAcc = False
                elif re.search("^\s+$", line) and foundAuth:
                    tmpconfig1 += line
                    foundAuth = False
                elif re.search("^account", line) or (re.search("^#", line) and
                                                     foundAcc):
                    tmpconfig2 += line
                    foundAcc = True
                    foundAuth = False
                elif re.search("^\s+$", line) and foundAcc:
                    tmpconfig2 += line
                    foundAcc = False
                else:
                    tmpconfig3 += line

            # If lines don't match set tmpconfig1 equal to data1
            if not re.search(regex1, tmpconfig1):
                debug = "auth lines don't match what we're looking for\n"
                self.logger.log(LogPriority.DEBUG, debug)
                tmpconfig1 = data1
                changed1 = True

            if not re.search(regex2, tmpconfig2):
                tmpconfig2 = data2 + tmpconfig2
                changed2 = True

            newconfig = tmpconfig3 + tmpconfig1 + tmpconfig2
            self.logger.log(LogPriority.DEBUG,
                            ['ConfigureSystemAuthentication',
                             'Tempstring: ' + newconfig])
            tmpfile = pam + ".tmp"
            if changed1 or changed2:
                if writeFile(tmpfile, newconfig, self.logger):
                    if self.ph.manager != "yum":
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {'eventtype': 'conf',
                                 'filepath': pam}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(pam, tmpfile,
                                                             myid)
                        os.rename(tmpfile, pam)
                        os.chown(pam, 0, 0)
                        os.chmod(pam, 420)
                        resetsecon(pam)
                    else:
                        os.rename(tmpfile, pam)
                        os.chown(pam, 0, 0)
                        os.chmod(pam, 420)
                        resetsecon(pam)
                else:
                    self.detailedresults += "unable to write changes to: " + \
                        pam + "\n"
                    success = False
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return success
###############################################################################

    def setPamtally2(self):
        pamfiles = []
        success = True
        regex1 = "^auth[ \t]+required[ \t]+pam_env.so"
        regex2 = "^auth[ \t]+required[ \t]+pam_tally2.so deny=5 " + \
            "unlock_time=600 onerr=fail"
        data1 = "auth\trequired\tpam_env.so\n"
        data2 = "auth\trequired\tpam_tally2.so deny=5 unlock_time=600 " + \
            "onerr=fail\n"
        if self.ph.manager == "yum":
            pamfiles.append(self.pam)
            pamfiles.append(self.pam2)
        else:
            pamfiles.append(self.pam2)
        for pam in pamfiles:
            if os.path.exists(pam):
                if not checkPerms(pam, [0, 0, 420], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(pam, [0, 0, 420], self.logger,
                                    "", self.statechglogger, myid):
                        self.detailedresults += "Unable to set permissions" + \
                            "on " + pam + " file\n"
                        success = False
            else:
                self.detailedresults += pam + " does not exist.  Due to " + \
                    "the complexity of pam stonix will not attempt to " + \
                    "create this file\n"
                return False
        for pam in pamfiles:
            changed = False
            tmpconfig1, tmpconfig2, tmpconfig3 = [], [], []
            if not os.path.exists(pam):
                self.detailedresults += "Pam file required to configure " + \
                    "pamtally2 does not exist\n"
                return False
            config = readFile(self.pam2, self.logger)

            # if the file is blank just add the two required lines
            if not config:
                self.detailedresults += "pam file required to configure " + \
                    "pamtally2 is blank.  Will not attempt to configure " + \
                    "this file\n"
                return False
            for line in config:
                # store lines beginning with auth in tmpconfig2
                if re.search("^auth", line.strip()):
                    tmpconfig2.append(line)
                # store all other lines in tmpconfig1
                else:
                    tmpconfig1.append(line)
            # check the first two lines and see if they contain the data we
            # want
            try:
                i = 0
                if not re.search(regex1, tmpconfig2[0].strip()):
                    tmpconfig3.append(data1)
                    changed = True
                else:
                    tmpconfig3.append(data1)
                    i += 1
                if not re.search(regex2, tmpconfig2[1].strip()):
                    tmpconfig3.append(data2)
                    changed = True
                else:
                    tmpconfig3.append(data2)
            except IndexError:
                # If there aren't at least two entries in tmpconfig2, we come
                # to the except block where we just store the two correct lines
                # in tmpconfig3
                tmpconfig3 = []
                tmpconfig3.append(data1)
                tmpconfig3.append(data2)
                changed = True
            if changed:
                if tmpconfig2:
                    for line in tmpconfig2:
                        tmpconfig3.append(line)
                if tmpconfig3:
                    for line in tmpconfig3:
                        tmpconfig1.append(line)
                tempstring = ""
                if tmpconfig1:
                    for line in tmpconfig1:
                        tempstring += line
                tmpfile = pam + ".tmp"
                if writeFile(tmpfile, tempstring, self.logger):
                    if self.ph.manager != "yum":
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {'eventtype': 'conf',
                                 'filepath': pam}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(pam, tmpfile,
                                                             myid)
                        os.rename(tmpfile, pam)
                        os.chown(pam, 0, 0)
                        os.chmod(pam, 420)
                        resetsecon(pam)
                    else:
                        os.rename(tmpfile, pam)
                        os.chown(pam, 0, 0)
                        os.chmod(pam, 420)
                        resetsecon(pam)
                else:
                    self.detailedresults += "unable to write changes to: " + \
                        pam + "\n"
                    success = False
        return success
###############################################################################

    def setdefpasshash(self):
        success = True
        if not checkPerms(self.logindefs, [0, 0, 420], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(self.logindefs, [0, 0, 420], self.logger,
                            self.statechglogger, myid):
                self.detailedresults += "Unable to set permissions " + \
                    "on " + self.logindefs + " file\n"
                success = False
        if self.ph.manager == "freebsd":
            pass
        else:
            if self.editor2:
                if self.editor2.fixables:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor2.setEventID(myid)
                    if self.editor2.fix():
                        if self.editor2.commit():
                            debug = "/etc/login.defs file has been corrected\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            os.chown(self.logindefs, 0, 0)
                            os.chmod(self.logindefs, 420)
                            resetsecon(self.logindefs)
                        else:
                            debug = "Unable to correct the " + \
                                "contents of /etc/login.defs\n"
                            self.detailedresults += "Unable to correct the " + \
                                "contents of /etc/login.defs\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            success = False
                    else:
                        self.detailedresults += "Unable to correct the " + \
                            "contents of /etc/login.defs\n"
                        debug = "Unable to correct the contents of " + \
                            "/etc/login.defs\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
        return success
