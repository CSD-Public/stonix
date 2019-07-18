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
Created on Sep 11, 2013

@author: dwalker
@change: 2014/04/18 dkennel Implemented new style CI in place of old style.
@change: 2014/12/15 dkennel replaced print statement with logger debug call.
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2015/10/22 eball Rebased code in several spots for readability, and to
    correct logic errors (e.g. unreachable code, unused vars)
@change: 2016/01/25 eball Changed pw policies to meet RHEL 7 STIG and
    CNSSI standards
@change: 2016/11/14 eball Updated for PAM configurations in localize.py
@change: 2017/08/28 ekkehard - Added self.sethelptext()
'''


import os
import re
from subprocess import call
import traceback
from ..KVEditorStonix import KVEditorStonix
from ..localize import PWQUALITY_HIGH_REGEX, PWQUALITY_REGEX, \
    CRACKLIB_HIGH_REGEX, CRACKLIB_REGEX, PAMFAIL_REGEX, PAMTALLY_REGEX, \
    AUTH_APT, ACCOUNT_APT, PASSWORD_ZYPPER, AUTH_ZYPPER, ACCOUNT_ZYPPER, \
    PASSWORD_NSLCD, AUTH_NSLCD, ACCOUNT_NSLCD, SESSION_NSLCD, AUTH_YUM, \
    ACCOUNT_YUM, SESSION_YUM, PASSWORD_YUM, PASSWORD_APT
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..rule import Rule
from ..stonixutilityfunctions import iterate, setPerms, checkPerms, readFile, \
    writeFile, resetsecon, createFile
from ..CommandHelper import CommandHelper

class ConfigureSystemAuthentication(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 57
        self.rulename = "ConfigureSystemAuthentication"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
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
        self.localize()

    def localize(self):
        myos = self.environ.getostype().lower()
        if re.search("red hat.*?release 6", myos):
            self.password = PASSWORD_NSLCD
            self.auth = AUTH_NSLCD
            self.acct = ACCOUNT_NSLCD
            self.session = SESSION_NSLCD
        elif re.search("suse", myos):
            self.password = PASSWORD_ZYPPER
            self.auth = AUTH_ZYPPER
            self.acct = ACCOUNT_ZYPPER
        elif re.search("debian|ubuntu", myos):
            self.password = PASSWORD_APT
            self.auth = AUTH_APT
            self.acct = ACCOUNT_APT
        else:
            self.password = PASSWORD_YUM
            self.auth = AUTH_YUM
            self.acct = ACCOUNT_YUM
            self.session = SESSION_YUM

    def report(self):
        '''ConfigureSystemAuthentication() report method to report if system
        is compliant with authentication and password settings
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool - True if system is compliant, False if it isn't

        '''
        try:
            self.ci2comp, self.ci3comp, self.ci4comp = True, True, True
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

    def fix(self):
        '''ConfigureSystemAuthentication.fix() method to fix the system to be
        compliant with authentication and password settings
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool - True if fix is successful, False if it isn't

        '''
        self.detailedresults = ""
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

    def reportLinux(self):
        '''Linux specific submethod for linux distributions.
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool - True if system is compliant, False if it isn't

        '''
        self.logindefs = "/etc/login.defs"
        debug = ""
        compliant = True
        self.editor1, self.editor2 = "", ""
        self.pwqeditor = ""
        self.usingpwquality, self.usingcracklib = False, False
        self.usingpamtally2, self.usingpamfail = False, False
        self.created1, self.created2 = False, False
        self.ph = Pkghelper(self.logger, self.environ)
        self.cracklibpkgs = ["libpam-cracklib",
                             "cracklib"]
        self.pwqualitypkgs = ["libpam-pwquality",
                              "pam_pwquality",
                              "libpwquality"]
        self.libuserfile = "/etc/libuser.conf"
        if self.ph.manager == "apt-get":
            self.pampassfile = "/etc/pam.d/common-password"
            self.pamauthfile = "/etc/pam.d/common-auth"
        elif self.ph.manager == "zypper":
            self.pampassfile = "/etc/pam.d/common-password-pc"
            self.pamauthfile = "/etc/pam.d/common-auth-pc"
        elif self.ph.manager == "dnf":
            self.pampassfile = "/etc/pam.d/password-auth"
            self.pamauthfile = "/etc/pam.d/system-auth"
        else:
            self.pampassfile = "/etc/pam.d/password-auth-ac"
            self.pamauthfile = "/etc/pam.d/system-auth-ac"

        if not self.checkpasswordreqs():
            self.ci2comp = False
            debug += "checkpasswordreqs method is False compliancy\n"
            compliant = False
        if not self.checkaccountlockout():
            self.ci3comp = False
            debug += "checkaccountlockout method is False compliancy\n"
            compliant = False
        if not self.checklogindefs():
            self.ci4comp = False
            debug += "checklogindefs method is False compliancy\n"
            compliant = False
        if not self.checklibuser():
            self.ci4comp = False
            debug += "checklibuser method is False compliancy\n"
            compliant = False
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return compliant
###############################################################################

    def fixLinux(self):
        '''Linux specific submethod to correct linux distributions.  If your
        system is portage based, i.e. gentoo, you will need to do a manual
        fix for everything except the login.defs file
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool - True if fix is successful, False if it isn't
        @change: Breen Malmberg - 9/26/2018 - added a check and installation of a
                necessary package for fedora 28, in order for the fix to continue

        '''

        success = True
        debug = ""
        self.detailedresults = ""

        try:
            if self.ph.manager == "dnf":
                if not self.ph.check("authconfig"):
                    self.ph.install("authconfig") # this is needed by fedora 28 to continue
        except:
            pass

        '''create backups of pamfiles'''
        if os.path.exists(self.pampassfile):
            createFile(self.pampassfile + ".backup", self.logger)
        if os.path.exists(self.pamauthfile):
            createFile(self.pamauthfile + ".backup", self.logger)
        self.cracklibpkgs = ["libpam-cracklib",
                             "cracklib"]
        self.pwqualitypkgs = ["libpam-pwquality",
                              "pam_pwquality",
                              "libpwquality"]
        if self.ci2.getcurrvalue():
            if not self.ci2comp:
                if self.usingpwquality:
                    self.password = re.sub("pam_cracklib\.so", "pam_pwquality.so",
                                       self.password)
                    if self.environ.getsystemfismacat() == "high":
                        self.password = re.sub("minlen=8", "minlen=14", self.password)
                        self.password = re.sub("minclass=3", "minclass=4", self.password)
                        regex = PWQUALITY_HIGH_REGEX
                    else:
                        regex = PWQUALITY_REGEX
                    if self.pwqinstalled:
                        if not self.setpasswordsetup(regex):
                            success = False
                    else:
                        if not self.setpasswordsetup(regex, self.pwqualitypkgs):
                            success = False
                elif self.usingcracklib:
                    self.password = re.sub("pam_pwquality\.so", "pam_cracklib.so",
                                       self.password)
                    if self.environ.getsystemfismacat() == "high":
                        self.password = re.sub("minlen=8", "minlen=14", self.password)
                        self.password = re.sub("minclass=3", "minclass=4", self.password)
                        regex = CRACKLIB_HIGH_REGEX
                    else:
                        regex = CRACKLIB_REGEX
                    if self.clinstalled:
                        if not self.setpasswordsetup(regex):
                            success = False
                    else:
                        if not self.setpasswordsetup(regex, self.cracklibpkgs):
                            success = False
                else:
                    error = "Could not find pwquality/cracklib pam " + \
                        "module. Fix failed."
                    self.logger.log(LogPriority.ERROR, error)
                    self.detailedresults += error + "\n"
                    return False
        if self.ci3.getcurrvalue():
            if not self.ci3comp:
                if self.usingpamfail:
                    regex = PAMFAIL_REGEX
                    if not self.setaccountlockout(regex):
                        success = False
                        self.detailedresults += "Unable to configure pam " + \
                            "for faillock\n"
                elif self.usingpamtally2:
                    regex = PAMTALLY_REGEX
                    if not self.setaccountlockout(regex):
                        success = False
                        self.detailedresults += "Unable to configure pam " + \
                            "for pam_tally2\n"
                else:
                    self.detailedresults += "There is no account lockout " + \
                        "program available for this system\n"
                    success = False
        if self.ci4.getcurrvalue():
            if not self.ci4comp:
                if not self.checklibuser():
                    if not self.setlibuser():
                        debug = "setlibuser() failed\n"
                        self.detailedresults += "Unable to configure " + \
                            "/etc/libuser.conf\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                if not self.checklogindefs():
                    if not self.setlogindefs():
                        debug = "setdefpasshash() failed\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        self.detailedresults += "Unable to configure " + \
                            "/etc/login.defs file\n"
                        success = False
        return success

    def checkpasswordreqs(self):
        '''Method to check which password checking program the system
        is or should be using.
        @author: dwalker


        :returns: bool

        '''
        self.pwqinstalled, self.clinstalled = False, False
        self.pwqpkg, self.crackpkg = "", ""
        '''Check if either pam_pwquality or cracklib are installed'''
        for pkg in self.pwqualitypkgs:
            if self.ph.check(pkg):
                self.pwqinstalled = True
        for pkg in self.cracklibpkgs:
            if self.ph.check(pkg):
                self.clinstalled = True
        '''if pwquality is installed we check to see if it's configured'''
        if self.pwqinstalled:
            '''If it's not, since it is already installed we want to
            configure pwquality and not cracklib since it's better'''
            if not self.checkpasswordsetup("pwquality"):
                self.usingpwquality = True
                self.detailedresults += "System is using pwquality but " + \
                    "it's not configured properly in PAM\n"
                return False
            else:
                '''pwquality is installed and configured'''
                return True
        elif self.clinstalled:
            '''Although we want pwquality over cracklib, if cracklib is
            already installed and configured correctly, we will go with that'''
            if not self.checkpasswordsetup("cracklib"):
                '''cracklib is not configured correctly so we check
                if pwquality is available for install'''
                for pkg in self.pwqualitypkgs:
                    if self.ph.checkAvailable(pkg):
                        self.usingpwquality = True
                        self.pwqpkg = pkg
                        self.detailedresults += "System has cracklib " + \
                            "installed but is not configured properly with " + \
                            "PAM and pwquality is available for install. " + \
                            "will install and configure pwquality\n"
                        return False
                self.detailedresults += "cracklib installed but not " + \
                    "configured properly\n"
                self.usingcracklib = True
            else:
                '''cracklib is installed and configured'''
                return True
        else:
            '''neither pwquality or cracklib is installed, we prefer
            pwquality so we check if it's available for install'''
            for pkg in self.pwqualitypkgs:
                if self.ph.checkAvailable(pkg):
                    self.usingpwquality = True
                    self.pwqpkg = pkg
                    self.detailedresults += "pwquality is available for " + \
                        "install\n"
                    return False
            '''pwquality wasn't available for install, check for cracklib'''
            for pkg in self.cracklibpkgs:
                if self.ph.checkAvailable(pkg):
                    self.usingcracklib = True
                    self.crackpkg = pkg
                    self.detailedresults += "cracklib is available for " + \
                        "install\n"
                    return False
            return False
    
    def checkpasswordsetup(self, package):
        '''Method called from within checkpasswordreqs method
        @author: dwalker

        :param package: pwquality or cracklib
        :returns: bool

        '''
        compliant = True
        if package == "pwquality":
            self.password = re.sub("pam_cracklib\.so", "pam_pwquality.so",
                                       self.password)
            if self.environ.getsystemfismacat() == "high":
                self.password = re.sub("minlen=8", "minlen=14", self.password)
                self.password = re.sub("minclass=3", "minclass=4", self.password)
                regex1 = PWQUALITY_HIGH_REGEX
            else:
                regex1 = PWQUALITY_REGEX
            if not self.chkpwquality():
                compliant = False
        elif package == "cracklib":
            self.password = re.sub("pam_pwquality\.so", "pam_cracklib.so",
                                       self.password)
            if self.environ.getsystemfismacat() == "high":
                self.password = re.sub("minlen=8", "minlen=14", self.password)
                self.password = re.sub("minclass=3", "minclass=4", self.password)
                regex1 = CRACKLIB_HIGH_REGEX
            else:
                regex1 = CRACKLIB_REGEX
        regex2 = "^password[ \t]+sufficient[ \t]+pam_unix.so sha512 shadow " + \
            "try_first_pass use_authtok remember=10"
        pamfiles = []
        if self.ph.manager in ("yum", "dnf"):
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
        else:
            pamfiles.append(self.pampassfile)
        for pamfile in pamfiles:
            found1, found2 = False, False
            if not os.path.exists(pamfile):
                self.detailedresults += pamfile + " doesn't exist\n"
                compliant = False
            else:
                if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                    self.detailedresults += ""
                    compliant = False
                contents = readFile(pamfile, self.logger)
                if not contents:
                    self.detailedresults += pamfile + " is blank\n"
                    compliant = False
                else:
                    for line in contents:
                        if re.search(regex1, line.strip()):
                            found1 = True
                        if re.search(regex2, line.strip()):
                            found2 = True
                    if not found1 or not found2:
                        self.detailedresults += "Didn't find the correct " + \
                            "contents in " + pamfile + "\n"
                        compliant = False
        return compliant

    def setpasswordsetup(self, regex1, pkglist = ""):
        regex2 = "^password[ \t]+sufficient[ \t]+pam_unix.so sha512 shadow " + \
            "try_first_pass use_authtok remember=10"
        success = True
        pamfiles = []
        installed = False
        if pkglist:
            for pkg in pkglist:
                if self.ph.check(pkg):
                    installed = True
                    break
        else:
            installed = True
        if not installed:
            for pkg in pkglist:
                if self.ph.checkAvailable(pkg):
                    if not self.ph.install(pkg):
                        self.detailedresults += "Unable to install pkg " + \
                            pkg + "\n" 
                        return False
                    else:
                        installed = True
                        if self.usingpwquality:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            comm = self.ph.getRemove() + pkg
                            event = {"eventtype": "commandstring",
                                     "command": comm}
                            self.statechglogger.recordchgevent(myid, event)
                            pwqfile = "/etc/security/pwquality.conf"
                            tmpfile = pwqfile + ".tmp"
                            if self.environ.getsystemfismacat() == "high":
                                data = {"difok": "7",
                                        "minlen": "14",
                                        "dcredit": "0",
                                        "ucredit": "0",
                                        "lcredit": "0",
                                        "ocredit": "0",
                                        "maxrepeat": "3",
                                        "minclass": "4"}
                            else:
                                data = {"difok": "7",
                                        "minlen": "8",
                                        "dcredit": "0",
                                        "ucredit": "0",
                                        "lcredit": "0",
                                        "ocredit": "0",
                                        "maxrepeat": "3",
                                        "minclass": "3"}
                            self.pwqeditor = KVEditorStonix(self.statechglogger,
                                                            self.logger, "conf",
                                                            pwqfile, tmpfile, data,
                                                            "present", "openeq")
                            self.pwqeditor.report()
                            break
        if not installed:
            self.detailedresults += "No password checking program available\n"
            return False
        if self.usingpwquality:
            if not self.setpwquality():
                success = False
        if self.ph.manager in ("yum", "dnf"):
            writecontents = self.auth + "\n" + self.acct + "\n" + \
                self.password + "\n" + self.session
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
        else:
            writecontents = self.password
            pamfiles.append(self.pampassfile)
        for pamfile in pamfiles:
            if not os.path.exists(pamfile):
                self.detailedresults += pamfile + " doesn't exist.\n" + \
                    "Stonix will not attempt to create this file " + \
                    "and the fix for the this rule will not continue\n"
                return False
        '''Check permissions on pam file(s)'''
        for pamfile in pamfiles:
            if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(pamfile, [0, 0, 0o644], self.logger, self.statechglogger, myid):
                    success = False
                    self.detailedresults += "Unable to set " + \
                        "correct permissions on " + pamfile + "\n"
            contents = readFile(pamfile, self.logger)
            found1, found2 = False, False
            for line in contents:
                if re.search(regex1, line.strip()):
                    found1 = True
                if re.search(regex2, line.strip()):
                    found2 = True
            if not found1 or not found2:
                tmpfile = pamfile + ".tmp"
                if writeFile(tmpfile, writecontents, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'conf',
                             'filepath': pamfile}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(pamfile, tmpfile, myid)
                    os.rename(tmpfile, pamfile)
                    os.chown(pamfile, 0, 0)
                    os.chmod(pamfile, 0o644)
                    resetsecon(pamfile)
                else:
                    self.detailedresults += "Unable to write to " + pamfile + "\n"
                    success = False
        return success
        ''''section of code commented out can be uncommented if we
        decide that we will create the pam files if they don't exist.
        Currently, if the pam file(s) don't exist, we don't do 
        anything.'''
#         '''Check existence of pam file(s)'''
#         for pamfile in pamfiles:
#             if not os.path.exists(pamfile):
#                 if createFile(pamfile, self.logger):
#                     if self.ph.manager == "yum":
#                         if pamfile == self.pamauthfile:
#                             self.created1 = True
#                         else:
#                             self.created2 = True
#                     else:
#                         self.created1 = True
#                     self.iditerator += 1
#                     myid = iterate(self.iditerator, self.rulenumber)
#                     event = {"eventtype": "creation",
#                              "filepath": pamfile}
#                     self.statechglogger.recordchgevent(myid, event)
#                 else:
#                     success = False
#                     self.detailedresults += "Unable to create " + pamfile + "\n"
#         '''Check permissions on pam file(s)'''
#         for pamfile in pamfiles:
#             if not os.path.exists(pamfile):
#                 if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
#                     if self.ph.manager == "yum":
#                         if pamfile == self.pamauthfile:
#                             if self.created1:
#                                 if not setPerms(pamfile, [0, 0, 0o644], self.logger):
#                                     success = False
#                                     self.detailedresults += "Unable to set " + \
#                                         "correct permissions on " + pamfile + "\n"
#                             else:
#                                 self.iditerator += 1
#                                 myid = iterate(self.iditerator, self.rulenumber)
#                                 if not setPerms(pamfile, [0, 0, 0o644], self.logger, self.statechglogger, myid):
#                                     success = False
#                                     self.detailedresults += "Unable to set " + \
#                                         "correct permissions on " + pamfile + "\n"
#                         elif pamfile == self.pampassfile:
#                             if self.created2:
#                                 if not setPerms(pamfile, [0, 0, 0o644], self.logger):
#                                     success = False
#                                     self.detailedresults += "Unable to set " + \
#                                         "correct permissions on " + pamfile + "\n"
#                             else:
#                                 self.iditerator += 1
#                                 myid = iterate(self.iditerator, self.rulenumber)
#                                 if not setPerms(pamfile, [0, 0, 0o644], self.logger, self.statechglogger, myid):
#                                     success = False
#                                     self.detailedresults += "Unable to set " + \
#                                         "correct permissions on " + pamfile + "\n"
#                     else:
#                         if self.created1:
#                             if not setPerms(pamfile, [0, 0, 0o644], self.logger):
#                                 success = False
#                                 self.detailedresults += "Unable to set " + \
#                                     "correct permissions on " + pamfile + "\n"
#                         else:
#                             self.iditerator += 1
#                             myid = iterate(self.iditerator, self.rulenumber)
#                             if not setPerms(pamfile, [0, 0, 0o644], self.logger, self.statechglogger, myid):
#                                 success = False
#                                 self.detailedresults += "Unable to set " + \
#                                     "correct permissions on " + pamfile + "\n"

    def checkaccountlockout(self):
        '''Method to determine which account locking program to
        use if any.
        @author: dwalker


        :returns: bool

        '''
        which = "/usr/bin/which "
        cmd1 = which + "faillock"
        cmd2 = which + "pam_tally2"
        ch = CommandHelper(self.logger)
        pamfiles = []
        compliant = True
        if ch.executeCommand(cmd1):
            debug = "ran " + cmd1 + " successfully\n"
            self.logger.log(LogPriority.DEBUG, debug)
            if ch.getReturnCode() == 0:
                debug = "return code of 0 and using faillock\n"
                self.logger.log(LogPriority.DEBUG, debug)
                self.usingpamfail = True
            elif ch.executeCommand(cmd2):
                debug = "ran " + cmd2 + " successfully\n"
                self.logger.log(LogPriority.DEBUG, debug)
                if ch.getReturnCode() == 0:
                    debug = "return code of 0 and using pam_tally2\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    self.usingpamtally2 = True
            else:
                self.detailedresults += "There is no account " + \
                        "locking program available for this " + \
                        "distribution\n"
                return False
        elif ch.executeCommand(cmd2):
                debug = "ran " + cmd2 + " successfully\n"
                self.logger.log(LogPriority.DEBUG, debug)
                if ch.getReturnCode() == 0:
                    debug = "return code of 0 and using pam_tally2\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    self.usingpamtally2 = True
                else:
                    self.detailedresults += "There is no account " + \
                        "locking program available for this " + \
                        "distribution\n"
                    return False
        else:
            self.detailedresults += "There is no account " + \
                "locking program available for this " + \
                "distribution\n"
            return False
        if self.usingpamfail:
            regex = "^auth[ \t]+required[ \t]+pam_faillock.so preauth silent audit " + \
                "deny=5 unlock_time=900 fail_interval=900"
        elif self.usingpamtally2:
            regex = "^auth[ \t]+required[ \t]+pam_tally2.so deny=5 " + \
                "unlock_time=900 onerr=fail"
        if self.ph.manager in("yum", "dnf"):
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
        else:
            pamfiles.append(self.pamauthfile)
        for pamfile in pamfiles:
            found = False
            if not os.path.exists(pamfile):
                self.detailedresults += "Critical pam file " + pamfile + \
                    "doesn't exist\n"
                compliant = False
            else:
                if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                    self.detailedresults += "Permissions aren't correct " + \
                        "on " + pamfile + "\n"
                    self.ci3comp = False
                    compliant = False
                contents = readFile(pamfile, self.logger)
                if not contents:
                    self.detailedresults += pamfile + " is blank\n"
                    self.ci3comp = False
                    compliant = False
                else:
                    for line in contents:
                        if re.search(regex, line.strip()):
                            found = True
                    if not found:
                        self.detailedresults += "Didn't find the correct " + \
                            "contents in " + pamfile + "\n"
                        self.ci3comp = False
                        compliant = False
        return compliant

    def setaccountlockout(self, regex):
        success = True
        pamfiles = []
        if self.ph.manager in ("yum", "dnf"):
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
            writecontents = self.auth + "\n" + self.acct + "\n" + \
                        self.password + "\n" + self.session
        else:
            pamfiles.append(self.pamauthfile)
            writecontents = self.auth
        for pamfile in pamfiles:
            if not os.path.exists(pamfile):
                self.detailedresults += pamfile + " doesn't exist.\n" + \
                    "Stonix will not attempt to create this file " + \
                    "and the fix for the this rule will not continue\n"
                return False
        '''Check permissions on pam file(s)'''
        for pamfile in pamfiles:
            if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(pamfile, [0, 0, 0o644], self.logger, self.statechglogger, myid):
                    success = False
                    self.detailedresults += "Unable to set " + \
                        "correct permissions on " + pamfile + "\n"
            contents = readFile(pamfile, self.logger)
            found = False
            for line in contents:
                if re.search(regex, line.strip()):
                    found = True
            if not found:
                tmpfile = pamfile + ".tmp"
                if writeFile(tmpfile, writecontents, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'conf',
                             'filepath': pamfile}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(pamfile, tmpfile, myid)
                    os.rename(tmpfile, pamfile)
                    os.chown(pamfile, 0, 0)
                    os.chmod(pamfile, 0o644)
                    resetsecon(pamfile)
                else:
                    self.detailedresults += "Unable to write to " + pamfile + "\n"
                    success = False
        return success

    def chkpwquality(self):
        compliant = True
        pwqfile = "/etc/security/pwquality.conf"
        if os.path.exists(pwqfile):
            tmpfile = pwqfile + ".tmp"
            if self.environ.getsystemfismacat() == "high":
                data = {"difok": "7",
                        "minlen": "14",
                        "dcredit": "0",
                        "ucredit": "0",
                        "lcredit": "0",
                        "ocredit": "0",
                        "maxrepeat": "3",
                        "minclass": "4"}
            else:
                data = {"difok": "7",
                        "minlen": "8",
                        "dcredit": "0",
                        "ucredit": "0",
                        "lcredit": "0",
                        "ocredit": "0",
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

    def chklockout(self):
        '''Systemauth.__chklockout() Private method to check the account lock
        out settings that should be enforced via pam_tally2. There are two
        potential styles of lockout, the old style setup by STOR 4.0 and the
        new style setup by STOR 4.1. Either version is valid.


        '''
        # the first auth line should be the pam_tally2.so line
        if self.ph.manager == "solaris":
            compliant = True
            path = "/etc/default/login"
            if os.path.exists(path):
                if not checkPerms(path, [0, 0, 0o444], self.logger):
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

###############################################################################

    def checklogindefs(self):
        '''Method to check the password hash algorithm settings in
        login.defs.


        '''
        compliant = True
        debug = ""
        if os.path.exists(self.logindefs):
            if not checkPerms(self.logindefs, [0, 0, 0o644], self.logger):
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
            tmppath = self.logindefs + ".tmp"
            self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                          "conf", self.logindefs, tmppath,
                                          data, "present", "space")
            if not self.editor2.report():
                debug = self.logindefs + " doesn't contain the correct " + \
                    "contents\n"
                self.detailedresults += self.logindefs + " doesn't contain " + \
                    "the correct contents\n"
                self.logger.log(LogPriority.DEBUG, debug)
                compliant = False
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

    def fixFreebsd(self):
        changed = False
        success = True
        if self.config:
            if not checkPerms(self.pam, [0, 0, 0o644], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.pam, [0, 0, 0o644], self.logger,
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
                    os.chmod(self.pam, 0o644)
                    resetsecon(self.pam)
                else:
                    success = False
        if self.config2:
            changed = False
            self.config = self.config2
            if not checkPerms(self.pam2, [0, 0, 0o644], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.pam2, [0, 0, 0o644], self.logger,
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
                    os.chmod(self.pam2, 0o644)
                    resetsecon(self.pam2)
                else:
                    success = False
        if not self.chkdefspasshash():
            if not self.fixLogin():
                success = False
        return success

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
        if not checkPerms(path, [0, 0, 0o644], self.logger):
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
        if not checkPerms(path, [0, 0, 0o644], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(path, [0, 0, 0o644], self.logger,
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
            os.chmod(path, 0o644)
            resetsecon(path)
        return True

###############################################################################

    def fixLogin(self):
        # only for freebsd
        tempstring = ""
        if os.path.exists(self.logindefs):
            if not checkPerms(self.logindefs, [0, 0, 0o640], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.logindefs, [0, 0, 0o640], self.logger,
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
                os.chmod(self.logindefs, 0o644)
            else:
                os.chmod(self.logindefs, 0o640)
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

    def setpwquality(self):
        success = True
        created = False
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
        if self.environ.getsystemfismacat() == "high":
            data = {"difok": "7",
                    "minlen": "14",
                    "dcredit": "0",
                    "ucredit": "0",
                    "lcredit": "0",
                    "ocredit": "0",
                    "maxrepeat": "3",
                    "minclass": "4"}
        else:
            data = {"difok": "7",
                    "minlen": "8",
                    "dcredit": "0",
                    "ucredit": "0",
                    "lcredit": "0",
                    "ocredit": "0",
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

###############################################################################

    def setlibuser(self):
        '''Method to check if libuser is installed and the contents of libuser
        file.
        @author: dwalker


        :returns: bool

        '''
        created = False
        success = True
        data = {"defaults": {"crypt_style": "sha512"}}
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
                    comm = self.ph.getRemove() + "libuser"
                    event = {"eventtype": "commandstring",
                             "command": comm}
                    self.statechglogger.recordchgevent(myid, event)
                    datatype = "tagconf"
                    intent = "present"
                    tmppath = self.libuserfile + ".tmp"
                    self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                                  datatype, self.libuserfile,
                                                  tmppath, data, intent, "openeq")
                    self.editor1.report()
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
            self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                          "tagconf", self.libuserfile,
                                          tmppath, data, "present", "openeq")
            self.editor1.report()
        if not checkPerms(self.libuserfile, [0, 0, 0o644], self.logger):
            if not created:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.libuserfile, [0, 0, 0o644], self.logger,
                                self.statechglogger, myid):
                    success = False
                    self.detailedresults += "Unable to set the " + \
                        "permissions on " + self.libuserfile + "\n"
            elif not setPerms(self.libuserfile, [0, 0, 0o644], self.logger):
                success = False
                self.detailedresults += "Unable to set the " + \
                        "permissions on " + self.libuserfile + "\n"
        if self.editor1.fixables:
            if not created:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.editor1.setEventID(myid)
            if self.editor1.fix():
                if self.editor1.commit():
                    debug = "/etc/libuser.conf has been corrected\n"
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

    def setlogindefs(self):
        success = True
        if not checkPerms(self.logindefs, [0, 0, 0o644], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(self.logindefs, [0, 0, 0o644], self.logger,
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
                            os.chmod(self.logindefs, 0o644)
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