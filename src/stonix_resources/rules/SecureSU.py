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
Created on Apr 25, 2013

The su command allows a user to gain the privileges of another user by entering
the password for that user's account. It is desirable to restrict the root user
so that only known administrators are ever allowed to access the root account.
This restricts password-guessing against the root account by unauthorized users
or by accounts which have been compromised.
By convention, the group wheel contains all users who are allowed to run
privileged commands. The PAM module pam_wheel.so is used to restrict root
access to this set of users.

@author: bemalmbe
@change: 03/12/2014 dwalker isapplicable method to fit normal convention
@change: 04/18/2014 ekkehard ci updates
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/10/08 eball Help text/PEP8 cleanup
'''


import os
import re
import traceback

from rule import Rule
from stonixutilityfunctions import readFile
from stonixutilityfunctions import resetsecon, writeFile, iterate
from stonixutilityfunctions import checkPerms, setPerms
from logdispatcher import LogPriority
from pkghelper import Pkghelper
from CommandHelper import CommandHelper


class SecureSU(Rule):
    '''The su command allows a user to gain the privileges of another user by
    entering the password for that user's account. It is desirable to restrict
    the root user so that only known administrators are ever allowed to access
    the root account. This restricts password-guessing against the root account
    by unauthorized users or by accounts which have been compromised. By
    convention, the group wheel contains all users who are allowed to run
    privileged commands. The PAM module pam_wheel.so is used to restrict root
    access to this set of users.


    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 50
        self.compliant = False
        self.rulename = 'SecureSU'
        self.mandatory = True
        self.sethelptext()
        self.formatDetailedResults("initialize")
        self.rootrequired = True
        datatype = 'bool'
        key = 'SECURESU'
        instructions = "To prevent the configuration of " + \
                       "access to the su command, set the value of " + \
                       "SecureSU to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.guidance = ['CIS', 'NSA 2.3.1.2', 'CCE 4274-7']
        self.iditerator = 0
        self.applicable = {'type': 'white',
                           'family': ['linux']}

    def report(self):
        '''The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailedresults and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.


        :returns: bool
        @author bemalmbe

        '''

        try:
            self.detailedresults = ""
            contents = readFile("/etc/shadow", self.logger)
            if not contents:
                self.detailedresults += "/etc/shadow is blank, can't proceed\n"
                return False
            for line in contents:
                if re.search("^root", line):
                    temp = line.split(":")
                    locked = '^\*LK\*|^!|^\*|^x$'
                    try:
                        if re.search(locked, temp[1]):
                            self.detailedresults += "root account is locked, \
No need to do anything\n"
                            self.compliant = True
                            return
                    except IndexError:
                        msg = "shadow in bad format for root user\n"
                        raise msg
            compliant = True
            self.pam = "/etc/pam.d/su"
            self.grp = "/etc/group"
            self.wheel = True
            self.pamwheel = True
            self.detailedresults = ""
            self.ph = Pkghelper(self.logger, self.environ)
            if self.ph.manager == "apt-get":
                if re.search("Debian", self.environ.getostype()):
                    self.compliant = True
                    self.formatDetailedResults("report", self.compliant,
                                               self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO,
                                         self.detailedresults)
                    return
                else:
                    wheelentry = "sudo"
            else:
                wheelentry = "wheel"
            # make sure wheel group exists on the system
            if os.path.exists(self.grp):
                if not checkPerms(self.grp, [0, 0, 420], self.logger):
                    compliant = False
                contents = readFile(self.grp, self.logger)
                found = False
                for line in contents:
                    if re.search("^" + wheelentry, line.strip()):
                        found = True
                if not found:
                    self.detailedresults += "did not find the " + \
                        wheelentry + " group in /etc/group file\n"
                    self.wheel = False
                    compliant = False
                else:
                    self.detailedresults += "The " + wheelentry + " group was \
found in the /etc/group file\n"
            else:
                self.detailedresults += "/etc/group file doesn't exist!\n"
            if os.path.exists(self.pam):
                if not checkPerms(self.pam, [0, 0, 420], self.logger):
                    compliant = False
                # check /etc/pam.d/su for pam_wheel.so entry
                found = False
                invalid = True
                contents = readFile(self.pam, self.logger)
                try:
                    for line in contents:
                        if re.search("pam_wheel.so", line):
                            found = True
                            templine = line.split()
                            if self.ph.manager == "apt-get":
                                if re.match("^auth", templine[0]) and \
                                   re.match("^required", templine[1]) and \
                                   re.search("group=sudo", line):
                                    invalid = False
                                    break
                            else:
                                if re.match("^auth", templine[0]) and \
                                   re.match("^required", templine[1]) and \
                                   re.search("use_uid", line):
                                    invalid = False
                                    break
                except IndexError:
                    self.detailedresults += "Index out of range\n"
                    raise
                if not found or invalid:
                    self.detailedresults += "Did not find the required line in \
pam su file\n"
                    self.pamwheel = False
                    compliant = False
                else:
                    self.detailedresults += "Found the required line in \
pam su\n"
            else:
                self.detailedresults += "/etc/pam.d/su file doesn't exist!\n"
            self.compliant = compliant
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

    def fix(self):
        '''The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.
        
        @author bemalmbe


        '''

        try:
            if not self.ci.getcurrvalue():
                return
            success = True
            self.detailedresults = ""
            debug = ""

            # clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if os.path.exists(self.grp):
                if not self.wheel:
                    ch = CommandHelper(self.logger)
                    if self.ph.manager == "apt-get":
                        cmd = ["/usr/sbin/groupadd", "sudo"]
                    else:
                        cmd = ["/usr/sbin/groupadd", "wheel"]
                    ch.executeCommand(cmd)
                    if ch.getReturnCode() != 0:
                        debug += "unable to create the wheel group, \
unable to continue with the rest of the rule\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        return False
                else:
                    if not checkPerms(self.grp, [0, 0, 420], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(self.grp, [0, 0, 420], self.logger,
                                        self.statechglogger, myid):
                            success = False
            else:
                self.detailedresults += "/etc/group file doesn\'t exist! \
Stonix will not attempt to create this file and will skip to next stage \
of the fix method\n"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                success = False

            if not self.pamwheel:
                if os.path.exists(self.pam):
                    if not checkPerms(self.pam, [0, 0, 420], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(self.pam, [0, 0, 420], self.logger,
                                        self.statechglogger, myid):
                            success = False
                    tempstring = ""
                    contents = readFile(self.pam, self.logger)
                    for line in contents:
                        if re.search("pam_wheel.so", line):
                            continue
                        else:
                            tempstring += line
                    if self.ph.manager == "apt-get":
                        tempstring += "auth    required    " + \
                            "pam_wheel.so group=sudo\n"
                    else:
                        tempstring += "auth    required    " + \
                            "pam_wheel.so use_uid\n"
                    tmpfile = self.pam + ".tmp"
                    if writeFile(tmpfile, tempstring, self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "conf",
                                 "filepath": self.pam}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(self.pam, tmpfile,
                                                             myid)
                        os.rename(tmpfile, self.pam)
                        os.chown(self.pam, 0, 0)
                        os.chmod(self.pam, 420)
                        resetsecon(self.pam)
                    else:
                        success = False
                self.rulessuccess = success
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
