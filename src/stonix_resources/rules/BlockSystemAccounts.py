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

"""
Created on Apr 2, 2013

The BlockSystemAccounts rule will search through /etc/passwd to determine if
there are any system accounts which currently allow login. If any are found
which do allow login, the fix method will append :/dev/null to the end of
the entry in /etc/passwd preventing future login from them. One exception is
the 'root' account which will not be blocked due access to it being required
by administrators in certain situations.

@author: Breen Malmberg
@change: 01/29/2014 Derek Walker revised
@change: 02/12/2014 Ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 Ekkehard Implemented isapplicable
@change: 02/19/2014 Ekkehard Make sure report always runs
@change: 04/18/2014 Dave Kennel Updated to new style configuration item.
@change: 2014/10/17 Ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/14 Dave Kennel Updated for new style isApplicable
@change: 2015/06/10 Breen Malmberg - updated author names; implemented correct
mac os x functionality; refactored code for readability; fixed pep8 violations
@change: 2015/08/28 Ekkehard [artf37764] : BlockSystemAccounts(40) - NCAF - OS X El Capitan 10.11
@change: 2015/11/09 Ekkehard - make eligible of OS X El Capitan
@change: 2017/07/07 Ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 Ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 Ekkehard - make eligible for macOS Mojave 10.14
@change: 2018/10/50 Breen Malmberg - refactor of rule
@change: 2019/03/12 Ekkehard - make eligible for macOS Sierra 10.12+
"""

from __future__ import absolute_import

import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from ..stonixutilityfunctions import readFile, iterate
from ..stonixutilityfunctions import resetsecon


class BlockSystemAccounts(Rule):
    """this module ensures that no system accounts have a login shell"""

    def __init__(self, config, enviro, logger, statechglogger):
        """
        private method to initialize this module

        :param config: configuration object instance
        :param enviro: environment object instance
        :param logger: logdispatcher object instance
        :param statechglogger: statechglogger object instance
        """

        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.environ = enviro
        self.rulenumber = 40
        self.rulename = 'BlockSystemAccounts'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        datatype = 'bool'
        key = 'BLOCKSYSACCOUNTS'
        instructions = """If you have system accounts that need to have valid \
shells set the value of this to False, or No."""
        default = True
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        self.ci = self.initCi(datatype, key, instructions,
                                               default)
        self.guidance = ['CIS', 'NSA(2.3.1.4)', 'cce-3987-5', '4525-2',
                         '4657-3', '4661-5', '4807-4', '4701-9', '4669-8',
                         '4436-2', '4815-7', '4696-1', '4216-8', '4758-9',
                         '4621-9', '4515-3', '4282-0', '4802-5', '4806-6',
                         '4471-9', '4617-7', '4418-0', '4810-8', '3955-2',
                         '3834-9', '4408-1', '4536-9', '4809-0', '3841-4']
        self.iditerator = 0

    def report(self):
        """report on the status of the system's compliance with disallowing
        system accounts to log in

        :return: self.compliant - boolean; True if compliant, False if not

        """

        self.detailedresults = ""
        self.compliant = True
        acceptable_nologin_shells = ["/sbin/nologin", "/dev/null", "", "/usr/bin/false"]
        self.ch = CommandHelper(self.logger)
        self.corrections_needed = []

        try:

            system_login_shells = self.getsysloginshells()
            for acc in system_login_shells:
                if system_login_shells[acc] not in acceptable_nologin_shells:
                    self.compliant = False
                    self.corrections_needed.append(acc)
            if self.corrections_needed:
                self.detailedresults += "\nThe following system accounts can log in:\n" + "\n".join(self.corrections_needed)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def getUIDMIN(self):
        """return this system's minimum user ID start value, if configured

        :return: uid_min - string; system's user id starting value

        """

        uid_min = ""
        logindefs = "/etc/login.defs"

        try:

            # get normal user uid start value
            logindefscontents = readFile(logindefs, self.logger)
            if logindefscontents:
                for line in logindefscontents:
                    if re.search("^UID_MIN", line, re.IGNORECASE):
                        sline = line.split()
                        uid_min = sline[1]

            if not uid_min:
                self.logger.log(LogPriority.DEBUG, "Unable to determine UID_MIN")

        except IndexError:
            pass
        except IOError:
            self.logger.log(LogPriority.DEBUG, "Failed to read uid_min from file")
            return uid_min

        return uid_min

    def getsystemaccounts(self):
        """
        return a list of system accounts

        :return: system_accounts_list - list of system accounts

        """

        system_accounts_list = []

        if self.environ.getosfamily() == "darwin":
            try:
                system_accounts_list = ["root", "nobody"]
                get_sys_accounts_cmd = "/usr/bin/dscl . list /Users | grep -i _"
                self.ch.executeCommand(get_sys_accounts_cmd)
                system_accounts_list += self.ch.getOutput()
            except OSError:
                self.logger.log(LogPriority.DEBUG, "Failed to retrieve list of system accounts")
                return system_accounts_list
        else:
            exclude_accounts = ["halt", "shutdown", "sync", "root"]
            system_accounts_list = []
            uid_min = self.getUIDMIN()
            if not uid_min:
                uid_min = "500"
            f = open("/etc/passwd", "r")
            contentlines = f.readlines()
            f.close()

            try:

                for line in contentlines:
                    sline = line.split(":")
                    if int(sline[2]) < int(uid_min):
                        if sline[0] not in exclude_accounts:
                            system_accounts_list.append(sline[0])

            except IndexError:
                pass

        return system_accounts_list

    def getloginshell(self, account):
        """
        retrieve the login shell, of the passed account, from passwd

        :param account: string; name of user account to get info for
        :return: loginshell - string; default login shell path for account
        """

        loginshell = ""

        try:
            f = open("/etc/passwd", "r")
            contentlines = f.readlines()
            f.close()
        except IOError:
            self.logger.log(LogPriority.DEBUG, "Could not read from passwd file")
            return loginshell

        try:

            for line in contentlines:
                if re.search("^"+account, line, re.IGNORECASE):
                    sline = line.split(":")
                    loginshell = sline[6]

        except IndexError:
            pass

        return loginshell

    def getsysloginshells(self):
        """
        return a dictionary of system accounts and their login shells

        :return: system_login_shells - dictionary of system accounts and their login shells
        """

        system_login_shells = {}
        system_accounts = self.getsystemaccounts()
        for acc in system_accounts:

            system_login_shells[acc] = self.getloginshell(acc).strip()

        return system_login_shells

    def setdefaultloginshell(self, account, shell):
        """
        set default shell for given user account

        :param account: string; name of user account to set default shell for
        :param shell: the type of shell to set for the given user account

        """

        change_shell_cmd = "/usr/bin/chsh -s " + shell + " " + account
        self.ch.executeCommand(change_shell_cmd)

    def fix(self):
        """The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.

        :return: self.rulesuccess - boolean; True if fix succeeds, False if not

        """

        self.detailedresults = ""
        self.rulesuccess = True
        path = "/etc/passwd"
        tmppath = path + ".stonixtmp"
        self.iditerator = 0
        newcontentlines = []

        try:

            if not self.ci.getcurrvalue():
                return self.rulesuccess

            f = open(path, "r")
            contentlines = f.readlines()
            f.close()

            for line in contentlines:
                sline = line.split(":")
                if sline[0] in self.corrections_needed:
                    sline[6] = "/sbin/nologin\n"
                line = ":".join(sline)
                newcontentlines.append(line)

            tf = open(tmppath, "w")
            tf.writelines(newcontentlines)

            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype': 'conf',
                     'filepath': path}

            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(path, tmppath, myid)

            os.rename(tmppath, path)
            os.chown(path, 0, 0)
            os.chmod(path, 420)
            resetsecon(path)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
