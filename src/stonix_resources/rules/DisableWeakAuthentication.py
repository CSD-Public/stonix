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
Created on Aug 12, 2013

@author: dwalker
@change: dkennel 04/18/2014 Replaced old style CI with new style
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated to use new isApplicable
@change: 2015/07/27 eball Fixed help text typos and improved PEP8 compliance
@change: 2015/10/27 eball Added feedback to report()
@change 2017/08/28 rsn Fixing to use new help text methods
'''

from ..stonixutilityfunctions import readFile, writeFile, setPerms, checkPerms
from ..stonixutilityfunctions import resetsecon
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
import os
import traceback
import re
import glob


class DisableWeakAuthentication(Rule):
    '''This rule will remove rsh(server and client) if installed, remove
    pam_rhosts entry from any pam file,


    '''
    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 30
        self.rulename = "DisableWeakAuthentication"
        self.mandatory = True
        self.formatDetailedResults("initialize")
        self.guidance = ["NSA 3.2.3.1"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd']}

        # Configuration item instantiation
        datatype = 'bool'
        key = 'DISABLEWEAKAUTHENTICATION'
        instructions = "To prevent the disabling of services using weak " + \
                       "authentication set DISABLEWEAKAUTHENTICATION to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.rsh = ["rshell",
                    "rsh-client",
                    "rsh-server",
                    "rsh",
                    "SUNWrcmdc"]
        self.pams = ["/etc/pam.conf",
                     "/etc/pam_ldap.conf",
                     "/etc/pam.conf-winbind"]
        self.incorrects = []
        self.iditerator = 0
        self.sethelptext()

    def report(self):
        '''DisableWeakAuthentication.report() Public method to report on the
        presence of certain r-command packages and contents in pam files.
        @author: dwalker


        :returns: bool - False if the method died during execution

        '''
        self.detailedresults = ""
        try:
            self.helper = Pkghelper(self.logger, self.environ)
            compliant = True
            for item in self.rsh:
                if self.helper.check(item):
                    compliant = False
                    self.detailedresults += item + " is still installed\n"
                    break
            for item in self.pams:
                found = False
                if os.path.exists(item):
                    contents = readFile(item, self.logger)
                    if contents:
                        for line in contents:
                            if re.match('^#', line) or \
                               re.match(r'^\s*$', line):
                                continue
                            elif re.search("pam_rhosts", line):
                                found = True
                                compliant = False
                                self.detailedresults += "pam_rhosts line " + \
                                    "found in " + item + "\n"
                                break
                        if found:
                            self.incorrects.append(item)
                        if not checkPerms(item, [0, 0, 420], self.logger):
                            compliant = False
                            self.detailedresults += "Permissions for " + \
                                item + " are incorrect\n"
            if os.path.exists("/etc/pam.d/"):
                fileItems = glob.glob("/etc/pam.d/*")
                for item in fileItems:
                    found = False
                    if os.path.islink(item) or os.path.isdir(item):
                        continue
                    contents = readFile(item, self.logger)
                    if not contents:
                        continue
                    for line in contents:
                        if re.match('^#', line) or re.match(r'^\s*$', line):
                            continue
                        elif re.search("pam_rhosts", line):
                            found = True
                            compliant = False
                            self.detailedresults += "pam_rhosts line " + \
                                "found in " + item + "\n"
                            break
                    if found:
                        self.incorrects.append(item)
                for item in fileItems:
                    if os.path.islink(item) or os.path.isdir(item):
                        continue
                    if not checkPerms(item, [0, 0, 420], self.logger):
                        compliant = False
                        self.detailedresults += "Permissions for " + \
                            item + " are incorrect\n"
                        break
            if self.incorrects:
                debug = "The following files need to be corrected: " + \
                    str(self.incorrects) + "\n\n"
                self.logger.log(LogPriority.DEBUG, debug)
            self.compliant = compliant
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''DisableWeakAuthentication.fix() Public method to fix any issues
        that were found in the report method.
        @author: dwalker


        :returns: bool - False if the method died during execution

        '''
        try:
            self.detailedresults = ""
            if not self.ci.getcurrvalue():
                return
            success = True
            for item in self.rsh:
                if self.helper.check(item):
                    if not self.helper.remove(item):
                        success = False
            if self.incorrects:
                for item in self.incorrects:
                    tempstring = ""
                    contents = readFile(item, self.logger)
                    if not contents:
                        continue
                    for line in contents:
                        if re.match('^#', line) or re.match(r'^\s*$', line):
                            tempstring += line
                        elif re.search("pam_rhosts", line):
                            continue
                        else:
                            tempstring += line
                    if not checkPerms(item, [0, 0, 420], self.logger):
                        if not setPerms(item, [0, 0, 420], self.logger):
                            success = False
                    tmpfile = item + ".tmp"
                    if writeFile(tmpfile, tempstring, self.logger):
                        os.rename(tmpfile, item)
                        os.chown(item, 0, 0)
                        os.chmod(item, 420)
                        resetsecon(item)
                    else:
                        success = False
            for item in self.pams:
                if os.path.exists(item):
                    if not checkPerms(item, [0, 0, 420], self.logger):
                        if not setPerms(item, [0, 0, 420], self.logger):
                            success = False
            if os.path.exists("/etc/pam.d/"):
                fileItems = glob.glob("/etc/pam.d/*")
                for item in fileItems:
                    if not checkPerms(item, [0, 0, 420], self.logger):
                        if not setPerms(item, [0, 0, 420], self.logger):
                            success = False
            return success
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def undo(self):
        '''There is no undo method for this rule since we don't ever want rsh
        installed or for the r services to be enabled.  Overrides the undo
        inside the rule.py class


        '''
        try:
            info = "no undo available"
            self.logger.log(LogPriority.INFO, info)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return False
