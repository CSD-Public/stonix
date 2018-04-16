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
Created on Aug 12, 2013

@author: dwalker
@change: dkennel 04/18/2014 Replaced old style CI with new style
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated to use new isApplicable
@change: 2015/07/27 eball Fixed help text typos and improved PEP8 compliance
@change: 2015/10/27 eball Added feedback to report()
'''
from __future__ import absolute_import
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
    pam_rhosts entry from any pam file, '''
    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 30
        self.rulename = "DisableWeakAuthentication"
        self.mandatory = True
        self.helptext = "The Berkeley r-commands are legacy services which " + \
                        "allow cleartext remote access and have an insecure" + \
                        " trust model. r-commands suffer from the same " + \
                        "hijacking and eavesdropping problems as telnet. " + \
                        "This rules ensures that no r-services are " + \
                        "implemented or installed"
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

    def report(self):
        '''DisableWeakAuthentication.report() Public method to report on the
        presence of certain r-command packages and contents in pam files.
        @author: dwalker
        @return: bool - False if the method died during execution
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
                    if not checkPerms(item, [0, 0, 420], self.logger):
                        compliant = False
                        self.detailedresults += "Permissions for " + \
                            item + " are incorrect\n"
                        break

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
        @return: bool - False if the method died during execution
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
        inside the rule.py class'''
        try:
            info = "no undo available"
            self.logger.log(LogPriority.INFO, info)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return False
