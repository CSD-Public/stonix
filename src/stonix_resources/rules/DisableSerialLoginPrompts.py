###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was  #
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
This rule disables serial port logins

@author: Eric Ball
@change: 2015/08/05 eball - Original implementation
@change: 2015/08/28 eball - Missing /etc/securetty no longer makes report false
@change: 2015/10/07 eball - Added check and set for permissions
@change 2017/08/28 rsn Fixing to use new help text methods
'''
from __future__ import absolute_import
import os
import re
import traceback
from ..stonixutilityfunctions import writeFile, readFile, iterate, resetsecon
from ..stonixutilityfunctions import checkPerms, setPerms
from ..rule import Rule
from ..logdispatcher import LogPriority


class DisableSerialLoginPrompts(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 70
        self.rulename = "DisableSerialLoginPrompts"
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.helptext = '''This rule disables serial port logins by removing \
serial port entries from /etc/securetty. The fix will also remove deprecated \
virtual console interfaces.'''
        self.applicable = {'type': 'white',
                           'family': ['linux']}

        # Configuration item instantiation
        datatype = "bool"
        key = "DISABLESERIALLOGINPROMPTS"
        instructions = "To disable this rule, set the value of " + \
                       "DISABLESERIALLOGINPROMPTS to false."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.guidance = ["NSA 2.3.1.1", "CCE 4111-1", "CCE 4256-4"]
        self.iditerator = 0
        self.myos = self.environ.getostype().lower()
        self.sethelptext()

    def report(self):
        try:
            self.path = "/etc/securetty"
            self.serialRE = r"^ttyS\d"
            self.compliant = True
            self.detailedresults = ""

            if re.search("red hat|centos|fedora", self.myos):
                perms = [0, 0, 0600]
            else:
                perms = [0, 0, 0644]
            self.perms = perms

            if os.path.exists(self.path):
                sttyText = readFile(self.path, self.logger)
                for line in sttyText:
                    if re.search(self.serialRE, line):
                        self.compliant = False
                        self.detailedresults += self.path + " contains " + \
                            "uncommented serial ports.\n"
                        break
                if not checkPerms(self.path, perms, self.logger):
                    self.compliant = False
                    self.detailedresults += self.path + " permissions " + \
                        "are incorrect.\n"
            else:
                debug = self.path + " does not exist. This is considered " + \
                    "secure, and should disable all serial ports.\n"
                self.logger.log(LogPriority.DEBUG, debug)

        except (KeyboardInterrupt, SystemExit):
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
        try:
            if not self.ci.getcurrvalue():
                return
            success = True
            self.detailedresults = ""
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if os.path.exists(self.path):
                sttyText = readFile(self.path, self.logger)
                newSttyText = []
                for line in sttyText:
                    # Check for both serial connections and the old style of
                    # virtual connections
                    if re.search(self.serialRE, line) or \
                       re.search(r"^vc/\d", line):
                        line = "#" + line
                    newSttyText.append(line)
                newSttyString = "".join(newSttyText)
                tmpfile = self.path + ".tmp"
                if writeFile(tmpfile, newSttyString, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf", "filepath": self.path}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.path,
                                                         tmpfile, myid)
                    os.rename(tmpfile, self.path)

                    perms = self.perms
                    setPerms(self.path, perms, self.logger,
                             self.statechglogger, myid)

                    resetsecon(self.path)
                else:
                    success = False
                    self.detailedresults += "Problem writing new " + \
                                            "contents to temporary file"
            self.rulesuccess = success
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
