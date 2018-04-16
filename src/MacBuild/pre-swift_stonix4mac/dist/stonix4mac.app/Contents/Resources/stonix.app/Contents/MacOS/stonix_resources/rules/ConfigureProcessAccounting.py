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
This rule will enable process accounting, using the acct/psacct service.

@author: Eric Ball
@change: 2015/04/18 eball Original implementation
'''
from __future__ import absolute_import
import re
import traceback
from ..stonixutilityfunctions import iterate
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..ServiceHelper import ServiceHelper


class ConfigureProcessAccounting(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 97
        self.rulename = "ConfigureProcessAccounting"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''This rule will enable process accounting, using \
the acct/psacct service.'''
        self.applicable = {"type": "white",
                           "family": ["linux"]}

        # Configuration item instantiation
        datatype = "bool"
        key = "CONFIGUREPROCESSACCOUNTING"
        instructions = "To disable this rule, set the value of " + \
                       "CONFIGUREPROCESSACCOUNTING to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.guidance = ["CCE-RHEL7-CCE-TBD 3.2.15"]
        self.iditerator = 0

    def report(self):
        try:
            compliant = True
            self.detailedresults = ""
            self.ph = Pkghelper(self.logger, self.environ)
            self.sh = ServiceHelper(self.environ, self.logger)
            myos = self.environ.getostype().lower()

            if re.search("red hat|fedora|centos", myos):
                package = "psacct"
            else:
                package = "acct"
            self.package = package

            if not self.ph.check(package):
                compliant = False
                if self.ph.checkAvailable(package):
                    self.detailedresults += package + " is not installed\n"
                else:
                    self.detailedresults += package + " is not available " + \
                        "for installation\n"
            elif not self.sh.auditservice(package):
                compliant = False
                self.detailedresults += package + " service is not enabled\n"

            self.compliant = compliant

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
            package = self.package

            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if not self.ph.check(package):
                if self.ph.checkAvailable(package):
                    self.ph.install(package)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "pkghelper", "pkgname": package,
                             "startstate": "removed", "endstate": "installed"}
                    self.statechglogger.recordchgevent(myid, event)
                else:
                    success = False
                    self.detailedresults += package + " is not available " + \
                        "for installation\n"

            if self.ph.check(package) and not self.sh.auditservice(package):
                self.sh.enableservice(package)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "servicehelper", "servicename": package,
                         "startstate": "disabled", "endstate": "enabled"}
                self.statechglogger.recordchgevent(myid, event)

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
