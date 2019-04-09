###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
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
"""
This rule will enable process accounting, using the acct/psacct service.

@author: Eric Ball
@change: 2015/04/18 eball Original implementation
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/10/23 rsn - change to new service helper interface
"""

from __future__ import absolute_import

import traceback

from ..stonixutilityfunctions import iterate
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..ServiceHelper import ServiceHelper


class ConfigureProcessAccounting(Rule):
    """
    Class docs
    """

    def __init__(self, config, environ, logger, statechglogger):
        """

        @param config:
        @param environ:
        @param logger:
        @param statechglogger:
        """

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 97
        self.rulename = "ConfigureProcessAccounting"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.guidance = ["CCE-RHEL7-CCE-TBD 3.2.15"]
        self.applicable = {"type": "white",
                           "family": ["linux"]}

        # Configuration item instantiation
        datatype = "bool"
        key = "CONFIGUREPROCESSACCOUNTING"
        instructions = "To disable this rule, set the value of " + \
                       "CONFIGUREPROCESSACCOUNTING to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.ph = Pkghelper(self.logger, self.environ)
        self.sh = ServiceHelper(self.environ, self.logger)

    def report(self):
        """

        @return: self.compliant
        @rtype: bool
        @author: Eric Ball
        @change: Breen Malmberg - 04/09/2019 - doc string added; method refactor;
                added debug logging
        """

        self.compliant = True
        self.detailedresults = ""
        self.packages = ["psacct", "acct"]

        try:

            if not any(self.ph.check(p) for p in self.packages):
                self.compliant = False
                self.detailedresults += "\nsystem accounting package is not installed"

            if not any(self.sh.auditService(p) for p in self.packages):
                self.compliant = False
                self.detailedresults += "\nsystem accounting service is not enabled"

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        """

        @return: self.rulesuccess
        @rtype: bool
        @author: Eric Ball
        @change: Breen Malmberg - 04/09/2019 - doc string added; method refactor;
                added debug logging
        """

        self.rulesuccess = True
        self.detailedresults = ""
        self.iditerator = 0

        try:

            if not self.ci.getcurrvalue():
                self.rulesuccess = False
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess

            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            for p in self.packages:
                if self.ph.install(p):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "pkghelper", "pkgname": p,
                             "startstate": "removed", "endstate": "installed"}
                    self.statechglogger.recordchgevent(myid, event)
            if self.iditerator == 0:
                self.rulesuccess = False
                self.detailedresults += "\nFailed to install system accounting package"

            for p in self.packages:
                if self.ph.check(p):
                    self.sh.enableService(p)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "servicehelper", "servicename": p,
                             "startstate": "disabled", "endstate": "enabled"}
                    self.statechglogger.recordchgevent(myid, event)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
