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
Created on 2018/07/09

Disable user and system statistics reporting on Ubuntu

@author: Breen Malmberg
'''

from __future__ import absolute_import

import traceback

from ..rule import Rule
from ..pkghelper import Pkghelper
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate

class DisableUbuntuDataCollection(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        '''

        @param config:
        @param environ:
        @param logger:
        @param statechglogger:
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.environ = environ
        self.rulenumber = 311
        self.rulename = "DisableUbuntuDataCollection"
        self.mandatory = True
        self.rootrequired = True
        self.formatDetailedResults("initialize")
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Ubuntu': ['16.04', '+']}}
        self.sethelptext()

        datatype = "bool"
        key = "DISABLEUBUNTUDATACOLLECTION"
        instructions = """To prevent the diabling of data collection from this system, set the value of DISABLEUBUNTUDATACOLLECTION to False."""
        default = True
        self.enabledCI = self.initCi(datatype, key, instructions, default)

    def report(self):
        '''
        Check for the existence of any of a number of data-collection
        and reporting utilities on the system
        report compliance status as not compliant if any exist
        report compliance status as compliant if none exist

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.detailedresults = ""
        self.ph = Pkghelper(self.logger, self.environ)
        self.compliant = True

        self.pkgslist = ["popularity-contest", "apport", "ubuntu-report"]
        self.removepkgs = []

        try:

            for pkg in self.pkgslist:
                if self.ph.check(pkg):
                    self.compliant = False
                    self.detailedresults += "\nData collection utility: " + str(pkg) + " is still installed"
                    self.removepkgs.append(pkg)

            print "\nThe following packages are in self.removepkgs:\n" + "\n".join(self.removepkgs)

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
        '''
        Remove any data-collection and reporting utilities from the system
        report success status as True if all are removed
        report success status as False if any remain

        @return: self.rulesuccess
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0

        try:

            if self.enabledCI.getcurrvalue():

                eventlist = self.statechglogger.findrulechanges(self.rulenumber)
                for event in eventlist:
                    self.statechglogger.deleteentry(event)

                for pkg in self.removepkgs:
                    print "\nAttempting to remove " + pkg
                    if not self.ph.remove(pkg):
                        self.detailedresults += "\nUnable to remove package: " + str(pkg)
                        self.rulesuccess = False
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        comm = self.ph.getRemove() + pkg
                        event = {"eventtype": "commandstring",
                                 "command": comm}
                        self.statechglogger.recordchgevent(myid, event)
                        self.logger.log(LogPriority.DEBUG, "Removing package: " + str(pkg))

            else:
                self.logger.log(LogPriority.DEBUG, "Rule was NOT enabled. Nothing was done.")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
