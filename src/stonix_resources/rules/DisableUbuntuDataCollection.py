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
Created on 2018/07/09

Disable user and system statistics reporting on Ubuntu

@author: Breen Malmberg
'''



import traceback

from rule import Rule
from pkghelper import Pkghelper
from logdispatcher import LogPriority
from stonixutilityfunctions import iterate

class DisableUbuntuDataCollection(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        '''

        :param config:
        :param environ:
        :param logger:
        :param statechglogger:

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
        '''Check for the existence of any of a number of data-collection
        and reporting utilities on the system
        report compliance status as not compliant if any exist
        report compliance status as compliant if none exist


        :returns: self.compliant

        :rtype: bool
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
        '''Remove any data-collection and reporting utilities from the system
        report success status as True if all are removed
        report success status as False if any remain


        :returns: self.rulesuccess

        :rtype: bool
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
