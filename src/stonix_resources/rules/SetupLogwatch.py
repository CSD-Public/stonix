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
Created on Oct 15, 2013

@author: bemalmbe
@change: 02/12/2014 ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 ekkehard ci updates and ci fix method implementation
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/10/08 eball Help text/PEP8 cleanup
'''


import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..stonixutilityfunctions import iterate


class SetupLogwatch(Rule):
    '''classdocs'''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 126
        self.rulename = 'SetupLogwatch'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.guidance = ['NSA(2.6.1.6)', 'CCE 4323-2']
        self.ci = self.initCi("bool",
                              "SETUPLOGWATCH",
                              "To prevent logwatch from being " +
                              "installed, set the value of " +
                              "SetupLogwatch to False.",
                              True)
        self.iditerator = 0
        self.applicable = {'type': 'white',
                           'family': ['linux', 'freebsd']}

    def report(self):
        '''@author bemalmbe'''

        try:
            self.detailedresults = ""
            self.compliant = False
            self.ph = Pkghelper(self.logger, self.environ)
            if self.ph.check('logwatch'):
                self.compliant = True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = str(err) + " - " + \
                str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)

        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''@author bemalmbe'''
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""
            if self.environ.geteuid() == 0:
                self.iditerator = 0
                eventlist = self.statechglogger.findrulechanges(self.rulenumber)
                for event in eventlist:
                    self.statechglogger.deleteentry(event)
            if self.ph.install('logwatch'):
                rmv = self.ph.getRemove() + "logwatch"
                event = {'eventtype': 'commandstring',
                         'command': rmv}
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.statechglogger.recordchgevent(myid, event)
                self.detailedresults += "Installed Logwatch successfully\n"
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = str(err) + " - " + \
                str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)

        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
