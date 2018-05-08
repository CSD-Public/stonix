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
Created on Oct 15, 2013

@author: bemalmbe
@change: 02/12/2014 ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 ekkehard ci updates and ci fix method implementation
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/10/08 eball Help text/PEP8 cleanup
'''

from __future__ import absolute_import
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..stonixutilityfunctions import iterate


class SetupLogwatch(Rule):
    '''
    classdocs
    '''

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
        '''

        @author bemalmbe
        '''

        try:
            self.detailedresults = ""
            self.compliant = False
            self.ph = Pkghelper(self.logger, self.environ)
            if self.ph.check('logwatch'):
                self.compliant = True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = str(err) + " - " + \
                str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)

        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''

        @author bemalmbe
        '''
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
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = str(err) + " - " + \
                str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)

        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
