###############################################################################
#                                                                             #
# Copyright 2016.  Los Alamos National Security, LLC. This material was       #
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
This method runs all the report methods for RuleKVEditors in defined in the
dictionary

@author: ekkehard j. koch
@change: 2016/03/04 ekkehard Original Implementation
'''
from __future__ import absolute_import
import traceback
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..SystemIntegrityProtection import SystemIntegrityProtection


class SystemIntegrityProtection(Rule):
    '''

    @author: ekkehard j. koch
    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        Rule.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 6
        self.rulename = 'SystemIntegrityProtection'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rules set the network setup of your OS X "
        self.rootrequired = True
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.11.0', 'r', '10.11.10']}}
        self.sipobject = SystemIntegrityProtection(self.logdispatch)

    def report(self):
        try:
            self.detailedresults = ""
            compliant = True
            if compliant:
                compliant = self.sipobject.report()
                self.resultAppend(self.sipobject.getDetailedresults())
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            self.resultAppend(messagestring)
            self.logdispatch.log(LogPriority.ERROR, messagestring)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant
