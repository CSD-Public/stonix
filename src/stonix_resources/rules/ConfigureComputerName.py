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
Created on Dec 3, 2014

@author: dwalker
@change: 2015/04/14 dkennel updated for new isApplicable
'''
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..lanlMacInfo import lanlMacInfo
import traceback
import types


class ConfigureComputerName(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 260
        self.rulename = "ConfigureComputerName"
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.10']}}
        self.formatDetailedResults("initialize")
        self.lmi = None
        self.mandatory = True
        self.helptext = "This rule sets the name of the computer based on " + \
        "information on the mac and information available in LDAP."
        self.rootrequired = True
        self.guidance = [""]
        self.CN = ""
        self.logger = logger
        self.iditerator = 0

        #configuration item instantiation
        datatype = 'bool'
        key = 'CONFIGURECOMPUTERNAME'
        instructions = "To disable this rule set the value of " + \
        "CONFIGURECOMPUTERNAME to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

    def report(self):
        try:
            self.resultReset()
            self.compliant = True
            self.initializeLanlMacInfo()
            self.lmi.messageReset()
            self.compliant = self.lmi.getComputerInfoCompliance()
            self.resultAppend(self.lmi.messageGet())
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            messagestring = traceback.format_exc()
            self.resultAppend(messagestring)
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.DEBUG, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            self.resultReset()
            self.initializeLanlMacInfo()
            self.lmi.messageReset()
            success = self.lmi.setComputerInfo()
            self.resultAppend(self.lmi.messageGet())
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            messagestring = traceback.format_exc()
            self.resultAppend(messagestring)
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################

    def initializeLanlMacInfo(self):
        if self.lmi == None:
            self.lmi = lanlMacInfo(self.logdispatch)

###############################################################################

    def resultAppend(self, pMessage=""):
        '''
        reset the current kveditor values to their defaults.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true
        @note: kveditorName is essential
        '''
        datatype = type(pMessage)
        if datatype == types.StringType:
            if not (pMessage == ""):
                messagestring = pMessage
                if (self.detailedresults == ""):
                    self.detailedresults = messagestring
                else:
                    self.detailedresults = self.detailedresults + "\n" + \
                    messagestring
        elif datatype == types.ListType:
            if not (pMessage == []):
                for item in pMessage:
                    messagestring = item
                    if (self.detailedresults == ""):
                        self.detailedresults = messagestring
                    else:
                        self.detailedresults = self.detailedresults + "\n" + \
                        messagestring
        else:
            raise TypeError("pMessage with value" + str(pMessage) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.StringType) + \
                            " or type " + str(types.ListType) + \
                            " as expected!")

###############################################################################

    def resultReset(self):
        '''
        reset the current kveditor values to their defaults.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true
        @note: kveditorName is essential
        '''
        self.detailedresults = ""
