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
This method runs all the report methods for RuleKVEditors in defined in the
dictionary

@author: ekkehard j. koch
@change: 2016/03/04 ekkehard Original Implementation
@change: 2017/06/27 ekkehard Update help text
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/07/26 ekkehard - make it an audit only rule
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''

import traceback
import types
from rule import Rule
from logdispatcher import LogPriority
from SystemIntegrityProtectionObject import SystemIntegrityProtectionObject


class SystemIntegrityProtection(Rule):
    '''@author: ekkehard j. koch'''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        Rule.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 6
        self.rulename = 'SystemIntegrityProtection'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        self.sipobject = SystemIntegrityProtectionObject(self.logdispatch)
        self.auditonly = True

    def report(self):
        try:
            self.detailedresults = ""
            compliant = True
            if compliant:
                compliant = self.sipobject.report()
                self.resultAppend(self.sipobject.messageGet())
            self.compliant = compliant
            self.rulesuccess = True
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            self.resultAppend(messagestring)
            self.logdispatch.log(LogPriority.ERROR, messagestring)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant
    
###############################################################################

    def resultAppend(self, pMessage=""):
        '''append results to detailed results.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pMessage:  (Default value = "")
        :returns: boolean - true
        @note: None

        '''
        datatype = type(pMessage)
        if datatype == bytes:
            if not (pMessage == ""):
                messagestring = pMessage
                if (self.detailedresults == ""):
                    self.detailedresults = messagestring
                else:
                    self.detailedresults = self.detailedresults + "\n" + \
                    messagestring
        elif datatype == list:
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
                            "type " + str(bytes) + \
                            " or type " + str(list) + \
                            " as expected!")

###############################################################################

    def resultReset(self):
        '''reset detailed results.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :returns: boolean - true
        @note: None

        '''
        self.detailedresults = ""
