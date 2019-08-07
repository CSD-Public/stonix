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
Created on Mar 20, 2018

This method runs all the report methods for RuleKVEditors in defined in the
dictionary

@author: bgonz12
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''

import traceback
import re
import os
import pwd

from ..ruleKVEditor import RuleKVEditor
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority

class ShowBluetoothIcon(RuleKVEditor):
    '''@author: bgonz12'''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 131
        self.rulename = 'ShowBluetoothIcon'
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.sethelptext()
        self.rootrequired = False
        self.guidance = []
        self.statechglogger = statechglogger
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        self.ch = CommandHelper(self.logdispatch)
        
        self.systemuiserver = ""
        self.bluetoothmenu = ""
        
        if self.environ.geteuid() != 0:
            user = pwd.getpwuid(os.getuid())[ 0 ]
            self.systemuiserver = "/Users/" + user + "/Library/Preferences/com.apple.systemuiserver"
            self.bluetoothmenu = "\"/System/Library/CoreServices/Menu Extras/Bluetooth.menu\""
            self.addKVEditor("ShowBluetoothIcon",
                             "defaults",
                             self.systemuiserver,
                             "",
                             {"menuExtras": [self.bluetoothmenu, "-array-add " + self.bluetoothmenu]},
                             "present",
                             "",
                             "Show Bluetooth Icon in the Menu Bar.",
                             None,
                             False,
                             {})

    def report(self):
        '''determine the compliance status of ShowBluetoothIcon
        on the current system


        :returns: self.compliant

        :rtype: bool
@author: bgonz12

        '''
        
        self.detailedresults = ""
        self.compliant = True
        compliant = True

        try:
            if not RuleKVEditor.report(self, True):
                compliant = False
                self.logdispatch.log(LogPriority.DEBUG, "KVeditor.report() returned False.")
                
            self.compliant = compliant

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

    def fix(self):
        '''run fixed actions for ShowBluetoothIcon
        return True if all succeed


        :returns: fixed

        :rtype: bool
@author: bgonz12

        '''
        self.detailedresults = ""
        fixed = True

        try:
            if not RuleKVEditor.fix(self, True):
                fixed = False
                self.logdispatch.log(LogPriority.DEBUG, "Kveditor fixed failed.")

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            fixed = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            self.resultAppend(messagestring)
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixed, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixed

###############################################################################

    def afterfix(self):
        '''reset the menu bar after fix


        :returns: afterfixsuccess

        :rtype: bool
@author: bgonz12

        '''
        afterfixsuccess = True

        try:
            cmd = "killall SystemUIServer"
            if not self.ch.executeCommand(cmd):
                afterfixsuccess = False
            
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            afterfixsuccess = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            self.resultAppend(messagestring)
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        return afterfixsuccess