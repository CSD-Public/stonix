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
Created on Mar 20, 2018

This method runs all the report methods for RuleKVEditors in defined in the
dictionary

@author: bgonz12
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''
from __future__ import absolute_import
import traceback
import re
import os
import pwd

from ..ruleKVEditor import RuleKVEditor
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority

class ShowBluetoothIcon(RuleKVEditor):
    '''
    
    @author: bgonz12
    '''

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
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
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
        '''
        determine the compliance status of ShowBluetoothIcon
        on the current system

        @return: self.compliant
        @rtype: bool
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
        except Exception, err:
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
        '''
        run fixed actions for ShowBluetoothIcon
        return True if all succeed

        @return: fixed
        @rtype: bool
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
        except Exception, err:
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
        '''
        reset the menu bar after fix

        @return: afterfixsuccess
        @rtype: bool
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