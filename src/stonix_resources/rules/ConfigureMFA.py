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
This method configures Multi Factor Authentication on LANL networks via 
managing the state of the pam configuration files.

@author: Roy Nielsen
'''
from __future__ import absolute_import
import re
import os
import copy
import datetime
import traceback

from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..FileStateManager import FileStateManager
from ..logdispatcher import LogPriority
from ..ruleKVEditor import RuleKVEditor
from ..ServiceHelper import ServiceHelper
from ..CheckApplicable import CheckApplicable

class ConfigureMFA(Rule):
    '''

    @author: Roy Nielsen
    '''
    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 388
        self.rulename = 'ConfigureMFA'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rules set the a macOS system to use Multi " +\
        "Factor Authentication.  After being configured, a macOS system " +\
        "will support crypto-card login."
        self.rootrequired = True
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.10.0', 'r', '10.12.10']}}

        datatype = "bool"
        key = "CCPOLICY"
        instructions = "To enable stonix to configure cryptocard login, set " +\
                       "the value of CCPOLICY to True."
        default = False
        self.ccci = self.initCi(datatype, key, instructions, default)

        self.chkApp = CheckApplicable(self.environ, self.logdispatch)
        self.macApplicable = {'type': 'white',
                              'os': {'Mac OS X': ['10.10.0', 'r', '10.12.10']}}

        self.fsm = FileStateManager(self.environ, self.logdispatch)
        self.fsm.setPrefix(self.environ.get_resources_path() + "/files/FileStateManager/pam")

        self.fsm.setVersion(self.environ.getstonixversion())
        self.filesLists = []
        self.fixState = ""
        self.filesList = []
        self.rulesuccess = True

    def report(self):
        '''
        '''
        self.logdispatch.log(LogPriority.DEBUG, "Entering ConfigureMFA.report()...")
        self.state = ""
        self.states = []
        success = False
        self.detailedresults = ""
        self.compliant = False

        try:
            #####
            # Build the "stateAfter" state string for the current platform
            macReportApplicable = copy.deepcopy(self.macApplicable)
            if self.chkApp.isApplicable(macReportApplicable):
                self.buildMacStates(self.environ.getosfamily(),
                                    self.environ.getostype(),
                                    self.environ.getosver(),
                                    ["sAadmin-sAmfa", "sBadmin-sAmfa"])

            if self.states:
                for state in self.states:
                    foundState, scratchFileList = self.fsm.getLatestFileSet(state)

                    #####
                    # Check that the path is correct                    
                    areInState = self.fsm.areFilesInState(foundState, scratchFileList)
                    if areInState:
                        self.compliant = True
                        self.detailedresults = "Configuration files state is compliant."
                        break
                self.logger.log(LogPriority, "filesLists: " + str(self.filesLists))
                if not self.compliant:
                    self.detailedresults = "Configuration files are not in a compliant state..."

            else:
                self.compliant = False
                self.detailedresults = "Unable to grok state..."
            
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            self.detailedresults += messagestring
            self.logdispatch.log(LogPriority.ERROR, str(self.detailedresults))
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        self.logdispatch.log(LogPriority.DEBUG, "Exiting ConfigureMFA.report() and returning self.compliant=" + str(self.compliant))

        return self.compliant

    def fix(self):
        '''
        '''
        self.detailedresults = ""
        self.logdispatch.log(LogPriority.DEBUG, "Entering fix method.")
        self.rulesuccess = False
        success = False
        fileList = []
        #if self.ccci.getcurrvalue():
        try:
            if self.ccci.getcurrvalue():

                self.logdispatch.log(LogPriority.DEBUG, "CI enabled.")

                macFixApplicable = copy.deepcopy(self.macApplicable)
                self.logdispatch.log(LogPriority.DEBUG, "macFixApplicable: " + str(macFixApplicable))
                if self.chkApp.isApplicable(macFixApplicable):
                    self.buildMacStates(self.environ.getosfamily(),
                                        self.environ.getostype(),
                                        self.environ.getosver(),
                                        ["sAadmin-sBmfa", "sBadmin-sBmfa"])
                else:
                    self.logdispatch.log(LogPriority.DEBUG, "Not appropriate" +\
                                         " for this operating system.")

                for state in self.states:
                    self.logdispatch.log(LogPriority.DEBUG, "self.states: " + str(self.states))
                    foundState, scratchFileList = self.fsm.getLatestFileSet(state)

                    if not self.fsm.areFilesInState(state, scratchFileList):
                        self.logdispatch.log(LogPriority.DEBUG, "state: " + str(state))
                        self.logdispatch.log(LogPriority.DEBUG, "file list: " + str(scratchFileList))
                        #####
                        # If they are, create a refState based on the
                        # miniState for copying the correct "to" state
                        if re.search("sAadmin-sBmfa", state):
                            refState = re.sub("sAadmin-sBmfa", "sAadmin-sAmfa", state)
                        elif re.search("sBadmin-sBmfa", state):
                            refState = re.sub("sBadmin-sBmfa", "sBadmin-sAmfa", state)
                        else:
                            continue

                        fullPathRefState, afterFileList = self.fsm.getLatestFileSet(refState)
                        self.logdispatch.log(LogPriority.DEBUG, "refState: " + str(refState))
                        self.logdispatch.log(LogPriority.DEBUG, "afterFileList: " + str(afterFileList))
                        #####
                        # Attept to change the files state
                        success = self.fsm.changeFilesState(fullPathRefState, afterFileList)
                        if success:
                            self.rulesuccess = True
                            self.detailedresults = "Configuration item success! "
                            self.logdispatch.log(LogPriority.DEBUG, "Configuration Success!")
                            break
                        else:
                            self.rulesuccess = False
                            self.logger.log(LogPriority.DEBUG, "Problem changing the files state.")
                            self.logger.log(LogPriority.DEBUG, "....")
                            continue
                    if not self.rulesuccess:
                        self.detailedresults = "Configuration state change from: " + str(availableBeforeStates) + " failed... "
                    else:
                        break
                if not self.rulesuccess:
                    self.logdispatch.log(LogPriority.DEBUG, "Problem with states . . .")
            else:
                self.rulesuccess = False
                self.detailedresults = "Configuration item not enabled "

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = 'ConfigureMFA: '
            self.detailedresults = self.detailedresults + \
                traceback.format_exc()
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                            self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        self.compliant = self.rulesuccess
        self.logdispatch.log(LogPriority.DEBUG, "Exiting fix method.")
        return self.rulesuccess

    def undo(self):
        '''
        '''
        pass

    def buildMacStates(self, osFamily="", osType="", osVers="", chkStates=[]):
        """
        """
        success = False
        pre_state = ""
        self.states = []
        self.logdispatch.log(LogPriority.DEBUG, str(osFamily))
        self.logdispatch.log(LogPriority.DEBUG, str(osType))
        self.logdispatch.log(LogPriority.DEBUG, str(osVers))

        if osFamily and osType and osVers:
            if len(osVers.split(".")) >= 2:
                tmpOsVers = '.'.join(osVers.split('.')[0:2])
            else:
                tmpOsVers = osVers
            tmpOsState = osFamily + "/" + osType + "/" + tmpOsVers 
            pre_state = re.sub(" ", "", tmpOsState)
        else:
            pre_state = ""
            self.logdispatch.log(LogPriority.DEBUG, "osVers: " )
        if pre_state and chkStates:
            for state in chkStates:
                self.states.append(pre_state + "/" + state)
            success = True
        else:
            self.logdispatch.log(LogPriority.DEBUG, "Something wrong acquiring states. . .")
            self.logdispatch.log(LogPriority.DEBUG, "pre_state: " + str(pre_state))
            self.logdispatch.log(LogPriority.DEBUG, "pre_state: " + str(self.states))
        self.logdispatch.log(LogPriority.DEBUG, "state: " + str(self.states))
        return success
