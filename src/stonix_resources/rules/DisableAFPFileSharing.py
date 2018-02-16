###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
This method disables AFP file sharing on mac os x systems

@author: Breen Malmberg
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2016/07/07 ekkehard converted to RuleKVEditor
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
'''

from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor

from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority

import re
import traceback


class DisableAFPFileSharing(RuleKVEditor):
    '''
AFP & SMB start up and stop

AFP Service
Starting and Stopping AFP Service
To start AFP service:
$ sudo serveradmin start afp
To stop AFP service:
$ sudo serveradmin stop afp
Checking AFP Service Status
To see if AFP service is running:
$ sudo serveradmin status afp
To see complete AFP status:
$ sudo serveradmin fullstatus afp
Viewing AFP Settings
To list all AFP service settings:
$ sudo serveradmin settings afp
To list a particular setting:
$ sudo serveradmin settings afp:setting
    This method disables AFP file sharing on mac os x systems

    @author: Breen Malmberg
    '''

###############################################################################

    def __init__(self, config, environ, logger, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logger,
                              statechglogger)
        self.rulenumber = 164
        self.rulename = 'DisableAFPFileSharing'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.logger = logger
        self.rootrequired = True
        self.guidance = ['CIS 1.4.14.3']

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.11.0', 'r', '10.13.10']}}

        if self.environ.getostype() == "Mac OS X":
            self.addKVEditor("DisableAFPFileSharing",
                             "defaults",
                             "/System/Library/LaunchDaemons/com.apple.AppleFileServer",
                             "",
                             {"Disabled": ["1", "-bool True"]},
                             "present",
                             "",
                             "Disable AFP File Sharing",
                             None,
                             False,
                             {})

        self.initObjs()
        self.determineOrigAFPstatus()
        self.sethelptext()

    def initObjs(self):
        '''
        initialize any objects to be used by this class

        @return: void
        @author: Breen Malmberg
        '''

        self.cmdhelper = CommandHelper(self.logger)

    def determineOrigAFPstatus(self):
        '''
        store the original operational state/status of
        Apple File Server as a bool
        '''

        # default init
        self.afporigstatus = False

        # if version = 10.10.*, then use KVEditor and ignore the other code
        if not re.search("10\.10.*", self.environ.getosver(), re.IGNORECASE):

            getafpstatuscmd = "launchctl list com.apple.AppleFileServer"
            self.cmdhelper.executeCommand(getafpstatuscmd)
            retcode = self.cmdhelper.getReturnCode()
            if retcode != 0:
                errstr = self.cmdhelper.getErrorString()
                self.logger.log(LogPriority.DEBUG, errstr)
            outputstr = self.cmdhelper.getOutputString()
            if not re.search("Could not find", outputstr, re.IGNORECASE):
                self.afporigstatus = True

    def fix(self):
        '''
        disable Apple File Sharing service

        @return: success
        @rtype: bool
        @author: Breen Malmberg
        '''

        success = True

        try:

            # if version = 10.10.*, then use KVEditor and ignore the other code
            if re.search("10\.10.*", self.environ.getosver(), re.IGNORECASE):
                RuleKVEditor.fix(self)
            else:

                clientfixpath1 = "/System/Library/LaunchDaemons/com.apple.AppleFileServer"
                clientfixtool = "launchctl"
                clientfixcmd1 = clientfixtool + " unload " + clientfixpath1

                # the below 'path' is actually an alias
                # which is understood by launchctl.
                # in mac terminology, this is called a 'target'
                clientfixpath2 = "system/com.apple.AppleFileServer"
                clientfixcmd2 = clientfixtool + " disable " + clientfixpath2

                self.cmdhelper.executeCommand(clientfixcmd1)
                retcode = self.cmdhelper.getReturnCode()
                if retcode != 0:
                    errstr = self.cmdhelper.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errstr)
                    success = False
                self.cmdhelper.executeCommand(clientfixcmd2)
                retcode = self.cmdhelper.getReturnCode()
                if retcode != 0:
                    errstr = self.cmdhelper.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errstr)
                    success = False

            if success:
                self.detailedresults += "\nApple File Server has successfully been disabled."

            self.formatDetailedResults('fix', success, self.detailedresults)
            return success
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

    def undo(self):
        '''
        restore Apple File Sharing service
        to its original state

        @return: void
        @author: Breen Malmberg
        '''

        success = True

        try:

            # if version = 10.10.*, then use KVEditor and ignore the other code
            if re.search("10\.10.*", self.environ.getosver(), re.IGNORECASE):
                RuleKVEditor.undo(self)
            else:

                if not self.afporigstatus:
                    undocmd1 = "launchctl enable system/com.apple.AppleFileServer"
                    undocmd2 = "launchctl load /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist"
                    self.cmdhelper.executeCommand(undocmd1)
                    retcode = self.cmdhelper.getReturnCode()
                    if retcode != 0:
                        success = False
                        errstr = self.cmdhelper.getErrorString()
                        self.logger.log(LogPriority.DEBUG, errstr)
                    self.cmdhelper.executeCommand(undocmd2)
                    retcode = self.cmdhelper.getReturnCode()
                    if retcode != 0:
                        success = False
                        errstr = self.cmdhelper.getErrorString()
                        self.logger.log(LogPriority.DEBUG, errstr)

                if not success:
                    self.detailedresults += "\nUndo failed to restore Apple File Sharing to its original state on this system."
                else:
                    self.detailedresults += "\nUndo has successfully restored Apple File Sharing to its original state on this system."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults('undo', success, self.detailedresults)
        return success
