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
This method disables AFP file sharing on mac os x systems

@author: Breen Malmberg
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2016/07/07 ekkehard converted to RuleKVEditor
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
'''

from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor

from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority

import re
import traceback


class DisableAFPFileSharing(RuleKVEditor):
    '''AFP & SMB start up and stop
    
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
                           'os': {'Mac OS X': ['10.11.0', 'r', '10.14.10']}}

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
        '''initialize any objects to be used by this class


        :returns: void
        @author: Breen Malmberg

        '''

        self.cmdhelper = CommandHelper(self.logger)

    def determineOrigAFPstatus(self):
        '''store the original operational state/status of
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
        '''disable Apple File Sharing service


        :returns: success

        :rtype: bool
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
        '''restore Apple File Sharing service
        to its original state


        :returns: void
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
