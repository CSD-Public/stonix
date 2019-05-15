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
Created on Oct 27, 2011
The DisableAutoLogin object is responsible for disabling auto-login on
the system.  This rule is specific to Mac systems.

@operating system: Mac OS X
@author: Roy Nielsen
@change: 02/13/2014 ekkehard Implemented self.detailedresults flow
@change: 02/13/2014 ekkehard Implemented isapplicable
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''
from __future__ import absolute_import
import re
import traceback

# The period was making python complain. Adding the correct paths to PyDev
# made this the working scenario.
from ..ruleKVEditor import RuleKVEditor
from ..filehelper import FileHelper
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority


class DisableAutoLogin(RuleKVEditor):
    '''This class disables Auto Login on the system.'''
    def __init__(self, config, environ, logdispatcher, statechglogger):
        '''
        Constructor
        '''
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 169
        self.rulename = 'DisableAutoLogin'
        self.formatDetailedResults("initialize")
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        self.mandatory = True
        self.rootrequired = True
        self.files = {"kcpassword": {"path": "/etc/kcpassword",
                                     "remove": True,
                                     "content": None,
                                     "permissions": None,
                                     "owner": None,
                                     "group": None,
                                     "eventid":
                                     str(self.rulenumber).zfill(4) +
                                     "kcpassword"}}
        self.addKVEditor("DisableAutoLogin",
                         "defaults",
                         "/Library/Preferences/com.apple.loginwindow",
                         "",
                         {"autoLoginUser": [re.escape("The domain/default pair of (/Library/Preferences/com.apple.loginwindow, autoLoginUser) does not exist"), None]},
                         "present",
                         "",
                         "This variable is to determine whether or not to " +
                         "disable auto login",
                         None,
                         False,
                         {})
        self.fh = FileHelper(self.logdispatch, self.statechglogger)
        self.ch = CommandHelper(self.logdispatch)
        for filelabel, fileinfo in sorted(self.files.items()):
            self.fh.addFile(filelabel,
                            fileinfo["path"],
                            fileinfo["remove"],
                            fileinfo["content"],
                            fileinfo["permissions"],
                            fileinfo["owner"],
                            fileinfo["group"],
                            fileinfo["eventid"])
        self.sethelptext()

    def report(self):
        '''Report on the status of this rule
        
        @author: Roy Nielsen


        '''
        try:
            self.detailedresults = ""
            self.kvcompliant = False
            self.fhcompliant = False
            self.kvcompliant = RuleKVEditor.report(self)
            if not self.kvcompliant:
                self.detailedresults = "DisableAutoLogin is not compliant!"
            else:
                self.detailedresults = "DisableAutoLogin is compliant!"
            self.fhcompliant = self.fh.evaluateFiles()
            if not self.fhcompliant:
                self.detailedresults = self.detailedresults + "\n" + \
                    self.fh.getFileMessage()
            if not self.fhcompliant or not self.kvcompliant:
                self.compliant = False
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''Disables Auto Login
        
        @author: Roy Nielsen


        '''
        try:
            self.detailedresults = ""
            fixed = False
            self.kvfix = False
            self.fhfix = False
            self.kvfix = RuleKVEditor.fix(self)
            if self.kvfix:
                self.fhfix = self.fh.fixFiles()
                if self.fhfix:
                    self.detailedresults = self.detailedresults + "\n" + \
                        self.fh.getFileMessage()
            if not self.kvfix or not self.fhfix:
                fixed = False
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixed,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixed
