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
This method runs all the report methods for RuleKVEditors in defined in the
dictionary

@author: ekkehard j. koch
@change: 03/25/2014 Original Implementation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2016/05/31 ekkehard fix help text
@change: 2016/06/22 eball Added &= to afterfix checks so that all checks before
    the last one are not discarded. Also cleaned up help text (again!)
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/10/23 rsn - change to new service helper interface
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
'''
from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor
from ..CommandHelper import CommandHelper
from ..ServiceHelper import ServiceHelper
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
from re import search
import traceback

class ConfigureFirewall(RuleKVEditor):
    '''

    @author: ekkehard j. koch
    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 14
        self.rulename = 'ConfigureFirewall'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']}}
        self.ch = CommandHelper(self.logdispatch)
        self.sh = ServiceHelper(self.environ, self.logdispatch)
        self.fwcmd = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        self.list = self.fwcmd + " --listapps"
        self.add = self.fwcmd + " --add "
        self.rmv = self.fwcmd + " --remove "
        self.iditerator = 0
        datatype = 'bool'
        key = 'CONFIGUREFIREWALL'
        instructions = "To disable this rule set CONFIGUREFIREWALL to False\n"
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.addKVEditor("FirewallOn",
                         "defaults",
                         "/Library/Preferences/com.apple.alf",
                         "",
                         {"globalstate": ["1", "-int 1"]},
                         "present",
                         "",
                         "Turn On Firewall. When enabled.",
                         None,
                         False,
                         {"globalstate": ["0", "-int 0"]})
        self.addKVEditor("FirewallLoginEnabled",
                         "defaults",
                         "/Library/Preferences/com.apple.alf",
                         "",
                         {"loggingenabled": ["1", "-int 1"]},
                         "present",
                         "",
                         "Login Enabled. When enabled.",
                         None,
                         False,
                         {"loggingenabled": ["0", "-int 0"]})
        self.addKVEditor("FirewallStealthDisabled",
                         "defaults",
                         "/Library/Preferences/com.apple.alf",
                         "",
                         {"stealthenabled": ["0", "-int 0"]},
                         "present",
                         "",
                         "Stealth Disabled. When enabled.",
                         None,
                         False,
                         {"stealthenabled": ["1", "-int 1"]})
        try:
            self.applist = []
            self.ch.executeCommand(self.list)
            output = self.ch.getOutput()
            for line in output:
                if search("^\d+\ :\s+/Applications", line) and search("/", line):
                    appsplit = line.split("/")
                    try:
                        app = appsplit[-1].strip()
                        self.applist.append(app)
                    except IndexError:
                        continue
            datatype = 'list'
            key = 'ALLOWEDAPPS'
            instructions = "Space separated list of Applications allowed by the firewall"
            default = self.applist
            self.appci = self.initCi(datatype, key, instructions, default)
        except OSError:
            datatype = 'string'
            key = "ALLOWEDAPPS"
            instructions = "Space separated list of Applications allowed by the firewall"
            default = "Unable to run command to obtain allowed applications"
            self.appci = self.initCi(datatype, key, instructions, default)

    def report(self):
        try:
            compliant = True
            self.detailedresults = ""
            if not RuleKVEditor.report(self, True):
                compliant = False
            self.allowedapps = self.appci.getcurrvalue()
            '''There are '''
            if self.allowedapps and isinstance(self.allowedapps, list):
                for app in self.allowedapps:
                    if app not in self.applist:
                        compliant = False
                        self.detailedresults += "Connections from " + app + \
                            "not allowed but should be.\n"
                    else:
                        self.applist.remove(app)
                if self.applist:
                    compliant = False
                    for item in self.applist:
                        self.detailedresults += item +  " is allowed but shouldn't be\n"
            elif self.applist:
                '''self.allowedapps is blank but there are apps being allowed through
                the firewall.  We must remove these from being allowed.'''
                compliant = False
                for item in self.applist:
                    self.detailedresults += item +  " is allowed but shouldn't be\n"
            self.compliant = compliant
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        try:
            success = True
            self.detailedresults = ""
            if not self.ci.getcurrvalue():
                return
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            if not RuleKVEditor.fix(self, True):
                success = False
            if self.allowedapps and isinstance(self.allowedapps, list):
                for app in self.allowedapps:
                    if app not in self.applist:
                        if not self.ch.executeCommand(self.add + "/Applications/" + app):
                            success = False
                            self.detailedresults += "Unable to add " + \
                                app + " to firewall allowed list\n"
                        else:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            undocmd = self.rmv + "/Applications/" + app
                            event = {"eventtype": "comm",
                                     "command": undocmd}
                            self.statechglogger.recordchgevent(myid, event)
            elif self.applist:
                tmp = []
                for app in self.applist:
                    if not self.ch.executeCommand(self.rmv + "/Applications/" + app):
                        success = False
                        self.detailedresults += "Unable to remove " + \
                            app + " from firewall allowed list\n"
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        undocmd = self.add + "/Applications/" + app
                        event = {"eventtype": "comm",
                                 "command": undocmd}
                        self.statechglogger.recordchgevent(myid, event)
                        tmp.append(app)
                for app in tmp:
                    self.applist.remove(app)
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def afterfix(self):
        afterfixsuccessful = True
        service = "/System/Library/LaunchDaemons/com.apple.alf.plist"
        servicename = "com.apple.alf"
        afterfixsuccessful &= self.sh.auditService(service, servicename=servicename)
        afterfixsuccessful &= self.sh.disableService(service, servicename=servicename)
        afterfixsuccessful &= self.sh.enableService(service, servicename=servicename)
        return afterfixsuccessful
