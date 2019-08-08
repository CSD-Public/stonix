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
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
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
    '''@author: ekkehard j. koch'''

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
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
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
        self.currallowed = []
        '''Any values inside stonix.conf overrule the values inserted 
        in the text field unless changes are saved to stonix.conf'''
        try:
            '''variable to hold apps currently allowed by firewall'''
            self.ch.executeCommand(self.list)
            output = self.ch.getOutput()
            for line in output:
                if search("^\d+\ :\s+/Applications", line) and search("/", line):
                    appsplit = line.split("/")
                    try:
                        '''Get the application name and store it in self.currallowed'''
                        app = appsplit[-1].strip()
                        self.currallowed.append(app)
                    except IndexError:
                        continue
            '''Put any already allowed apps into the CI'''
            datatype = 'list'
            key = 'ALLOWEDAPPS'
            instructions = "Space separated list of Applications allowed by the firewall\n" + \
                "All applications end with .app.  For a list of applications check the\n" + \
                "/Applications folder."
            default = self.currallowed
            self.appci = self.initCi(datatype, key, instructions, default)
        except OSError:
            '''There are no currently allowed apps for the fw'''
            datatype = 'list'
            key = 'ALLOWEDAPPS'
            instructions = "Space separated list of Applications allowed by the firewall\n" + \
                "All applications end with .app.  For a list of applications check the\n" + \
                "/Applications folder."
            default = self.currallowed
            self.appci = self.initCi(datatype, key, instructions, default)

    def report(self):
        '''@summary: Checks compliancy of system according to this rule
        @author: dwalker


        :returns: bool - True or False

        '''
        try:
            self.iditerator = 0
            self.rulesuccess = True
            compliant = True
            self.detailedresults = ""
            '''Check to see if other parts of rule are compliant'''
            if not RuleKVEditor.report(self, True):
                compliant = False
            self.applist = []
            '''Run the list command to see which applications are
            currently allowed past the firewall'''
            self.ch.executeCommand(self.list)
            output = self.ch.getOutput()
            for line in output:
                if search("^\d+\ :\s+/Applications", line) and search("/", line):
                    appsplit = line.split("/")
                    try:
                        '''Get the application name and store it in self.applist'''
                        app = appsplit[-1].strip()
                        self.applist.append(app)
                    except IndexError:
                        continue
            '''self.allowedapps is the value in the text field.  By
            default it is the current apps already allowed when stonix
            is run however this list can be manually changed and saved
            by the user'''
            self.allowedapps = self.appci.getcurrvalue()
            debug = "self.allowedapps: " + str(self.allowedapps) + "\n"
            self.logdispatch.log(LogPriority.DEBUG, debug)
            debug = "self.allowedapps is the value obtained from the text field\n"
            self.logdispatch.log(LogPriority.DEBUG, debug)
            '''Here we make a copy of self.applist which is a list
            of the currently allowed apps and store it in templist.
            '''
            self.templist = self.applist[:]
            if self.allowedapps:
                for app in self.allowedapps:
                    '''One of the apps the user wants allowed isn't showing
                    up in the allowed apps output'''
                    if app not in self.applist:
                        compliant = False
                        self.detailedresults += "Connections from " + app + \
                            " not allowed but should be.\n"
                    else:
                        '''This app is already being allowed so we can remove
                        it from self.templist'''
                        self.templist.remove(app)
                debug = "self.allowedapps after removing: " + str(self.allowedapps) + "\n"
                self.logdispatch.log(LogPriority.DEBUG, debug)
                '''If there are any application names remaining in self.templist
                then we have apps that the user didn't specify to be allowed'''
                if self.templist:
                    debug =  "There are still items left in self.templist\n"
                    self.logdispatch.log(LogPriority.DEBUG, debug)
                    debug =  "self.templist: " + str(self.applist) +"\n"
                    self.logdispatch.log(LogPriority.DEBUG, debug)
                    compliant = False
                    for item in self.templist:
                        self.detailedresults += item +  " is allowed but shouldn't be\n"
            elif self.applist:
                '''self.allowedapps is blank but there are apps being allowed through
                the firewall.  We must remove these from being allowed.'''
                debug = "inside the elif block of report"
                self.logdispatch.log(LogPriority.DEBUG, debug)
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
        '''@summary: Fixes the system is report returns False
        @author: dwalker


        :returns: bool - True or False

        '''
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
            self.templist = self.applist[:]
            if self.allowedapps:
                debug = "there are allowedapps in fix: " + str(self.allowedapps) + "\n"
                self.logdispatch.log(LogPriority.DEBUG, debug)
                for app in self.allowedapps:
                    '''The current application should be allowed but isn't
                    so on the next line we're going to try and allow it'''
                    if app not in self.applist:
                        if not self.ch.executeCommand(self.add + "/Applications/" + app):
                            '''Trying to add the application to the allowed apps
                            wasn't successful'''
                            success = False
                            self.detailedresults += "Unable to add " + \
                                app + " to firewall allowed list\n"
                        else:
                            '''Adding the application to the allowed apps was
                            successful so record an even to remove it on undo'''
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            undocmd = self.rmv + "/Applications/" + app
                            event = {"eventtype": "comm",
                                     "command": undocmd}
                            self.statechglogger.recordchgevent(myid, event)
                    else:
                        self.templist.remove(app)
                if self.templist:
                    for app in self.templist:
                        debug = app + " isn't in " + str(self.allowedapps) + " so we're going to remove it\n"
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
    