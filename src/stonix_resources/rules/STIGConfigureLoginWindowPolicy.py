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
Created on Aug 25, 2016

@author: dwalker
@change: 2017/03/30 dkennel Marked as FISMA high
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''

import traceback
import os
from re import search
from rule import Rule
from logdispatcher import LogPriority
from stonixutilityfunctions import iterate
from CommandHelper import CommandHelper


class STIGConfigureLoginWindowPolicy(Rule):
    '''Deploy LoginWindow Policy configuration profiles for OS X Yosemite 10.10'''
    def __init__(self, config, environ, logdispatch, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logdispatch, statechglogger)

        self.logger = logdispatch
        self.rulenumber = 362
        self.rulename = "STIGConfigureLoginWindowPolicy"
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']},
                           'fisma': 'high'}
        datatype = "bool"
        key = "STIGLOGINCONFIG"
        instructions = "To disable the installation of the login window " + \
            "profile set the value of STIGLOGINCONFIG to False"
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.iditerator = 0
        self.identifier = "mil.disa.STIG.loginwindow.alacarte"
        if search("10\.10.*", self.environ.getosver()):
#             self.profile = "/Users/username/stonix/src/" + \
#                 "stonix_resources/files/" + \
#                 "U_Apple_OS_X_10-10_Workstation_V1R2_STIG_Login_Window_Policy.mobileconfig"
            self.profile = "/Applications/stonix4mac.app/Contents/" + \
                         "Resources/stonix.app/Contents/MacOS/" + \
                         "stonix_resources/files/" + \
                         "U_Apple_OS_X_10-10_Workstation_V1R2_STIG_Login_Window_Policy.mobileconfig"
        elif search("10\.11\.*", self.environ.getosver()):
#             self.profile = "/Users/username/stonix/src/" + \
#                 "stonix_resources/files/" + \
#                 "U_Apple_OS_X_10-11_V1R1_STIG_Login_Window_Policy.mobileconfig"
            self.profile = "/Applications/stonix4mac.app/Contents/" + \
                         "Resources/stonix.app/Contents/MacOS/" + \
                         "stonix_resources/files/" + \
                         "U_Apple_OS_X_10-11_V1R1_STIG_Login_Window_Policy.mobileconfig"
        else:
#             self.profile = "/Users/username/stonix/src/" + \
#                 "stonix_resources/files/" + \
#                 "U_Apple_macOS_10-12_V1R1_STIG_Login_Window_Policy.mobileconfig "
            self.profile = "/Applications/stonix4mac.app/Contents/" + \
                         "Resources/stonix.app/Contents/MacOS/" + \
                         "stonix_resources/files/" + \
                         "U_Apple_macOS_10-12_V1R1_STIG_Login_Window_Policy.mobileconfig"
    def report(self):
        try:
            compliant = False
            self.detailedresults = ""
            self.ch = CommandHelper(self.logger)
            cmd = ["/usr/bin/profiles", "-P"]
            if not self.ch.executeCommand(cmd): 
                compliant = False
                self.detailedresults += "Unable to run profiles command\n"
            else:
                output = self.ch.getOutput()
                if output:
                    for line in output:
                        if search("^There are no configuration profiles installed", line.strip()):
                            compliant = False
                            self.detailedresults += "There are no configuration profiles installed\n"
                            break
                        elif search("mil\.disa\.STIG\.loginwindow\.alacarte$", line.strip()):
                            self.detailedresults += "Couldn't find loginwindow profile\n"
                            compliant = True
                            break
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
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
            if not self.ci.getcurrvalue():
                return
            success = True
            if os.path.exists(self.profile):
                success = True
                self.detailedresults = ""
                self.iditerator = 0
                eventlist = self.statechglogger.findrulechanges(self.rulenumber)
                for event in eventlist:
                    self.statechglogger.deleteentry(event)
                cmd = ["/usr/bin/profiles", "-I", "-F", self.profile]
                if not self.ch.executeCommand(cmd):
                    debug = "Unable to install profile\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    cmd = ["/usr/bin/profiles", "-R", "-p", self.identifier]
                    event = {"eventtype": "comm",
                             "command": cmd}
                    self.statechglogger.recordchgevent(myid, event)
            else:
                success = False
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess