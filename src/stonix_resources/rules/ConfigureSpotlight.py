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
@change: 2014-11-24 ekkehard - Original Implementation
@change: 2/4/2015 dwalker finishing rule
@change: 2012-03-01 - ekkehard Fixed detailed result initialization
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/10/07 eball PEP8 cleanup
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''
from __future__ import absolute_import
import re
import traceback
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class ConfigureSpotlight(Rule):
    '''
    @author: ekkehard j. koch
    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        '''
        This rule should normally be a rulekveditor rule, but there has
        recently been an issue discovered with subprocess for this
        particular rule where a paramaterized list for the command doesn't
        behave as would expected which KVADefault class uses when performing
        the defaults read command.  Can change back if this issue is resolved
        with Mac/Python.
        '''
        Rule.__init__(self, config, environ, logdispatcher, statechglogger)
        self.rulenumber = 17
        self.rulename = 'ConfigureSpotlight'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = False
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}

        datatype1 = "bool"
        key1 = "CONFIGURESPOTLIGHT"
        instructions1 = "To disable this configuration set the value of " + \
            "CONFIGURESPOTLIGHT to False."
        default1 = True
        self.ci1 = self.initCi(datatype1, key1, instructions1, default1)

        datatype2 = "bool"
        key2 = "SAFARISEARCH"
        instructions2 = "To disable this configuration set the value of " + \
            "SAFARISEARCH to False."
        default2 = True
        self.ci2 = self.initCi(datatype2, key2, instructions2, default2)

    def report(self):
        try:
            self.detailedresults = ""
            self.slv = {0: {'enabled': '1', 'name': 'APPLICATIONS'},
                        1: {'enabled': '0', 'name':
                            '\"MENU_SPOTLIGHT_SUGGESTIONS\"'},
                        2: {'enabled': '1', 'name': '\"MENU_CONVERSION\"'},
                        3: {'enabled': '1', 'name': '\"MENU_EXPRESSION\"'},
                        4: {'enabled': '1', 'name': '\"MENU_DEFINITION\"'},
                        5: {'enabled': '1', 'name': '\"SYSTEM_PREFS\"'},
                        6: {'enabled': '1', 'name': 'DOCUMENTS'},
                        7: {'enabled': '1', 'name': 'DIRECTORIES'},
                        8: {'enabled': '1', 'name': 'PRESENTATIONS'},
                        9: {'enabled': '1', 'name': 'SPREADSHEETS'},
                        10: {'enabled': '1', 'name': 'PDF'},
                        11: {'enabled': '1', 'name': 'MESSAGES'},
                        12: {'enabled': '1', 'name': 'CONTACT'},
                        13: {'enabled': '1', 'name': '\"EVENT_TODO\"'},
                        14: {'enabled': '1', 'name': 'IMAGES'},
                        15: {'enabled': '1', 'name': 'BOOKMARKS'},
                        16: {'enabled': '1', 'name': 'MUSIC'},
                        17: {'enabled': '1', 'name': 'MOVIES'},
                        18: {'enabled': '1', 'name': 'FONTS'},
                        19: {'enabled': '1', 'name': '\"MENU_OTHER\"'},
                        20: {'enabled': '0', 'name': '\"MENU_WEBSEARCH\"'}}
            self.spotRead = "/usr/bin/defaults read com.apple.Spotlight " + \
                "orderedItems "
            self.spotwrite = "/usr/bin/defaults write com.apple.Spotlight " + \
                "orderedItems "
            self.safRead = "/usr/bin/defaults read com.apple.Safari " + \
                "UniversalSearchEnabled "
            self.safWrite = "/usr/bin/defaults write com.apple.Safari " + \
                "UniversalSearchEnabled "
            compliant = True
            self.slvlook = "("
            self.slvset = "\'("
            for _, v in sorted(self.slv.items()):
                self.slvset += "{\"enabled\"=" + str(v['enabled']) + "; " + \
                    "\"name\"=" + str(v['name']) + ";},"
            self.slvset += ")\';"
            i = 0
            for _, v in sorted(self.slv.items()):
                if i == 20:
                    self.slvlook += "{enabled=" + str(v["enabled"]) + ";" + \
                        "name=" + str(v["name"]) + ";}"
                    break
                else:
                    self.slvlook += "{enabled=" + str(v["enabled"]) + ";" + \
                        "name=" + str(v["name"]) + ";},"
                i += 1
            self.slvlook += ")"
            lookstring = "The regex we are looking for from the defaults " + \
                "read command: " + self.slvlook + "\n"
            self.logdispatch.log(LogPriority.DEBUG, lookstring)
            setstring = "The plist string we will set defaults write " + \
                "command to: " + self.slvset + "\n"
            self.logdispatch.log(LogPriority.DEBUG, setstring)
            self.ch = CommandHelper(self.logdispatch)
            if self.ch.executeCommand(self.spotRead):
                output = self.ch.getOutputString()
                output = re.sub("(\s)", "", output)
                error = self.ch.getErrorString()
                if output:
                    if not re.search(self.slvlook, output):
                        self.detailedresults += "Output for orderedItems " + \
                            "key in com.apple.Spotlight plist isn't correct\n"
                        compliant = False
                elif error:
                    if re.search("does not exist", error):
                        self.detailedresults += "Either com.apple." + \
                            "Spotlight plist doesn't exist or the key " + \
                            "orderedItems doesn't exist\n"
                        compliant = False
            output, error = "", ""
            if self.ch.executeCommand(self.safRead):
                output = self.ch.getOutputString()
                error = self.ch.getErrorString()
                if output:
                    if not re.search("0", output):
                        self.detailedresults += "Output for " + \
                            "UniversalSearchEnabled key in " + \
                            "com.apple.Safari plist isn't correct\n"
                        compliant = False
                elif error:
                    if re.search("does not exist", error):
                        self.detailedresults += "Either com.apple.Safari " + \
                            "plist doesn't exist or the key " + \
                            "UniversalSearchEnabled doesn't exist\n"
            self.compliant = compliant
            if self.compliant:
                self.detailedresults += "ConfigureSpotlight has been run " + \
                    "and is compliant\n"
            else:
                self.detailedresults += "ConfigureSpotlight has been run " + \
                    "and is not compliant\n"
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        try:
            if not self.ci1.getcurrvalue() and not self.ci2.getcurrvalue():
                return
            self.detailedresults = ""

            success = True
            if self.ch.executeCommand(self.spotRead):
                output = self.ch.getOutputString()
                output = re.sub("(\s)", "", output)
                re.sub
                error = self.ch.getErrorString()
                if output:
                    if not re.search(self.slvlook, output):
                        cmd = self.spotwrite + self.slvset
                        if not self.ch.executeCommand(cmd):
                            self.detailedresults += "Unable to perform " + \
                                "defaults write command for " + \
                                "com.apple.Spotlight\n"
                            success = False
                elif error:
                    if re.search("does not exist", error):
                        cmd = self.spotwrite + self.slvset
                        if not self.ch.executeCommand(cmd):
                            self.detailedresults += "Unable to perform " + \
                                "defaults write command for " + \
                                "com.apple.Safari\n"
                            success = False

            output, error = "", ""
            if self.ch.executeCommand(self.safRead):
                output = self.ch.getOutputString()
                error = self.ch.getErrorString()
                if output:
                    if not re.search("0", output):
                        cmd = self.safWrite + "-bool no"
                        if not self.ch.executeCommand(cmd):
                            self.detailedresults += "Unable to perform " + \
                                "defaults write command for com.apple.Safari\n"
                            success = False
                elif error:
                    if re.search("does not exist", error):
                        cmd = self.safWrite + "-bool no"
                        if not self.ch.executeCommand(cmd):
                            self.detailedresults += "Unable to perform " + \
                                "defaults write command for com.apple.Safari\n"
            self.rulesuccess = success
            if self.rulesuccess:
                self.detailedresults += "ConfigureSpotlight rule ran to " + \
                    "completion successfully\n"
            else:
                self.detailedresults += "ConfigureSpotlight rule did not " + \
                    "run to completion successfully\n"
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

###############################################################################

    def undo(self):
        try:
            self.detailedresults = "no undo available"
            self.logger.log(LogPriority.INFO, self.detailedresults)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
