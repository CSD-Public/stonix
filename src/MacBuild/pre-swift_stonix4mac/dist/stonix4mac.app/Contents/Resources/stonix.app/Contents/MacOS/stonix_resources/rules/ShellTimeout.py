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
This rule creates scripts to automatically log out bash and csh shells
after 15 minutes.

@author: Eric Ball
@change: 2015/07/01 eball Original implementation
@change: 2015/08/28 eball - Fixed permissions changes, cleaned up code
@change: 2016/04/26 eball - Added KVEditor undo events
@change: 2016/04/26 eball - Fixed detailedresults flow; this will overwrite
    Ekkehard's change of the same nature (due to merge conflicts)
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, setPerms, checkPerms
from ..stonixutilityfunctions import resetsecon, createFile, writeFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix
import traceback
import os
import re


class ShellTimeout(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 120
        self.rulename = "ShellTimeout"
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.helptext = '''This optional rule will set up shell scripts in \
/etc/profile.d which will log a user out of a bash or csh login shell after \
15 minutes of inactivity. This is not practical for systems which run X \
Windows, as it will close terminal windows in the X environment.'''
        datatype = "bool"
        key = "SHELLTIMEOUT"
        instructions = "To disable this rule set the value of " + \
                       "SHELLTIMEOUT to False."
        default = False
        self.ci = self.initCi(datatype, key, instructions, default)

        self.guidance = ["NSA 2.3.5.5", "CCE 3689-7", "CCE 3707-7"]
        self.applicable = {"type": "white",
                           "family": ["linux"]}
        self.iditerator = 0
        self.created = False

    def report(self):
        try:
            self.path1 = "/etc/profile.d/tmout.sh"
            self.data1 = {"TMOUT": "900"}
            self.data2 = {"readonly": "TMOUT", "export": "TMOUT"}
            self.path2 = "/etc/profile.d/autologout.csh"
            self.cshData = "set -r autologout 15"
            compliant = True
            self.detailedresults = ""

            if os.path.exists(self.path1):
                # Shell scripts in profile.d do not require +x, so they can
                # be either 0755 (0755) or 0644 (0644)
                if not checkPerms(self.path1, [0, 0, 0755], self.logger) and \
                   not checkPerms(self.path1, [0, 0, 0644], self.logger):
                    compliant = False
                    self.detailedresults += self.path1 + \
                        " permissions incorrect\n"
                self.tmppath1 = self.path1 + ".tmp"
                self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", self.path1,
                                              self.tmppath1, self.data1,
                                              "present", "closedeq")
                kveReport1 = self.editor1.report()
                self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", self.path1,
                                              self.tmppath1, self.data2,
                                              "present", "space")
                kveReport2 = self.editor2.report()
                if not kveReport1 or not kveReport2:
                    compliant = False
                    self.detailedresults += self.path1 + \
                        " does not contain the correct values\n"
            else:
                compliant = False
                self.detailedresults += self.path1 + " does not exist\n"

            if os.path.exists(self.path2):
                if not checkPerms(self.path2, [0, 0, 0755], self.logger) and \
                   not checkPerms(self.path2, [0, 0, 0644], self.logger):
                    compliant = False
                    self.detailedresults += self.path2 + \
                        " permissions incorrect\n"
                cshText = open(self.path2, "r").read()
                if not re.search(self.cshData, cshText):
                    compliant = False
                    self.detailedresults += self.path2 + \
                        " does not contain the correct values\n"
            else:
                compliant = False
                self.detailedresults += self.path2 + " does not exist\n"

            self.compliant = compliant
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

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                self.detailedresults += "CI not enabled\n"
            else:
                success = True
                self.detailedresults = ""
                self.iditerator = 0
                eventlist = self.statechglogger.findrulechanges(self.rulenumber)
                for event in eventlist:
                    self.statechglogger.deleteentry(event)

                if not os.path.exists(self.path1):
                    createFile(self.path1, self.logger)
                    self.created = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": self.path1}
                    self.statechglogger.recordchgevent(myid, event)

                self.tmppath = self.path1 + ".tmp"
                self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", self.path1, self.tmppath,
                                              self.data1, "present",
                                              "closedeq")
                self.editor1.report()
                self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", self.path1, self.tmppath,
                                              self.data2, "present", "space")
                self.editor2.report()

                if self.editor1.fixables or self.editor2.fixables:
                    if self.editor1.fix():
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.editor1.setEventID(myid)
                        if self.editor1.commit():
                            debug = self.path1 + "'s contents have been " + \
                                "corrected\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            resetsecon(self.path1)
                        else:
                            debug = "kveditor commit not successful\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            success = False
                            self.detailedresults += self.path1 + \
                                " properties could not be set\n"
                    else:
                        debug = "kveditor fix not successful\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                        self.detailedresults += self.path1 + \
                            " properties could not be set\n"
                    if self.editor2.fix():
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.editor2.setEventID(myid)
                        if self.editor2.commit():
                            debug = self.path1 + "'s contents have been " + \
                                "corrected\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            resetsecon(self.path1)
                        else:
                            debug = "kveditor commit not successful\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            success = False
                            self.detailedresults += self.path1 + \
                                " properties could not be set\n"
                    else:
                        debug = "kveditor fix not successful\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                        self.detailedresults += self.path1 + \
                            " properties could not be set\n"
                if not checkPerms(self.path1, [0, 0, 0755], self.logger) and \
                   not checkPerms(self.path1, [0, 0, 0644], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.path1, [0, 0, 0644], self.logger,
                                    self.statechglogger, myid):
                        success = False
                        self.detailedresults += "Could not set permissions " + \
                            "for " + self.path1 + "\n"

                if not os.path.exists(self.path2):
                    createFile(self.path2, self.logger)
                    self.created = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": self.path2}
                    self.statechglogger.recordchgevent(myid, event)
                writeFile(self.path2, self.cshData, self.logger)
                if not checkPerms(self.path2, [0, 0, 0755], self.logger) and \
                   not checkPerms(self.path2, [0, 0, 0644], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.path2, [0, 0, 0644],
                                    self.logger, self.statechglogger, myid):
                        success = False
                        self.detailedresults += "Could not set permissions " + \
                            "for " + self.path2 + "\n"

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
