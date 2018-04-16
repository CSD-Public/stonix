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
Created on Dec 16, 2013

@author: dwalker
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2014 dkennel Updated CI invocation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/09/09 eball OS X El Capitan compatibility
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import resetsecon, checkPerms, setPerms, iterate
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix
import os
import traceback


class RestrictAdminSSH(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 269
        self.rulename = "RestrictAdminSSH"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        datatype = 'bool'
        key = 'RESTRICTADMINSSH'
        instructions = '''To disable this rule set the value of
RESTRICTADMINSSH to False.'''
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.guidance = []
        self.ssh = {"DenyGroups": "admin"}
        self.iditerator = 0
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']}}

    def usesSip(self):
        """
        Determines whether this is Mac OS X >= v10.11
        @author: Eric Ball
        @return: True if this is Mac OS X >= v10.11
        """
        if self.environ.getosfamily() == "darwin":
            versplit = self.environ.getosver().split(".")
            verlist = []
            for num in versplit:
                verlist.append(int(num))
            if verlist[0] >= 10 and verlist[1] >= 11:
                return True
        return False

    def report(self):
        try:
            results = ""
            compliant = True
            path1 = "/private/etc/sshd_config"
            path2 = "/private/etc/ssh/sshd_config"
            if self.usesSip():
                if os.path.exists(path2):
                    self.path = path2
                elif os.path.exists(path1):
                    self.path = path1
                else:
                    compliant = False
                    results += "Could not find path to sshd_config file\n"
            else:
                if os.path.exists(path1):
                    self.path = path1
                elif os.path.exists(path2):
                    self.path = path2
                else:
                    compliant = False
                    results += "Could not find path to sshd_config file\n"
            self.tmppath = self.path + ".tmp"
            if os.path.exists(self.path):
                self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                             "conf", self.path, self.tmppath,
                                             self.ssh, "present", "space")
                if not self.editor.report():
                    compliant = False
                    results += "Settings in " + self.path + " are not " + \
                        "correct\n"
                if not checkPerms(self.path, [0, 0, 0644], self.logger):
                    compliant = False
                    results += self.path + " permissions are incorrect\n"
            self.detailedresults = results
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

            results = ""
            success = True

            # Clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if os.path.exists(self.path):
                if not checkPerms(self.path, [0, 0, 0644], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.path, [0, 0, 0644], self.logger,
                                    self.statechglogger, myid):
                        success = False
                        results += "Could not set permissions on " + \
                            self.path + "\n"
                if self.editor.fixables or self.editor.removeables:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor.setEventID(myid)
                    if not self.editor.fix():
                        debug = "kveditor fix did not run successfully\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                    elif not self.editor.commit():
                        debug = "kveditor commit did not run  successfully\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                    os.chown(self.path, 0, 0)
                    os.chmod(self.path, 0644)
                    resetsecon(self.path)
            else:
                success = False
                results += "Could not find path to sshd_config\n"
            self.detailedresults = results
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            success = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
