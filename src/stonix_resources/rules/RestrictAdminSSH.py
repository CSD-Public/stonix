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
Created on Dec 16, 2013

@author: dwalker
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2014 dkennel Updated CI invocation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/17 dkennel updated for new isApplicable
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import resetsecon, checkPerms, setPerms, iterate
from ..rule import Rule
from ..configurationitem import ConfigurationItem
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
        self.helptext = '''This rule disables root login access to another \
machine via ssh.  Another important thing to prevent root loging via ssh is \
the PermitRootLogin no key-value pair but that is already being configured in \
SecureSSH rule.  This additional k-v pair only needs to exist in MacOSX'''
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
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}

###############################################################################

    def report(self):
        try:
            self.detailedresults = ""
            self.path = "/private/etc/sshd_config"
            self.tmppath = "/private/etc/sshd_config.tmp"
            compliant = True
            self.editor = KVEditorStonix(self.statechglogger, self.logger,
                "conf", self.path, self.tmppath, self.ssh, "present", "space")
            if not self.editor.report():
                compliant = False
            if not checkPerms(self.path, [0, 0, 420], self.logger):
                compliant = False
            if compliant:
                self.compliant = True
                self.detailedresults += "RestrictAdminSSH report has been run \
and is compliant\n"
            else:
                self.compliant = False
                self.detailedresults += "RestrictAdminSSH report has been run \
and is not compliant\n"
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
    
###############################################################################

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            
            self.detailedresults = ""
            success = True

            #clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if not checkPerms(self.path, [0, 0, 420], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.path, [0, 0, 420], self.logger,
                                                    self.statechglogger, myid):
                    success = False
            if self.editor.fixables or self.editor.removeables:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.editor.setEventID(myid)
                if not self.editor.fix():
                    debug = "kveditor fix did not run successfully, returning\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                elif not self.editor.commit():
                    debug = "kveditor commit did not run  successfully\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                os.chown(self.path, 0, 0)
                os.chmod(self.path, 420)
                resetsecon(self.path)
            if success:
                self.detailedresults += "RestrictAdminSSH seems to have run \
with no issues\n"
            else:
                self.detailedresults += "RestrictAdminSSH seems to have had \
issues during the fix\n"
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