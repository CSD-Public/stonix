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
Created on Oct 30, 2012
The DisableInteractiveStartup class disables the ability to enter interactive
startup mode for all supported flavors of Linux operating systems.
@author: bemalmbe
@change: dwalker, implemented kveditor, removed unnecessary variable overrides
        in init method, updated with new isapplicable section 4/16/2014
@change: dkennel 04/18/2014 Replaced old style CI with new
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text/PEP8 cleanup
'''
from __future__ import absolute_import
import os
import traceback

from ..rule import Rule
from ..stonixutilityfunctions import resetsecon, checkPerms
from ..stonixutilityfunctions import iterate, setPerms, createFile
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..KVEditorStonix import KVEditorStonix
from ..CommandHelper import CommandHelper


class DisableInteractiveStartup(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 119
        self.rulename = 'DisableInteractiveStartup'
        self.mandatory = True
        self.formatDetailedResults("initialize")
        self.guidance = ['CCE 4245-7']
        self.applicable = {'type': 'white',
                           'family': ['linux']}

        # configuration item instantiation
        datatype = 'bool'
        key = 'DISABLEINTERACTIVESTARTUP'
        instructions = "To prevent the disabling of interactive startup, " + \
            "set the value of DISABLEINTERACTIVESTARTUP to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.iditerator = 0
        self.ch = CommandHelper(self.logger)
        self.restart = ""
        self.created = False
        self.sethelptext()

    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailedresults and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.
        Perform a check to see if PROMPT has been set to 'no' or not

        @return bool
        @author bemalmbe
        @change: dwalker
        '''
        try:
            self.detailedresults = ""
            compliant = True
            self.perms = [0, 0, 420]
            self.helper = Pkghelper(self.logger, self.environ)
            if self.helper.manager == "portage":
                self.filepath = "/etc/conf.d/rc"
                keyval = {"RC_INTERACTIVE": "no"}
            elif self.helper.manager == "zypper":
                self.filepath = "/etc/sysconfig/boot"
                keyval = {"PROMPT_FOR_CONFIRM": "no"}
            elif self.helper.manager == "apt-get":
                self.filepath = "/etc/default/grub"
                keyval = {"GRUB_DISABLE_RECOVERY": '"true"'}
                self.restart = "/usr/sbin/update-grub"
            elif self.helper.manager == "yum" or self.helper.manager == "dnf":
                self.filepath = "/etc/sysconfig/init"
                keyval = {"PROMPT": "no"}
            tmpPath = self.filepath + ".tmp"
            if not os.path.exists(self.filepath):
                if createFile(self.filepath, self.logger):
                    self.created = True
            if not checkPerms(self.filepath, self.perms, self.logger):
                compliant = False
                self.detailedresults += "Permissions are not correct on " + \
                    self.filepath + "\n"
            self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                         "conf", self.filepath, tmpPath,
                                         keyval, "present", "closedeq")
            if os.path.exists(self.filepath):
                if not self.editor.report():
                    self.detailedresults += "Configuration for " + \
                        self.filepath + " is incorrect via kveditor report\n"
                    compliant = False
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

###############################################################################

    def fix(self):
        '''
        The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.
        Search for the /etc/sysconfig/init configuration file and set the
        PROMPT setting to PROMPT=no

        @author bemalmbe
        @change: dwalker 4/8/2014 implementing KVEditorStonix
        '''
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""

            # clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if os.path.exists(self.filepath):
                if not checkPerms(self.filepath, self.perms, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.filepath, self.perms, self.logger,
                                    self.statechglogger, myid):
                        self.rulesuccess = False
            if self.editor.fixables:
                if not self.created:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor.setEventID(myid)
                if self.editor.fix():
                    self.detailedresults += "kveditor fix ran successfully\n"
                    if self.editor.commit():
                        self.detailedresults += "kveditor commit ran " + \
                            "successfully\n"
                    else:
                        self.detailedresults += "kveditor commit did not " + \
                            "run successfully\n"
                        self.rulesuccess = False
                else:
                    self.detailedresults += "kveditor fix did not run " + \
                        "successfully\n"
                    self.rulesuccess = False
                os.chown(self.filepath, self.perms[0], self.perms[1])
                os.chmod(self.filepath, self.perms[2])
                resetsecon(self.filepath)
            if self.restart:
                self.ch.executeCommand(self.restart)
                if self.ch.getReturnCode() != 0:
                    self.detailedresults += "Unable to restart Grub with " + \
                        "new changes\n"
                    self.rulesuccess = False
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
