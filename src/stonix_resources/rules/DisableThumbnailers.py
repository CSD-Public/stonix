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
Created on Apr 22, 2015

@author: dwalker
@change: 2015/10/07 eball Help text cleanup
@change 2017/08/28 rsn Fixing to use new help text methods
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import iterate
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from ..pkghelper import Pkghelper
from re import search
import os
import traceback


class DisableThumbnailers(Rule):

    def __init__(self, config, environ, logdispatcher, statechglogger):
        Rule.__init__(self, config, environ, logdispatcher, statechglogger)
        self.logger = logdispatcher
        self.rulenumber = 111
        self.mandatory = True
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd']}
        self.formatDetailedResults("initialize")
        self.guidance = ["NSA 2.2.2.6"]
        self.rulename = "DisableThumbnailers"
        datatype = 'bool'
        key = 'DISABLETHUMBNAILERS'
        instructions = "To disable this rule set the value of " + \
            "DISABLETHUMBNAILERS to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.iditerator = 0
        self.gconf = "/usr/bin/gconftool-2"
        self.sethelptext()

    def report(self):

        ''''''
        try:
            compliant = True
            self.ch = CommandHelper(self.logger)
            self.ph = Pkghelper(self.logger, self.environ)
            if self.ph.check("gnome") or self.ph.check("gdm"):
                cmd = self.gconf + \
                    " --get /desktop/gnome/thumbnailers/disable_all"
                if self.ch.executeCommand(cmd):
                    output = self.ch.getOutputString()
                    error = self.ch.getErrorString()
                    if output or error:
                        if search("No value set for", output) or \
                                search("False", output) or \
                                search("No value set for", error) or \
                                search("False", error):
                            compliant = False
                else:
                    self.detailedresults += "There was an error running " + \
                        "the gconf command\n"
                    compliant = False
            else:
                self.detailedresults += "gnome is not installed\n"
            if compliant:
                self.detailedresults = "DisableThumbnailers report has " + \
                    "been run and is compliant"
                self.compliant = True
            else:
                self.detailedresults = "DisableThumbnailers report has " + \
                    "been run and is not compliant"
                self.compliant = False
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
        ''''''
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""
            self.iditerator = 0
            success = True
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            if self.ph.check("gnome") or self.ph.check("gdm"):
                cmd = self.gconf + \
                    " --get /desktop/gnome/thumbnailers/disable_all"
                if self.ch.executeCommand(cmd):
                    output = self.ch.getOutputString()
                    error = self.ch.getErrorString()
                    if output or error:
                        if search("No value set for", output) or \
                                search("False", output) or \
                                search("No value set for", error) or \
                                search("False", error):
                            cmd = self.gconf + " --direct --config-source " + \
                                "xml:readwrite:/etc/gconf/gconf.xml.mandatory " + \
                                "--type bool --set " + \
                                "/desktop/gnome/thumbnailers/disable_all true"
                            if not self.ch.executeCommand(cmd):
                                success = False
                            else:
                                cmd = self.gconf + " --direct --config-source " + \
                                    "xml:readwrite:/etc/gconf/gconf.xml.mandatory " + \
                                    "--type bool --set " + \
                                    "/desktop/gnome/thumbnailers/disable_all false"
                                event = {"eventtype": "commandstring",
                                         "command": cmd}
                                myid = iterate(self.iditerator, self.rulenumber)
                                self.statechglogger.recordchgevent(myid, event)
                else:
                    self.detailedresults += "There was an error running " + \
                        "the gconf command\n"
                    success = False
            self.rulesuccess = success
            if self.rulesuccess:
                self.detailedresults += "DisableThumbnailers " + \
                    "ran to completion\n"
            else:
                self.detailedresults += "DisableThumbnailers " + \
                    "did not run to completion\n"
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
