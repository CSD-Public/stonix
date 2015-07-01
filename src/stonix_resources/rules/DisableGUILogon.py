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
Created on 2015/07/01

@author: Eric Ball
'''
from __future__ import absolute_import

import os
import re
from subprocess import call
import traceback
from ..KVEditorStonix import KVEditorStonix
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..ServiceHelper import ServiceHelper
from ..stonixutilityfunctions import iterate, setPerms, checkPerms, readFile, \
    writeFile, resetsecon, createFile


class DisableGUILogon(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 105
        self.rulename = "DisableGUILogon"
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.helptext = '''Add help text'''
        self.applicable = {'type': 'white',
                           'family': ['linux']}

        # Configuration item instantiation
        datatype = "bool"
        key = "DISABLEX"
        instructions = "To enable this item, set the value of DISABLEX " + \
        "to True. When enabled, this rule will disable the automatic " + \
        "GUI login, and the system will instead boot to the console " + \
        "(runlevel 3). This will not remove any GUI components, and the " + \
        "GUI can still be started using the \"startx\" command."
        default = False
        self.ci1 = self.initCi(datatype, key, instructions, default)

        datatype = "bool"
        key = "LOCKDOWNX"
        instructions = "To enable this item, set the value of LOCKDOWNX " + \
        "to True. When enabled, this item will help secure X Windows by " + \
        "disabling the X Font Server (xfs) service and disabling X " + \
        "Window System Listening. This item should be enabled if X " + \
        "Windows is disabled but will be occasionally started via " + \
        "startx, unless there is a mission-critical need for xfs or " + \
        "a remote display."
        default = False
        self.ci2 = self.initCi(datatype, key, instructions, default)
        
        datatype = "bool"
        key = "REMOVEX"
        instructions = "To enable this item, set the value of REMOVEX " + \
        "to True. When enabled, this item will completely remove X Windows " + \
        "from the system."
        default = False
        self.ci3 = self.initCi(datatype, key, instructions, default)

        self.guidance = ["NSA 3.6.1.1", "NSA 3.6.1.2", "NSA 3.6.1.3",
                         "CCE 4462-8", "CCE 4422-2", "CCE 4448-7", "CCE 4074-1"]
        self.iditerator = 0
        self.created = False

    def report(self):
        '''
        @author: Eric Ball
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''
        try:
            self.ph = Pkghelper(self.logger, self.environ)
            self.ch = CommandHelper(self.logger)
            self.sh = ServiceHelper(self.environ, self.logger)
            compliant = True
            results = ""
            
            if self.ci1.getcurrvalue():
                if os.path.exists("/bin/systemctl"):
                    compliant, results = self.reportSystemd()
                elif re.search("Debian", self.environ.getostype()):
                    compliant, results = self.reportDebian()
                elif re.search("Ubuntu", self.environ.getostype()):
                    compliant, results = self.reportUbuntu()
                else:
                    compliant, results = self.reportInittab()
            if self.ci2.getcurrvalue():
                # something
                pass
            
            self.compliant = compliant
            if self.compliant:
                self.detailedresults = "ConfigureSystemAuthentication report \
has been run and is compliant"
            else:
                self.detailedresults = "ConfigureSystemAuthentication report \
has been run and is not compliant\n" + results
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportInittab(self):
        compliant = False
        results = ""
        inittab = "/etc/inittab"
        initData = readFile(inittab, self.logger)
        for line in initData:
            if line == "id:3:initdefault:":
                compliant = True
                break
        if not compliant:
            results = "inittab not set to runlevel 3; GUI logon is enabled\n"
        return compliant, results
        
    def reportSystemd(self):
        compliant = True
        results = ""
        cmd = ["/bin/systemctl", "get-default"]
        self.ch.executeCommand(cmd)
        defaultTarget = self.ch.getOutputString()
        if not re.search("multi-user.target", defaultTarget):
            compliant = False
            results = "systemd default target is not multi-user.target; " + \
                      "GUI logon is enabled\n"
        return compliant, results
    
    def reportDebian(self):
        compliant = True
        results = ""
        dmlist = ["gdm", "gdm3", "lightdm", "xdm", "kdm"]
        for dm in dmlist:
            if self.sh.auditservice(dm):
                compliant = False
                results = dm + " is still in init folders; GUI logon is enabled\n"
        return compliant, results
    
    def reportUbuntu(self):
        compliant = False
        results = ""
        lightdmOverride = "/etc/init/lightdm.override"
        if os.path.exists(lightdmOverride):
            lightdmText = readFile(lightdmOverride, self.logger)
            if "manual" in lightdmText:
                compliant = True
        if not compliant:
            results = "/etc/init does not contain proper override file " + \
                      "for lightdm; GUI logon is enabled\n"
        return compliant, results

    def fix(self):
        '''
        @author: Eric Ball
        @param self - essential if you override this definition
        @return: bool - True if fix is successful, False if it isn't
        '''
        try:
            if not self.ci1.getcurrvalue() and not self.ci2.getcurrvalue() \
                and not self.ci3.getcurrvalue():
                return
            #delete past state change records from previous fix
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
                
            if self.environ.getosfamily() == "linux":
                self.rulesuccess = self.fixLinux()
            elif self.environ.getosfamily() == "freebsd":
                self.rulesuccess = self.fixFreebsd()
            elif self.environ.getosfamily() == "solaris":
                self.rulesuccess = self.fixSolaris()
            elif self.environ.getosfamily() == "darwin":
                self.rulesuccess = self.fixMac()
            if self.rulesuccess:
                self.detailedresults = "ConfigureSystemAuthentication fix " + \
                "has been run to completion"
            else:
                self.detailedresults = "ConfigureSystemAuthentication fix " + \
                "has been run but not to completion"
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
