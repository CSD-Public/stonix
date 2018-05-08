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
Created on Apr 22, 2015

@author: dwalker
@change: 2015/10/07 eball Help text cleanup
@change: 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/12/06 bgonz12 Removed the --direct option from the gconf commands
            so the command doesn't fail while gconfd is running
@change: 01/23/2018 - Breen Malmberg - re-wrote much of the class; cleaned up
        unnecessary bloat, condensed code, added code comments and doc's; added
        logging; improved code readability
'''

from __future__ import absolute_import

import os
import re
import traceback

from ..stonixutilityfunctions import iterate
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from ..pkghelper import Pkghelper


class DisableThumbnailers(Rule):
    '''
    disable the thumbnail creation feature in nautilus/gnome
    '''

    def __init__(self, config, environ, logdispatcher, statechglogger):
        '''
        private method to intialize class variables and template object instance

        @return: void
        @author: Derek Walker
        '''

        Rule.__init__(self, config, environ, logdispatcher, statechglogger)
        self.logger = logdispatcher
        self.rulenumber = 111
        self.mandatory = True
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd']}
        self.formatDetailedResults("initialize")
        self.guidance = ["NSA 2.2.2.6"]
        self.rulename = "DisableThumbnailers"
        self.rulesuccess = True

        datatype = 'bool'
        key = 'DISABLETHUMBNAILERS'
        instructions = "To disable this rule set the value of DISABLETHUMBNAILERS to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.iditerator = 0
        self.gconf = "/usr/bin/gconftool-2"
        self.packages = ["gnome", "gdm"]
        self.sethelptext()

    def report(self):
        '''
        check the gdm/gnome setting for thumbnailers to determine
        if it is off or on. report compliant if it is off,
        non-compliant if it is on.

        @return: self.compliant
        @rtype: bool
        @author: Derek Walker
        @change: 01/19/2018 - Breen Malmberg - re-wrote most of rule; added more detailed logging
        '''

        self.compliant = True
        self.ch = CommandHelper(self.logger)
        self.ph = Pkghelper(self.logger, self.environ)
        self.gconf = "/usr/bin/gconftool-2"
        self.getcmd = self.gconf + " --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /desktop/gnome/thumbnailers/disable_all"
        self.setcmd = self.gconf + " --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /desktop/gnome/thumbnailers/disable_all true"
        self.detailedresults = ""
        searchterms = re.compile("(No value set for)|(False)|(false)")
        gnomeinstalled = True

        try:

            # if gnome is not installed, we don't need to configure anything
            gnomeinstalled = True in [self.ph.check(p) for p in self.packages]
            if not gnomeinstalled:
                self.detailedresults += "\nGnome not installed. Nothing to configure."
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant

            # if gnome is installed and the configuration tool, that we need, exists,
            # then get the value of thumbnailers
            if os.path.exists(self.gconf):
                self.ch.executeCommand(self.getcmd)
                retcode = self.ch.getReturnCode()
                output = self.ch.getOutputString()
                error = self.ch.getErrorString()
                sources = [output, error]
                if retcode == 0:
                    for s in sources:
                        if re.search(searchterms, s):
                            self.detailedresults += "\nThumbnail creation is still enabled."
                            self.compliant = False
                else:
                    self.detailedresults += "\nAn error occurred while attempting to read the configuration value.\n" + str(error)
                    self.compliant = False
            else:
                self.detailedresults += "\nA required configuration tool could not be found (gconftool-2). Aborting..."
                self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''
        run the gconftool-2 command to set the value for
        thumbnailers to disable it

        @return: self.rulesuccess
        @rtype: bool
        @author: Derek Walker
        @change: 01/22/2018 - Breen Malmberg - re-wrote most of the rule; added
                some more detailed logging
        '''

        self.rulesuccess = True
        self.detailedresults = ""
        self.iditerator = 0
        undocmd = self.setcmd.replace("true", "false")

        try:

            if not self.ci.getcurrvalue():
                self.detailedresults += "\nRule was not enabled. Nothing was done."
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess

            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            self.ch.executeCommand(self.setcmd)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                error = self.ch.getErrorString()
                self.detailedresults += "\nThere was an error while trying to disable thumbnails.\n" + str(error)
                self.rulesuccess = False
            else:
                event = {"eventtype": "commandstring",
                         "command": undocmd}
                myid = iterate(self.iditerator, self.rulenumber)
                self.statechglogger.recordchgevent(myid, event)

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
