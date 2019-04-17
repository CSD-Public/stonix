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
        self.dconf = "/usr/bin/gsettings"
        self.gconf = "/usr/bin/gconftool-2"
        self.detailedresults = ""
        gnomeinstalled = True

        try:

            # if gnome is not installed, we don't need to configure anything
            gnomeinstalled = True in [self.ph.check(p) for p in self.packages]
            if not gnomeinstalled:
                self.detailedresults += "\nGnome not installed. Nothing to configure."
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant

            # gnome is installed and system is using dconf/gsettings
            if os.path.exists(self.dconf) and not os.path.exists(self.gconf):
                if not self.reportdconf():
                    self.compliant = False
            # gnome is installed system is using gconf/gconftool-2
            elif os.path.exists(self.gconf):
                if not self.reportgconf():
                    self.compliant = False
            else:
                self.detailedresults += "\nNo suitable reporting tool could be found (gconftool-2 or gsettings). Could not read configuration value."
                self.compliant = False

            if not self.compliant:
                self.detailedresults += "\nThumbnailers is enabled or thumbnailers configuration value could not be read."

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportdconf(self):
        '''

        @return:
        '''

        self.logger.log(LogPriority.DEBUG, "Using gsettings to determine configuration value...")

        retval = False
        gsettings = "/usr/bin/gsettings"
        schema = "org.gnome.desktop.thumbnailers"
        key = "disable-all"
        value = "true"
        getthumbnailers = gsettings + " get " + schema + " " + key

        self.ch.executeCommand(getthumbnailers)
        retcode = self.ch.getReturnCode()
        if retcode == 0:
            outputstr = self.ch.getOutputString()

            if re.search(value, outputstr):
                retval = True
        else:
            errmsg = self.ch.getErrorString()
            self.logger.log(LogPriority.DEBUG, errmsg)

        return retval

    def reportgconf(self):
        '''

        @return:
        '''

        self.logger.log(LogPriority.DEBUG, "Using gconftool-2 to determine configuration value...")

        retval = False
        self.getcmd = self.gconf + " --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /desktop/gnome/thumbnailers/disable_all"
        value = "true"

        self.ch.executeCommand(self.getcmd)
        retcode = self.ch.getReturnCode()
        if retcode == 0:
            outputstr = self.ch.getOutputString()
            if re.search(value, outputstr):
                retval = True
        else:
            errmsg = self.ch.getErrorString()
            self.logger.log(LogPriority.DEBUG, errmsg)

        return retval

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

        try:

            if not self.ci.getcurrvalue():
                self.detailedresults += "\nRule was not enabled. Nothing was done."
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess

            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            # gnome is installed and system is using dconf/gsettings
            if os.path.exists(self.dconf) and not os.path.exists(self.gconf):
                if not self.fixdconf():
                    self.rulesuccess = False
            # gnome is installed system is using gconf/gconftool-2
            elif os.path.exists(self.gconf):
                if not self.fixgconf():
                    self.rulesuccess = False
            else:
                self.detailedresults += "\nNo suitable configuration tool could be found (gconftool-2 or gsettings). Could not set configuration value."
                self.rulesuccess = False

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

    def fixgconf(self):
        '''

        @return:
        '''

        self.logger.log(LogPriority.DEBUG, "Using gconftool-2 to set configuration value...")

        retval = True
        self.gconfcmd = self.gconf + " --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /desktop/gnome/thumbnailers/disable_all true"
        undocmd = self.gconfcmd.replace("true", "false")

        self.ch.executeCommand(self.gconfcmd)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            error = self.ch.getErrorString()
            self.detailedresults += "\nRule encountered a problem while trying to disable thumbnailers.\n" + str(error)
            retval = False
        else:
            self.iditerator += 1
            event = {"eventtype": "commandstring",
                     "command": undocmd}
            myid = iterate(self.iditerator, self.rulenumber)
            self.statechglogger.recordchgevent(myid, event)
        return retval

    def fixdconf(self):
        '''

        @return:
        '''

        self.logger.log(LogPriority.DEBUG, "Using gsettings to set configuration value...")

        retval = True
        self.dconfcmd = self.dconf + " set org.gnome.desktop.thumbnailers disable-all true"
        undocmd = self.dconfcmd.replace("true", "false")

        self.ch.executeCommand(self.dconfcmd)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            error = self.ch.getErrorString()
            self.detailedresults += "\nRule encountered a problem while trying to disable thumbnailers.\n" + str(error)
            retval = False
        else:
            self.iditerator += 1
            event = {"eventtype": "commandstring",
                     "command": undocmd}
            myid = iterate(self.iditerator, self.rulenumber)
            self.statechglogger.recordchgevent(myid, event)
        return retval
