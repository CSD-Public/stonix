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

"""
Created on Apr 22, 2015

@author: Derek Walker, Breen Malmberg
@change: 2015/10/07 Eric Ball Help text cleanup
@change: 2017/08/28 Roy Nielsen Fixing to use new help text methods
@change: 2017/12/06 Brandon Gonzales Removed the --direct option from the gconf commands
            so the command doesn't fail while gconfd is running
@change: 01/23/2018 - Breen Malmberg - re-wrote much of the class; cleaned up
        unnecessary bloat, condensed code, added code comments and doc's; added
        logging; improved code readability
"""

from __future__ import absolute_import

import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from ..pkghelper import Pkghelper
from ..stonixutilityfunctions import iterate


class DisableThumbnailers(Rule):
    """disable the thumbnail creation feature in nautilus/gnome"""

    def __init__(self, config, environ, logdispatcher, statechglogger):
        """

        :param config:
        :param environ:
        :param logdispatcher:
        :param statechglogger:
        """

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
        self.sethelptext()

        datatype = 'bool'
        key = 'DISABLETHUMBNAILERS'
        instructions = "To disable this rule set the value of DISABLETHUMBNAILERS to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.localize()

    def localize(self):
        """
        set paths based on what versions of which utilities exist on the system

        :return: void
        """

        self.gsettings = "/usr/bin/gsettings"
        self.gconf = "/usr/bin/gconftool-2"
        self.dconf = "/usr/bin/dconf"
        self.getcmd = ""
        self.setcmd = ""
        self.updatecmd = ""
        packages = ["gnome", "gdm", "gdm3", "gnome3"]
        self.lockfile = "/etc/dconf/db/local.d/locks/stonix-thumbnailers"
        self.locksetting = "/org/gnome/desktop/thumbnailers/disable-all"

        if os.path.exists(self.gsettings):
            self.getcmd = self.gsettings + " get org.gnome.desktop.thumbnailers disable-all"
            self.setcmd = self.gsettings + " set org.gnome.desktop.thummailerss disable-all true"
        elif os.path.exists(self.gconf):
            self.getcmd = self.gconf + " --get /schemas/org/gnome/desktop/thumbnailers/disable_all"
            self.setcmd = self.gconf + " --type bool --set /schemass/org/gnome/desktop/thumbnailers/disable_all true"
        if os.path.exists(self.dconf):
            self.updatecmd = self.dconf + " update"

        self.ch = CommandHelper(self.logger)
        self.ph = Pkghelper(self.logger, self.environ)
        self.gnome_installed = False
        if self.environ.getosname() != "Mac OS":
            if [self.ph.check(p) for p in packages]:
                self.gnome_installed = True

    def report(self):
        """check the gdm/gnome setting for thumbnailers to determine
        if it is off or on. report compliant if it is off,
        non-compliant if it is on.


        :return: self.compliant
        :rtype: bool
        """

        self.compliant = True
        self.ch = CommandHelper(self.logger)
        self.ph = Pkghelper(self.logger, self.environ)
        self.detailedresults = ""

        try:

            if self.gnome_installed:
                # This portion of the code is relevant to user context
                if self.environ.geteuid() != 0:
                    self.ch.executeCommand(self.getcmd)
                    if not self.ch.findInOutput("true"):
                        self.compliant = False
                        self.detailedresults += "\nGnome thumbnailers are enabled"
                # This portion of the code is relevant to root context
                else:
                    if not self.checkLockFile():
                        self.compliant = False
            else:
                self.logger.log(LogPriority.DEBUG, "Gnome is not installed. Nothing to check.")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def checkLockFile(self):
        """

        :return: compliant
        :rtype: bool
        """

        compliant = True

        if not os.path.exists(self.lockfile):
            compliant = False
            self.detailedresults += "\nThe thumbnailers lock file doesn't exist"
            return compliant

        f = open(self.lockfile, "r")
        contents = f.read()
        f.close()

        if not re.search(self.locksetting, contents):
            compliant = False
            self.detailedresults += "\nThe thumbnailers lock file is not properly configured"

        return compliant

    def fix(self):
        """
        set the value of schema thumbnailers disable-all to true
        and create the thumbnailers lock file if it doesn't exist

        :return: self.rulesuccess
        :rtype: bool
        """

        self.rulesuccess = True
        self.detailedresults = ""
        self.iditerator = 0

        try:

            if self.ci.getcurrvalue():
                # This portion of the code is run in user context
                if self.environ.geteuid() != 0:
                    if not self.setValue():
                        self.rulesuccess = False
                # This portion of the code has to be run in root context
                else:
                    self.setLockFile()

                if os.path.exists(self.dconf):
                    self.ch.executeCommand(self.updatecmd)
            else:
                self.logger.log(LogPriority.DEBUG, "CI not enabled. Fix was not performed.")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess

    def setValue(self):
        """
        set the thumbnailers disable-all configuration value to true

        :return: success
        :rtype: bool
        """

        success = True

        self.ch.executeCommand(self.setcmd)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            success = False
            errstr = self.ch.getErrorString()
            self.detailedresults += "\n" + errstr

        return success

    def setLockFile(self):
        """
        create the lock file for disable thumbnailers (if running in root context)

        :return: void
        """

        success = True

        if not os.path.exists("/etc/dconf/db/local.d/locks"):
            try:
                os.makedirs("/etc/dconf/db/local.d/locks", 0755)
            except Exception:
                pass
        try:

            f = open(self.lockfile, "w")
            f.write(self.locksetting)
            f.close()
            os.chmod(self.lockfile, 0o644)
            os.chown(self.lockfile, 0, 0)

        except Exception:
            success = False

        if success:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": self.lockfile}
            self.statechglogger.recordchgevent(myid, event)
        else:
            self.logger.log(LogPriority.DEBUG, "Failed to create thumbnailers lock file")

        return success
