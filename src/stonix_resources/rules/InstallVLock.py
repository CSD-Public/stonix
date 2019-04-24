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
Created on Jun 27, 2012
This InstallVLock object installs the vlock package to enable screen locking
@author: Derek T Walker
@change: dkennel 04/18/2014 replaced old-style CI invocation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
"""

from __future__ import absolute_import

import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
from ..CommandHelper import CommandHelper
from ..pkghelper import Pkghelper


class InstallVLock(Rule):
    """
    This class installs the vlock package to enable screen locking
    vlock is the package name on opensuse 15+, debian, ubuntu
    kbd is the package name on opensuse 42.3-, rhel, fedora, centos (contains vlock package)

    references:
    https://pkgs.org/download/vlock
    https://access.redhat.com/discussions/3543671
    """

    def __init__(self, config, environ, logger, statechglogger):
        """
        Constructor
        """

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 121
        self.rulename = "InstallVLock"
        self.mandatory = True
        self.rootrequired = True
        self.formatDetailedResults("initialize")
        self.guidance = ["NSA 2.3.5.6"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'freebsd']}

        # Configuration item instantiation
        datatype = 'bool'
        key = 'INSTALLVLOCK'
        instructions = "To disable installation of the command line " + \
            "screen lock program vlock set the value of INSTALLVLOCK to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.sethelptext()

    def set_pkg(self):
        """
        set package name based on distro

        @return:
        """

        majorver = self.environ.getosmajorver()

        if self.ph.manager in ["yum", "dnf"]:
            self.pkg = "kbd"
        elif bool(self.ph.manager == "zypper" and majorver == "42"):
            self.pkg = "kbd"
        else:
            self.pkg = "vlock"

    def report(self):
        """
        Perform a check to see if package is already installed.
        If so, there is  no need to run Fix method

        @return: self.compliant
        @rtype: bool
        @author: Derek T Walker
        """

        try:

            self.detailedresults = ""
            self.ph = Pkghelper(self.logger, self.environ)
            self.ch = CommandHelper(self.logger)
            self.compliant = True

            self.set_pkg()

            if not self.ph.check(self.pkg):
                self.compliant = False
                self.detailedresults += "\nvlock Package is NOT installed"
            else:
                self.detailedresults += "\nvlock Package is installed"

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        """
        The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.
        Attempt to install Vlock, record success or failure in event
        logger.

        @return: self.rulesuccess
        @rtype: bool
        @author: Derek T Walker
        """

        try:

            self.detailedresults = ""
            self.rulesuccess = True
            self.iditerator = 0

            if not self.ci.getcurrvalue():
                return self.rulesuccess

            # Clear out event history so only the latest fix is recorded
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            undocmd = self.ph.getRemove()

            if not self.ph.install(self.pkg):
                self.rulesuccess = False
                self.detailedresults += "\nFailed to install vlock package"
            else:
                undocmd += self.pkg
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "comm",
                         "command": undocmd}
                self.statechglogger.recordchgevent(myid, event)
                self.detailedresults += "\nvlock Package was installed successfully"

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
