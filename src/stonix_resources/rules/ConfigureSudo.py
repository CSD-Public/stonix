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
Created on Mar 7, 2013

@author: Derek Walker
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 02/14/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel Updated to use new style CI
@change: 2015/04/14 dkennel upddated to use new isApplicable
@change: 2015/09/06 Breen Malmberg, re-wrote rule
@change: 2015/10/07 eball Help text cleanup
@change: 2015/10/09 eball Fixed bad variable name in report
@change: 2016/05/09 rsn put default on Mac as admin, also
                        fixed search string and stopped removing lines.
@change: Breen Malmberg - 2/13/2017 - set the default group name to sudo on ubuntu and debian
        systems; set a default initialization of the group name variable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
"""

import os
import traceback
import shutil

from rule import Rule
from logdispatcher import LogPriority
from KVEditorStonix import KVEditorStonix
from stonixutilityfunctions import resetsecon


class ConfigureSudo(Rule):
    """

    """

    def __init__(self, config, environ, logger, statechglogger):
        """

        :param config:
        :param environ:
        :param logger:
        :param statechglogger:
        """
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 56
        self.rulename = "ConfigureSudo"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.guidance = ["NSA 2.3.1.3"]
        self.applicable = {'type': 'white',
                           'family': 'linux',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

        datatype2 = 'bool'
        key2 = 'CONFIGURESUDO'
        instructions2 = """To disable this rule set the value of CONFIGURESUDO to False."""
        default2 = True
        self.primary_ci = self.initCi(datatype2, key2, instructions2, default2)

        self.localization()

    def localization(self):
        """
        set up class variables, specific to OS type
        """

        self.logger.log(LogPriority.DEBUG, "Running localization() method...")

        ostype = self.environ.getostype()
        osname = self.environ.getosname()

        if ostype == "darwin":
            self.sudoers_file = "/private/etc/sudoers"
        else:
            self.sudoers_file = "/etc/sudoers"

        if ostype == "darwin":
            self.sudoers_opts = {"root": "ALL = (ALL) ALL",
                                 "%admin": "ALL = (ALL) ALL"}
        elif osname == "Debian":
            self.sudoers_opts = {"root": "ALL=(ALL:ALL) ALL",
                                 "%sudo": "ALL=(ALL:ALL) ALL"}
        elif osname == "Ubuntu":
            self.sudoers_opts = {"root": "ALL=(ALL:ALL) ALL",
                                 "%admin": "ALL=(ALL) ALL",
                                 "%sudo": "ALL=(ALL:ALL) ALL"}
        else:
            self.sudoers_opts = {"root": "ALL=(ALL) ALL",
                                 "%wheel": "ALL=(ALL) ALL"}

    def report(self):
        """
        ConfigureScreenLocking.report() method to report whether system is
        configured with a sudoers group.
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool - True if system is compliant, False if it isn't
        """

        try:

            self.detailedresults = ""
            self.compliant = True

            if not self.sudoers_file:
                self.detailedresults += "\nCan't find sudoers file!"
                self.compliant = False
            elif not os.path.isfile(self.sudoers_file):
                self.detailedresults += "\nCan't find sudoers file!"
                self.compliant = False
            else:
                self.sudoers_backup = self.sudoers_file + ".stonixbak"
                tmppath = self.sudoers_file + ".stonixtmp"
                self.sudoers_editor = KVEditorStonix(self.statechglogger, self.logger, "conf", self.sudoers_file, tmppath, self.sudoers_opts, "present", "space")
                if not self.sudoers_editor.report():
                    if self.sudoers_editor.fixables:
                        self.detailedresults += "\nThe following configuration options are missing or incorrect in the sudoers file:\n" + "\n".join(self.sudoers_editor.fixables)
                        self.compliant = False
                    else:
                        self.detailedresults += "\nOne or more configuration options are missing or incorrect in the sudoers file"
                        self.compliant = False

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
        Fix method that writes specified or default sudo group to sudoers file
        if not present from the report method

        :param self: essential if you override this definition
        :returns: bool - True if fix is successful, False if it isn't
        """

        self.detailedresults = ""
        self.rulesuccess = True

        try:

            if not self.primary_ci.getcurrvalue():
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess

            if not os.path.isfile(self.sudoers_backup):
                shutil.copy2(self.sudoers_file, self.sudoers_backup)

            if not self.sudoers_editor.fix():
                self.detailedresults += "\nFailed to update sudoers configuration"
                self.rulesuccess = False
            elif not self.sudoers_editor.commit():
                self.detailedresults += "\nFailed to update sudoers configuration"
                self.rulesuccess = False
            else:
                self.detailedresults += "\nSuccessfully updated sudoers configuration"

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess

    def undo(self):
        """
        Revert all fix actions taken by this rule
        """

        try:

            if os.path.isfile(self.sudoers_backup):
                os.rename(self.sudoers_backup, self.sudoers_file)
                resetsecon(self.sudoers_file)
                os.remove(self.sudoers_backup)
                self.detailedresults += "\nOriginal files/settings restored."
            else:
                self.detailedresults += "\nNo files/settings to restore."

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
