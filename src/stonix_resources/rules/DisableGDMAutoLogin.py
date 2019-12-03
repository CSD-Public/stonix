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
Created on November 14, 2019

@author: Breen Malmberg
"""

import os
import traceback

from rule import Rule
from logdispatcher import LogPriority
from KVEditorStonix import KVEditorStonix


class DisableGDMAutoLogin(Rule):
    """
    The GNOME Display Manager (GDM) can allow users to automatically login without user interaction or credentials. User
should always be required to authenticate themselves to the system that they are authorized to use.
    """

    def __init__(self, config, environ, logger, statechglogger):
        """
        Constructor
        """

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 192
        self.rulename = 'DisableGDMAutoLogin'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'family': ['linux']}
        self.guidance = ['RHEL 7 STIG CCE-80104-3']
        datatype = 'bool'
        key = 'DISABLEGDMAUTOLOGIN'
        instructions = """To disable this rule set the value of DISABLEGDMAUTOLOGIN to False."""
        default = True
        self.PrimaryCI = self.initCi(datatype, key, instructions, default)

    def report(self):
        """

        :return: self.compliant
        :rtype: bool
        """

        self.detailedresults = ""
        self.compliant = True
        basedir = "/etc/gdm/"

        try:

            # if there is no gdm folder then there is likely no reason to configure it
            if not os.path.isdir(basedir):
                self.logger.log(LogPriority.DEBUG, "Rule does not apply to this system in its current state")
                return self.compliant

            kvtype = "tagconf"
            path = basedir + "custom.conf"
            tmppath = path + ".stonixtmp"
            data = {"daemon": {"AutomaticLoginEnable": "False",
                               "TimedLoginEnable": "False"}}
            intent = "present"
            delimiter = "closedeq"
            self.gdm_editor = KVEditorStonix(self.statechglogger, self.logger, kvtype, path, tmppath, data, intent, delimiter)

            if not self.gdm_editor.report():
                self.compliant = False
                try:
                    self.detailedresults += "\nThe following config options in " + str(path) + " are incorrect:\n" + "\n".join(self.gdm_editor.fixables)
                except:
                    self.detailedresults += "\nOne or more config options in " + str(path) + " are incorrect"

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

        :return: self.rulesuccess
        :rtype: bool
        """

        self.detailedresults = ""
        self.rulesuccess = True
        basedir = "/etc/gdm/"

        try:

            # if there is no gdm folder then there is likely no reason to configure it
            if not os.path.isdir(basedir):
                self.logger.log(LogPriority.DEBUG, "Rule does not apply to this system in its current state")
                return self.rulesuccess

            if not self.gdm_editor.fix():
                self.rulesuccess = False
                self.logger.log(LogPriority.DEBUG, "KVEditor fix failed")
            elif not self.gdm_editor.commit():
                self.rulesuccess = False
                self.logger.log(LogPriority.DEBUG, "KVEditor commit failed")

            if not self.rulesuccess:
                self.detailedresults += "\nFailed to disable GDM Auto Login"

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
