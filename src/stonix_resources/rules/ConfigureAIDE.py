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
Created on Mar 19, 2013

Install and configure Advanced Intrusion Detection Environment (AIDE).
This rule is optional and will install and configure AIDE when it is run.

@author: Breen Malmberg
@change: 02/12/2014 Ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 Ekkehard Implemented isapplicable
@change: 04/18/2014 Dave Kennel Updated for new style CI. Fixed bug where the bool
@change: 06/26/2014 Derek Walker tasked with figuring out installation bug, will
        be modifying rule as well
        CI was not referenced in the fix and report method.
@change: 2015/04/14 Dave Kennel updated to use new is applicable
@change: 2015/10/07 Eric Ball PEP8 cleanup
@change: 2017/08/28 Ekkehard - Added self.sethelptext()
"""



import os
import re
import traceback

from rule import Rule
from logdispatcher import LogPriority
from pkghelper import Pkghelper
from stonixutilityfunctions import iterate
from CommandHelper import CommandHelper
from KVEditorStonix import KVEditorStonix


class ConfigureAIDE(Rule):
    """Install and configure Advanced Intrusion Detection Environment (AIDE).
This rule is optional and will install and configure AIDE when it is run."""

    def __init__(self, config, environ, logger, statechglogger):
        """
        private method to initialize the module

        :param config: configuration object instance
        :param environ: environment object instance
        :param logger: logdispatcher object instance
        :param statechglogger: statechglogger object instance
        """

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 110
        self.rulename = 'ConfigureAIDE'
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.guidance = ['NSA(2.1.3)', 'cce-4209-3']

        # init CIs
        datatype = 'bool'
        key = 'CONFIGUREAIDE'
        instructions = 'If you set the ConfigureAIDE variable to yes, or ' + \
            'true, ConfigureAIDE will install and set up the Advanced ' + \
            'Intrusion Detection Environment on this system.'
        default = False
        self.applicable = {'type': 'white',
                           'family': ['linux']}
        self.ci = self.initCi(datatype, key, instructions, default)

        datatype2 = 'string'
        key2 = 'AIDEJOBTIME'
        instructions2 = """This string contains the time when the cron job for
        /usr/sbin/aide --check will run in /etc/crontab. The default value is
        00 18 * * 07 (which means weekly, on sundays at 6pm)"""
        default2 = "00 18 * * 07"
        self.aidetime = self.initCi(datatype2, key2, instructions2, default2)
        pattern = "^([0-9]{1,2})\s+([0-9]{1,2})\s+(\*|(3[0-1]|[0-2]?[0-9]))\s+(\*|(0[0-9]|[0-1]?[0-2]))\s+(\*|([0]?[0-7]))$"
        self.aidetime.setregexpattern(pattern)

    def report(self):
        """Check if AIDE is installed and properly configured.
        If the config is correct then the self.compliant, self.detailed results
        and self.currstate properties are updated to reflect the system status.
        self.rulesuccess will be updated if the rule does not succeed.

        :return: self.compliant
        :rtype: bool

        """

        try:

            self.compliant = True
            self.detailedresults = ""

            self.init_objs()

            try:
                self.set_aide_paths()
                self.set_aide_cron_job()
            except:
                pass

            if not self.report_aide_installed():
                self.compliant = False
            else:
                if not self.report_aide_conf():
                    self.compliant = False
                if not self.report_aide_cronjob():
                    self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def init_objs(self):
        """

        """

        self.ph = Pkghelper(self.logger, self.environ)
        self.ch = CommandHelper(self.logger)

    def set_aide_paths(self):
        """

        """

        self.aide_conf_file = ""
        aide_conf_paths = ["/etc/aide/aide.conf", "/etc/aide.conf"]
        for p in aide_conf_paths:
            if os.path.isfile(p):
                self.aide_conf_file = p
                break
        self.aide_package = "aide"
        self.aide_cron_file = "/etc/cron.d/stonix_aide_check"
        self.aide_bin_path = ""
        aide_bin_paths = ["/usr/sbin/aide", "/usr/bin/aide"]
        for p in aide_bin_paths:
            if os.path.isfile(p):
                self.aide_bin_path = p
                break
        self.crontab_bin = ""
        crontab_bin_locs = ["/bin/crontab", "/sbin/crontab"]
        for b in crontab_bin_locs:
            if os.path.isfile(b):
                self.crontab_bin = b
                break

    def set_aide_cron_job(self):
        """

        """

        aidetime = self.aidetime.getcurrvalue()

        if not aidetime:
            self.aide_cron_job = ""
        else:

            if self.ph.manager == "apt-get":

                self.aide_cron_job = str(self.aidetime.getcurrvalue()) + " root nice -n 19 " + self.aide_bin_path + " -c " + self.aide_conf_file + " --check"
            else:
                self.aide_cron_job = str(self.aidetime.getcurrvalue()) + " root nice -n 19 " + self.aide_bin_path + " --check"

    def report_aide_installed(self):
        """

        :return: compliant
        :rtype: bool
        """

        compliant = True

        if not self.ph.check(self.aide_package):
            compliant = False
            self.detailedresults += "\naide is not installed"

        return compliant

    def report_aide_conf(self):
        """

        :return: compliant
        :rtype: bool
        """

        compliant = True

        aide_conf_dict = {"/boot": "R",
                          "/etc": "R",
                          "/lib": "R",
                          "/lib64": "R",
                          "/sbin$": "R"}

        tmppath = self.aide_conf_file + ".stonixtmp"
        self.aide_conf_editor = KVEditorStonix(self.statechglogger, self.logger, "conf", self.aide_conf_file, tmppath, aide_conf_dict, "present", "space")
        if not self.aide_conf_editor.report():
            compliant = False
            self.detailedresults += "\nThe following aide conf file options are incorrect:\n" + "\n".join(self.aide_conf_editor.fixables)

        return compliant

    def report_aide_cronjob(self):
        """

        :return: compliant
        :rtype: bool

        """

        compliant = False

        if not os.path.isfile(self.aide_cron_file):
            compliant = False
            self.detailedresults += "\naide cron job not found"

        return compliant

    def fix(self):
        """Attempt to install and configure AIDE.
        self.rulesuccess will be updated if the rule does not succeed.

        :return: self.rulesuccess - True if fix succeeded; False if not
        :rtype: bool

        """

        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0

        try:

            if not self.ci.getcurrvalue():
                self.detailedresults += '\nThis rule is currently not enabled, so nothing was done'
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess

            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if not self.fix_aide_installed():
                self.rulesuccess = False
            if not self.fix_aide_conf():
                self.rulesuccess = False
            if not self.fix_aide_init():
                self.rulesuccess = False
            if not self.fix_aide_cronjob():
                self.rulesuccess = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess

    def fix_aide_conf(self):
        """

        :return: success
        :rtype: bool
        """

        success = True

        self.logger.log(LogPriority.DEBUG, "Fixing aide configuration file")

        if not self.aide_conf_editor.fix():
            success = False
        elif not self.aide_conf_editor.commit():
            success = False

        if not success:
            self.logger.log(LogPriority.DEBUG, "Failed to configure aide.conf")

        return success

    def fix_aide_cronjob(self):
        """

        :return: success
        :rtype: bool
        """

        success = True

        self.logger.log(LogPriority.DEBUG, "Creating aide cron job")

        try:

            f = open(self.aide_cron_file, "w")
            f.write(self.aide_cron_job)
            f.close()
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": self.aide_cron_file}
            self.statechglogger.recordchgevent(myid, event)

        except:
            success = False
            self.logger.log(LogPriority.DEBUG, "Failed to create aide cron job")

        return success

    def fix_aide_installed(self):
        """

        :return: success
        :rtype: bool
        """

        success = True

        self.logger.log(LogPriority.DEBUG, "Installing aide package")

        if not self.ph.install(self.aide_package):
            success = False
            self.logger.log(LogPriority.DEBUG, "Failed to install aide package")
            if not self.ph.checkAvailable(self.aide_package):
                self.logger.log(LogPriority.DEBUG, "aide package not available on this system")
        else:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "pkghelper",
                     "pkgname": self.aide_package,
                     "startstate": "removed",
                     "endstate": "installed"}
            self.statechglogger.recordchgevent(myid, event)
            self.set_aide_paths()
            self.set_aide_cron_job()
            self.report_aide_conf()
            self.report_aide_cronjob()

        return success

    def fix_aide_init(self):
        """

        :return: success
        :rtype: bool
        """

        success = True

        self.logger.log(LogPriority.DEBUG, "Initializing aide database")

        if self.ph.manager == "apt-get":
            aide_init_cmd = "aideinit"
        else:
            aide_init_cmd = self.aide_bin_path + " --init"

        self.ch.executeCommand(aide_init_cmd)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            success = False
            errmsg = self.ch.getErrorString()
            self.logger.log(LogPriority.DEBUG, errmsg)
        else:
            # to start using the aide database created by aide init,
            # remove the 'new' part of the aide database string
            # this must be done before check can be run
            # (https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-using-aide)
            if os.path.isfile('/var/lib/aide/aide.db.new.gz'):
                newaidedb = '/var/lib/aide/aide.db.new.gz'
                aidedb = '/var/lib/aide/aide.db.gz'
            elif os.path.isfile('/var/lib/aide/aide.db.new'):
                newaidedb = '/var/lib/aide/aide.db.new'
                aidedb = '/var/lib/aide/aide.db'
            else:
                newaidedb = ""
                aidedb = ""
            if bool(newaidedb and aidedb):
                os.rename(newaidedb, aidedb)
                os.chmod(aidedb, 0o600)
                os.chown(aidedb, 0, 0)
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to locate aide database")
                success = False

        return success
