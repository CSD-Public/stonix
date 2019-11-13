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
Created on Apr 15, 2015

System accounting is an optional process which gathers baseline system data
(CPU utilization, disk I/O, etc.) every 10 minutes, by default. The data may be
accessed with the sar command, or by reviewing the nightly report files named
/var/ log/sa/sar*. Once a normal baseline for the system has been established,
with frequent monitoring - unauthorized activity (password crackers and other
CPU-intensive jobs, and activity outside of normal usage hours) may be detected
due to departures from the normal system performance curve.

@author: Breen Malmberg
@change: 2015/09/25 eball Added Deb/Ubuntu compatibility
@change: 2015/09/29 Breen Malmberg - Added initialization of variable self.iditerator in fix()
@change: 2015/10/08 eball Help text cleanup
@change: 2015/11/18 eball Added undo events to fix
@change: 2016/05/19 Breen Malmberg - added docstrings to every method; added a check in reporting to see if rule is enabled or not;
added some in-line comments to several methods, where needed; changed the CI instructions to be more clear to the end user; added
messaging to indicate to the user whether the method will run or not, based on current CI status
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
"""

import traceback
import os
import re

from rule import Rule
from pkghelper import Pkghelper
from CommandHelper import CommandHelper
from logdispatcher import LogPriority
from KVEditorStonix import KVEditorStonix


class SystemAccounting(Rule):
    """
    """

    def __init__(self, config, environ, logger, statechglogger):
        """
        Constructor
        """
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 9
        self.rulename = 'SystemAccounting'
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.rootrequired = True
        self.sethelptext()
        self.guidance = ['CIS 2.4', 'cce-3992-5']
        self.applicable = {'type': 'white',
                           'family': 'linux',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

        # set up configuration item for this rule
        datatype = 'bool'
        key = 'SYSTEMACCOUNTING'
        instructions = "This is an optional rule and is disabled by default, due to the significant load it can place on the system when enabled. To enable system accounting, set the value of SYSTEMACCOUNTING to True."
        default = False
        self.ci = self.initCi(datatype, key, instructions, default)

        self.ostype = self.environ.getostype()
        self.ph = Pkghelper(self.logger, self.environ)
        self.ch = CommandHelper(self.logger)
        self._set_paths()

    def _set_paths(self):
        """

        """

        self.sysstat_package = "sysstat"
        self.sysstat_service_file = ""
        sysstat_service_locs = ["/usr/lib/systemd/system/sysstat.service", "/lib/systemd/system/sysstat.service",  "/etc/init.d/sysstat"]
        for ss in sysstat_service_locs:
            if os.path.isfile(ss):
                self.sysstat_service_file = ss
                break
        self.accton = "/usr/sbin/accton"
        self.acct_file = "/var/account/acct"
        self.cron_file = "/etc/cron.d/sysstat"

        self.sa1 = ""
        sa1_locs = ["/usr/lib64/sa/sa1", "/usr/local/lib64/sa/sa1", "/usr/lib/sysstat/sa1"]
        for sl in sa1_locs:
            if os.path.isfile(sl):
                self.sa1 = sl
                break

        self.sa2 = ""
        sa2_locs = ["/usr/lib64/sa/sa2", "/usr/local/lib64/sa/sa2", "/usr/lib/sysstat/sa2"]
        for sl in sa2_locs:
            if os.path.isfile(sl):
                self.sa2 = sl
                break

        self.sysstat_service_contents = """# /usr/lib/systemd/system/sysstat.service
# (C) 2012 Peter Schiffer (pschiffe <at> redhat.com)
#
# sysstat-10.1.7 systemd unit file:
#     Insert a dummy record in current daily data file.
#     This indicates that the counters have restarted from 0.

[Unit]
Description=Resets System Activity Logs

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
ExecStart=""" + self.sa1 + """ --boot

[Install]
WantedBy=multi-user.target
"""

        self.sysstat_cron_contents = """# Run system activity accounting tool every 60 minutes
*/60 * * * * root """ + self.sa1 + """ 1 1
# Generate a daily summary of process accounting at 23:53
53 23 * * * root """ + self.sa2 + """ -A"""

    def _report_configuration(self):
        """

        :return: compliant
        :rtype: bool
        """

        compliant = True

        if self.ostype == "Mac OS X":
            self.conf_file = ""
            conf_files = ["/etc/rc.conf", "/etc/rc.common"]
            for cf in conf_files:
                if os.path.isfile(cf):
                    self.conf_file = cf
                    break
            tmpfile = self.conf_file + ".stonixtmp"

            config_data = {"accounting_enable": "YES"}

            self.conf_editor = KVEditorStonix(self.statechglogger, self.logger, "conf", self.conf_file, tmpfile, config_data, "present", "closedeq")
            if not self.conf_editor.report():
                compliant = False
        else:


            if not os.path.isfile(self.sysstat_service_file):
                compliant = False
                self.detailedresults += "\nSystem accounting service file is missing"
            else:
                f = open(self.sysstat_service_file, "r")
                contents = f.read()
                f.close()
                if self.sysstat_service_file != "/etc/init.d/sysstat":
                    if contents != self.sysstat_service_contents:
                        compliant = False
                        self.detailedresults += "\nSystem accounting service file has incorrect contents"

        if os.path.isfile("/etc/default/sysstat"):
            f = open("/etc/default/sysstat", "r")
            contents = f.read()
            f.close()
            if not re.search('ENABLED="true"', contents):
                compliant = False
                self.detailedresults += "\n/etc/default/sysstat file has incorrect contents"

        return compliant

    def _report_installation(self):
        """

        :return: compliant
        :rtype: bool
        """

        compliant = True

        if self.ostype != "Mac OS X":
            if not self.ph.check(self.sysstat_package):
                compliant = False
                self.detailedresults += "\nSystem accounting package is not installed"

        return compliant

    def _report_schedule(self):
        """

        :return: compliant
        :rtype: bool
        """

        compliant = True

        if self.ostype == "Mac OS X":
            if not os.path.isfile(self.acct_file):
                compliant = False
                self.detailedresults += "\nSystem accounting is not enabled on this system"
        else:
            if not os.path.isfile(self.cron_file):
                compliant = False
            else:
                f = open(self.cron_file, "r")
                contents = f.read()
                f.close()
                if contents != self.sysstat_cron_contents:
                    self.compliant = False
                    self.detailedresults += "\nSystem account cron job has incorrect contents"

        return compliant

    def report(self):
        """

        :return: compliant
        :rtype: bool
        """

        self.detailedresults = ""
        self.compliant = True

        try:

            if not self._report_installation():
                self.compliant = False
            else:
                if not self._report_configuration():
                    self.compliant = False
                if not self._report_schedule():
                    self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def _fix_installation(self):
        """

        :return: success
        :rtype: bool
        """

        success = True

        if self.ostype != "Mac OS X":
            if not self.ph.install(self.sysstat_package):
                success = False
                self.logger.log(LogPriority.DEBUG, "Failed to install sysstat package")

        return success

    def _fix_configuration(self):
        """

        :return: success
        :rtype: bool
        """

        success = True

        if self.ostype == "Mac OS X":
            if not self.conf_editor.fix():
                success = False
                self.logger.log(LogPriority.DEBUG, "kveditor failed to fix()")
            elif not self.conf_editor.commit():
                success = False
                self.logger.log(LogPriority.DEBUG, "kveditor failed to commit()")
        else:
            try:
                if self.sysstat_service_file != "/etc/init.d/sysstat":
                    f = open(self.sysstat_service_file, "w")
                    f.write(self.sysstat_service_contents)
                    f.close()
            except:
                success = False

        if os.path.isfile("/etc/default/sysstat"):
            default_sysstat_contents = """# 
# Default settings for /etc/init.d/sysstat, /etc/cron.d/sysstat 
# and /etc/cron.daily/sysstat files 
# 

# Should sadc collect system activity information? Valid values 
# are 'true' and 'false'. Please do not put other values, they 
# will be overwritten by debconf! 
ENABLED="true"
"""
            f = open("/etc/default/sysstat", "w")
            f.write(default_sysstat_contents)
            f.close()

        return success

    def _fix_schedule(self):
        """

        :return: success
        :rtype: bool
        """

        success = True

        try:

            if self.ostype == "Mac OS X":
                if not os.path.isdir("/var/account"):
                    os.mkdir("/var/account", 0o755)
                open(self.acct_file, "a").close()
                self.ch.executeCommand(self.accton + " " + self.acct_file)
            else:
                f = open(self.cron_file, "w")
                f.write(self.sysstat_cron_contents)
                f.close()
                os.chown(self.cron_file, 0, 0)
                os.chmod(self.cron_file, 0o644)
        except:
            success = False

        return success

    def fix(self):
        """

        :return: self.rulesuccess
        :rtype: bool
        """

        self.detailedresults = ""
        self.rulesuccess = True

        try:

            if not self._fix_installation():
                self.rulesuccess = False
            else:
                self._set_paths()
            if not self._fix_configuration():
                self.rulesuccess = False
            if not self._fix_schedule():
                self.rulesuccess = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
