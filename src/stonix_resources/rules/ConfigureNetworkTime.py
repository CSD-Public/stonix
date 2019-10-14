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
Created on Jan 14, 2013

The ConfigureNetworkTime class specifies network time servers and enables the appropriate service

@author: Breen Malmberg
@change: 2014/04/18 ekkehard ci updates and ci fix method implementation
@change: 2014/08/27 - ekkehard - added self.ss = "/usr/sbin/systemsetup" to make sure we use the full path
@change: 08/27/2014 Breen Malmberg added colons after each docblock parameter
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/10/08 eball Help text cleanup
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
"""


import os
import re
import traceback

from rule import Rule
from logdispatcher import LogPriority
from pkghelper import Pkghelper
from stonixutilityfunctions import iterate
from localize import NTPSERVERSINTERNAL
from localize import NTPSERVERSEXTERNAL
from CommandHelper import CommandHelper
from get_libc import getLibc
from KVEditorStonix import KVEditorStonix

class ConfigureNetworkTime(Rule):
    """The ConfigureNetworkTime class specifies network time servers and enables the appropriate service"""

    def __init__(self, config, environ, logger, statechglogger):
        """
        Constructor
        """
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 96
        self.rulename = 'ConfigureNetworkTime'
        self.formatDetailedResults("initialize")
        self.logger = logger
        self.sethelptext()
        self.mandatory = True
        self.rootrequired = True
        self.guidance = ['CIS', 'NSA(3.10.2)', 'CCE-4134-3', 'CCE-4385-1',
                         'CCE-4032-9', 'CCE-4424-8', 'CCE-3487-6']

        # init CI
        self.ci = self.initCi("bool", "CONFIGURENETWORKTIME", "To prevent STONIX from configuring network time servers for this system, set the value of CONFIGURENETWORKTIME to False.", True)

        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

        self.libc = getLibc()

    def _set_paths(self):
        """

        """

        self.time_package = "chrony"

        self.time_conf_file = ""
        time_conf_files = ["/etc/chrony.conf", "/etc/chrony/chrony.conf"]
        for cf in time_conf_files:
            if os.path.isfile(cf):
                self.time_conf_file = cf
                break

    def _test_connection(self, hostname):
        """

        :param str hostname: host to test connection to
        :return: reachable
        :rtype: bool
        """

        reachable = False

        if isinstance(hostname, list):
            for h in hostname:
                response = os.system("ping -c 1 " + h)
                if response == 0:
                    reachable = True
                    break
        else:
            response = os.system("ping -c 1 " + hostname)
            if response == 0:
                reachable = True

        return reachable

    def _report_install(self):
        """

        :return: installed
        :rtype: bool
        """

        installed = True

        if not self.ph.check('chrony'):
            installed = False

        return installed

    def _report_conf(self):
        """

        :return: configured
        :rtype: bool
        """

        configured = True

        self.time_conf_dict = {"driftfile": "/var/lib/chrony/drift",
                               "makestep": "1.0 3",
                               "rtcsync": "",
                               "logdir": "/var/log/chrony",
                               "cmddeny": "all",
                               "server": []}
        for ts in self.time_servers:
            self.time_conf_dict["server"].append(ts)

        tmpfile = self.time_conf_file + ".stonixtmp"

        self.time_conf_editor = KVEditorStonix(self.statechglogger, self.logger, "conf", self.time_conf_file, tmpfile, self.time_conf_dict, "present", "space")
        if not self.time_conf_editor.report():
            configured = False
            self.detailedresults += "\nThe following configuration options are incorrect in " + str(self.time_conf_file) +  ":\n" + "\n".join(self.time_conf_editor.fixables)

        return configured

    def _report_linux(self):
        """

        :return: compliant
        :rtype: bool
        """

        self._set_paths()

        compliant = True

        if not self._test_connection(self.time_servers):
            compliant = False
            self.detailedresults += "\nCould not reach network time servers"
        if not self._report_install():
            compliant = False
            self.detailedresults += "\nCould not install network time package"
        elif not self._report_conf():
            compliant = False
            self.detailedresults += "\nFailed to properly configure network time configuration file"

        return compliant

    def report(self):
        """determine whether the fix() method of this rule has run successfully
        yet or not

        :return: self.compliant
        :rtype: bool
        """

        self.detailedresults = ""

        # UPDATE THIS SECTION IF THE CONSTANTS BEING USED IN THIS CLASS CHANGE
        self.constlist = [NTPSERVERSEXTERNAL, NTPSERVERSINTERNAL]
        if not any(self.constlist):
            self.compliant = False
            self.detailedresults += "\nThis rule requires that at least one of the following constants, in localize.py, be defined and not None: NTPSERVERSEXTERNAL, NTPSERVERSINTERNAL"
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            return self.compliant

        self.ph = Pkghelper(self.logger, self.environ)
        self.ch = CommandHelper(self.logger)

        if self._test_connection(NTPSERVERSINTERNAL):
            self.time_servers = NTPSERVERSINTERNAL
        else:
            self.time_servers = NTPSERVERSEXTERNAL

        self.compliant = True

        try:

            if self.environ.getosfamily() == "darwin":
                self.ss = "/usr/sbin/systemsetup"
                if not self._report_darwin():
                    self.compliant = False
            else:
                if not self._report_linux():
                    self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def _report_darwin(self):
        """determine rule compliance status for darwin based systems


        :return: configured
        :rtype:
        """

        # defaults
        configured = True
        usingnetworktime = False
        timeserverfound = False

        try:

            cmd = [self.ss, "-getnetworktimeserver"]
            self.ch.executeCommand(cmd)
            self.output = self.ch.getOutput()

            for line in self.output:
                for item in self.time_servers:
                    if re.search(item, line):
                        timeserverfound = True

            cmd2 = [self.ss, "-getusingnetworktime"]
            self.ch.executeCommand(cmd2)
            self.output2 = self.ch.getOutput()

            for line in self.output2:
                if re.search('On', line):
                    usingnetworktime = True

            if not usingnetworktime:
                self.detailedresults += '\nusingnetworktime not set to on'
                configured = False
            if not timeserverfound:
                self.detailedresults += '\ncorrect time server not configured'
                configured = False

        except Exception:
            raise
        return configured

    def fix(self):
        """Decide which fix sub method to run, and run it to configure network time

        :return: self.rulesuccess
        :rtype: bool
        """

        # UPDATE THIS SECTION IF THE CONSTANTS BEING USED IN THIS CLASS CHANGE
        if not self.checkConsts(self.constlist):
            self.rulesuccess = False
            self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
            return self.rulesuccess

        self.detailedresults = ""
        self.iditerator = 0
        self.rulesuccess = True

        try:

            if self.ci.getcurrvalue():

                if self.environ.getosfamily() == "darwin":
                    if not self._fix_darwin():
                        self.rulesuccess = False
                else:
                    if not self._fix_linux():
                        self.rulesuccess = False

            else:
                self.detailedresults += "\nRule was not enabled. No action was taken."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def _fix_linux(self):
        """

        :return: success
        :rtype: bool
        """

        success = True

        if not self._fix_install():
            success = False
        else:
            self._set_paths()
            self._report_conf()
        if not self._fix_conf():
            success = False

        return success

    def _fix_install(self):
        """

        :return: success
        :rtype: bool
        """

        success = True

        if not self.ph.install(self.time_package):
            success = False
            self.logger.log(LogPriority.DEBUG, "Failed to install network time package")

        return success

    def _fix_conf(self):
        """

        :return: success
        :rtype: bool
        """

        success = True

        if not self.time_conf_editor.fix():
            success = False
            self.logger.log(LogPriority.DEBUG, "KVEditor failed to fix")
        elif not self.time_conf_editor.commit():
            success = False
            self.logger.log(LogPriority.DEBUG, "KVEditor failed to commit")

        return success

    def _fix_darwin(self):
        """
        private method to perform fix operations for mac os x machines
        
        :return: fixresult
        :rtype: bool
        """

        parseoutput1 = []
        parseoutput2 = []
        fixresult = True

        try:

            # set network time on
            cmd1 = [self.ss, "-setusingnetworktime", "on"]
            try:
                self.ch.executeCommand(cmd1)
                self.libc.sync()
            except Exception as errmsg:
                self.logger.log(LogPriority.DEBUG, str(errmsg))

            try:

                # set undo cmd to restore original network time state
                for line in self.output2:
                    if re.search('Network Time', line):
                        parseoutput1 = line.split(':')
                originaltimestate = parseoutput1[1].strip()

            except KeyError:
                originaltimestate = "off"

            undocmd1 = self.ss + " -setusingnetworktime " + originaltimestate
            event = {"eventtype": "commandstring",
                     "command": undocmd1}
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.statechglogger.recordchgevent(myid, event)

            # set network time server
            cmd2 = [self.ss, "-setnetworktimeserver", str(self.time_servers[0])]
            try:
                self.ch.executeCommand(cmd2)
            except Exception as errmsg:
                self.logger.log(LogPriority.DEBUG, str(errmsg))

            try:

                # set undo cmd to reinstate original time server
                for line in self.output:
                    if re.search('Network Time Server', line):
                        parseoutput2 = line.split(':')
                originalnetworktimeserver = parseoutput2[1].strip()

            except (IndexError, KeyError):
                originalnetworktimeserver = NTPSERVERSINTERNAL[0]

            undocmd2 = self.ss + " -setusingnetworktime " + \
            originalnetworktimeserver
            event = {"eventtype": "commandstring",
                     "command": undocmd2}
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.statechglogger.recordchgevent(myid, event)

        except:
            raise

        return fixresult
