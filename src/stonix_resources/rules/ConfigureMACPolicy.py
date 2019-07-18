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
Created on Jan 30, 2013

The ConfigureMACPolicy class enables and configures SELinux on support OS
platforms.

@author: Breen Malmberg
@change: 2014/03/10 Derek Walker
@change: 2014/04/18 Dave Kennel Replaced old style CI invocation
@change: 2015/04/15 Dave Kennel updated for new isApplicable
@change: 2015/10/07 Eric Ball Help text cleanup
@change: 2015/10/20 Derek Walker Update report and fix methods for applicability
@change: 2015/10/26 Breen Malmberg - merged apparmor code with selinux code;
    added method doc strings
@change: 2016/10/20 Eric Ball Improve feedback, PEP8 fixes
"""



import traceback
import re
import os

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..CommandHelper import CommandHelper
from ..ServiceHelper import ServiceHelper
from ..KVEditorStonix import KVEditorStonix
from ..stonixutilityfunctions import iterate


class ConfigureMACPolicy(Rule):
    """The ConfigureMACPolicy class configures either selinux or apparmor
    depending on the os platform.
    @change: Derek Walker - created two config items, one for enable/disable, and
        another for whether the user wants to use permissive or enforcing

    """

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 107
        self.rulename = 'ConfigureMACPolicy'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.guidance = ['NSA(2.1.1.6)(2.4.2)', 'CCE-3977-6', 'CCE-3999-0',
                         'CCE-3624-4', 'CIS 1.7']
        self.applicable = {'type': 'white',
                           'family': ['linux']}

        datatype = "bool"
        key = "CONFIGUREMAC"
        instructions = "To prevent the configuration of a mandatory " + \
            "access control policy, set the value of CONFIGUREMAC to " + \
            "False. Note: The 'mandatory access control' is either SELinux " + \
            "or AppArmor, depending on what is available to your current system."
        default = True
        self.ConfigureMAC = self.initCi(datatype, key, instructions, default)

        datatype2 = "string"
        key2 = "MODE"
        default2 = "permissive"
        instructions2 = "Valid modes for SELinux are: permissive or " + \
            "enforcing\nValid modes for AppArmor are: complain or enforce"
        self.modeci = self.initCi(datatype2, key2, instructions2, default2)

    def report(self):
        """

        :return: 
        """

        self.selinux = False
        self.apparmor = False
        self.ph = Pkghelper(self.logger, self.environ)
        self.ch = CommandHelper(self.logger)
        self.sh = ServiceHelper(self.environ, self.logger)
        selinux_packages = ["selinux", "libselinux", "selinux-basics"]
        apparmor_packages = ["apparmor"]
        self.mac_package = ""

        # discover whether this system can use - or is using - selinux
        # or if it should use apparmor (selinux takes precedence)
        for p in selinux_packages:
            if self.ph.check(p):
                self.selinux = True
                self.mac_package = p
                break
        if not self.selinux:
            for p in apparmor_packages:
                if self.ph.check(p):
                    self.apparmor = True
                    self.mac_package = p
                    break
        if not bool(self.selinux or self.apparmor):
            for p in selinux_packages:
                if self.ph.checkAvailable(p):
                    self.selinux = True
                    self.mac_package = p
                    break
            if not self.selinux:
                for p in apparmor_packages:
                    if self.ph.checkAvailable(p):
                        self.apparmor = True
                        self.mac_package = p
                        break

        self.compliant = True
        self.detailedresults = ""
        self.mode = str(self.modeci.getcurrvalue())

        try:

            if self.selinux:
                if not self.reportSelinux():
                    self.compliant = False
            elif self.apparmor:
                if not self.reportApparmor():
                    self.compliant = False
            else:
                self.detailedresults +=  "\nCould not find either selinux or apparmor installed and nother appears to be available to this system!"
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

    def reportSelinux(self):
        """

        :return:
        """

        compliant = True
        conf_option_dict = {"selinux\s+status:\s+enabled": "status",
                            "current\s+mode:\s+" + self.mode: "mode"}

        # check if selinux is installed
        if not self.ph.check(self.mac_package):
            compliant = False
            self.detailedresults += "\nSELinux is not installed"

        # check sestatus for current configuration of selinux
        self.ch.executeCommand("/usr/sbin/sestatus")
        output = self.ch.getOutput()
        for co in conf_option_dict:
            rco = re.compile(co, re.I)
            if not list(filter(rco.match, output)):
                compliant = False
                self.detailedresults += "\nSELinux " + conf_option_dict[co] + " is not configured properly"

        # discover correct location of selinux config file
        self.selinux_config_file = "/etc/sysconfig/selinux"
        selinux_config_files = ["/etc/selinux/config", "/etc/sysconfig/selinux"]
        for p in selinux_config_files:
            if os.path.exists(p):
                self.selinux_config_file = p
                break

        # check selinux config file for correct configuration so setting is
        # persistent after reboot
        selinux_tmp_file = self.selinux_config_file + ".stonixtmp"
        selinux_config_dict = {"SELINUX": self.mode}
        self.selinux_config_editor = KVEditorStonix(self.statechglogger, self.logger, "conf", self.selinux_config_file, selinux_tmp_file, selinux_config_dict, "present", "closedeq")
        self.selinux_config_editor.report()
        if self.selinux_config_editor.fixables:
            compliant = False
            self.detailedresults += "\nFollowing option(s) not configured correctly in " + self.selinux_config_file + " :\n" + "\n".join(self.selinux_config_editor.fixables)

        return compliant

    def reportApparmor(self):
        """

        :return:
        """

        compliant = True

        aa_enabled = "Yes"

        # check if apparmor is installed
        if not self.ph.check(self.mac_package):
            compliant = False
            self.detailedresults += "\nApparmor is not installed"

        # check if apparmor is enabled
        self.ch.executeCommand("/usr/bin/aa-enabled")
        output = self.ch.getOutputString()
        if not re.search(aa_enabled, output):
            compliant = False
            self.detailedresults += "\nApparmor is not enabled"

        # check if boot configuration for apparmor is correct
        f = open("/etc/default/grub", "r")
        contents = f.readlines()
        f.close()
        for line in contents:
            if re.search("GRUB_CMDLINE_LINUX_DEFAULT=", line):
                if not re.search("apparmor=1", line):
                    compliant = False
                    self.detailedresults += "\nApparmor not enabled in boot config"
                elif not re.search("security=apparmor", line):
                    compliant = False
                    self.detailedresults += "\nApparmor not enabled in boot config"
                break

        return compliant

    def fix(self):
        """

        :return: 
        """

        self.rulesuccess = True
        self.detailedresults = ""
        self.iditerator = 0

        try:

            if self.selinux:
                if not self.fixSelinux():
                    self.rulesuccess = False
            elif self.apparmor:
                if not self.fixApparmor():
                    self.rulesuccess = False
            else:
                self.rulesuccess = False
                self.detailedresults += "\nNeither SELinux nor Apparmor appears to be available to this system!"

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess

    def fixSelinux(self):
        """

        :return:
        """

        success = True
        self.iditerator = 0
        activate_utility = "/usr/sbin/selinux-activate"

        # install selinux package if it is not installed
        if not self.ph.check(self.mac_package):
            if not self.ph.install(self.mac_package):
                success = False
                self.detailedresults += "\nFailed to install selinux package"
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype":"pkghelper",
                         "pkgname":self.mac_package}
                self.statechglogger.recordchgevent(myid, event)

        if os.path.exists(activate_utility):
            self.ch.executeCommand(activate_utility)
            output = self.ch.getOutputString()
            if re.search("need to reboot", output, re.I):
                self.detailedresults += "\nSElinux has been configured, but you will need to reboot before selinux can become active. This rule will not report compliant until this is done."

        # set enforcement mode for selinux
        self.ch.executeCommand("/usr/sbin/setenforce " + self.mode)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            success = False
            self.detailedresults += "\nFailed to set selinux mode to: " + self.mode

        self.iditerator += 1
        myid = iterate(self.iditerator, self.rulenumber)
        self.selinux_config_editor.setEventID(myid)

        # configure the selinux config file for persistence through reboot
        if not self.selinux_config_editor.fix():
            success = False
            self.detailedresults += "\nFailed to fix " + self.selinux_config_file
        elif not self.selinux_config_editor.commit():
            success = False
            self.detailedresults += "\nFailed to fix " + self.selinux_config_file

        return success

    def fixApparmor(self):
        """

        :return:
        """

        success = True
        profiles_dir = "/etc/apparmor.d/"
        valid_modes = ["complain", "enforce"]
        grub_file = "/etc/default/grub"
        tmp_grub_file = grub_file + ".stonixtmp"

        # install apparmor package if not installed
        if not self.ph.check(self.mac_package):
            if not self.ph.install(self.mac_package):
                success = False
                self.detailedresults += "\nFailed to install apparmor package"
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype":"pkghelper",
                         "pkgname":self.mac_package}
                self.statechglogger.recordchgevent(myid, event)
        if not self.ph.check("apparmor-profiles"):
            self.ph.install("apparmor-profiles")
        if not self.ph.check("apparmor-utils"):
            self.ph.install("apparmor-utils")

        # set apparmor enforcement mode
        if self.mode.lower() in ["complain", "permissive"]:
            self.ch.executeCommand("/usr/sbin/aa-complain " + profiles_dir + "*")
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                success = False
                self.detailedresults += "\nFailed to set apparmor profiles to complain mode"
        elif self.mode.lower() in ["enforce", "enforcing"]:
            if os.path.exists(profiles_dir):
                self.ch.executeCommand("/usr/sbin/aa-enforce " + profiles_dir + "*")
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    success = False
                    self.detailedresults += "\nFailed to set apparmor profiles to enforce mode"
            else:
                self.logger.log(LogPriority.DEBUG, "apparmor profiles directory does not exist")
                success = False
                self.detailedresults += "\nFailed to set apparmor mode to: " + self.mode
        else:
            success = False
            self.detailedresults += "\nPlease specify one of the following options in the MODE field:\n" + "\n".join(valid_modes)

        # correct apparmor boot config
        # (can't use kveditor because it can't handle appending to a config line)
        if os.path.exists(grub_file):
            f = open(grub_file, "r")
            contents = f.readlines()
            f.close()
            for n, i in enumerate(contents):
                if re.search("GRUB_CMDLINE_LINUX_DEFAULT=", i):
                    contents[n] = i.strip()[:-1]+' apparmor=1 security=apparmor"\n'
            tf = open(tmp_grub_file, "w")
            tf.writelines(contents)
            tf.close()

            self.iditerator += 1
            event = {"eventtype":"conf",
                     "filepath":grub_file}
            myid = iterate(self.iditerator, self.rulenumber)
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(grub_file, tmp_grub_file, myid)

            os.rename(tmp_grub_file, grub_file)

        # run update-grub to apply the new grub config
        self.ch.executeCommand("/usr/sbin/update-grub")

        return success
