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
Created on Sep 17, 2015
The Boot Security rule configures the system to run a job at system boot time
that handles turning off potential vulnerability points such as: wifi,
bluetooth, microphones, and cameras.

@author: Dave Kennel
@change: 2015/10/07 Eric Ball Help text cleanup
@change: 2016/02/22 Ekkehard Updated Plist Name from
@change: 2016/04/26 Ekkehard Results Formatting
        /Library/LaunchDaemons/stonixBootSecurity.plist to
        /Library/LaunchDaemons/gov.lanl.stonix.bootsecurity.plist
@change: 2017/07/07 Ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 - Ekkehard - Added self.sethelptext()
@change: 2017/10/23 Roy Nielsen - change to new service helper interface
@change: 2017/11/13 Ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 Ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 Ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
"""



import traceback
import os
import re

from rule import Rule
from logdispatcher import LogPriority
from ServiceHelper import ServiceHelper
from CommandHelper import CommandHelper
from stonixutilityfunctions import iterate
from KVEditorStonix import KVEditorStonix


class BootSecurity(Rule):
    """The Boot Security rule configures the system to run a job at system boot
    time that handles turning off potential vulnerability points such as: wifi,
    bluetooth, microphones, and cameras.

    """

    def __init__(self, config, environ, logger, statechglogger):
        """
        private method to initialize the module

        :param config: configuration object instance
        :param environ: environment object instance
        :param logger: logdispatcher object instance
        :param statechglogger: statechglogger object instance
        """

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 18
        self.rulename = 'BootSecurity'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = []
        self.applicable = {'type': 'white',
                           'family': ['linux'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        self.servicehelper = ServiceHelper(environ, logger)
        self.ch = CommandHelper(self.logdispatch)
        self.type = 'rclocal'
        self.rclocalpath = '/etc/rc.local'
        if os.path.islink(self.rclocalpath):
                paths = ['/etc/rc.d/rc.local', '/etc/init.d/rc.local']
                for rcpath in paths:
                    if os.path.isfile(rcpath):
                        self.rclocalpath = rcpath
        self.logdispatch.log(LogPriority.DEBUG, 'Using rc.local file ' + self.rclocalpath)
        if os.path.exists('/bin/systemctl'):
            self.type = 'systemd'
        elif os.path.exists('/sbin/launchd'):
            self.type = 'mac'

        datatype = 'bool'
        key = 'BOOTSECURITY'
        instructions = """To disable this rule set the value of BOOTSECURITY to False."""
        default = True
        self.bootci = self.initCi(datatype, key, instructions, default)

        self.set_paths()

    def set_paths(self):
        """

        """

        self.systemd_boot_service_file = "/etc/systemd/system/stonixBootSecurity.service"
        self.rc_boot_script = "/usr/bin/stonix_resources/stonixBootSecurityLinux.py"
        self.systemd_service_name = "stonixBootSecurity.service"
        self.stonix_launchd_plist = "/Library/LaunchDaemons/gov.lanl.stonix.bootsecurity.plist"
        self.stonix_launchd_name = "gov.lanl.stonix.bootsecurity"
        self.grub_file = "/etc/default/grub"
        self.grub_config_file = ""
        grub_configs = ["/boot/grub2/grub.cfg", "/boot/efi/EFI/redhat/grub.cfg"]
        for c in grub_configs:
            if os.path.isfile(c):
                self.grub_config_file = c
                break
        self.grub_updater_cmd = ""
        grub_updater_locs = ["/sbin/grub2-mkconfig", "/usr/sbin/update-grub", "/sbin/update-grub"]
        for l in grub_updater_locs:
            if os.path.isfile(l):
                self.grub_updater_cmd = l
                break

        if self.grub_updater_cmd == "/sbin/grub2-mkconfig":
            self.grub_updater_cmd += " -o " + self.grub_config_file

    def auditsystemd(self):
        """
        check whether the stonixbootsecurity.service service
        module is loaded

        :return: boolean; True if the stonixbootsecurity.service service
        module is loaded, False if not
        """

        compliant = True

        self.stonix_boot_service_contents = """[Unit]
        Description=Stonix Boot Security
        After=network.target

        [Service]
        ExecStart=/usr/bin/stonix_resources/stonixBootSecurityLinux.py

        [Install]
        WantedBy=multi-user.target
        """

        try:

            # check if service file exists
            if not os.path.isfile(self.systemd_boot_service_file):
                compliant = False
                self.detailedresults += "\nstonix boot service unit does not exist"
            else:
                # check contents of service file
                f = open(self.systemd_boot_service_file, "r")
                contents = f.read()
                f.close()
                if contents != self.stonix_boot_service_contents:
                    compliant = False
                    self.detailedresults += "\nstonix boot service unit contents incorrect"

            # check if service is enabled
            if not self.servicehelper.auditService(self.systemd_service_name):
                compliant = False
                self.detailedresults += "\nstonix boot service is not enabled"

        except:
            raise

        return compliant

    def auditrclocal(self):
        """
        check whether the rclocal configuration file contains the correct
        stonixBootSecurity line entry

        :return: compliant - boolean; True if compliant, False if not
        """

        compliant = True

        try:

            tmppath = self.rc_boot_script + ".stonixtmp"
            data = {"python": self.rc_boot_script}
            self.rc_boot_security_editor = KVEditorStonix(self.statechglogger, self.logdispatch, "conf", self.rc_boot_script, tmppath, data, "present", "space")
            if not self.rc_boot_security_editor.report():
                self.detailedresults += "\nThe following config line is missing or incorrect from " + str(self.rc_boot_script) + "\n" + "\n".join(self.rc_boot_security_editor.fixables)
                compliant = False

        except:
            raise

        return compliant

    def auditmac(self):
        """
        check whether the stonixbootsecurity launchd job exists

        :return:
        """

        compliant = True

        self.logdispatch.logger(LogPriority.DEBUG,  "Looking for macOS launchd job")

        self.stonix_plist_contents = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>gov.lanl.stonix.bootsecurity</string>
            <key>Program</key>
            <string>/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix_resources/stonixBootSecurityMac</string>
            <key>RunAtLoad</key>
            <true/>
        </dict>
        </plist>"""

        try:
            if not os.path.exists(self.stonix_launchd_plist):
                compliant = False
                self.detailedresults += "\nCould not locate stonix boot security launchd job"

        except:
            raise

        return compliant

    def report_boot_fips(self):
        """

        :return:
        """

        found_fips = False
        compliant = True

        if self.grub_file:
            f = open(self.grub_file, "r")
            contentlines = f.readlines()
            f.close()

#!FIXME find some way to check/add fips=1 without clobbering the option that configuremacpolicy adds (security=<whatever>)
            for line in contentlines:
                if re.search('^GRUB_CMDLINE_LINUX_DEFAULT=', line, re.I):
                    if re.search("fips=1", line, re.I):
                        found_fips = True

        if not found_fips:
            compliant = False
            self.detailedresults += "\nfips not enabled in boot config"

        return compliant

    def report(self):
        """
        check whether the current system complies with the boot security settings
        to disable wifi, bluetooth and microphone at boot time

        :return: self.compliant - boolean; True if system is compliant, False if not
        """

        self.detailedresults = ""
        self.compliant = True

        try:

            if self.type == 'mac':
                self.logdispatch.log(LogPriority.DEBUG, 'Checking for Mac plist')
                if not self.auditmac():
                    self.compliant = False
                    self.detailedresults += '\nPlist for stonixBootSecurity Launch Daemon not found.'

            elif self.type == 'systemd':
                self.logdispatch.log(LogPriority.DEBUG, 'Checking for systemd service')
                if not self.auditsystemd():
                    self.compliant = False
                    self.detailedresults += '\nService for stonixBootSecurity not active.'

            elif self.type == 'rclocal':
                self.logdispatch.log(LogPriority.DEBUG, 'Checking rc.local')
                if not self.auditrclocal():
                    self.compliant = False
                    self.detailedresults += '\nstonixBootSecurity-Linux not scheduled in rc.local.'
            else:
                self.compliant = False
                self.detailedresults += "\nThis platform is not supported by STONIX"

            if os.path.isfile(self.grub_file):
                if not self.report_boot_fips():
                    self.compliant = False

            if self.compliant:
                self.detailedresults += '\nstonixBootSecurity correctly scheduled for execution at boot.'
                self.currstate = 'configured'

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)

        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def setsystemd(self):
        """
        create a systemd service unit which will run an installed script to
        disable wifi, bluetooth and microphone at boot time

        """

        self.logdispatch.log(LogPriority.DEBUG, "Creating stonix boot security service unit")

        try:

            # create the new service unit
            f = open(self.systemd_boot_service_file, "w")
            f.write(self.stonix_boot_service_contents)
            f.close()
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": self.systemd_boot_service_file}
            self.statechglogger.recordchgevent(myid, event)
            os.chown(self.systemd_boot_service_file, 0, 0)
            os.chmod(self.systemd_boot_service_file, 0o644)

            # make the service manager aware of the new service unit
            reloadcmd = '/bin/systemctl daemon-reload'
            try:
                self.ch.executeCommand(reloadcmd)
            except Exception:
                pass

            # ensure that the new service is enabled
            self.servicehelper.enableService('stonixBootSecurity')

        except (KeyboardInterrupt, SystemExit):

            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)

    def setrclocal(self):
        """
        install and run a boot security script which will disable
        wifi, bluetooth and microphone at boot time

        """

        success = True

        try:

            if not self.rc_boot_security_editor.fix():
                self.logger.log(LogPriority.DEBUG, "KVEditor failed to fix")
                success = False
            elif not self.rc_boot_security_editor.commit():
                self.logger.log(LogPriority.DEBUG, "KVEditor failed to commit changes")
                success = False

        except:
            raise

        return success

    def setmac(self):
        """
        install a boot security plist on mac, which will run an oascript
        to disable microphone on mac at boot time

        """

        success = True

        try:

            whandle = open(self.stonix_launchd_plist, 'w')
            whandle.write(self.stonix_plist_contents)
            whandle.close()
            os.chown(self.stonix_boot_plist, 0, 0)
            os.chmod(self.stonix_launchd_plist, 0o644)

        except:
            raise

        return success

    def fix_boot_fips(self):
        """

        :return:
        """

        success = True
        fixed_fips = False
        tmpfile = self.grub_file + ".stonixtmp"

        f = open(self.grub_file, "r")
        contentlines = f.readlines()
        f.close()

        for line in contentlines:
            if re.search("^GRUB_CMDLINE_LINUX_DEFAULT=", line, re.I):
                contentlines = [c.replace(line, line.strip()[:-1] + ' fips=1"\n') for c in contentlines]
                fixed_fips = True

        if not fixed_fips:
            contentlines.append('GRUB_CMDLINE_LINUX_DEFAULT="splash quiet audit=1 fips=1"\n')
            fixed_fips = True

        tf = open(tmpfile, "w")
        tf.writelines(contentlines)
        tf.close()

        self.iditerator += 1
        myid = iterate(self.iditerator, self.rulenumber)
        event = {"eventtype": "conf",
                 "filepath": self.grub_file}
        self.statechglogger.recordchgevent(myid, event)
        self.statechglogger.recordfilechange(tmpfile, self.grub_file, myid)
        os.rename(tmpfile, self.grub_file)

        self.ch.executeCommand(self.grub_updater_cmd)

        return success

    def fix(self):
        """
        install system job which will run and disable bluetooth, microphone and wifi at boot

        """

        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0

        if self.bootci.getcurrvalue():
            if self.type == 'mac':
                self.logdispatch.log(LogPriority.DEBUG,
                                     'Creating Mac plist')
                self.setmac()
            elif self.type == 'systemd':
                self.logdispatch.log(LogPriority.DEBUG,
                                     'Creating systemd service')
                self.setsystemd()
            elif self.type == 'rclocal':
                self.logdispatch.log(LogPriority.DEBUG,
                                     'Creating rc.local entry')
                self.setrclocal()
            else:
                self.detailedresults = 'ERROR: Fix could not determine where boot job should be scheduled!'
                self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
                self.rulesuccess = False

            if os.path.isfile(self.grub_file):
                if not self.fix_boot_fips():
                    self.rulesuccess = False

            if self.rulesuccess:
                self.currstate = 'configured'
            else:
                self.currstate = 'notconfigured'
                self.detailedresults += "\nFailed to install boot security job"

        else:
            self.logdispatch.log(LogPriority.DEBUG, "Rule not enabled. Nothing was done.")
            self.currstate = 'notconfigured'

        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
