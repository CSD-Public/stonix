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
from pkghelper import Pkghelper


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

        if os.path.exists('/bin/systemctl'):
            self.type = 'systemd'
        elif os.path.exists('/sbin/launchd'):
            self.type = 'mac'
        else:
            self.type = 'rclocal'
            self.rclocalpath = '/etc/rc.local'
            if os.path.islink(self.rclocalpath):
                paths = ['/etc/rc.d/rc.local', '/etc/init.d/rc.local']
                for rcpath in paths:
                    if os.path.isfile(rcpath):
                        self.rclocalpath = rcpath
            self.logdispatch.log(LogPriority.DEBUG, 'Using rc.local file ' + self.rclocalpath)

        datatype = 'bool'
        key = 'BOOTSECURITY'
        instructions = """To disable this rule set the value of BOOTSECURITY to False."""
        default = True
        self.bootci = self.initCi(datatype, key, instructions, default)

        datatype2 = 'bool'
        key2 = 'ENABLEFIPS'
        instructions2 = """!WARNING! DO NOT ENABLE THIS OPTION IF YOUR SYSTEM IS ARLEADY FDE ENCRYPTED! To enable full fips compliance on this system, at boot, set the value of ENABLEFIPS to True."""
        default2 = False
        self.fips_ci = self.initCi(datatype2, key2, instructions2, default2)

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
        grub_updater_locs = ["/usr/sbin/grub2-mkconfig","/sbin/grub2-mkconfig", "/usr/sbin/update-grub", "/sbin/update-grub"]
        for l in grub_updater_locs:
            if os.path.isfile(l):
                self.grub_updater_cmd = l
                break

        if self.grub_updater_cmd in ["/usr/sbin/grub2-mkconfig","/sbin/grub2-mkconfig"]:
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
            data = {"python3": self.rc_boot_script}
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

        self.logdispatch.log(LogPriority.DEBUG,  "Looking for macOS launchd job")

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

        try:

            if not self.fips_ci.getcurrvalue():
                self.logdispatch.log(LogPriority.DEBUG, "fips compliance check disabled. Skipping fips compliance check.")
                return compliant
            else:
                self.logdispatch.log(LogPriority.DEBUG, "fips compliance check enabled. Checking for fips compliance...")

            # check grub template file for fips
            if self.grub_file:
                f = open(self.grub_file, "r")
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('^GRUB_CMDLINE_LINUX_DEFAULT=', line, re.I):
                        if re.search("fips=1", line, re.I):
                            found_fips = True

            # check permanent grub config file for fips
            if self.grub_config_file:
                f = open(self.grub_config_file, "r")
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search("fips=1", line, re.I):
                        found_fips = True

            if self.is_luks_encrypted():
                if found_fips:
                    # fips=1 will break boot config if luks encrypted
                    compliant = False
                    self.detailedresults += "\nfips=1 config option found in boot config line. This will break system boot while the system is luks encrypted. Will remove this line and fips compatibility for luks will be configured instead."
                else:
                    self.detailedresults += "\nNo problems detected with boot config"
            else:
                if not found_fips:
                    compliant = False
                    self.detailedresults += "\nfips=1 config option not found in boot config line. As this system is not luks encrypted, this line will be added to the boot config."
                else:
                    self.detailedresults += "\nfips enabled in boot config"

        except:
            raise

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

            if self.compliant:
                self.detailedresults += '\nstonixBootSecurity correctly scheduled for execution at boot.'

            if not self.report_boot_fips():
                self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.compliant = False
            self.detailedresults += traceback.format_exc()
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
            except:
                pass

            # ensure that the new service is enabled
            self.servicehelper.enableService('stonixBootSecurity')

        except:
            raise

    def setrclocal(self):
        """
        install and run a boot security script which will disable
        wifi, bluetooth and microphone at boot time

        """

        success = True

        try:

            if not self.rc_boot_security_editor.fix():
                self.logdispatch.log(LogPriority.DEBUG, "KVEditor failed to fix")
                success = False
            elif not self.rc_boot_security_editor.commit():
                self.logdispatch.log(LogPriority.DEBUG, "KVEditor failed to commit changes")
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
            os.chown(self.stonix_launchd_plist, 0, 0)
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

        try:

            if not self.fips_ci.getcurrvalue():
                self.logdispatch.log(LogPriority.DEBUG, "fips compliance option disabled. Skipping fips compliance fix...")
                return success
            else:
                self.logdispatch.log(LogPriority.DEBUG, "fips compliance option enabled. Proceeding with fix compliance fix...")

            if self.environ.getosname() == "RHEL":
                self.logdispatch.log(LogPriority.DEBUG, "System detected as RHEL. Running RHEL specific fixes...")
                if not self.fix_rhel7_boot_fips():
                    success = False
                return success
            else:
                self.logdispatch.log(LogPriority.DEBUG, "System is not RHEL-based. Running generic fixes...")

                f = open(self.grub_file, "r")
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search("^GRUB_CMDLINE_LINUX_DEFAULT=", line, re.I):
                        contentlines = [c.replace(line, line.strip()[:-1] + ' fips=1"\n') for c in contentlines]
                        fixed_fips = True

                if not fixed_fips:
                    contentlines.append('GRUB_CMDLINE_LINUX_DEFAULT="splash quiet audit=1 fips=1"\n')

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

        except:
            raise

        return success

    def remove_fips_line(self):
        """
        the fips=1 configuration option at the end of the
        linuxefi boot line in grub config (for efi-based systems)
        causes rhel to revert to an emergency dracut mode instead of
        booting normally, when the system is encrypted with luks
        this method will ensure that line is removed and the grub
        configuration is updated.

        :return:
        """

        success = True

        self.logdispatch.log(LogPriority.DEBUG, "Attempting to remove fips=1 option from grub boot config...")

        tmpfile = self.grub_file + ".stonixtmp"

        f = open(self.grub_file, "r")
        contentlines = f.readlines()
        f.close()

        for line in contentlines:
            if re.search("^GRUB_CMDLINE_LINUX_DEFAULT=", line, re.I):
                self.logdispatch.log(LogPriority.DEBUG, "fips=1 found in boot config file")
                line2 = line.replace("fips=1", "")
                self.logdispatch.log(LogPriority.DEBUG, "removing fips=1 from " + str(self.grub_file))
                contentlines = [c.replace(line, line2) for c in contentlines]

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

        self.logdispatch.log(LogPriority.DEBUG, "regenerating efi boot config file...")
        self.ch.executeCommand(self.grub_updater_cmd)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            self.logdispatch.log(LogPriority.WARNING, "Failed to update efi boot config file!")

        f = open(self.grub_config_file, "r")
        contentlines = f.readlines()
        f.close()

        for line in contentlines:
            if re.search("fips=1", line, re.I):
                success = False

        if not success:
            self.logdispatch.log(LogPriority.WARNING, "fips=1 option still found in efi boot configuration!")
        else:
            self.logdispatch.log(LogPriority.DEBUG, "fips option successfully removed from efi boot configuration")

        return success

    def is_luks_encrypted(self):
        """
        check all drive devices to see if any are luks encrypted

        :return: luks_encrypted
        :rtype: bool
        """

        luks_encrypted = False

        command = "/sbin/blkid"
        devices = []

        if not os.path.isfile(command):
            self.logdispatch.log(LogPriority.WARNING, "Unable to check devices for luks encryption due to missing utility 'blkid'")
            return luks_encrypted

        self.logdispatch.log(LogPriority.DEBUG, "Checking if any devices are luks encrypted...")

        try:

            self.ch.executeCommand(command)
            output = self.ch.getOutput()
            for line in output:
                if re.search('TYPE="crypto_LUKS"', line, re.I):
                    luks_encrypted = True
                    try:
                        devices.append(str(line.split()[0]))
                    except (IndexError, KeyError):
                        continue

        except:
            raise

        for d in devices:
            if re.search(":", d):
                devices = [d.replace(":", "") for d in devices]

        if luks_encrypted:
            self.logdispatch.log(LogPriority.DEBUG, "The following devices are luks encrypted:\n" + "\n".join(devices))

        return luks_encrypted

    def configure_luks_compatibility(self):
        """
        configure rhel 7 systems, which are LUKS encrypted, to be compatible with fips
        https://access.redhat.com/solutions/137833

        :return:
        """

        prelink_pkg = "prelink"
        prelink = "/usr/sbin/prelink"
        dracut_aes_pkg = "dracut-fips-aesni"
        dracut_fips_pkg = "dracut-fips"
        prelink_conf_file = "/etc/sysconfig/prelink"
        dracut = "/usr/bin/dracut"
        grep = "/usr/bin/grep"

        mv = "/usr/bin/mv"
        prelink_installed = False
        aes_supported = False

        try:

            if self.is_luks_encrypted():
                if not self.remove_fips_line():
                    self.detailedresults += "\nFailed to remove fips=1 from efi boot configuration file. Please run: 'sudo grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg' manually!"

            # check for cpu aes compatibility
            self.ch.executeCommand(grep + " -w aes /proc/cpuinfo")
            outputstring = self.ch.getOutputString()
            if re.search("aes", outputstring, re.I):
                aes_supported = True

            # check if prelink package is installed
            if self.ph.check(prelink_pkg):
                prelink_installed = True

            # install dracut fips package
            self.ph.install(dracut_fips_pkg)

            # install dracut aes package if cpu supports it
            if aes_supported:
                self.ph.install(dracut_aes_pkg)

            # disable prelinking if installed
            if prelink_installed:
                f = open(prelink_conf_file, "w")
                f.write("PRELINKING=no")
                f.close()
                os.chmod(prelink_conf_file, 0o644)
                os.chown(prelink_conf_file, 0, 0)
                self.ch.executeCommand(prelink + " -uav")

            # backup existing initramfs
            self.ch.executeCommand(mv + " -v /boot/initramfs-$(uname -r).img{,.bak}")

            # rebuild initramfs (this command may take some time)
            self.ch.executeCommand(dracut)

        except:
            raise

    def fix_rhel7_boot_fips(self):
        """
        enable fips compliance on redhat 7 systems
        https://access.redhat.com/solutions/137833

        :return: success
        :rtype: bool
        """

        success = True
        self.ph = Pkghelper(self.logdispatch, self.environ)
        grubby = "/usr/sbin/grubby"
        findmnt = "/usr/bin/findmnt"

        try:

            # configure the system to be compatible with luks and fips
            self.configure_luks_compatibility()

            # add fips=1 to kernel boot line (requires sytem restart to take effect)
            self.ch.executeCommand(grubby + " --update-kernel=$(" + grubby + " --default-kernel) --args=fips=1")
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                success = False
                self.detailedresults += "\nFailed to enable fips compliance in kernel boot line"

            # update boot partition info
            uuid = ""
            self.ch.executeCommand(findmnt + " -no uuid /boot")
            retcode = self.ch.getReturnCode()
            if retcode == 0:
                uuid = self.ch.getOutputString()
            else:
                success = False
                self.detailedresults += "\nFailed to update boot partition info"
            if uuid:
                self.ch.executeCommand(
                    "[[ -n $uuid ]] && " + grubby + " --update-kernel=$(" + grubby + " --default-kernel) --args=boot=UUID=${uuid}")

        except:
            raise

        return success

    def fix(self):
        """
        install system job which will run and disable bluetooth, microphone and wifi at boot

        """

        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0

        try:

            if self.bootci.getcurrvalue():

                if self.type == 'mac':
                    self.logdispatch.log(LogPriority.DEBUG, 'Creating Mac plist')
                    self.setmac()

                elif self.type == 'systemd':
                    self.logdispatch.log(LogPriority.DEBUG, 'Creating systemd service')
                    self.setsystemd()

                elif self.type == 'rclocal':
                    self.logdispatch.log(LogPriority.DEBUG, 'Creating rc.local entry')
                    self.setrclocal()

                else:
                    self.detailedresults = 'ERROR: Fix could not determine where boot job should be scheduled!'
                    self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
                    self.rulesuccess = False

                if self.fips_ci.getcurrvalue():
                    if not self.fix_boot_fips():
                        self.rulesuccess = False

            else:
                self.logdispatch.log(LogPriority.DEBUG, "Rule not enabled. Nothing was done.")

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
