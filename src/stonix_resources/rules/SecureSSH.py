###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
# produced under U.S. Government contract DE-AC52-06NA25396 for Los Alamos    #
# National Laboratory (LANL), which is operated by Los Alamos National        #
# Security, LLC for the U.S. Department of Energy. The U.S. Government has    #
# rights to use, reproduce, and distribute this software.  NEITHER THE        #
# GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY, LLC MAKES ANY WARRANTY,        #
# EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.  #
# If software is modified to produce derivative works, such modified software #
# should be clearly marked, so as not to confuse it with the version          #
# available from LANL.                                                        #
#                                                                             #
# Additionally, this program is free software; you can redistribute it and/or #
# modify it under the terms of the GNU General Public License as published by #
# the Free Software Foundation; either version 2 of the License, or (at your  #
# option) any later version. Accordingly, this program is distributed in the  #
# hope that it will be useful, but WITHOUT ANY WARRANTY; without even the     #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    #
# See the GNU General Public License for more details.                        #
#                                                                             #
###############################################################################
"""
Created on Feb 19, 2013

@author: Breen Malmberg, Derek Walker
@change: 02/16/2014 Ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 Ekkehard Implemented isapplicable
@change: 04/21/2014 Ekkehard ci updates and ci fix method implementation
@change: 06/02/2014 Dave Kennel multiple bug fixes for undefined variable issues.
@change: 2015/04/17 Dave Kennel updated for new isApplicable
@change: 2015/09/23 Eric Ball Removed Banner setting to resolve InstallBanners conflict
@change: 2015/10/08 Eric Ball Help text cleanup
@change: 2015/11/09 Ekkehard - make eligible of OS X El Capitan
@change: 2017/01/04 Breen Malmberg - added more detail to the help text to make
        it more clear to the end user, what the rule actually does.
@change: 2017/07/17 Ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/10/23 Roy Nielsen - change to new service helper interface
@change: 2017/11/13 Ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 Ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/06/11 dwalker - updated rule to properly record events, created sub
    methods for linux and mac.
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
"""



import os
import traceback
import re

from rule import Rule
from stonixutilityfunctions import iterate, checkPerms, setPerms, resetsecon
from stonixutilityfunctions import createFile
from KVEditorStonix import KVEditorStonix
from logdispatcher import LogPriority
from pkghelper import Pkghelper
from ServiceHelper import ServiceHelper


class SecureSSH(Rule):
    """
    The SecureSSH class makes a number of configuration changes to SSH in \
    order to ensure secure use of the functionality.

    """

    def __init__(self, config, environ, logger, statechglogger):
        """
        Constructor
        """
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 8
        self.rulename = 'SecureSSH'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.environ = environ
        self.sethelptext()
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        datatype = 'bool'
        key = 'SECURESSH'
        instructions = "To disable this rule set the value " + \
                       "of SECURESSH to False"
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.guidance = ['CIS, NSA(3.5.2.1)', 'CCE 4325-7', 'CCE 4726-6',
                         'CCE 4475-0', 'CCE 4370-3', 'CCE 4387-7',
                         'CCE 3660-8', 'CCE 4431-3', 'CCE 14716-5',
                         'CCE 14491-5']
        self.ed1, self.ed2 = "", ""

        self.osname = self.environ.getosname()
        if self.osname == "Mac OS":
            mpa_datatype = "bool"
            mpa_key = "ENABLEMACPIVAUTHSSH"
            mpa_instructions = "To enable piv authentication over ssh, on Mac OS, set the value of ENABLEMACPIVAUTHSSH to True"
            mpa_default = False
            self.mac_piv_auth_CI = self.initCi(mpa_datatype, mpa_key, mpa_instructions, mpa_default)

    def report(self):
        """
        check if ssh is installed and if the correct configuration options
        are set in the configuration files

        :return: self.compliant
        :rtype: bool

        """
        try:
            self.detailedresults = ""
            self.installed = False
            packages = ["ssh", "openssh", "openssh-server", "openssh-client"]
            self.ph = Pkghelper(self.logger, self.environ)
            self.compliant = True
            self.sh = ServiceHelper(self.environ, self.logger)
            self.macloaded = False
            compliant = True
            self.client = {"Host": "*",
                           "Protocol": "2",
                           "GSSAPIAuthentication": "yes",
                           "GSSAPIDelegateCredentials": "yes"}
            self.server = {"Protocol": "2",
                           "SyslogFacility": "AUTHPRIV",
                           "PermitRootLogin": "no",
                           "MaxAuthTries": "5",
                           "RhostsRSAAuthentication": "no",
                           "HostbasedAuthentication": "no",
                           "IgnoreRhosts": "yes",
                           "PermitEmptyPasswords": "no",
                           "PasswordAuthentication": "yes",
                           "ChallengeResponseAuthentication": "no",
                           "KerberosAuthentication": "yes",
                           "GSSAPIAuthentication": "yes",
                           "GSSAPICleanupCredentials": "yes",
                           "UsePAM": "yes",
                           "Ciphers": "aes128-ctr,aes192-ctr,aes256-ctr",
                           "PermitUserEnvironment": "no",
                           "PrintLastLog": "yes",
                           "MACs": "hmac-sha2-256,hmac-sha2-512"}

            if self.environ.getostype() == "Mac OS X":
                self.serverfile = '/private/etc/ssh/sshd_config'
                self.clientfile = '/private/etc/ssh/ssh_config'
            else:
                self.serverfile = "/etc/ssh/sshd_config"  # server file
                self.clientfile = "/etc/ssh/ssh_config"  # client file

            # Portion for non mac systems i.e. linux
            if self.environ.getostype() != "Mac OS X":
                for package in packages:
                    if self.ph.check(package):
                        self.installed = True
                        break
                # If ssh is not installed there is no need to configure, return True
                if not self.installed:
                    self.formatDetailedResults("report", self.compliant, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return self.compliant
            # Portion for Mac systems
            else:
                # ssh is installed/enabled
                if self.sh.auditService("/System/Library/LaunchDaemons/ssh.plist", serviceTarget="com.openssh.sshd"):
                    self.macloaded = True

                # if ssh not installed/enabled, no need to configure, return True
                if not self.macloaded:
                    self.detailedresults += "SSH not installed/enabled. Nothing to configure.\n"
                    self.formatDetailedResults("report", self.compliant, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return self.compliant
                # if not self.reportMac():
                #     compliant = False

            # Portion for both mac and linux reporting
            if not self.reportSSHFile(self.serverfile, self.server):
                compliant = False
            if not self.reportSSHFile(self.clientfile, self.client):
                compliant = False
            self.compliant = compliant

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        """
        Main fix method divided up into mac and linux sub methods for
        correcting ssh server and client files as well as configuring
        Mac OS smart card authentication.

        :return: self.rulesuccess
        :rtype: bool

        """
        try:
            self.detailedresults = ""
            self.iditerator = 0
            success = True
            debug = ""
            if not self.ci.getcurrvalue():
                self.detailedresults += "The rule CI was not enabled, so nothing was done.\n"
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                self.rulesuccess = success
                return self.rulesuccess

            # Clear events from any previous fix run
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            # Portion for both linux and Mac
            if not self.fixSSHFile(self.serverfile, self.server):
                success = False
            if not self.fixSSHFile(self.clientfile, self.client):
                success = False
            # Mac only portion
            if self.osname == "Mac OS":
                # runs the fix for the smartcard authentication for mac
                if not self.fixMac():
                    success = False
            self.rulesuccess = success

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def reportSSHFile(self, sshfile, directives):
        """
        Report configuration options of config files
        :param: sshfile - filepath string
        :param: directives - dictionary of desired directives
        :return: compliant
        :rtype: bool

        """
        compliant = True
        debug = ""
        directives = dict(directives)
        tpath = sshfile + ".tmp"

        if os.path.exists(sshfile):
            if re.search("Ubuntu", self.environ.getostype()):
                if sshfile == "/etc/ssh/sshd_config":
                    del (directives["GSSAPIAuthentication"])
                    del (directives["KerberosAuthentication"])
                elif sshfile == "/etc/ssh/ssh_config":
                    del (directives["GSSAPIAuthentication"])
            elif self.environ.getostype() == "Mac OS X" and self.mac_piv_auth_CI.getcurrvalue():
                if sshfile == "/private/etc/ssh/sshd_config":
                    directives["PasswordAuthentication"] = "no"
                    self.server = directives
            editor = KVEditorStonix(self.statechglogger,
                                      self.logger, "conf",
                                      sshfile, tpath,
                                      directives, "present",
                                      "space")
            if not editor.report():
                self.detailedresults += "Did not find the correct " + \
                                        "contents in sshd_config\n"
                compliant = False

            # for ubuntu systems we want to make sure the following two
            # directives don't exist in the server file
            if re.search("Ubuntu", self.environ.getostype()):
                if sshfile == "/etc/ssh/sshd_config":
                    directives = {"GSSAPIAuthentication": "",
                               "KerberosAuthentication": ""}
                elif sshfile == "/etc/ssh/ssh_config":
                    directives = {"GSSAPIAuthentication": ""}
                editor.setIntent("notpresent")
                editor.setData(directives)
                if not editor.report():
                    self.detailedresults += "didn't find the correct" + \
                            " contents in sshd_config\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    compliant = False
            if not checkPerms(sshfile, [0, 0, 0o644],
                              self.logger):
                self.detailedresults += "Incorrect permissions for " + \
                                        "file " + self.serverfile + "\n"
                compliant = False
        else:
            self.detailedresults += sshfile + " does not exist\n"
            compliant = False
        return compliant

    def fixSSHFile(self, sshfile, directives):
        """
        apply configuration options to config files
        :param: sshfile - filepath string
        :param: directives - dictionary of desired directives
        :return: compliant
        :rtype: bool

        """
        success = True
        debug = ""
        directives = dict(directives)
        tpath = sshfile + ".tmp"
        created = False
        if not os.path.exists(sshfile):
            createFile(sshfile, self.logger)
            created = True
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": sshfile}
            self.statechglogger.recordchgevent(myid, event)
        if os.path.exists(sshfile):
            if re.search("Ubuntu", self.environ.getostype()):
                if sshfile == "/etc/ssh/sshd_config":
                    del (directives["GSSAPIAuthentication"])
                    del (directives["KerberosAuthentication"])
                elif sshfile == "/etc/ssh/ssh_config":
                    del (directives["GSSAPIAuthentication"])
            elif self.environ.getostype() == "Mac OS X" and self.mac_piv_auth_CI.getcurrvalue():
                if sshfile == "/private/etc/ssh/sshd_config":
                    directives["ChallengeResponseAuthentication"] = "no"
                    directives["PasswordAuthentication"] = "no"
            editor = KVEditorStonix(self.statechglogger,
                                      self.logger, "conf", sshfile,
                                      tpath, directives, "present",
                                      "space")
            editor.report()
            if re.search("Ubuntu", self.environ.getostype()):
                if sshfile == "/etc/ssh/sshd_config":
                    directives = {"GSSAPIAuthentication": "",
                                  "KerberosAuthentication": ""}
                elif sshfile == "/etc/ssh/ssh_config":
                    directives = {"GSSAPIAuthentication": ""}
                editor.setIntent("notpresent")
                editor.setData(directives)
                editor.report()
            if not checkPerms(sshfile, [0, 0, 0o644], self.logger):
                if not created:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(sshfile, [0, 0, 0o644], self.logger,
                                    self.statechglogger, myid):
                        success = False
                else:
                    if not setPerms(sshfile, [0, 0, 0o644], self.logger):
                        success = False
            if editor.fixables or editor.removeables:
                if not created:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    editor.setEventID(myid)
                if editor.fix():
                    if editor.commit():
                        os.chown(sshfile, 0, 0)
                        os.chmod(sshfile, 0o644)
                        resetsecon(sshfile)
                    else:
                        self.detailedresults += "Unable to correct contents " + \
                            "in " + sshfile + "\n"
                        debug = "kveditor1 commit did not run successfully"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                else:
                    self.detailedresults += "Unable to correct contents " + \
                                            "in " + sshfile + "\n"
                    debug = "kveditor1 fix did not run successfully"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
        return success

    def fixMac(self):
        """

        :return: success
        :rtype: bool
        """

        success = True

        # reload ssh to read the new configurations
        self.logger.log(LogPriority.DEBUG, "Restarting sshd service to read/load the new configuration changes")
        if self.osname == "Mac OS":
            if not self.sh.reloadService("/System/Library/LaunchDaemons/ssh.plist",
                                         serviceTarget="com.openssh.sshd"):
                success = False
                self.detailedresults += "Failed to load the new ssh configuration changes\n"
        else:
            if not self.sh.reloadService("sshd"):
                success = False
                self.detailedresults += "Failed to load the new ssh configuration changes\n"

        return success
