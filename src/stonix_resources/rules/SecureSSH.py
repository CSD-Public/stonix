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
@change: 2019/03/12 Ekkehard - make eligible for macOS Sierra 10.12+
"""

from __future__ import absolute_import

import os
import traceback
import re

from ..rule import Rule
from ..stonixutilityfunctions import iterate, checkPerms, setPerms, resetsecon
from ..stonixutilityfunctions import createFile
from ..KVEditorStonix import KVEditorStonix
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..ServiceHelper import ServiceHelper


class SecureSSH(Rule):
    """
    The SecureSSH class makes a number of configuration changes to SSH in \
    order to ensure secure use of the functionality.

    @author: Breen Malmberg
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
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
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
        self.init_objs()
        self.set_paths()

    def init_objs(self):
        """

        @return:
        """

        self.ph = Pkghelper(self.logger, self.environ)
        self.sh = ServiceHelper(self.environ, self.logger)

    def set_paths(self):
        """

        @return:
        """

        self.osname = self.environ.getosname()

        # determine ssh server and client config file locations
        # based on OS
        if self.osname == "Mac OS":
            self.server_path = '/private/etc/ssh/sshd_config'
            self.client_path = '/private/etc/ssh/ssh_config'
        else:
            self.server_path = "/etc/ssh/sshd_config"
            self.client_path = "/etc/ssh/ssh_config"

    def isinstalled(self, packagenames):
        """

        @param packagenames:
        @return:
        """

        self.installed = False

        for p in packagenames:
            if self.ph.check(p):
                self.installed = True


    def report(self):
        """
        check if ssh is installed and if the correct configuration options
        are set in the configuration files

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        @change: Breen Malmberg - 5/11/2017 - added checks for mac to ensure
                that ssh is already loaded before we report on its configuration
        """

        self.detailedresults = ""
        packages = ["ssh", "openssh", "openssh-server", "openssh-client"]
        self.compliant = True
        self.macloaded = False

        try:

            if self.osname != "Mac OS":
                self.isinstalled(packages)
                if not self.installed:
                    self.detailedresults += "\nSSH is not installed. Nothing to configure."
                    self.formatDetailedResults("report", self.compliant, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return self.compliant
            else:
                if self.sh.auditService("/System/Library/LaunchDaemons/ssh.plist", serviceTarget="com.openssh.sshd"):
                    self.macloaded = True
                if not self.macloaded:
                    self.detailedresults += "\nSSH not installed/enabled. Nothing to configure."
                    self.formatDetailedResults("report", self.compliant, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return self.compliant

            self.client_set_config = {"Host": "*",
                                      "Protocol": "2",
                                      "GSSAPIAuthentication": "yes",
                                      "GSSAPIDelegateCredentials": "yes"}
            self.server_set_config = {"Protocol": "2",
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
                                      "PermitUserEnvironment": "no"}

            # ubuntu-specific considerations
            self.client_remove_config = {"GSSAPIAuthentication": ""}
            self.server_remove_config = {"GSSAPIAuthentication": "",
                                         "KerberosAuthentication": ""}

            # set up the client config editor
            c_kvtype = "conf"
            c_tmppath = self.client_path + ".stonixtmp"
            c_intent = "present"
            c_configtype = "space"
            self.client_editor = KVEditorStonix(self.statechglogger, self.logger, c_kvtype, self.client_path, c_tmppath, self.client_set_config, c_intent, c_configtype)

            # set up the server config editor
            s_kvtype = "conf"
            s_tmppath = self.server_path + ".stonixtmp"
            s_intent = "present"
            s_configtype = "space"
            self.server_editor = KVEditorStonix(self.statechglogger, self.logger, s_kvtype, self.server_path, s_tmppath, self.server_set_config, s_intent, s_configtype)

            # set up the ubuntu-specific removal client and server editors
            if self.osname == "Ubuntu":
                rm_intent = "notpresent"
                self.client_rm_editor = KVEditorStonix(self.statechglogger, self.logger, c_kvtype, self.client_path, c_tmppath, self.client_remove_config, rm_intent, c_configtype)
                self.server_rm_editor = KVEditorStonix(self.statechglogger, self.logger, s_kvtype, self.server_path, s_tmppath, self.server_remove_config, rm_intent, s_configtype)

            # run report on each of the editors
            if not self.client_editor.report():
                self.compliant = False
                self.detailedresults += "\nThe following options are not configured correctly in ssh_config:\n" + "\n".join(self.client_editor.fixables) + "\n"
            if not self.server_editor.report():
                self.compliant = False
                self.detailedresults += "\nThe following options are not configured correctly in sshd_config:\n" + "\n".join(self.server_editor.fixables)

            if self.osname == "Ubuntu":
                if not self.client_rm_editor.report():
                    self.compliant = False
                    self.detailedresults += "\nThe following options are present but should be removed from ssh_config:\n" + "\n".join(self.client_rm_editor.removeables) + "\n"
                if not self.server_rm_editor.report():
                    self.compliant = False
                    self.detailedresults += "\nThe following options are present but should be removed from sshd_config:\n" + "\n".join(self.server_rm_editor.removeables)

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
        apply configuration options to config files

        @return: self.rulesuccess
        @rtype: bool
        @author: Breen Malmberg
        @change: Breen Malmberg - 5/11/2017 - added checks for mac to ensure
                that ssh is already loaded before we attempt to configure it;
                added logging
        """

        self.detailedresults = ""
        self.iditerator = 0
        self.rulesuccess = True

        try:

            if not self.ci.getcurrvalue():
                self.detailedresults += "\nThe rule CI was not enabled, so nothing was done."
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess

            if self.osname != "Mac OS":
                if not self.installed:
                    self.detailedresults += "\nSSH is not installed. Nothing to configure."
                    self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return self.rulesuccess
            else:
                if not self.macloaded:
                    self.detailedresults += "\nSSH is not loaded. Will not configure it."
                    self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return self.rulesuccess

            # run fix and commit actions for each editor
            if not self.client_editor.fix():
                self.rulesuccess = False
                self.detailedresults += "\nFailed to correct ssh client options"
            else:
                if not self.client_editor.commit():
                    self.rulesuccess = False
                    self.detailedresults += "\nFailed to write ssh client configuration changes to disk"
            if not self.server_editor.fix():
                self.rulesuccess = False
                self.detailedresults += "\nFailed to correct ssh server options"
            else:
                if not self.server_editor.commit():
                    self.rulesuccess = False
                    self.detailedresults += "\nFailed to write ssh server configuration changes to disk"

            # run fix and commit for ubuntu-specific removal editors
            if self.osname == "Ubuntu":
                if not self.client_rm_editor.fix():
                    self.rulesuccess = False
                    self.detailedresults += "\nFailed to remove unwanted options from ssh client config file"
                else:
                    if not self.client_rm_editor.commit():
                        self.rulesuccess = False
                        self.detailedresults += "\nFailed to write ssh client configuration changes to disk"
                if not self.server_rm_editor.fix():
                    self.rulesuccess = False
                    self.detailedresults += "\nFailed to remove unwanted options from ssh server config file"
                else:
                    if not self.server_rm_editor.commit():
                        self.rulesuccess = False
                        self.detailedresults += "\nFailed to write ssh server configuration changes to disk"

            # reload ssh to read the new configurations
            self.logger.log(LogPriority.DEBUG, "Restarting sshd service to read/load the new configuration changes")
            if self.osname == "Mac OS":
                if not self.sh.reloadService("/System/Library/LaunchDaemons/ssh.plist", serviceTarget="com.openssh.sshd"):
                    self.rulesuccess = False
                    self.detailedresults += "\nFailed to load the new ssh configuration changes"
            else:
                if not self.sh.reloadService("sshd"):
                    self.rulesuccess = False
                    self.detailedresults += "\nFailed to load the new ssh configuration changes"

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
