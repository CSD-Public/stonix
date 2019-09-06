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
Created on Jul 6, 2016

This class audits for passwordless ssh keys on the system.

@author: Breen Malmberg
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/06/13 Breen Malmberg - updated documentation to reST format;
        added missing documentation
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
"""



import traceback
import os
import re

from rule import Rule
from logdispatcher import LogPriority
from glob import glob
from CommandHelper import CommandHelper
from stonixutilityfunctions import getOctalPerms


class AuditSSHKeys(Rule):
    """
    This class audits for password-less ssh keys on the system

    """

    def __init__(self, config, environ, logger, statechglogger):
        """
        private method to initialize module

        :param config: configuration object instance
        :param environ: environment object instance
        :param logger: logdispatcher object instance
        :param statechglogger: statechglogger object instance
        """

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.environ = environ
        self.rulenumber = 62
        self.rulename = 'AuditSSHKeys'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['LANL CAP', 'OpenSSH Security Best Practices']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        datatype = 'bool'
        key = 'AUDITSSHKEYS'
        instructions = "To prevent this rule from modifying permissions on ssh keys, set the value of AUDITSSHKEYS to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.localize()

    def localize(self):
        """determine which OS the system is, and set
        certain variables accordingly

        """

        self.logger.log(LogPriority.DEBUG, "Running localize() ...")

        self.mac = False
        self.linux = False

        os = self.environ.getosfamily()
        if os == 'darwin':
            self.logger.log(LogPriority.DEBUG, "System OS type detected as: darwin")
            self.mac = True
        else:
            self.logger.log(LogPriority.DEBUG, "System OS type detected as: linux")
            self.linux = True

    def report(self):
        """check status of private ssh keys (whether they are encrypted with passwords or not)

        :returns: self.compliant - boolean; True if compliant, False if not compliant

        """

        searchterm = "Proc-Type:"
        self.searchdirs = []
        keylist = []
        self.keydict = {}
        self.compliant = True
        self.detailedresults = ""
        self.ch = CommandHelper(self.logger)

        try:

            self.logger.log(LogPriority.DEBUG, "Getting list of user home directories...")
            self.searchdirs = self.get_search_dirs()
            self.logger.log(LogPriority.DEBUG, "Getting list of ssh keys...")
            keylist = self.get_key_list(self.searchdirs)

            if keylist:
                self.logger.log(LogPriority.DEBUG, "Searching list of ssh keys...")
                for key in keylist:
                    self.keydict[key] = False
                    f = open(key, "r")
                    contentlines = f.readlines()
                    f.close()
                    for line in contentlines:
                        if re.search(searchterm, line):
                            self.keydict[key] = True

                for key in self.keydict:
                    if not self.keydict[key]:
                        self.compliant = False
                        self.detailedresults += "\nThe SSH key: " + str(key) + " was made without a password!"
                    if getOctalPerms(key) != 600:
                        self.compliant = False
                        self.detailedresults += "\nThe SSH key: " + str(key) + " has incorrect permissions"

                if self.compliant:
                    self.detailedresults += "\nAll SSH keys on this system are encrypted"

            else:
                self.detailedresults += "\nNo SSH keys were found on this system."

            if not self.compliant:
                self.detailedresults += "\n\nThis rule's fix only changes permissions on insecure keys. We cannot fix keys which were made without a password."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults = str(traceback.format_exc())
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        return self.compliant

    def get_key_list(self, searchdirs):
        """walk the ssh directory/ies and build and return a list of private keys (file names)

        :param searchdirs: list of directories to search for private ssh keys
        :returns: keylist - list; list of ssh key files

        """

        keylist = []

        if not searchdirs:
            self.logger.log(LogPriority.DEBUG, "Parameter searchdirs was empty! Returning empty keylist...")
            return keylist

        try:

            self.logger.log(LogPriority.DEBUG, "Building keylist...")
            for loc in searchdirs:
                files = glob(loc + "*")
                for f in files:
                    if os.path.isfile(f):
                        fh = open(f, "r")
                        contentlines = fh.readlines()
                        fh.close()
                        for line in contentlines:
                            if re.search("BEGIN\s+\w+\s+PRIVATE KEY", line):
                                keylist.append(f)
                                self.logger.log(LogPriority.DEBUG, "Adding SSH key file: " + str(f) + " to keylist...")

            self.logger.log(LogPriority.DEBUG, "Finished building keylist")

        except Exception:
            raise
        return keylist

    def get_search_dirs(self):
        """build and return a list of search directories to look for ssh keys

        :returns: searchdirs - list; directories to search for ssh keys in

        """

        searchdirs = []

        try:

            if self.mac:
                # the system is mac-based
                getuserscmd = "/usr/bin/dscl . -list /Users NFSHomeDirectory"
                self.ch.executeCommand(getuserscmd)
                retcode = self.ch.getReturnCode()
                if retcode == "0":
                    self.logger.log(LogPriority.DEBUG, "Command to get list of users' home directories ran successfully")
                    output = self.ch.getOutput()
                    self.logger.log(LogPriority.DEBUG, "Searching command output and building searchdirs list...")
                    for line in output:
                        sline = line.split()
                        if sline[1] not in ["/var/empty", "/dev/null"]:
                            if os.path.exists(sline[1] + "/.ssh/"):
                                searchdirs.append(sline[1] + "/.ssh/")
            else:
                # the system is linux-based
                # determine the start of the user id's on this system (500 or 1000)
                self.logger.log(LogPriority.DEBUG, "Setting default uidstart to 500...")
                uidstart = 500
                if os.path.exists('/etc/login.defs'):
                    self.logger.log(LogPriority.DEBUG, "login defs file exists. Getting actual uid start value...")
                    f = open('/etc/login.defs')
                    contentlines = f.readlines()
                    f.close()
                    for line in contentlines:
                        if re.search('^UID\_MIN\s+500', line, re.IGNORECASE):
                            uidstart = 500
                            self.logger.log(LogPriority.DEBUG, "Actual uid start value is 500")
                        if re.search('^UID\_MIN\s+1000', line, re.IGNORECASE):
                            uidstart = 1000
                            self.logger.log(LogPriority.DEBUG, "Actual uid start value is 1000")

                self.logger.log(LogPriority.DEBUG, "Building list of searchdirs...")
                # get list of user home directories from /etc/passwd
                f = open("/etc/passwd", "r")
                contentlines = f.readlines()
                f.close()
                for line in contentlines:
                    sline = line.split(":")
                    if len(sline) > 2:
                        if int(sline[2]) >= uidstart:
                            # build list of search directories based on home directories
                            if os.path.exists(sline[5] + "/.ssh/"):
                                searchdirs.append(sline[5] + "/.ssh/")
                                self.logger.log(LogPriority.DEBUG, "Adding directory: " + str(sline[5]) + "/.ssh/ to list of searchdirs...")

                # add the root ssh directory if it exists
                if os.path.exists("/root/.ssh/"):
                    searchdirs.append("/root/.ssh/")
                    self.logger.log(LogPriority.DEBUG, "Adding /root/.ssh/ to list of searchdirs...")

            self.logger.log(LogPriority.DEBUG, "Finished building searchdirs list")

        except Exception:
            raise
        return searchdirs

    def fix(self):
        """set permissions on all ssh keys to 0600 (384; -rw------)

        :returns: self.rulesuccess - boolean; True if fix operations succeeded, False if not

        """

        fixedkeys = []
        self.rulesuccess = True
        self.detailedresults = ""

        try:

            keylist = self.get_key_list(self.searchdirs)

            for key in keylist:
                self.logger.log(LogPriority.DEBUG, "Setting permissions on file: " + str(key) + " to 600...")
                os.chmod(key, 0o600)
                fixedkeys.append(key)

            if fixedkeys:
                self.detailedresults += "\nCorrected permissions on the following files:\n" + "\n".join(fixedkeys)
            else: self.detailedresults += "\nNo keys were modified."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = str(traceback.format_exc())
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        return self.rulesuccess
