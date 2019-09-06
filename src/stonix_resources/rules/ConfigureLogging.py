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
Created on May 20, 2013

@author: Derek Walker
@change: 02/12/2014 ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel updated to use new CI class
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2016/01/22 eball Changed daemon log level from daemon.info to daemon.*
@change: 2016/05/31 ekkehard Added OpenDirectory Logging
@change: 2016/06/22 eball Improved report feedback for reportMac
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/10/23 rsn - change to new service helper interface
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
"""

from stonixutilityfunctions import iterate, resetsecon, createFile, getUserGroupName
from stonixutilityfunctions import readFile, writeFile, checkPerms, setPerms, checkUserGroupName
from ruleKVEditor import RuleKVEditor
from pkghelper import Pkghelper
from logdispatcher import LogPriority
from ServiceHelper import ServiceHelper
from CommandHelper import CommandHelper
from localize import WINLOG, LANLLOGROTATE
from subprocess import PIPE, Popen
import os
import traceback
import re
import grp
import stat


class ConfigureLogging(RuleKVEditor):
    """

    """

    def __init__(self, config, environ, logger, statechglogger):
        """

        :param config:
        :param environ:
        :param logger:
        :param statechglogger:
        """

        RuleKVEditor.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 16
        self.rulename = "ConfigureLogging"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.guidance = ["2.6.1.1", "2.6.1.2", "2.6.1.3"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'freebsd'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

        datatype = 'bool'
        key = 'CONFIGURELOGGING'
        instructions = "To disable this rule set the value of CONFIGURELOGGING to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.rootrequired = True
        self.service = ""
        self.logd = ""
        self.daemon = ""
        self.sh = ServiceHelper(self.environ, self.logger)
        self.ch = CommandHelper(self.logger)
        self.logs = {"rsyslog": False,
                     "syslog": False}
        self.created1, self.created2 = True, True
        self.bootlog = "/var/log/boot.log"
        self.ostype = self.environ.getostype()
        self.osfamily = self.environ.getosfamily()
        self.osver = self.environ.getosver()
        if self.ostype == "Mac OS X":
            self.addKVEditor("OpenDirectoryLogging",
                             "defaults",
                             "/Library/Preferences/OpenDirectory/opendirectoryd",
                             "",
                             {"Debug Logging Level": ["5", "5"]},
                             "present",
                             "",
                             'Set OpenDirectory "Debug Logging Level" Level to 5 ' + \
                             "This show user creation and deletion events " + \
                             "in '/private/var/log/opendirectoryd.log'.",
                             None,
                             False,
                             {})

    def report(self):
        """ConfigureLogging.report() Public method to report on the
        configuration status of the logging daemons and associated files.
        Configures logging and log rotation
        @author: Derek Walker

        :param self: essential if you override this definition
        :returns: bool - True if system is compliant, False if it isn't

        """

        self.compliant = True
        self.detailedresults = ""
        self.wronglogrot = []
        self.missinglogrot = []
        self.config = []

        try:

            if self.osfamily == "linux":
                self.ph = Pkghelper(self.logger, self.environ)
                self.compliant = self.reportSysRSyslog()

#!FIXME self.path does not appear to be set to anything, anywhere
# "Unresolved attribute reference 'path' for class ConfigureLogging"
            elif self.osfamily == "freebsd":
                if self.path:
                    self.compliant = self.reportFreebsd(self.path[0], self.path[1])
                else:
                    self.detailedresults = "no log daemons exist\n"

            elif self.ostype == "Mac OS X":
                self.compliant = self.reportMac()

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def fix(self):
        """ConfigureLogging.fix() Public method to fix any issues that were
        found in the report method.
        @author: Derek Walker

        :param self: essential if you override this definition
        :returns: bool - False if the method died during execution

        """

        self.rulesuccess = True
        self.iditerator = 0
        self.detailedresults = ""

        try:

            if not self.ci.getcurrvalue():
                return self.rulesuccess

            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.osfamily == "linux":
                if not self.fixSysRsyslog():
                    self.rulesuccess = False

            elif self.osfamily == "freebsd":
# !FIXME self.path does not appear to be set to anything, anywhere
# "Unresolved attribute reference 'path' for class ConfigureLogging"
                if not self.path:
                    self.detailedresults += "report previously found no log daemon, will not attempt to install one, unable to proceed with fix\n"
                    self.formatDetailedResults("fix", False, self.detailedresults)
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    self.rulesuccess = False

                elif not self.fixFreebsd(self.path[0], self.path[1]):
                    self.rulesuccess = False

            elif self.ostype == "Mac OS X":
                if not self.fixMac():
                    self.rulesuccess = False

            else:
                self.logger.log(LogPriority.DEBUG, "Unrecognized system architecture: " + str(self.osfamily) + " " + str(self.ostype))
                self.rulesuccess = False

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess

    def reportSysRSyslog(self):
        """ConfigureLogging.reporSysRsyslog reports on the logging facilities,
        the log files, and the logging daemons of syslog and rsyslog
        @author: Derek Walker


        :returns: bool - True or False upon success
        @change: bgonz12 - 2018/1/18 - reduced the debug output for an
                 exception handled Traceback.

        """

        debug = ""
        compliant = True
        self.fixables = []
        fixables = []
        specs = ["rotate 4",
                 "weekly",
                 "missingok",
                 "notifempty",
                 "compress",
                 "delaycompress",
                 "sharedscripts",
                 "postrotate",
                 "/bin/kill -HUP `/bin/cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true",
                 "/bin/kill -HUP `/bin/cat /var/run/syslog.pid 2> /dev/null` 2> /dev/null || true",
                 "/bin/kill -HUP `/bin/cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null || true",
                 "endscript"]
        self.logfiles = ["mark.* /var/log/messages",
                         "mark.* /var/log/auth",
                         "*.* /var/log/messages",
                         "daemon.* /var/log/daemon",
                         "auth.* /var/log/auth",
                         "authpriv.* /var/log/auth",
                         "user.* /var/log/user",
                         "kern.* /var/log/kern",
                         "lpr.* /var/log/lpr",
                         "syslog.* /var/log/syslog",
                         "cron.* /var/log/cron",
                         "mail.* /var/log/maillog",
                         "uucp.* /var/log/maillog",
                         "news.* /var/log/maillog",
                         "local0.* /var/log/local",
                         "local1.* /var/log/local",
                         "local2.* /var/log/local",
                         "local4.* /var/log/local",
                         "local5.* /var/log/local",
                         "local6.* /var/log/local",
                         "local7.* /var/log/local", 
                         "local7.* /var/log/boot.log",
                         "ftp.* /var/log/ftp"]
        self.directories = ["/var/log/daemon",
                            "/var/log/auth",
                            "/var/log/user",
                            "/var/log/kern",
                            "/var/log/lpr",
                            "/var/log/syslog",
                            "/var/log/cron",
                            "/var/log/maillog",
                            "/var/log/local",
                            "/var/log/ftp",
                            "/var/log/messages"]
        if WINLOG is not None and isinstance(WINLOG, str):
            self.logfiles.append("mark.* " + WINLOG)
            self.logfiles.append("authpriv.* " + WINLOG)
            self.logfiles.append("auth.* " + WINLOG)
        # opensuse 13 and later uses systemd-logger instead of rsyslog
        # this logging daemon doesn't have the functionality we need so
        # we remove it firsthand and install rsyslog in the fix.
        if re.search("opensuse", self.ostype, re.I):
            if self.ph.check("systemd-logger"):
                compliant = False
        # check if rsyslog is installed and turned on
        if self.ph.check("rsyslog"):
            self.logs["rsyslog"] = True
            if not self.checkSysRsyslogOn():
                self.detailedresults += "Rsyslog is installed but not on\n"
                compliant = False

        # check if syslog is installed and turned on if rsyslog not installed
        elif self.ph.check("syslog"):
            self.logs["syslog"] = True
            specs.remove("/bin/kill -HUP `/bin/cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null || true',")
            if not self.checkSysRsyslogOn():
                self.detailedresults += "Syslog is installed but not on\n"
                compliant = False

        # there is no logging daemon installed
        else:
            compliant = False
            self.detailedresults += "There is no logging daemon installed\n"

        # check if all necessary dirs are present and correct perms
        for item in self.directories:
            if not os.path.exists(item):
                self.detailedresults += item + " doesn't exist\n"
                compliant = False
            else:
                if self.ph.manager == "apt-get":
                    if re.search("debian", self.ostype, re.I):
                        distroowner = "root"
                    elif re.search("ubuntu", self.ostype, re.I):
                        distroowner = "syslog"
                    statdata = os.stat(item)
                    mode = stat.S_IMODE(statdata.st_mode)
                    ownergrp = getUserGroupName(item)
                    owner = ownergrp[0]
                    group = ownergrp[1]
                    if mode != 384:
                        compliant = False
                        self.detailedresults += "permissions on " + item + "aren't 600\n"
                        debug = "permissions on " + item + " aren't 600\n"
                        self.logger.log(LogPriority.DEBUG, debug)
#!FIXME distroowner can be referenced before being assigned, here
                    if owner != distroowner:
                        compliant = False
                        self.detailedresults += "Owner of " + item + \
                            " isn't syslog\n"
                        debug = "Owner of " + item + \
                            " isn't syslog\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                    if group != "adm":
                        compliant = False
                        self.detailedresults += "Group of " + item + \
                            " isn't adm\n"
                        debug = "Group of " + item + \
                            " isn't adm\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                elif not checkPerms(item, [0, 0, 384], self.logger):
                    self.detailedresults += "Permissions are not correct on all required logging files"
                    compliant = False
                    break
        if not os.path.exists(self.bootlog):
            self.detailedresults += self.bootlog + " doesn't exist\n"
            compliant = False
        elif not checkPerms(self.bootlog, [0, 0, 420], self.logger):
            self.detailedresults += "Permissions are not correct on bootlog file\n"
            compliant = False
        if self.logs["rsyslog"]:
            if self.ph.manager == "apt-get":
                self.logpath = "/etc/rsyslog.d/50-default.conf"
            else:
                self.logpath = "/etc/rsyslog.conf"
        elif self.logs["syslog"]:
            self.logpath = "/etc/syslog.conf"
        else:
            self.logpath = "/etc/rsyslog.conf"
        self.logfilescopy = []
        # check if correct contents of rsyslog.conf file
        if os.path.exists(self.logpath):
            if not checkPerms(self.logpath, [0, 0, 420], self.logger):
                self.detailedresults += "permissions aren't correct on log daemon config file: " + self.logpath
                compliant = False
            contents = readFile(self.logpath, self.logger)
            for key in self.logfiles:
                keytemp = key.split()
                for line in contents:
                    if re.search("^#", line.strip()) or re.match("^\s*$", line.strip()):
                        continue
                    line = line.strip()
                    line = re.sub("(\s)+", " ", line)
                    temp = line.split()
                    try:
                        if re.search(re.escape(keytemp[0]), temp[0].strip()):
                            if re.search(keytemp[1], temp[1]):
                                if key not in self.logfilescopy:
                                    self.logfilescopy.append(key)
                                break
                    except IndexError:
                        debug = "Index out of range from line: " + line + "\n"
                        continue
            if self.logfilescopy:
                for item in self.logfilescopy:
                    self.logfiles.remove(item)
            if self.logfiles:
                compliant = False
                for item in self.logfiles:
                    self.detailedresults += item + " not found in " + self.logpath + "\n"
        else:
            self.detailedresults += self.logpath + "doesn't exist\n"
            compliant = False
        self.logger.log(LogPriority.DEBUG, debug)

        # check if correct contents of logrotate file exist
        self.logrotpath = self.checkLogRotation()
        if self.logrotpath:
            if os.path.exists(self.logrotpath):
                if re.search("Red Hat", self.ostype, re.I) and \
                        re.search("^6", self.osver):
                    statdata = os.stat(self.logrotpath)
                    mode = stat.S_IMODE(statdata.st_mode)
                    ownergrp = getUserGroupName(self.logrotpath)
                    owner = ownergrp[0]
                    group = ownergrp[1]
                    if mode != 420:
                        debug = "permissions on " + self.logrotpath + " aren't 644\n"
                        self.detailedresults += debug
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False

                    if owner != "root":
                        debug = "Owner of " + self.logrotpath + " isn't root\n"
                        self.detailedresults += debug
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False

                    if group != "sys":
                        debug = "Group owner of " + self.logrotpath + " isn't sys\n"
                        self.detailedresults += debug
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False

                elif not checkPerms(self.logrotpath, [0, 0, 420], self.logger):
                    self.detailedresults += "permissions aren't correct on log rotation config file: " + self.logrotpath
                    compliant = False
                
                contents = readFile(self.logrotpath, self.logger)
                for directory in self.directories:
                    found = False
                    i = 0
                    for line in contents:
                        if re.search("^#", line.strip()) or re.match("^\s*$",
                                                                 line.strip()):
                            i += 1
                            continue
                        if re.search("\s+", line):
                            line = re.sub("\s", " ", line)
                            # found the directory to rotate we're looking for
                            if re.search("^" + directory + " ", line) or \
                                re.search(" " + directory + " ", line) or \
                                re.search(" " + directory + " {", line) or \
                                re.search(" " + directory + "{", line) or \
                                re.search("^" + directory + "{", line) :
                                found = True
                                # contents2 list will contain current line containing directory and rest of file
                                contents2 = contents[i:]
                                j = 0
                                # finished variable to be an indicator while going
                                # through contents2 so that we don't continue to
                                # traverse contents2 even after finding the specs
                                # for the directory once
                                finished = False
                                # traverse through contents 2 and look for
                                # opening bracket that shall contain the log
                                # rotation specifications
                                for line2 in contents2:
                                    if re.search("^#", line2.strip()) or re.match("^\s*$",
                                                                 line2.strip()):
                                        j += 1
                                        continue
                                    # found the first opening bracket in contents2 list
                                    if finished:
                                        break
                                    if re.search("{$", line2.strip()):
                                        finished = True
                                        j += 1
                                        # contents3 list will contain next line
                                        # after line with bracket and then rest
                                        # of file
                                        contents3 = contents2[j:]
                                        k = 0
                                        # traverse through contents3 list until
                                        # reaching } which will indicate the end
                                        # of log rotation specifications for
                                        # current directory
                                        try:
                                            specstemp = ["rotate 4",
                                                         "weekly",
                                                         "missingok",
                                                         "notifempty",
                                                         "compress",
                                                         "delaycompress",
                                                         "sharedscripts",
                                                         "postrotate",
                                                         "/bin/kill -HUP `/bin/cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true",
                                                         "/bin/kill -HUP `/bin/cat /var/run/syslog.pid 2> /dev/null` 2> /dev/null || true",
                                                         "/bin/kill -HUP `/bin/cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null || true",
                                                         "endscript"]
                                            unwantedspecs = False
                                            while not re.search("^}$", contents3[k].strip()):
                                                if re.search("^#", contents3[k].strip()) or re.match("^\s*$",
                                                                     contents3[k].strip()):
                                                    k += 1
                                                    continue
                                                if re.search("}$", contents3[k].strip()):
                                                    line = re.sub("}", "", contents3[k].strip())
                                                    if re.search("^\s*$", line):
                                                        break
                                                    if line in specstemp:
                                                        specstemp.remove(line)
                                                    elif line not in specstemp:
                                                        unwantedspecs = True
                                                    break
                                                # we found a spec that we want in
                                                # between the braces.  Remove from
                                                # specs list as found
                                                if contents3[k].strip() in specstemp:
                                                    specstemp.remove(contents3[k].strip())
                                                    # we found a spec that we don't
                                                    # want in between the braces.  Set
                                                    # variable unwantedspecs True
                                                elif contents3[k].strip() not in specstemp:
                                                    unwantedspecs = True
                                                    break
                                                k += 1
                                        except IndexError:
                                            self.detailedresults += self.logrotpath + " is in bad format\n"
                                            unwantedspecs = True
                                        # If there were any specs left in list
                                        # then we didn't find all the specs inside
                                        # braces we desired or if unwantedspecs
                                        # variable is True then we found specs
                                        # inside braces that were undesired so
                                        # break out of for loop
#!FIXME specstemp can be referenced before being assigned, here
                                        if specstemp or unwantedspecs:
                                            break
                                    else:
                                        j += 1
#!FIXME unwantedspecs can be referenced before being assigned, here
                                if specstemp or unwantedspecs:
                                    self.detailedresults += directory + " has incorrect log rotation specifications\n"
                                    fixables.append(directory)
                                    break
                            else:
                                i += 1
                        else:
                            i += 1
                    if not found:
                        self.detailedresults += directory + " was not found in logrotate file\n"
                        fixables.append(directory)
        if fixables:
            self.fixables = fixables
            compliant = False
        return compliant

    def fixSysRsyslog(self):
        """corrects the syslog/rsyslog files and also logrotation files.
        Some failed actions may result in a change of the success variable's
        value which is ultimately returned at the end of the method and some
        failed actions may result in an immediate False return due to
        inability to continue with the rest of the fix.  Appropriate logging
        will occur
        @author: Derek Walker


        :returns: bool - True or False upon success

        """

        self.detailedresults = ""
        success = True
        specs = ["rotate 4",
                 "weekly",
                 "missingok",
                 "notifempty",
                 "compress",
                 "delaycompress",
                 "sharedscripts",
                 "postrotate",
                 "/bin/kill -HUP `/bin/cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true",
                 "/bin/kill -HUP `/bin/cat /var/run/syslog.pid 2> /dev/null` 2> /dev/null || true",
                 "/bin/kill -HUP `/bin/cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null || true",
                 "endscript"]

        # this should actually remove systemd-logger and automatically install
        # rsyslog (for opensuse systems only)
        if re.search("opensuse", self.ostype, re.I):
            if self.ph.check("systemd-logger"):
                if not self.ph.remove("systemd-logger"):
                    debug = "Couldn't remove systemd-logger\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                else:
                    self.logs["rsyslog"] = True
                    self.logrotpath = self.checkLogRotation()
                    self.logd = "rsyslog"
        # check if rsyslog package is installed
        if not self.ph.check("rsyslog"):
            if self.ph.checkAvailable("rsyslog"):
                if not self.ph.install("rsyslog"):
                    debug = "Couldn\'t install rsyslog package\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                else:
                    for directory in self.directories:
                        self.fixables.append(directory)
                    self.logs["rsyslog"] = True
                    self.logrotpath = self.checkLogRotation()
                    self.logd = "rsyslog"
            elif not self.ph.check("syslog"):
                if self.ph.checkAvailable("syslog"):
                    if not self.ph.install("syslog"):
                        debug = "Couldn\'t install syslog package\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                    else:
                        self.logs["syslog"] = True
                        self.logrotpath = self.checkLogRotation()
                        self.logd = "syslog"
                        specs.remove("/bin/kill -HUP `/bin/cat " + \
                        "/var/run/rsyslogd.pid 2> /dev/null` 2> " + \
                        "/dev/null || true")
                else:
                    debug = "There is no logging daemon available\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False

        # check if all necessary dirs are present and correct perms
        if re.search("debian", self.ostype, re.I):
            distroowner = "root"
        elif re.search("ubuntu", self.ostype, re.I):
            distroowner = "syslog"
        for item in self.directories:
            if os.path.exists(item):
                if self.ph.manager == "apt-get":
                    statdata = os.stat(item)
                    mode = stat.S_IMODE(statdata.st_mode)
                    ownergrp = getUserGroupName(item)
#!FIXME distroowner can be referenced before being assigned, here
                    retval = checkUserGroupName(ownergrp, distroowner, "adm",
                                                mode, 384, self.logger)
                    if isinstance(retval, list):
                        origuid = statdata.st_uid
                        origgid = statdata.st_gid
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "perm",
                                 "startstate": [origuid, origgid, mode],
                                 "endstated": [retval[0], retval[1], 384],
                                 "filepath": item}
                        self.statechglogger.recordchgevent(myid, event)
                        os.chown(item, retval[0], retval[1])
                        os.chmod(item, 384)
                    elif not retval:
                        self.detailedresults += "There was a problem getting permissions on " + \
                            item + "\n"
                        success = False
                elif not checkPerms(item, [0, 0, 384], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(item, [0, 0, 384], self.logger,
                                    self.statechglogger, myid):
                        debug = "Unable to set " + "permissions on " + item + "\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
            else:
                if not createFile(item, self.logger):
                    debug = "Unable to create necessary log file: " + item + \
                        "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                else:
                    self.detailedresults += "Successfully created file: " + \
                        item + "\n"
                    if self.ph.manager == "apt-get":
                        statdata = os.stat(item)
                        mode = stat.S_IMODE(statdata.st_mode)
                        ownergrp = getUserGroupName(item)
                        retval = checkUserGroupName(ownergrp, distroowner,
                                                    "adm", mode, 384, self.logger)
                        if isinstance(retval, list):
                            os.chown(item, retval[0], retval[1])
                            os.chmod(item, 384)
                    else:
                        os.chown(item, 0, 0)
                        os.chmod(item, 384)
                    resetsecon(item)
        if os.path.exists(self.bootlog):
            if not checkPerms(self.bootlog, [0, 0, 420], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.bootlog, [0, 0, 420], self.logger,
                                self.statechglogger, myid):
                    debug = "Unable to set " + "permissions on " + self.bootlog + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
        elif not createFile(self.bootlog, self.logger):
            debug = "Unable to create necessary log file: " + self.bootlog + "\n"
            self.logger.log(LogPriority.DEBUG, debug)
            success = False
        else:
            self.detailedresults += "Successfully created file: " + \
                self.bootlog + "\n"
            os.chown(self.bootlog, 0, 0)
            os.chmod(self.bootlog, 420)
            resetsecon(self.bootlog)

        # correct rsyslog/syslog file
        if not os.path.exists(self.logpath):
            if not createFile(self.logpath, self.logger):
                debug = "Unable to create missing log daemon config " + \
                        "file: " + self.logpath + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                success = False
            else:
                self.created1 = True
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": self.logpath}
                self.statechglogger.recordchgevent(myid, event)
                debug = "successfully create log daemon config file: " + \
                    self.logpath + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                if not checkPerms(self.logpath, [0, 0, 420], self.logger):
                    if not setPerms(self.logpath, [0, 0, 420], self.logger):
                        debug = "Unable to set " + \
                            "permissions on " + self.logpath + "\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                    resetsecon(self.logpath)
        if os.path.exists(self.logpath):
            if self.logfiles:
                contents = readFile(self.logpath, self.logger)
                tempstring = ""
                tmpfile = self.logpath + '.stonixtmp'
                for line in contents:
                    tempstring += line
                for item in self.logfiles:
                    tempstring += item + "\n"
                if not writeFile(tmpfile, tempstring, self.logger):
                    debug = "Unable to write to file " + tmpfile + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                else:
                    if not self.created1:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "conf",
                                 "filepath": self.logpath}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(self.logpath,
                                                             tmpfile, myid)
                    os.rename(tmpfile, self.logpath)
                    os.chown(self.logpath, 0 ,0)
                    os.chmod(self.logpath, 420)
                    resetsecon(self.logpath)

        # correct log rotate file
        #if logrotation file doesn't exist, create it, record createfile event
        if not os.path.exists(self.logrotpath):
            if not createFile(self.logrotpath, self.logger):
                debug = "Unable to create missing log rotation config " + \
                    "file: " + self.logrotpath + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
            else:
                self.created2 = True
                self.detailedresults += "successfully created log \
rotation config file: " + self.logrotpath + "\n"
                event = {"eventtype": "creation",
                         "filepath": self.logrotpath}
#!FIXME myid can be referenced before beign assigned, here
                self.statechglogger.recordchgevent(myid, event)
        #if system is redhat 6 we need to make sure the group owner is sys
        if re.search("^Red Hat*", self.ostype.strip()) and \
                re.search("^6*", self.osver):
            gid = grp.getgrnam("sys")[2]
            statdata = os.stat(self.logrotpath)
            mode = stat.S_IMODE(statdata.st_mode)
            ownergrp = getUserGroupName(self.logrotpath)
            owner = ownergrp[0]
            group = ownergrp[1]
            if mode != 420 or owner != "root" or group != "sys":
                origuid = statdata.st_uid
                origgid = statdata.st_gid
                if grp.getgrnam("sys")[2]:
                    if not self.created2:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "perm",
                                 "startstate": [origuid, origgid, mode],
                                 "endstate": [0, gid, 420],
                                 "filepath": self.logrotpath}
                        self.statechglogger.recordchgevent(myid, event)
                    os.chmod(self.logrotpath, 420)
                    os.chown(self.logrotpath, 0, gid)
                    resetsecon(self.logrotpath)
                else:
                    success = False
                    debug = "Unable to determine the id number of sys group.  Will not change permissions on " + self.logrotpath + " file\n"
                    self.logger.log(LogPriority.DEBUG, debug)
        elif not checkPerms(self.logrotpath, [0, 0, 420], self.logger):
            if not setPerms(self.logrotpath, [0, 0, 420], self.logger):
                debug = "Unable to set " + "permissions on " + self.logrotpath + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                success = False
        if self.fixables:
            contents = readFile(self.logrotpath, self.logger)
            tempstring = ""
            tempcontents = []
            for line in contents:
                templine = re.sub("[ \t\r\f\v]", " ", line)
                tempcontents.append(templine)
            for directory in self.fixables:
                tempcontents2 = []
                for line in tempcontents:
                    if re.search("^|\s+" + directory + "\s*(\{{0,1}|\s*)", line, re.I):
                        templine = re.sub(directory, "", line)
                        tempcontents2.append(templine)
                    else:
                        tempcontents2.append(line)
                tempcontents = tempcontents2
            for item in tempcontents:
                tempstring += item
            for item in self.fixables:
                tempstring += item + "\n"
            tempstring += "{\n"
            for spec in specs:
                tempstring += spec + "\n"
            tempstring += "}\n"
            tmpfile = self.logrotpath + ".stonixtmp"
            if not writeFile(tmpfile, tempstring, self.logger):
                return False
            if not self.created2:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf",
                         "filepath": self.logrotpath}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(self.logrotpath, tmpfile, myid)
            os.rename(tmpfile, self.logrotpath)
            if re.search("^Red Hat", self.ostype.strip()) and \
                    re.search("^6", self.osver):
#!FIXME gid can be referenced before being assigned, here
                os.chown(self.logrotpath, 0, gid)
            else:
                os.chown(self.logrotpath, 0, 0)
            os.chmod(self.logrotpath, 420)
            resetsecon(self.logrotpath)
        if not self.sh.reloadService("rsyslog", _="_"):
            debug = "Unable to restart the log daemon part 1\n"
            self.logger.log(LogPriority.DEBUG, debug)
        if not self.ch.getReturnCode() != "0":
            debug = "Unable to restart the log daemon part 2\n"
            self.logger.log(LogPriority.DEBUG, debug)

        return success

    def reportFreebsd(self, logpath, logrotpath):
        """

        :param logpath:
        :param logrotpath:
        :return:
        """

        compliant = True
        self.missinglogrot = False
        debug = ""

        # check if all necessary dirs are present and correct perms
        for item in self.directories:
            if not os.path.exists(item):
                self.detailedresults += item + " doesn't exist\n"
                compliant = False
            else:
                if not checkPerms(item, [0, 0, 384], self.logger):
                    compliant = False

        # check if correct contents of syslog.conf file
        if os.path.exists(logpath):
            if not checkPerms(logpath, [0, 0, 420], self.logger):
                compliant = False
            contents = readFile(logpath, self.logger)
            if contents:
                for key in self.logfiles:
                    found = False
                    for item in contents:
                        if re.search("^#", item) or re.match('^\s*$', item):
                            continue
                        else:
                            line = item.strip()
                            line = re.sub('(\s)+', " ", line)
                            temp = line.split()
                            if temp[0].strip() == key:
                                if self.logfiles[key] == temp[1].strip():
                                    found = True
                                    break
                    if not found:
                        self.config.append(key + "\t\t\t" + self.logfiles[key] + "\n")
                        compliant = False
        else:
            self.detailedresults += logpath + "doesn\'t exist\n"
            for key in self.logfiles:
                self.config.append(key + "\t\t\t" + self.logfiles[key] + "\n")
            compliant = False

        # check /etc/newsyslog.conf file
        if os.path.exists(logrotpath):
            if not checkPerms(logrotpath, [0, 0, 420], self.logger):
                compliant = False
            contents = readFile(logrotpath, self.logger)
            if contents:
                for directory in self.directories:
                    found = False
                    for line in contents:
                        if re.match('^#', line.strip()) or re.match('^\s*$', line):
                            continue
                        if re.search('^' + directory, line.strip()):
                            found = True
                            line = re.sub('(\s)+', " ", line)
                            temp = line.split()
                            temp.pop(0)
                            try:
                                if re.search(':', temp[0]):
                                    temp.pop(0)
                                # if re.match('[1-7][0-7]{2}', temp[0]):#for the mode
                                if re.match("[0-7][0-7][0-7]", temp[0]):
                                    if temp[0] != "600":
                                        self.missinglogrot = True
                                        compliant = False
                                    temp.pop(0)
                                else:
                                    self.missinglogrot = True
                                if re.match('[0-9]{1,4}', temp[0]):  # for the count
                                    if temp[0] != "4":
                                        self.missinglogrot = True
                                        compliant = False
                                    temp.pop(0)
                                else:
                                    self.missinglogrot = True
                                if re.match('[*]{1}|[0-9]{1,4}', temp[0]):
                                    if temp[0] != "*":
                                        self.missinglogrot = True
                                        compliant = False
                                    temp.pop(0)
                                else:
                                    self.missinglogrot = True
                                if re.match('^[@$*]{1}([A-Z]|[0-9])*', temp[0]):
                                    if temp[0] != "$W0D23":
                                        self.missinglogrot = True
                                        compliant = False
                                else:
                                    self.missinglogrot = True
                            except IndexError:
                                raise
                            except Exception:
                                debug += traceback.format_exc() + "\n"
                                debug += "Index out of range\n"
                    if not found:
                        self.missinglogrot = True
                        compliant = False
        else:
            self.missinglogrot = True
            self.detailedresults += logrotpath + " doesn't exist"
            compliant = False

        return compliant

    def fixFreebsd(self, logpath, logrotpath):
        """Assumptions: for logrotate file, we assume newsyslog.conf doesn't
        contain duplicate entries for files to be logrotated and that the 5
        mandatory fields are actually present(filename,mode,count,size,when)
        If either of these cases apply to the system, the user must delete or
        correct the line in question

        :param logpath: 
        :param logrotpath: 

        """

        universal = "\n# The following lines were added by stonix\n"
        success = True
        debug = ""

        # create and/or correct perms on missing log files
        for item in self.directories:
            if os.path.exists(item):
                if not checkPerms(item, [0, 0, 384], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(item, [0, 0, 384], self.logger,
                                    self.statechglogger, myid):
                        success = False
            else:
                if not createFile(item, self.logger):
                    self.detailedresults += "Unable to create necessary log file: " + item + "\n"
                    success = False
                else:
                    self.detailedresults += "Successfully created log file: " + item + "\n"
                    os.chown(item, 0, 0)
                    os.chmod(item, 384)
                    resetsecon(item)

        if self.config:
            tempstring = ""
            tmpfile = logpath + '.stonixtmp'
            if not os.path.exists(logpath):
                if not createFile(logpath, self.logger):
                    self.detailedresults += "unable to create the log file: " + logpath + "\n"
                elif not checkPerms(logpath, [0, 0, 420], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(logpath, [0, 0, 420], self.logger,
                                    self.statechglogger, myid):
                        success = False
            else:
                if not checkPerms(logpath, [0, 0, 420], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(logpath, [0, 0, 420], self.logger,
                                    self.statechglogger, myid):
                        success = False
            if os.path.exists(logpath):
                contents = readFile(logpath, self.logger)
                if contents:
                    for item in contents:
                        tempstring += item
                    tempstring += universal
                    for item in self.config:
                        tempstring += item
                    if not writeFile(tmpfile, tempstring, self.logger):
                        return False
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": logpath}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(logpath, tmpfile,
                                                         myid)
                    os.rename(tmpfile, logpath)
                    os.chown(logpath, 0, 0)
                    os.chmod(logpath, 420)
                    resetsecon(logpath)

        if self.missinglogrot:
            tempstring = ""
            tmpfile = logrotpath + '.stonixtmp'
            if not os.path.exists(logrotpath):
                if not createFile(logrotpath, self.logger):
                    self.detailedresults += "unable to create log rotation file: " + logrotpath + "\n"
                elif not checkPerms(logrotpath, [0, 0, 420], self.logger):
                    if not setPerms(logrotpath, [0, 0, 420], self.logger):
                        success = False
            else:
                if not checkPerms(logrotpath, [0, 0, 420], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(logrotpath, [0, 0, 420], self.logger, self.statechglogger, myid):
                        success = False
            found = False
            if os.path.exists(logrotpath):
                contents = readFile(logrotpath, self.logger)
                if contents:
                    for line in contents:
                        if re.match('^#', line.strip()) or re.match('^\s*$', line):
                            tempstring += line
                            continue
                        for directory in self.directories:
                            badformat = False
                            found = False
                            if re.match('^' + directory, line.strip()):
                                found = True
                                string = ""
                                self.directories.remove(directory)
                                line = re.sub('(\s)+', " ", line)
                                temp = line.split()
                                string += temp.pop(0) + " "
                                try:
                                    if re.search(':', temp[0]):
                                        string += temp.pop(0) + " "
                                    else:
                                        string += '\t\t\t'
                                    # if re.match('[1-7][0-7]{2}',temp[0]):
                                    if re.match("[0-7][0-7][0-7]", temp[0]):
                                        if temp[0] != "600":
                                            string += "600  "
                                            temp.pop(0)
                                        else:
                                            string += temp.pop(0) + "  "
                                    else:
                                        badformat = True
                                        break
                                    if re.match('[0-9]{1,3}', temp[0]):
                                        if temp[0] != "4":
                                            string += "4     "
                                            temp.pop(0)
                                        else:
                                            string += temp.pop(0) + "    "

                                    else:
                                        badformat = True
                                        break
                                    if re.match('[*]{1}|[0-9]{1,3}', temp[0]):
                                        if temp[0] != "*":
                                            string += "*    "
                                            temp.pop(0)
                                        else:
                                            string += temp.pop(0) + "    "
                                    else:
                                        badformat = True
                                        break
                                    if re.match('^[@$*]{1}([A-Z]|[0-9])*',
                                                temp[0]):
                                        if temp[0] != "$W0D23":
                                            string += "$W0D23 "
                                            temp.pop(0)
                                        else:
                                            string += temp.pop(0) + " "
                                    else:
                                        badformat = True
                                        break
                                except IndexError:
                                    debug += traceback.format_exc() + "\n"
                                    debug += " Index out of range\n"
                                    self.logger.log(LogPriority.DEBUG, debug)
                                    raise
                                try:
                                    if temp[0]:  # if flags value exists
                                        string += temp.pop(0) + " "
                                    if temp[0]:  # if /pid_file exists
                                        string += temp.pop(0) + " "
                                    if temp[0]:  # if sig_num exists
                                        string += temp.pop(0) + " "
                                except IndexError:
                                    debug += traceback.format_exc() + "\n"
                                    debug += "Index out of range but that's ok because these values are optional\n"
                                    self.logger.log(LogPriority.DEBUG, debug)
                                    break
                                tempstring += string + "\n"
                                badformat = False
                                found = True
#!FIXME badformat can be referenced before being assigned, here
                        if badformat:
#!FIXME directory can be referenced before being assigned, here
                            tempstring += directory + "\t\t\t\t" + "600  " + "4     " + "*    " + "$W0D23" + "\n"
                        elif not found:
                            tempstring += line
                if self.directories:
                    for directory in self.directories:
                        tempstring += directory + "\t\t\t\t" + "600  " + "4     " + "*    " + "$W0D23" + "\n"
                if not writeFile(tmpfile, tempstring, self.logger):
                    return False
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf",
                         "filepath": logrotpath}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(logrotpath, tmpfile, myid)
                os.rename(tmpfile, logrotpath)
                os.chown(logrotpath, 0, 0)
                os.chmod(logrotpath, 420)
                resetsecon(logrotpath)
        self.missinglogrot = {}

        if not self.checkSysRsyslogOn():
            message = Popen([self.service, "restart"], stdout=PIPE,
                            stderr=PIPE, shell=False)
            while message.poll() is None:
                continue
            if message.poll() != 0:
                self.detailedresults += "Couldn't' restart syslog daemon\n"
                success = False

        return success

    def reportMac(self):
        """

        :return:
        """

        compliant = RuleKVEditor.report(self, True)
        self.detailedresults += "\n"
        self.badsyslog = False
        self.macDirs = ["/var/log/cron.log",
                        "/var/log/daemon.log",
                        "/var/log/kern.log",
                        "/var/log/local.log",
                        "/var/log/syslog.log",
                        "/var/log/user.log",
                        "/var/log/stonix.log",
                        "/var/log/system.log",
                        "/var/log/lpr.log",
                        "/var/log/mail.log",
                        "/var/log/install.log",
                        "/var/log/netinfo.log",
                        "/var/log/secure.log"]
        self.logfiles = ["*.* /var/log/system.log",
                         "daemon.* /var/log/daemon.log",
                         "auth.* /var/log/secure.log",
                         "user.* /var/log/user.log",
                         "kern.* /var/log/kern.log",
                         "lpr.* /var/log/lpr.log",
                         "syslog.* /var/log/syslog.log",
                         "cron.* /var/log/cron.log",
                         "mail.* /var/log/mail.log",
                         "uucp.* /var/log/mail.log",
                         "news.* /var/log/mail.log",
                         "local.* /var/log/local.log",
                         "local0.* /var/log/local.log",
                         "local1.* /var/log/local.log",
                         "local2.* /var/log/local.log",
                         "local3.* /var/log/local.log",
                         "local4.* /var/log/local.log",
                         "local5.* /var/log/local.log",
                         "local6.* /var/log/local.log",
                         "local7.* /var/log/local.log",
                         "local5.* /var/log/stonix.log",
                         "install.* /var/log/install.log",
                         "netinfo.* /var/log/netinfo.log",
                         "remoteauth.* /var/log/secure.log",
                         "*authpriv.* /var/log/secure.log",
                         "*.crit /dev/console"]

        if WINLOG is not None and isinstance(WINLOG, str):
            self.logfiles.append("mark.* " + WINLOG)
            self.logfiles.append("authpriv.* " + WINLOG)
            self.logfiles.append("auth.* " + WINLOG)
            # self.directories only gets instantiated if the system is linux
            # (line 133 -> line 157) so we can't reference it in code that
            # only gets called if the system is mac (reportmac)
            # this is why I commented out the following line
            ##self.directories.append(WINLOG)

        self.asl = ["? [T com.apple.message.domain] store_dir /var/log/DiagnosticMessages",
                    "? [A= Facility com.apple.performance] store_dir /var/log/performance",
                    "? [A= Facility com.apple.eventmonitor] store_dir /var/log/eventmonitor",
                    "? [= Facility authpriv] access 0 80",
                    "? [= Facility remoteauth] [<= Level critical] access 0 80",
                    "? [= Level emergency] broadcast",
                    "? [<= PID 1] store",
                    "? [= Facility internal] ignore",
                    "? [<= Level notice] store",
                    "? [= Facility install] file /var/log/install.log format=bsd",
                    "? [= Facility install] ignore",
                    "? [= Sender kernel] file /var/log/system.log mode=0600 gid=80 format=bsd",
                    "? [<= Level notice] file /var/log/system.log",
                    "? [= Facility auth] [<= Level info] file /var/log/system.log",
                    "? [= Facility authpriv] file /var/log/system.log",
                    "? [= Facility mail] file /var/log/mail.log mode=0644 format=bsd",
                    "? [= Facility com.apple.alf.logging] file /var/log/appfirewall.log]"]
        self.logpath = "/etc/syslog.conf"
        newsyslog = "/etc/newsyslog.conf"
        aslfile = "/etc/asl.conf"
        service = " /System/Library/LaunchDaemons/com.apple.syslogd.plist"
        servicename = "com.apple.syslogd"
        for path in self.macDirs:
            if not os.path.exists(path):
                compliant = False
                self.detailedresults += path + " logfile doesn't exist\n"

        # if LANLLOGROTATE const is set to none, this is a public environment
        # (not lanl related) so ignore the next bit of code
        if LANLLOGROTATE is not None:
            if os.path.exists("/etc/periodic/weekly/" + LANLLOGROTATE):
                compliant = False
                self.detailedresults += "old logrotation file exists\n"

        # check for correct contents of rsyslog.conf file
        # temporary quick fix to fix broken macs with corrupted syslog file
        regex = "*.* /var/log/system.log\n" + \
                "daemon.* /var/log/daemon.log\n" + \
                "auth.* /var/log/secure.log\n" + \
                "user.* /var/log/user.log\n" + \
                "kern.* /var/log/kern.log\n" + \
                "lpr.* /var/log/lpr.log\n" + \
                "syslog.* /var/log/syslog.log\n" + \
                "cron.* /var/log/cron.log\n" + \
                "mail.* /var/log/mail.log\n" + \
                "uucp.* /var/log/mail.log\n" + \
                "news.* /var/log/mail.log\n" + \
                "local,local0,local1,local2,local3,local4,local5,local6,local7.* /var/log/local.log\n" + \
                "local5.* /var/log/stonix.log\n" + \
                "install.* /var/log/install.log\n" + \
                "netinfo.* /var/log/netinfo.log\n" + \
                "remoteauth.* /var/log/secure.log\n" + \
                "*authpriv.* /var/log/secure.log\n" + \
                "*.crit /dev/console\n"

        if os.path.exists(self.logpath):
            contents = readFile(self.logpath, self.logger)
            filestring = ""
            for line in contents:
                filestring += line
            if not re.search(re.escape(regex), filestring):
                self.detailedresults += self.logpath + " doesn't contain correct contents\n"
                compliant = False
                self.badsyslog = True
        else:
            compliant = False
            self.detailedresults += self.logpath + " doesn't exist\n"
        bad = False
        exist = []
        missing = []
        contents = readFile(aslfile, self.logger)
        for asl in self.asl:
            found = False
            for line in contents:
                if line.strip() == asl:
                    found = True
                    break
            if found:
                exist.append(asl)
            else:
                bad = True
                debug = "didn't find: " + str(asl) + " in " + aslfile + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                missing.append(asl)
                compliant = False
        if exist:
            for item in exist:
                self.asl.remove(item)
        if bad:
            self.detailedresults += "The following lines were not found in " + \
                aslfile + ":\n"
            for item in missing:
                self.detailedresults += str(item) + "\n"
        # check newsyslog.conf file
        if os.path.exists(newsyslog):
            contents = readFile(newsyslog, self.logger)
            for directory in self.macDirs:
                found = False
                for line in contents:
                    if re.match('^#', line.strip()) or re.match('^\s*$', line):
                        continue
                    if re.search('^' + directory, line.strip()):
                        found = True
                        line = re.sub('(\s)+', " ", line)
                        temp = line.split()
                        temp.pop(0)
                        try:
                            if re.search(':', temp[0]):
                                temp.pop(0)
                            # if re.match('[1-7][0-7]{2}', temp[0]):#for the mode
                            if re.match("[0-7][0-7][0-7]", temp[0]):
                                if temp[0] != "600":
                                    self.missinglogrot = True
                                    compliant = False
                                temp.pop(0)
                            else:
                                self.missinglogrot = True
                            if re.match('[0-9]{1,4}', temp[0]):  # for the count
                                if temp[0] != "4":
                                    self.missinglogrot = True
                                    compliant = False
                                temp.pop(0)
                            else:
                                self.missinglogrot = True
                            if re.match('[*]{1}|[0-9]{1,4}', temp[0]):
                                if temp[0] != "*":
                                    self.missinglogrot = True
                                    compliant = False
                                temp.pop(0)
                            else:
                                self.missinglogrot = True
                            if re.match('^[@$*]{1}([A-Z]|[0-9])*', temp[0]):
                                if temp[0] != "$W0D23":
                                    self.missinglogrot = True
                                    compliant = False
                            else:
                                self.missinglogrot = True
                        except IndexError:
                            debug = "Index out of range\n"
                            self.logger.log(LogPriority.DEBUG, debug)

                if not found:
                    self.missinglogrot = True
                    compliant = False
        if not self.sh.isRunning(service, servicename=servicename):
            compliant = False
            self.detailedresults += "syslogd is not running\n"
        if not compliant:
            self.detailedresults += "Log rotation is not correctly set up in " + newsyslog + "\n"

        return compliant

    def fixMac(self):
        """

        :return:
        """

        newsyslog = "/etc/newsyslog.conf"
        aslfile = "/etc/asl.conf"
        service = "/System/Library/LaunchDaemons/com.apple.syslogd.plist"
        servicename = "com.apple.syslogd"
        tempstring = "*.* /var/log/system.log\n" + \
                "daemon.* /var/log/daemon.log\n" + \
                "auth.* /var/log/secure.log\n" + \
                "user.* /var/log/user.log\n" + \
                "kern.* /var/log/kern.log\n" + \
                "lpr.* /var/log/lpr.log\n" + \
                "syslog.* /var/log/syslog.log\n" + \
                "cron.* /var/log/cron.log\n" + \
                "mail.* /var/log/mail.log\n" + \
                "uucp.* /var/log/mail.log\n" + \
                "news.* /var/log/mail.log\n" + \
                "local,local0,local1,local2,local3,local4,local5,local6,local7.* /var/log/local.log\n" + \
                "local5.* /var/log/stonix.log\n" + \
                "install.* /var/log/install.log\n" + \
                "netinfo.* /var/log/netinfo.log\n" + \
                "remoteauth.* /var/log/secure.log\n" + \
                "*authpriv.* /var/log/secure.log\n" + \
                "*.crit /dev/console\n"

        success = RuleKVEditor.fix(self, True)
        universal = "# The following lines were added by stonix\n"

        for path in self.macDirs:
            if not os.path.exists(path):
                if not createFile(path, self.logger):
                    success = False
                    self.detailedresults += "unsuccessful in creating file: " + path + "\n"

        # if the LANLLOGROTATE const is set to none, this is a public environment
        # (not lanl related) so ignore the next bit of code
        if LANLLOGROTATE is not None:
            if os.path.exists("/etc/periodic/weekly/" + LANLLOGROTATE):
                os.remove("/etc/periodic/weekly/" + LANLLOGROTATE)

        # quick fix for corrupted syslog files
        if os.path.exists(self.logpath):
            if self.badsyslog:
                tmpfile = self.logpath + ".stonixtmp"
                if writeFile(tmpfile, tempstring, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": self.logpath}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.logpath, tmpfile, myid)
                    os.rename(tmpfile, self.logpath)
                else:
                    success = False
                    self.detailedresults += "Unable to write to /etc/asl.conf\n"
        else:
            if not createFile(self.logpath, self.logger):
                debug = "Unable to create missing log rotation config " + \
                    "file: " + self.logpath + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                success = False
            else:
                self.detailedresults += "successfully created " + \
                    self.logpath + " file\n"
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": self.logpath}
                tmpfile = self.logpath + ".stonixtmp"
                self.statechglogger.recordchgevent(myid, event)
                if not writeFile(tmpfile, tempstring, self.logger):
                    debug = "Unable to write to file " + tmpfile + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                else:
                    os.rename(tmpfile, self.logpath)

        if os.path.exists(aslfile):
            contents = readFile(aslfile, self.logger)
            tempstring = ""
            for line in contents:
                if re.search(universal, line):
                    continue
                tempstring += line
            tempstring += universal

            for item in self.asl:
                tempstring += item + "\n"
            tmpfile = aslfile + ".stonixtmp"

            if writeFile(tmpfile, tempstring, self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf",
                         "filepath": aslfile}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(aslfile, tmpfile, myid)
                os.rename(tmpfile, aslfile)
            else:
                success = False
                self.detailedresults += "Unable to write to /etc/asl.conf\n"
        else:
            success = False
            self.detailedresults += "/etc/asl.conf does not exist, will not attempt to create this file.\n"
        if os.path.exists(newsyslog):
            contents = readFile(newsyslog, self.logger)
            if contents:
                tempstring = ""
                for line in contents:
                    if re.match('^#', line.strip()) or re.match('^\s*$', line):
                        tempstring += line
                        continue
                    for directory in self.macDirs:
                        badformat = False
                        found = False
                        if re.match('^' + directory, line.strip()):
                            found = True
                            string = ""
                            self.macDirs.remove(directory)
                            line = re.sub('(\s)+', " ", line)
                            temp = line.split()
                            string += temp.pop(0) + " "
                            try:
                                if re.search(':', temp[0]):
                                    string += temp.pop(0) + " "
                                else:
                                    string += '\t\t\t'
                                if re.match("[0-7][0-7][0-7]", temp[0]):
                                    if temp[0] != "600":
                                        string += "600  "
                                        temp.pop(0)
                                    else:
                                        string += temp.pop(0) + "  "
                                else:
                                    badformat = True
                                    break
                                if re.match('[0-9]{1,3}', temp[0]):
                                    if temp[0] != "4":
                                        string += "4     "
                                        temp.pop(0)
                                    else:
                                        string += temp.pop(0) + "    "
                                else:
                                    badformat = True
                                    break
                                if re.match('[*]{1}|[0-9]{1,3}', temp[0]):
                                    if temp[0] != "*":
                                        string += "*    "
                                        temp.pop(0)
                                    else:
                                        string += temp.pop(0) + "    "
                                else:
                                    badformat = True
                                    break
                                if re.match('^[@$*]{1}([A-Z]|[0-9])*',temp[0]):
                                    if temp[0] != "$W0D23":
                                        string += "$W0D23 "
                                        temp.pop(0)
                                    else:
                                        string += temp.pop(0) + " "
                                else:
                                    badformat = True
                                    break
                            except IndexError:
                                debug = " Index out of range\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                badformat = True
                            try:
                                if temp[0]:  # if flags value exists
                                    string += temp.pop(0) + " "
                                if temp[0]:  # if /pid_file exists
                                    string += temp.pop(0) + " "
                                if temp[0]:  # if sig_num exists
                                    string += temp.pop(0) + " "
                            except IndexError:
                                debug = "Index out of range but that's ok because these values are optional\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                tempstring += string + "\n"
                                break
                            tempstring += string + "\n"
                            badformat = False
                            found = True
#!FIXME badformat can be referenced before being assigned, here
                    if badformat:
#!FIXME directory can be referenced before being assigned, here
                        tempstring += directory + "\t\t\t\t" + "600  " + "4     " + "*    " + "$W0D23" + "\n"
                        self.macDirs.remove(directory)
#!FIXME found can be referenced before being assigned, here
                    if not found:
                        tempstring += line
            if self.macDirs:
                for directory in self.macDirs:
                    tempstring += directory + "\t\t\t\t" + "600  " + "4     " + "*    " + "$W0D23" + "\n"
#!FIXME tmpfile can be referenced before being assigned, here
            if writeFile(tmpfile, tempstring, self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf",
                         "filepath": newsyslog}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(newsyslog, tmpfile, myid)
                os.rename(tmpfile, newsyslog)
            else:
                success = False
                debug = "Unable to write to /etc/newsyslog.conf\n"
                self.logger.log(LogPriority, debug)
        else:
            success = False
            debug = "/etc/newsyslog.conf does not exist, will not attempt to create this file.\n"
            self.logger.log(LogPriority, debug)

        if not self.sh.reloadService(service, servicename=servicename):
            success = False

        return success

    def checkSysRsyslogOn(self):
        """checks if rsyslog/syslog daemon is running
        @author: Derek Walker


        :returns: bool

        """

        if re.search("opensuse", self.ostype, re.I):
            ps = "/usr/bin/ps"
        else:
            ps = "/bin/ps"
        message = Popen([ps, '-elf'], stdout=PIPE, stderr=PIPE, shell=False)
        info = message.stdout.readlines()
        for line in info:
            if re.search(self.daemon, line.decode('utf-8')):
                return True

        return False

    def checkLogRotation(self):
        """checks the path of the log rotation
        @author: Derek Walker


        :returns: string

        """
        logrotpath = ""
        if self.logs["rsyslog"]:
            if os.path.exists("/etc/logrotate.d/syslog"):
                logrotpath = "/etc/logrotate.d/syslog"
            elif os.path.exists("/etc/logrotate.d/syslog.conf"):
                logrotpath = "/etc/logrotate.d/syslog.conf"
            elif os.path.exists("/etc/logrotate.d/rsyslog"):
                logrotpath = "/etc/logrotate.d/rsyslog"
            elif os.path.exists("/etc/logrotate.d/rsyslog.conf"):
                logrotpath = "/etc/logrotate.d/rsyslog.conf"
            else:
                logrotpath = "/etc/logrotate.d/syslog"
        elif self.logs["syslog"]:
            if os.path.exists("/etc/logrotate.d/syslog"):
                logrotpath = "/etc/logrotate.d/syslog"
            elif os.path.exists("/etc/logrotate.d/syslog.conf"):
                logrotpath = "/etc/logrotate.d/syslog.conf"
            else:
                logrotpath = "/etc/logrotate.d/syslog"
        return logrotpath
