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

'''
Created on Apr 22, 2015

@author: dwalker
@change: 2015/09/25 eball Added info to help text and removed failure for
    missing configuration file
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, setPerms, checkPerms
from ..stonixutilityfunctions import resetsecon, createFile, readFile, writeFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix
from ..pkghelper import Pkghelper
import traceback
import os
import re


class SecureDHCPServer(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 134
        self.rulename = "SecureDHCPServer"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        datatype = "bool"
        key = "SECUREDHCPSERVER"
        instructions = '''To disable this rule set the value of \
SECUREDHCPSERVER to False.'''
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.guidance = ["NSA 3.9.4", "CCE 4257-2", "CCE 4403-2", "CCE 4345-5",
                         "CCE 3724-2", "CCE 4243-2", "CCE 4389-3",
                         "CCE 3913-1", "CCE 4169-9", "CCE 4318-2",
                         "CCE 4319-0", "CCE 3733-3"]
        self.applicable = {"type": "white",
                           "family": ["linux"]}
        self.iditerator = 0
        self.created = False

    def report(self):
        try:
            self.detailedresults = ""
            self.ph = Pkghelper(self.logger, self.environ)
            self.data1 = {"ddns-update-style": "none;",
                          "deny": ["declines;",
                                   "bootp;"]}
            self.data2 = ["domain-name",
                          "domain-name-servers",
                          "nis-domain",
                          "nis-servers",
                          "ntp-servers",
                          "routers",
                          "time-offset"]
            if self.ph.manager == "zypper":
                self.path = "/etc/dhcpd.conf"
            elif self.ph.manager == "yum" or self.ph.manager == "dnf":
                self.path = "/etc/dhcp/dhcpd.conf"
            elif self.ph.manager == "apt-get":
                self.path = "/etc/dhcp/dhcpd.conf"
            self.tmppath = self.path + ".tmp"
            compliant = True
            if os.path.exists(self.path):
                if not checkPerms(self.path, [0, 0, 0644], self.logger):
                    self.detailedresults += "The permissions on " + \
                        self.path + " are incorrect\n"
                    compliant = False
                self.editor = KVEditorStonix(self.statechglogger,
                                             self.logger, "conf",
                                             self.path, self.tmppath,
                                             self.data1, "present",
                                             "space")
                if not self.editor.report():
                    self.detailedresults += self.path + " doesn't contain " + \
                        "the correct contents\n"
                    compliant = False
                contents = readFile(self.path, self.logger)
                for line in contents:
                    if re.match('^#', line) or re.match(r'^\s*$', line):
                        continue
                    if re.search("^option", line):
                        linesplit = line.split()
                        if len(linesplit) >= 2:
                            for item in self.data2:
                                if re.search(item, linesplit[1]):
                                    compliant = False
                                    self.detailedresults += "Unwanted " + \
                                        "option found in " + self.path + \
                                        ": " + line
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            success = True
            # Clean out old undo events
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            self.detailedresults = ""
            if not os.path.exists(self.path):
                createFile(self.path, self.logger)
                self.created = True
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": self.path}
                self.statechglogger.recordchgevent(myid, event)
                self.editor = KVEditorStonix(self.statechglogger,
                                             self.logger, "conf",
                                             self.path, self.tmppath,
                                             self.data1, "present",
                                             "space")
                self.editor.report()
            tempstring = ""
            tmpfile = self.path + ".tmp"
            contents = readFile(self.path, self.logger)
            changes = False
            for line in contents:
                found = False
                if re.match('^#', line) or re.match(r'^\s*$', line):
                    tempstring += line
                    continue
                if re.search("^option", line):
                    temp = line.split()
                    if len(temp) >= 2:
                        for item in self.data2:
                            if re.search(item, temp[1]):
                                found = True
                                changes = True
                                break
                        if found:
                            continue
                        else:
                            tempstring += line
                else:
                    tempstring += line
            if changes:
                debug = "Writing changes to " + tmpfile
                self.logger.log(LogPriority.DEBUG, debug)
                if not writeFile(tmpfile, tempstring, self.logger):
                    debug = "Unable to write changes to " + tmpfile
                    self.detailedresults += debug
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": self.path}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.path,
                                                         tmpfile, myid)
                    os.rename(tmpfile, self.path)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    setPerms(self.path, [0, 0, 0644], self.logger,
                             self.statechglogger, myid)
                    resetsecon(self.path)
            if self.editor.fixables:
                if not self.created:
                    if not checkPerms(self.path, [0, 0, 0644], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(self.path, [0, 0, 0644],
                                        self.logger, self.statechglogger,
                                        myid):
                            success = False
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor.setEventID(myid)
                if self.editor.fix():
                    if self.editor.commit():
                        debug = self.path + "'s contents have been " + \
                            "corrected\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        os.chown(self.path, 0, 0)
                        os.chmod(self.path, 0644)
                        resetsecon(self.path)
                    else:
                        debug = "kveditor commit not successful\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                else:
                    debug = "kveditor fix not successful\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
