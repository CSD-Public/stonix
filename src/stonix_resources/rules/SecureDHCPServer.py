###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
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
'''
Created on Apr 22, 2015

@author: dwalker
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
        self.helptext = '''Configures DHCP functionality '''
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
            print "inside report!!!!\n\n"
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
#                 self.package = "dhcp-server"
                self.path = "/etc/dhcpd.conf"
            elif self.ph.manager == "yum":
                #self.package = "dhcp"
                self.path = "/etc/dhcp/dhcpd.conf"
            elif self.ph.manager == "apt-get":
                #self.package = "isc-dhcp-server"
                self.path = "/etc/dhcp/dhcpd.conf"
            self.tmppath = self.path + ".tmp"
            compliant = True
            #if self.ph.check(self.package):
            if os.path.exists(self.path):
                if not checkPerms(self.path, [0, 0, 420], self.logger):
                    compliant = False
                self.editor = KVEditorStonix(self.statechglogger,
                                             self.logger, "conf",
                                             self.path, self.tmppath,
                                             self.data1, "present",
                                             "space")
                if not self.editor.report():
                    compliant = False
                contents = readFile(self.path, self.logger)
                for line in contents:
                    if re.match('^#', line) or re.match(r'^\s*$', line):
                        continue
                    if re.search("^option", line):
                        print "line is: " + line + "\n\n"
                        line = line.split()
                        if len(line) >= 2:
                            print "line has two or more placeholders\n\n"
                            for item in self.data2:
                                if re.search(item, line[1]):
                                    compliant = False
#                 self.editor.setData(self.data2)
#                 self.editor.setIntent("notpresent")
#                 if not self.editor.report():
#                     compliant = False
            else:
                compliant = False
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
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            #if self.ph.check(self.package):
            print "inside fix!\n\n"
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
                self.editor.setData(self.data2)
                self.editor.setIntent("notpresent")
                self.editor.report()
            tempstring = ""
            tmpfile = self.path + ".tmp"
            contents = readFile(self.path, self.logger)
            for line in contents:
                found = False
                if re.match('^#', line) or re.match(r'^\s*$', line):
                    tempstring += line
                    continue
                if re.search("^option", line):
                    print "here's an option line!\n\n" + line + "\n\n"
                    temp = line.split()
                    if len(temp) >= 2:
                        print "line has 2 or more placeholders"
                        for item in self.data2:
                            if re.search(item, temp[1]):
                                print "we found the line we don't want"
                                found = True
                                break
                        if found:
                            print "found = True, skip this line"
                            continue
                        else:
                            tempstring += line
                else:
                    tempstring += line
            print "tempstring: " + tempstring + "\n\n"
            if tempstring:
                if not writeFile(tmpfile, tempstring, self.logger):
                    self.detailedresults += "Unable to write changes to " + \
                        self.path
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    success = False
                else:
                    if not self.editor.fixables:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "conf",
                                 "filepath": self.path}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(self.path,
                                                             tmpfile, myid)
                        os.rename(tmpfile, self.path)
                        os.chown(self.path, 0, 0)
                        os.chmod(self.path, 420)
                        resetsecon(self.path)
            if self.editor.fixables:
                if not self.created:
                    if not checkPerms(self.path, [0, 0, 420], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(self.path, [0, 0, 420],
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
                        os.chmod(self.path, 420)
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
