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
Created on Jul 7, 2015

@author: dwalker
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, setPerms, checkPerms
from ..stonixutilityfunctions import resetsecon, readFile, writeFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
import traceback
import os
import re


class SecureSquidProxy(Rule):
    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 143
        self.rulename = "SecureSquidProxy"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''Secures Squid Proxy functionality '''

        datatype1 = "bool"
        key1 = "SECURESQUIDPROXY"
        instructions1 = '''To disable this rule set the value of \
        SECURESQUIDPROXY to False.  MinimizeServices rule disables squid \
        by default however this rule will still configure it if installed'''
        default1 = True
        self.ci1 = self.initCi(datatype1, key1, instructions1, default1)

        self.guidance = ["NSA 3.19", "CCE 4454-5", "CCE 4353-9", "CCE 4503-9",
                         "CCE 3585-7", "CCE 4419-8", "CCE 3692-1",
                         "CCE 4459-4", "CCE 4476-8", "CCE 4181-4",
                         "CCE 4577-3", "CCE 4344-8", "CCE 4494-1",
                         "CCE 4511-2", "CCE 4529-4", "CCE 3610-3",
                         "CCE 4466-9", "CCE 4607-8", "CCE 4255-6",
                         "CCE 4127-7", "CCE 4519-5", "CCE 4413-1",
                         "CCE 4373-7"]

        self.applicable = {"type": "white",
                           "family": ["linux"]}
        self.iditerator = 0

    def report(self):
        ''''''
        try:
            compliant = True
            debug = ""
            self.ph = Pkghelper(self.logger, self.environ)
            if self.ph.check("squid"):
                if self.ph.manager in ("zypper", "yum"):
                    self.path = "/etc/squid/squid.conf"
                elif self.ph.manager == "apt-get":
                    self.path = "/etc/squid3/squid.conf"
                if not checkPerms(self.path, [0, 0, 420], self.logger):
                    self.detailedresults += "Permissions are not correct " + \
                        "on " + self.path + "\n"
                self.data1 = {"ftp_passive": "ftp_passive on",
                              "ftp_sanitycheck": "ftp_sanitycheck on",
                              "check_hostnames": "check_hostnames on",
                              "request_header_max_size": "request_header_max_size 20 KB",
                              "reply_header_max_size": "reply_header_max_size 20 KB",
                              "cache_effective_user": "cache_effective_user squid",
                              "cache_effective_group": "cache_effective_group squid",
                              "ignore_unknown_nameservers": "ignore_unknown_nameservers on",
                              "allow_underscore": "allow_underscore off",
                              "httpd_suppress_version_string": "httpd_suppress_version_string on",
                              "forwarded_for": "forwarded_for off",
                              "log_mime_hdrs": "log_mime_hdrs on"}
                self.data2 = "http access deny to_localhost"

                #make sure these aren't in the file
                self.denied = ["acl Safe_ports port 70",
                               "acl Safe_ports port 210",
                               "acl Safe_ports port 280",
                               "acl Safe_ports port 488",
                               "acl Safe_ports port 591",
                               "acl Safe_ports port 777"]
                contents = readFile(self.path, self.logger)
                for key in self.data1:
                    found = False
                    for line in contents:
                        if re.match('^#', line) or re.match(r'^\s*$', line):
                            continue
                        elif re.search(key, line):
                            if found:
                                continue
                            temp = line.strip()
                            temp = re.sub("\s+", " ", temp)
                            if re.search("^" + key, line):
                                if re.search(self.data1[key], temp):
                                    found = True
                                else:
                                    found = False
                                    break
                    if not found:
                        debug += key + " either not found or has wrong value\n"
                        self.detailedresults += key + " either not found " + \
                            "or has wrong value\n"
                        compliant = False
                if debug:
                    self.logger.log(LogPriority.DEBUG, debug)
                debug = ""
                contents = readFile(self.path, self.logger)
                for line in contents:
                    if re.search("^" + "acl", line):
                        temp = line.strip()
                        temp = re.sub("\s+", " ", temp)
                        if temp in self.denied:
                            debug += "line: " + temp + \
                                "should not exist in this file\n"
                            self.detailedresults += "line: " + temp + \
                                "should not exist in this file\n"
                            compliant = False
                if debug:
                    self.logger.log(LogPriority.DEBUG, debug)
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
        ''''''
        try:
            if not self.ci1.getcurrvalue():
                return
            self.detailedresults = ""
            deleted1 = []
            deleted2 = []
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.ph.check("squid"):
                tempstring = ""
                contents = readFile(self.path, self.logger)
                if not checkPerms(self.path, [0, 0, 420], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.path, [0, 0, 420], self.logger,
                                    self.statechglogger, myid):
                        success = False
                for key in self.data1:
                    i = 0
                    found = False
                    for line in contents:
                        if re.match('^#', line) or re.match(r'^\s*$', line):
                            i += 1
                            continue
                        temp = line.strip()
                        if re.search("^" + key, temp):

                            if found:
                                deleted1.append(contents.pop(i))
                                continue
                            temp = re.sub("\s+", " ", temp)
                            if re.search(self.data1[key], temp):
                                i += 1
                                found = True
                                continue
                            else:
                                deleted1.append(contents.pop(i))
                        else:
                            i += 1
                    if found:
                        deleted2.append(key)
            if deleted2:
                for item in deleted2:
                    del self.data1[item]
            for item in contents:
                tempstring += item
            if self.data1:
                tempstring += "#The follwing lines were added by stonix\n"
                for item in self.data1:
                    tempstring += self.data1[item] + "\n"
            tmpfile = self.path + ".tmp"
            if not writeFile(tmpfile, tempstring, self.logger):
                success = False
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf",
                         "filepath": self.path}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(self.path, tmpfile, myid)
                os.rename(tmpfile, self.path)
                os.chown(self.path, 0, 0)
                os.chmod(self.path, 420)
                resetsecon(self.path)
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess 