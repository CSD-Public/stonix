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
Created on Jul 7, 2015

@author: dwalker
@change: 2016/04/26 ekkehard Results Formatting
'''

from ..stonixutilityfunctions import iterate, setPerms, checkPerms
from ..stonixutilityfunctions import resetsecon, readFile, writeFile, createFile
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
        self.sethelptext()
        datatype1 = "bool"
        key1 = "SECURESQUIDPROXY"
        instructions1 = "To disable this rule set the value of " + \
            "SECURESQUIDPROXY to False.  MinimizeServices rule disables " + \
            "squid by default however this rule will still configure it " + \
            "if installed"
        default1 = True
        self.ci = self.initCi(datatype1, key1, instructions1, default1)

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
        ''' '''
        try:
            self.detailedresults = ""
            compliant = True
            debug = ""
            self.ph = Pkghelper(self.logger, self.environ)
            self.installed = False
            if self.ph.manager == "apt-get":
                if self.ph.check("squid3"):
                    self.installed = True
                    self.squidfile = "/etc/squid3/squid.conf"
                elif self.ph.check("squid"):
                    self.installed = True
                    self.squidfile = "/etc/squid/squid.conf"
            if self.ph.check("squid"):
                self.installed = True
                self.squidfile = "/etc/squid/squid.conf"
            if self.installed:
                self.data1 = {"ftp_passive": "on",
                              "ftp_sanitycheck": "on",
                              "check_hostnames": "on",
                              "request_header_max_size": "20 KB",
                              "reply_header_max_size": "20 KB",
                              "cache_effective_user": "squid",
                              "cache_effective_group": "squid",
                              "ignore_unknown_nameservers": "on",
                              "allow_underscore": "off",
                              "httpd_suppress_version_string": "on",
                              "forwarded_for": "off",
                              "log_mime_hdrs": "on"}
                self.data2 = {"http_access": "deny to_localhost"}
                #make sure these aren't in the file
                self.denied = ["acl Safe_ports port 70",
                               "acl Safe_ports port 210",
                               "acl Safe_ports port 280",
                               "acl Safe_ports port 488",
                               "acl Safe_ports port 591",
                               "acl Safe_ports port 777"]
                if os.path.exists(self.squidfile):
                    if not checkPerms(self.squidfile, [0, 0, 420], self.logger):
                        self.detailedresults += "Permissions are not correct " + \
                            "on " + self.squidfile + "\n"
                    contents = readFile(self.squidfile, self.logger)
                    if contents:
                        found = False
                        for line in contents:
                            if re.search("^http_access", line.strip()):
                                temp = line.strip()
                                temp = re.sub("\s+", " ", temp)
                                temp = re.sub("http_access\s+", "", temp)
                                if re.search("^deny to_localhost", temp):
                                    found = True
                                    break
                        if not found:
                            compliant = False
                        for key in self.data1:
                            found = False
                            for line in contents:
                                if re.match('^#', line) or re.match(r'^\s*$', line):
                                    continue
                                elif re.search("^" + key + " ", line):
                                    temp = line.strip()
                                    temp = re.sub("\s+", " ", temp)
                                    temp = temp.split(" ")
                                    if len(temp) >= 3:
                                        joinlist = [temp[1], temp[2]]
                                        joinstring = " ".join(joinlist)
                                        if self.data1[key] == joinstring:
                                            found = True
                                        else:
                                            found = False
                                            break
                                    else:
                                        if self.data1[key] == temp[1]:
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
                        for entry in self.denied:
                            for line in contents:
                                if re.search(entry + "\s+", line.strip()):
                                    debug += "line: " + line + \
                                        "should not exist in this file\n"
                                    self.detailedresults += "line: " + line + \
                                        "should not exist in this file\n"
                                    compliant = False
                        if debug:
                            self.logger.log(LogPriority.DEBUG, debug)
                    else:
                        compliant = False
                        self.detailedresults += "Contents of squid " + \
                            "configuration file are blank\n"
                else:
                    compliant = False
                    self.detailedresults += "squid configuration file " + \
                        "doesn't exist\n"
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
        ''' '''
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""
            success = True
            created = False
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.installed:
                if not os.path.exists(self.squidfile):
                    if not createFile(self.squidfile, self.logger):
                        success = False
                    else:
                        created = True
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "creation",
                                 "filepath": self.squidfile}
                        self.statechglogger.recordchgevent(myid, event)
                if not checkPerms(self.squidfile, [0, 0, 420], self.logger):
                    if not created:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(self.squidfile, [0, 0, 420], self.logger,
                                        self.statechglogger, myid):
                            success = False
                    else:
                        if not setPerms(self.squidfile, [0, 0, 420], self.logger):
                            success = False
                tempstring = ""
                contents = readFile(self.squidfile, self.logger)
                newcontents = []
                if contents:
                    '''Remove any undesired acl lines'''
                    for line in contents:
                        if re.match('^#', line) or re.match(r'^\s*$', line):
                            newcontents.append(line)
                        elif re.search("^acl Safe_ports port ", line.strip()):
                            m = re.search("acl Safe_ports port ([0-9]+).*", line)
                            if m.group(1):
                                item = "acl Safe_ports port " + m.group(1)
                                if item in self.denied:
                                    continue
                                else:
                                    newcontents.append(line)
                        else:
                            newcontents.append(line)
                    '''removeables list holds key vals we find in the file
                    that we can remove from self.data'''
                    removeables = []
                    '''deleteables list holds key vals we can delete from 
                    newcontents list if it's incorrect.'''
                    deleteables = {}
                    for key in self.data1:
                        found = False
                        for line in reversed(newcontents):
                            if re.match('^#', line) or re.match(r'^\s*$', line):
                                continue
                            elif re.search("^" + key + " ", line) or re.search("^" + key, line):
                                temp = line.strip()
                                temp = re.sub("\s+", " ", temp)
                                temp = temp.split(" ")
                                if len(temp) >= 3:
                                    joinlist = [temp[1], temp[2]]
                                    joinstring = " ".join(joinlist)
                                    if self.data1[key] == joinstring:
                                        '''We already found this line and value
                                        No need for duplicates'''
                                        if found:
                                            newcontents.remove(line)
                                            continue
                                        removeables.append(key)
                                        found = True
                                    else:
                                        try:
                                            deleteables[line] = ""
                                        except Exception:
                                            continue
                                        continue
                                elif len(temp) == 2:
                                    if self.data1[key] == temp[1]:
                                        '''We already found this line and value
                                        No need for duplicates'''
                                        if found:
                                            newcontents.remove(line)
                                            continue
                                        removeables.append(key)
                                        found = True
                                    else:
                                        try:
                                            deleteables[line] = ""
                                        except Exception:
                                            continue
                                        continue
                                elif len(temp) == 1:
                                    try:
                                        deleteables[line] = ""
                                    except Exception:
                                        continue
                                    continue
                    if deleteables:
                        for item in deleteables:
                            newcontents.remove(item)
                    '''anything in removeables we found in the file so
                    we will remove from the self.data1 dictionary'''
                    if removeables:
                        for item in removeables:
                            del(self.data1[item])
                    '''now check if there is anything left over in self.data1
                    if there is we need to add that to newcontents list'''
                    if self.data1:
                        for item in self.data1:
                            line = item + " " + self.data1[item] + "\n"
                            newcontents.append(line)
                    for line in newcontents:
                        found = False
                        if re.search("^http_access", line.strip()):
                            temp = line.strip()
                            temp = re.sub("\s+", " ", temp)
                            temp = re.sub("http_access\s+", "", temp)
                            if re.search("^deny to_localhost", temp):
                                found = True
                                break
                    if not found:
                        newcontents.append("http_access deny to_localhost\n")
                    for item in newcontents:
                        tempstring += item
                    tmpfile = self.squidfile + ".tmp"
                    if not writeFile(tmpfile, tempstring, self.logger):
                        success = False
                    else:
                        if not created:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "conf",
                                     "filepath": self.squidfile}
                            self.statechglogger.recordchgevent(myid, event)
                            self.statechglogger.recordfilechange(self.squidfile,
                                                                 tmpfile, myid)
                            os.rename(tmpfile, self.squidfile)
                            os.chown(self.squidfile, 0, 0)
                            os.chmod(self.squidfile, 420)
                            resetsecon(self.squidfile)
                else:
                    tempstring = ""
                    for item in self.data1:
                        tempstring += item + " " + self.data1[item] + "\n"
                    for item in self.data2:
                        tempstring += item + " " + self.data2[item] + "\n"
                    tmpfile = self.squidfile + ".tmp"
                    if not writeFile(tmpfile, tempstring, self.logger):
                        success = False
                    else:
                        if not created:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "conf",
                                     "filepath": self.squidfile}
                            self.statechglogger.recordchgevent(myid, event)
                            self.statechglogger.recordfilechange(self.squidfile,
                                                                 tmpfile, myid)
                        os.rename(tmpfile, self.squidfile)
                        os.chown(self.squidfile, 0, 0)
                        os.chmod(self.squidfile, 420)
                        resetsecon(self.squidfile)
                self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess 