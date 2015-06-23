'''
Created on Apr 22, 2015

@author: dwalker
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, setPerms, checkPerms
from ..stonixutilityfunctions import resetsecon, createFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix
from ..pkghelper import Pkghelper
import traceback
import os


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
            self.ph = Pkghelper(self.logger, self.environ)
            self.data1 = {"ddns-update-style": "none;",
                          "deny": ["declines;",
                                   "bootp;"]}
            self.data2 = {"option": ["domain-name;",
                                     "domain-name-servers;",
                                     "nis-domain;",
                                     "nis-servers;",
                                     "ntp-servers;",
                                     "routers;",
                                     "time-offset;"]}
            if self.ph.manager == "zypper":
                self.package = "dhcp-server"
                self.path = "/etc/dhcpd.conf"
            elif self.ph.manager == "yum":
                self.package = "dhcp"
                self.path = "/etc/dhcp/dhcpd.conf"
            elif self.ph.manager == "apt-get":
                self.package = "isc-dhcp-server"
                self.path = "/etc/dhcp/dhcpd.conf"
            compliant = True
            if self.ph.check(self.package):
                if os.path.exists(self.path):
                    if not checkPerms(self.path, [0, 0, 420], self.logger):
                        compliant = False
                    self.tmppath = self.path + ".tmp"
                    self.editor = KVEditorStonix(self.statechglogger,
                                                 self.logger, "conf",
                                                 self.path, self.tmppath,
                                                 self.data1, "present",
                                                 "space")
                    if not self.editor.report():
                        compliant = False
                    self.editor.setData(self.data2)
                    self.editor.setIntent("notpresent")
                    if not self.editor.report():
                        compliant = False
                else:
                    compliant = False
            self.compliant = compliant
            if self.compliant:
                self.detailedresults = "SecureDHCP report has been run " + \
                    "and is compliant"
            else:
                self.detailedresults = "SecureDHCP report has been run " + \
                    "and is not compliant"
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
            if self.ph.check(self.package):
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
                if self.editor.fixables or self.editor.removeables:
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
            if self.rulesuccess:
                self.detailedresults = "SecureDHCP fix has been run to " + \
                    "completion"
            else:
                self.detailedresults = "SecureDHCP fix has been run " + \
                    "but not to completion"
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
