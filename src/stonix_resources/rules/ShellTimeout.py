'''
Created on 07/01/2015

@author: eball
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


class ShellTimeout(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 120
        self.rulename = "ShellTimeout"
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.helptext = '''Configures DHCP functionality '''
        datatype = "bool"
        key = "SHELLTIMEOUT"
        instructions = '''To disable this rule set the value of \
        SHELLTIMEOUT to False.'''
        default = False
        self.ci = self.initCi(datatype, key, instructions, default)

        self.guidance = ["NSA 2.3.5.5", "CCE 3689-7", "CCE 3707-7"]
        self.applicable = {"type": "white",
                           "family": ["linux"]}
        self.iditerator = 0
        self.created = False

    def report(self):
        try:
            #self.ph = Pkghelper(self.logger, self.environ)
            self.path = "/etc/profile.d/tmout.sh"
            self.data1 = {"TMOUT": "900"}
            self.data2 = {["readonly", "export"]: "TMOUT"}
            compliant = True
            if os.path.exists(self.path):
                if not checkPerms(self.path, [0, 0, 755], self.logger) and \
                   not checkPerms(self.path, [0, 0, 644], self.logger):
                    compliant = False
                self.tmppath = self.path + ".tmp"
                self.editor = KVEditorStonix(self.statechglogger,
                                             self.logger, "conf",
                                             self.path, self.tmppath,
                                             self.data1, "present",
                                             "closedeq")
                if not self.editor.report():
                    compliant = False
                self.editor = KVEditorStonix(self.statechglogger,
                                             self.logger, "conf",
                                             self.path, self.tmppath,
                                             self.data2, "present",
                                             "space")
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
