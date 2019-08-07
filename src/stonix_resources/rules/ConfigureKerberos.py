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
This method runs all the report methods for RuleKVEditors in defined in the
dictionary

@author: Ekkehard J. Koch
@change: 04/21/2014 Ekkehard - Original Implementation
@change: 2014/06/17 David Kennel - Fixed traceback on Debian
@change: 2014/07/14 Ekkehard - Fixed report to self.fh.evaluateFiles()
@change: 2015/04/14 David Kennel updated for new isApplicable
@change: 2015/08/17 Eric Ball - Updated to work with Linux
@change: 2015/10/07 Eric Ball - Help text cleanup
@change: 2015/11/02 Eric Ball - Added undo events to package installation
@change: 2015/11/09 Ekkehard - make eligible for OS X El Capitan
@change: 2017/07/07 Ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 Ekkehard - Added self.sethelptext()
@change: 2017/10/24 Roy Nielsen - removed unused service helper
@change: 2017/11/13 Ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 Ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 Ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
"""



import os
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..filehelper import FileHelper
from ..CommandHelper import CommandHelper
from ..pkghelper import Pkghelper
from ..stonixutilityfunctions import iterate
from ..localize import MACKRB5, LINUXKRB5


class ConfigureKerberos(Rule):
    '''@author: Ekkehard J. Koch'''

    def __init__(self, config, environ, logdispatcher, statechglogger):
        """

        @param config:
        @param environ:
        @param logdispatcher:
        @param statechglogger:
        """

        Rule.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 255
        self.rulename = 'ConfigureKerberos'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = []
        self.applicable = {'type': 'white', 'family': 'linux',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        # This if/else statement fixes a bug in Configure Kerberos that
        # occurs on Debian systems due to the fact that Debian has no wheel
        # group by default.
        if self.environ.getosfamily() == 'darwin':
            self.files = {"krb5.conf":
                          {"path": "/etc/krb5.conf",
                           "remove": False,
                           "content": MACKRB5,
                           "permissions": 0o644,
                           "owner": os.getuid(),
                           "group": "wheel",
                           "eventid": str(self.rulenumber).zfill(4) + "krb5"},
                          "edu.mit.Kerberos":
                          {"path": "/Library/Preferences/edu.mit.Kerberos",
                           "remove": True,
                           "content": None,
                           "permissions": None,
                           "owner": None,
                           "group": None,
                           "eventid": str(self.rulenumber).zfill(4) +
                           "Kerberos"},
                          "edu.mit.Kerberos.krb5kdc.launchd":
                          {"path": "/Library/Preferences/edu.mit.Kerberos.krb5kdc.launchd",
                           "remove": True,
                           "content": None,
                           "permissions": None,
                           "owner": None,
                           "group": None,
                           "eventid": str(self.rulenumber).zfill(4) +
                           "krb5kdc"},
                          "kerb5.conf":
                          {"path": "/etc/kerb5.conf",
                           "remove": True,
                           "content": None,
                           "permissions": None,
                           "owner": None,
                           "group": None,
                           "eventid": str(self.rulenumber).zfill(4) + "kerb5"},
                          "edu.mit.Kerberos.kadmind.launchd":
                          {"path": "/Library/Preferences/edu.mit.Kerberos.kadmind.launchd",
                           "remove": True,
                           "content": None,
                           "permissions": None,
                           "owner": None,
                           "group": None,
                           "eventid": str(self.rulenumber).zfill(4) +
                           "kadmind"},
                          }
        else:
            self.files = {"krb5.conf":
                          {"path": "/etc/krb5.conf",
                           "remove": False,
                           "content": LINUXKRB5,
                           "permissions": 0o644,
                           "owner": "root",
                           "group": "root",
                           "eventid": str(self.rulenumber).zfill(4) + "krb5"}}
        self.ch = CommandHelper(self.logdispatch)
        self.fh = FileHelper(self.logdispatch, self.statechglogger)
        if self.environ.getosfamily() == 'linux':
                self.ph = Pkghelper(self.logdispatch, self.environ)
        self.filepathToConfigure = []
        for filelabel, fileinfo in sorted(self.files.items()):
            if fileinfo["remove"]:
                msg = "Remove if present " + str(fileinfo["path"])
            else:
                msg = "Add or update if needed " + str(fileinfo["path"])
            self.filepathToConfigure.append(msg)
            self.fh.addFile(filelabel,
                            fileinfo["path"],
                            fileinfo["remove"],
                            fileinfo["content"],
                            fileinfo["permissions"],
                            fileinfo["owner"],
                            fileinfo["group"],
                            fileinfo["eventid"]
                            )
        # Configuration item instantiation
        datatype = "bool"
        key = "CONFIGUREFILES"
        instructions = "When Enabled will fix these files: " + \
            str(self.filepathToConfigure)
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

    def report(self):
        '''run report actions for configure kerberos
        determine compliance status of the current system
        return True if compliant, False if non-compliant


        :returns: self.compliant

        :rtype: bool
@author: ???
@change: Breen Malmberg - 2/23/2017 - added doc string; added const checks preamble to report and fix methods

        '''

        self.compliant = True
        self.detailedresults = ""

        # UPDATE THIS SECTION IF YOU CHANGE THE CONSTANTS BEING USED IN THE RULE
        constlist = [MACKRB5, LINUXKRB5]
        if not self.checkConsts(constlist):
            self.compliant = False
            self.detailedresults = "\nPlease ensure that the constants: MACKRB5, LINUXKRB5, in localize.py, are defined and are not None. This rule will not function without them."
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            return self.compliant

        try:

            if self.environ.getosfamily() == 'linux':
                packagesRpm = ["pam_krb5", "krb5-libs", "krb5-workstation",
                               "sssd-krb5", "sssd-krb5-common"]
                packagesDeb = ["krb5-config", "krb5-user", "libpam-krb5"]
                packagesSuse = ["pam_krb5", "sssd-krb5", "sssd-krb5-common",
                                "krb5-client", "krb5"]
                if self.ph.determineMgr() == "apt-get":
                    self.packages = packagesDeb
                elif self.ph.determineMgr() == "zypper":
                    self.packages = packagesSuse
                else:
                    self.packages = packagesRpm
                for package in self.packages:
                    if not self.ph.check(package) and self.ph.checkAvailable(package):
                        self.compliant = False
                        self.detailedresults += package + " is not installed\n"
            if not self.fh.evaluateFiles():
                self.compliant = False
                self.detailedresults += self.fh.getFileMessage()

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''run fix actions


        :returns: self.rulesuccess

        :rtype: bool
@author: ???
@change: Breen Malmberg - 2/23/2017 - added doc string; added checkconsts preamble to ensure
        the rule does not attempt to run without requied information (from localize.py)

        '''

        self.rulesuccess = True
        self.detailedresults = ""
        self.iditerator = 0

        # UPDATE THIS SECTION IF YOU CHANGE THE CONSTANTS BEING USED IN THE RULE
        constlist = [MACKRB5, LINUXKRB5]
        if not self.checkConsts(constlist):
            fixsuccess = False
            self.formatDetailedResults("fix", fixsuccess, self.detailedresults)
            return fixsuccess

        try:

            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.ci.getcurrvalue():
                pkgsToInstall = []
                if self.environ.getosfamily() == 'linux':
                    for package in self.packages:
                        if not self.ph.check(package):
                            if self.ph.checkAvailable(package):
                                pkgsToInstall.append(package)
                    for package in pkgsToInstall:
                        if self.ph.install(package):
                            self.iditerator += 1
                            myid = iterate(self.iditerator,
                                           self.rulenumber)
                            event = {"eventtype": "pkghelper",
                                     "pkgname": package,
                                     "startstate": "removed",
                                     "endstate": "installed"}
                            self.statechglogger.recordchgevent(myid, event)
                        else:
                            self.rulesuccess = False
                            self.detailedresults += "Installation of " + package + " did not succeed.\n"
                if not self.fh.fixFiles():
                    self.rulesuccess = False
                    self.detailedresults += self.fh.getFileMessage()
            else:
                self.rulesuccess = False
                self.detailedresults = str(self.ci.getkey()) + " was disabled. No action was taken!"

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
