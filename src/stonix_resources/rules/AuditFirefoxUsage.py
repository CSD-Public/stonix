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
Created on 2016/05/04

Checks the root user's Firefox history for non-local browsing. The root user
should only use the browser for administration tasks.

@author: Eric Ball
@change: 2017/08/28 Ekkehard - Added self.sethelptext()
@changee 2019/06/13 Breen Malmberg - updated documentation to reST format;
        filled in missing documentation
"""


from CommandHelper import CommandHelper
from localize import LOCALDOMAINS
from logdispatcher import LogPriority
from pkghelper import Pkghelper
from rule import Rule
from glob import glob
import os
import re
import traceback

try:
    import sqlite3
except ImportError:
    pass


class AuditFirefoxUsage(Rule):
    """
    This module will audit firefox browser usage to determine
    if any site not listed in the APPROVEDDOMAINS CI has been visited
    while running in root mode

    """

    def __init__(self, config, environ, logger, statechglogger):
        """
        private method to initialize the module

        :param config: configuration object instance
        :param environ: environment object instance
        :param logger: logdispatcher object instance
        :param statechglogger: statechglogger object instance
        """

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 84
        self.rulename = "AuditFirefoxUsage"
        self.mandatory = True
        self.rootrequired = True
        self.sethelptext()
        self.formatDetailedResults("initialize")
        self.guidance = []
        self.applicable = {'type': 'white',
                           'family': ['linux']}
        # Configuration item instantiation
        datatype = 'list'
        key = 'APPROVEDDOMAINS'
        instructions = """This is a list of domains which the root user is \
approved to browse."""
        default = LOCALDOMAINS
        if default is None:
            default = ["localhost"]
        elif not default:
            default = ["localhost"]
        self.approvedDomainsCi = self.initCi(datatype, key, instructions, default)

        datatype = 'bool'
        key = 'DISABLEPROXY'
        instructions = """To disable Firefox's proxy settings, ensuring that \
browsing is limited to local domains in a proxied environment, set \
DISABLEPROXY to True."""
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.ph = Pkghelper(self.logger, self.environ)
        self.auditonly = True

    def report(self):
        """
        report the status of the rule's compliance with root-enabled firefox browsing

        :returns: self.compliant - True if compliant, False if not

        """

        # UPDATE THIS SECTION IF YOU CHANGE THE CONSTANTS BEING USED IN THE RULE
        constlist = [LOCALDOMAINS]
        if not self.checkConsts(constlist):
            self.compliant = False
            self.detailedresults = "\nPlease ensure that the constant: LOCALDOMAINS, in localize.py, is defined and is not None. This rule will not function without it."
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            return self.compliant

        try:
            self.detailedresults = ""
            compliant = True
            ffDirs = self.getFirefoxDirs()
            urls = []
            package = ""

            if self.ph.checkAvailable("sqlite3"):
                package = "sqlite3"
            elif self.ph.checkAvailable("sqlite"):
                package = "sqlite"
            if not self.ph.check(package):
                self.ph.install(package)

            for ffDir in ffDirs:
                placesPath = ffDir + "/places.sqlite"
                if not os.path.exists(placesPath):
                    continue
                ch = CommandHelper(self.logger)
                command = ["/usr/bin/sqlite3", placesPath, ".tables"]
                ch.executeCommand(command)
                if not ch.getReturnCode() == 0:
                    # The version of sqlite3 on RHEL 6 cannot read these dbs.
                    # Instead, we will examine the file manually, looking for
                    # entries beginning with %\x08.
                    sqlBin = open(placesPath, "rb").read()
                    if isinstance(sqlBin, bytes):
                        try:
                            sqlBin = sqlBin.decode("utf-8")
                        except:
                            pass
                    sqlBin = str(sqlBin)
                    urlList = re.findall("%\x08https?://.*?/", sqlBin)
                    for url in urlList:
                        urls.append(url[2:])
                else:
                    conn = sqlite3.connect(placesPath)
                    c = conn.cursor()
                    c.execute("SELECT host FROM moz_hosts")
                    results = c.fetchall()
                    debug = "Results of 'SELECT host FROM moz_hosts': " + \
                        str(results)
                    self.logger.log(LogPriority.DEBUG, debug)
                    # Results are inside of a tuple
                    for item in results:
                        urls.append(item[0])
            badUrls = []
            urls = list(set(urls))
            if urls:
                self.logger.log(LogPriority.DEBUG, "URLs found: " + str(urls))
                for url in urls:
                    approved = self.approvedDomainsCi.getcurrvalue()
                    foundApproved = False
                    for site in approved:
                        if re.search(site, url):
                            foundApproved = True
                    if not foundApproved:
                        compliant = False
                        badUrls.append(url)
                if badUrls:
                    self.detailedresults = "URLs found in root's " + \
                        "Firefox history that are not on the approved " + \
                        "list: " + ", ".join(badUrls) + "\n"
            self.logger.log(LogPriority.DEBUG,
                            "Bad URLs found: " + str(badUrls))
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def getFirefoxDirs(self):
        """Discover the randomly-generated Firefox profile directory(ies) for the
        root user.

        :returns: ffDirs - List of Firefox profile directories on the system

        """
        # It's possible to have several FF profiles for each user account. This
        # method will therefore return a list.
        ffDirs = []
        homeDir = "/root"
        ffParent = homeDir + "/.mozilla/firefox"
        if os.path.exists(ffParent):
            profileDirs = glob(ffParent + "/*.default")
            debug = "Found the following Firefox profile directories: " + \
                str(profileDirs)
            self.logger.log(LogPriority.DEBUG, debug)
            for pDir in profileDirs:
                # Since we gave glob the full path, the returned list will
                # have the full path for each entry
                ffDirs.append(pDir)
        return ffDirs
