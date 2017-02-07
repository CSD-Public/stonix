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
Created on 2016/05/04

Checks the root user's Firefox history for non-local browsing. The root user
should only use the browser for administration tasks.
@author: Eric Ball
'''
from __future__ import absolute_import
from ..CommandHelper import CommandHelper
from ..localize import LOCALDOMAINS
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..rule import Rule
from glob import glob
import os
import re
import traceback

try:
    import sqlite3
except ImportError:
    pass


class AuditFirefoxUsage(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 84
        self.rulename = "AuditFirefoxUsage"
        self.mandatory = True
        self.helptext = """This audit-only rule checks the root user's \
Firefox history for non-local browsing. The root user should only use the \
browser for administration tasks."""
        self.rootrequired = True
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
        self.approvedDomainsCi = self.initCi(datatype, key, instructions,
                                             default)

        datatype = 'bool'
        key = 'DISABLEPROXY'
        instructions = """To disable Firefox's proxy settings, ensuring that \
browsing is limited to local domains in a proxied environment, set \
DISABLEPROXY to True."""
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.ph = Pkghelper(self.logger, self.environ)

    def report(self):
        '''
        @author: Eric Ball
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''
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
                command = ["sqlite3", placesPath, ".tables"]
                ch.executeCommand(command)
                if not ch.getReturnCode() == 0:
                    # The version of sqlite3 on RHEL 6 cannot read these dbs.
                    # Instead, we will examine the file manually, looking for
                    # entries beginning with %\x08.
                    sqlBin = open(placesPath, "rb").read()
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
        '''
        Discover the randomly-generated Firefox profile directory(ies) for the
        root user.

        @author: Eric Ball
        @return: List of Firefox profile directories on the system
        @rtype: list
        '''
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
