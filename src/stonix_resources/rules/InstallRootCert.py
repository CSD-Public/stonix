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
Created on 2016/03/23

Installs the local root certificate in the Linux cert chain
@author: Eric Ball
'''
from __future__ import absolute_import
from ..CommandHelper import CommandHelper
from ..localize import ROOTCERT
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..rule import Rule
from ..stonixutilityfunctions import createFile, writeFile, iterate, resetsecon
from glob import glob
import os
import re
import traceback


class InstallRootCert(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 10
        self.rulename = "InstallRootCert"
        self.mandatory = False
        self.helptext = "This rule will install the local root certificate " + \
            "into the Linux certificate chain. It will also attempt to " + \
            "register this certificate with Firefox/Iceweasel."
        self.rootrequired = True
        self.detailedresults = "InstallRootCert has not yet been run."
        self.guidance = []
        self.applicable = {'type': 'white',
                           'family': ['linux']}
        # Configuration item instantiation
        datatype = 'bool'
        key = 'INSTALLROOTCERTSYSTEM'
        instructions = """This CI will install the local root certificate at \
the system level. This will not install the certificate for any web browsers. \
To disable system-level installation of the local root certificate, set the \
value of INSTALLROOTCERTSYSTEM to False."""
        default = True
        self.SysCi = self.initCi(datatype, key, instructions, default)

        datatype = 'bool'
        key = 'INSTALLROOTCERTBROWSER'
        instructions = """This CI will install the local root certificate into \
Firefox/Iceweasel for all users with at least one profile in their \
/home/[user]/.mozilla/firefox directory. This will not install the certificate \
for any other web browsers. To disable installation of the local root \
certificate into Firefox, set the value of INSTALLROOTCERTBROWSER to False."""
        default = True
        self.FfCi = self.initCi(datatype, key, instructions, default)

    def report(self):
        '''
        @author: Eric Ball
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''
        try:
            self.detailedresults = ""
            systemFound = False
            browserFound = False
            self.ch = CommandHelper(self.logger)
            rootcert = re.escape(ROOTCERT)
            # Replace newlines with whitespace escapes so that \r\n is accepted
            rootcert = rootcert.replace("\\\n", "\s+")

            myos = self.environ.getostype().lower()
            self.isDeb = False
            self.isSuse = False
            if re.search("debian|ubuntu", myos):
                self.isDeb = True
            elif re.search("opensuse", myos):
                self.isSuse = True

            if self.isDeb:
                certsPath = "/usr/local/share/ca-certificates/"
                certs = []
                if os.path.exists(certsPath):
                    certs = os.listdir(certsPath)
                for cert in certs:
                    certText = open(certsPath + cert).read()
                    if re.search(rootcert, certText):
                        systemFound = True
                if not systemFound:
                    self.detailedresults += "Could not find DOE " + \
                        "certificate in " + certsPath + "\n"
            elif self.isSuse:
                anchorsPath = "/etc/pki/trust/anchors/"
                anchors = []
                if os.path.exists(anchorsPath):
                    anchors = os.listdir(anchorsPath)
                for anchor in anchors:
                    anchorText = open(anchorsPath + anchor).read()
                    if re.search(rootcert, anchorText):
                        systemFound = True
                if not systemFound:
                    self.detailedresults += "Could not find DOE " + \
                        "certificate in " + anchorsPath + "\n"
            else:
                anchorsPath = "/etc/pki/ca-trust/source/anchors/"
                anchors = []
                if os.path.exists(anchorsPath):
                    anchors = os.listdir(anchorsPath)
                for anchor in anchors:
                    anchorText = open(anchorsPath + anchor).read()
                    if re.search(rootcert, anchorText):
                        systemFound = True
                        debug = "Root cert found in " + anchorsPath + anchor
                        self.logger.log(LogPriority.DEBUG, debug)
                certsPath = "/etc/pki/tls/certs/"
                certs = []
                if os.path.exists(certsPath):
                    certs = os.listdir(certsPath)
                for cert in certs:
                    certText = open(certsPath + cert).read()
                    if re.search(rootcert, certText):
                        systemFound = True
                        debug = "Root cert found in " + certsPath + cert
                        self.logger.log(LogPriority.DEBUG, debug)
                if not systemFound:
                    self.detailedresults += "Could not find DOE certificate in " + \
                        anchorsPath + " or " + certsPath + "\n"

            # certutil is needed for this functionality. We will install the
            # necessary package if it is not already on the system.
            ph = Pkghelper(self.logger, self.environ)
            if self.isDeb:
                pkg = "libnss3-tools"
            elif self.isSuse:
                pkg = "mozilla-nss-tools"
            else:
                pkg = "nss-tools"
            if not ph.check(pkg):
                ph.install(pkg)

            ffDirs = self.getFirefoxDirs()
            debug = "Firefox directories found: " + str(ffDirs)
            self.logger.log(LogPriority.DEBUG, debug)
            if len(ffDirs) == 0:
                # If there are no Firefox directories, rule is compliant
                browserFound = True
            name = "Department of Energy - U.S. Government"
            for ffDir in ffDirs:
                try:
                    cmd = ["certutil", "-L", "-an", name, "-d", ffDir]
                    self.ch.executeCommand(cmd)
                except OSError:
                    browserFound = False
                else:
                    if re.search(rootcert, self.ch.getAllString()):
                        browserFound = True
            if not browserFound:
                self.detailedresults += "Could not find DOE certificate " + \
                    "in Firefox database for one or more users\n"
                self.ffDirs = ffDirs

            self.systemFound = systemFound
            self.browserFound = browserFound
            self.compliant = systemFound and browserFound
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
        Discover the randomly-generated Firefox profile directories for all
        users that have a home directory.

        @author: Eric Ball
        @return: List of Firefox profile directories on the system
        @rtype: list
        '''
        homeDirs = os.listdir("/home")
        debug = "Found home dirs for users: " + str(homeDirs)
        self.logger.log(LogPriority.DEBUG, debug)
        ffDirs = []
        for hDir in homeDirs:
            ffParent = "/home/" + hDir + "/.mozilla/firefox"
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

    def fix(self):
        '''
        @author: Eric Ball
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''
        try:
            self.detailedresults = ""
            success = True
            if not self.SysCi.getcurrvalue() and not self.FfCi.getcurrvalue():
                return

            # Clear out event history so only the latest fix is recorded
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            self.iditerator = 0

            if not self.systemFound and self.SysCi.getcurrvalue():
                if self.isDeb:
                    certPath = "/usr/local/share/ca-certificates/lanl-root.pem"
                    cmd = "update-ca-certificates"
                elif self.isSuse:
                    certPath = "/etc/pki/trust/anchors/lanl-root.pem"
                    cmd = "update-ca-certificates"
                else:
                    certPath = "/etc/pki/ca-trust/source/anchors/lanl-root.pem"
                    cmd = "update-ca-trust"

                if createFile(certPath, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation", "filepath": certPath}
                    self.statechglogger.recordchgevent(myid, event)
                else:
                    success = False
                    self.detailedresults += "Failed to create file: " + \
                        certPath + "\n"

                if writeFile(certPath, ROOTCERT, self.logger):
                    resetsecon(certPath)
                else:
                    success = False
                    self.detailedresults += "Failed to write settings " + \
                        "to file: " + certPath + "\n"
                if success:
                    if not self.ch.executeCommand(cmd):
                        success = False
                        self.detailedresults += 'Command "' + cmd + \
                            '" failed\n'
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "comm", "command": cmd}
                        self.statechglogger.recordchgevent(myid, event)

            if not self.browserFound and self.FfCi.getcurrvalue():
                ffDirs = self.ffDirs
                tmppath = "/tmp/lanl-root.pem"
                writeFile(tmppath, ROOTCERT, self.logger)
                for ffDir in ffDirs:
                    cmd = ["certutil", "-A", "-n", "Department of Energy - " +
                           "U.S. Government", "-t", "TCu,Cu,Cu", "-i",
                           tmppath, "-d", ffDir]
                    if not self.ch.executeCommand(cmd):
                        success = False
                        self.detailedresults += 'Command "' + cmd + \
                            '" failed\n'
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        cmd = ["certutil", "-D", "-n", "Department of " +
                               "Energy - U.S. Government", "-d", ffDir]
                        event = {"eventtype": "comm", "command": cmd}
                        self.statechglogger.recordchgevent(myid, event)

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
