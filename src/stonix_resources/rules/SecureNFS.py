###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
Created on Mar 11, 2015

@author: dwalker
@change: 2015/04/14 dkennel - Now using new isApplicable method
@change: 2015/07/27 eball - Added logger to setPerms call in fix()
@change: 2016/02/09 eball - Added dnf pkghelper, did PEP8 cleanup
@change: 2016/04/26 Breen Malmberg - added doc string sections to report and fix;
added 2 new methods: checknfscontents() and checkNFSexports(); made variable returns more consistent;
added detailedresults messaging; added formatdetailedresults calls where needed;
added 3 new imports: listdir, isfile, join; added check for nfs exports in report method;
removed unnecessary return call (return success) - in fix method - which was at the same tab level as the
method's return self.rulesuccess call, but before it, so it was always being called instead of
return self.rulesuccess. self.rulesuccess will now return instead of success.
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/10/23 rsn - change to new service helper interface
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
'''

from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, setPerms, checkPerms
from ..stonixutilityfunctions import createFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix
from ..pkghelper import Pkghelper
from ..ServiceHelper import ServiceHelper
import traceback
import os
import re
from os import listdir
from os.path import isfile, join


class SecureNFS(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 39
        self.rulename = "SecureNFS"
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']}}
        self.guidance = ["NSA(3.13.4)", "cce-4241-6", "cce-4465-1",
                         "cce-4559-1", "cce-4015-4", "cce-3667-3",
                         "cce-4310-9", "cce-4438-8", "cce-3579-0"]

        # Configuration item instantiation
        datatype = 'bool'
        key = 'SECURENFS'
        instructions = "To disable this rule set the value of SECURENFS to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

    def report(self):
        '''
        Run report actions for SecureNFS

        @return: self.compliant
        @rtype: bool
        @author: dwalker
        @change: Breen Malmberg - 4/26/2016 - added check for nfs exports
        '''

        self.detailedresults = ""
        self.compliant = True
        nfsexports = True

        try:

            if self.environ.getosfamily() == "linux":
                self.ph = Pkghelper(self.logger, self.environ)

            self.sh = ServiceHelper(self.environ, self.logger)
            if self.environ.getostype() == "Mac OS X":
                nfsfile = "/etc/nfs.conf"
                data1 = {"nfs.lockd.port": "",
                         "nfs.lockd.tcp": "1",
                         "nfs.lockd.udp": "1"}
                if not self.sh.auditService('/System/Library/LaunchDaemons/' +
                                            'com.apple.nfsd.plist',
                                            'com.apple.nfsd'):
                    self.compliant = True
                    self.formatDetailedResults("report", self.compliant,
                                               self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO,
                                         self.detailedresults)
                    return self.compliant
            elif self.ph.manager in ("yum", "zypper", "dnf"):
                nfsfile = "/etc/sysconfig/nfs"
                data1 = {"LOCKD_TCPPORT": "32803",
                         "LOCKD_UDPPORT": "32769",
                         "MOUNTD_PORT": "892",
                         "RQUOTAD_PORT": "875",
                         "STATD_PORT": "662",
                         "STATD_OUTGOING_PORT": "2020"}
                if self.ph.manager == "zypper":
                    nfspackage = "nfs-kernel-server"
                elif self.ph.manager == "yum" or self.ph.manager == "dnf":
                    nfspackage = "nfs-utils"
            elif self.ph.manager == "apt-get":
                nfsfile = "/etc/services"
                data1 = {"rpc.lockd": ["32803/tcp",
                                       "32769/udp"],
                         "rpc.mountd": ["892/tcp",
                                        "892/udp"],
                         "rpc.quotad": ["875/tcp",
                                        "875/udp"],
                         "rpc.statd": ["662/tcp",
                                       "662/udp"],
                         "rpc.statd-bc": ["2020/tcp",
                                          "2020/udp"]}
                nfspackage = "nfs-kernel-server"
            if self.environ.getostype() != "Mac OS X":
                if self.ph.manager in ("apt-get", "zypper", "yum", "dnf"):
                    if not self.ph.check(nfspackage):
                        self.compliant = True
                        self.formatDetailedResults("report", self.compliant,
                                                   self.detailedresults)
                        self.logdispatch.log(LogPriority.INFO,
                                             self.detailedresults)
                        return self.compliant

            if not self.checkNFSexports():
                nfsexports = False

            if os.path.exists(nfsfile):
                nfstemp = nfsfile + ".tmp"
                eqtype = ""
                eqtypestr = ""
                if self.environ.getostype() == "Mac OS X":
                    eqtype = "openeq"
                    self.editor1 = KVEditorStonix(self.statechglogger,
                                                  self.logger, "conf", nfsfile,
                                                  nfstemp, data1, "present",
                                                  eqtype)
                elif self.ph.manager in ("yum", "zypper", "dnf"):
                    eqtype = "closedeq"
                    self.editor1 = KVEditorStonix(self.statechglogger,
                                                  self.logger, "conf", nfsfile,
                                                  nfstemp, data1, "present",
                                                  eqtype)
                elif self.ph.manager == "apt-get":
                    eqtype = "space"
                    self.editor1 = KVEditorStonix(self.statechglogger,
                                                  self.logger, "conf", nfsfile,
                                                  nfstemp, data1, "present",
                                                  eqtype)
                if eqtype == "openeq":
                    eqtypestr = " = "
                elif eqtype == "closedeq":
                    eqtypestr = "="
                elif eqtype == "space":
                    eqtypestr = " "

                if not self.editor1.report():
                    if self.editor1.fixables:
                        missingconfiglines = []
                        for item in self.editor1.fixables:
                            if isinstance(data1[item], list):
                                for li in data1[item]:
                                    missingconfiglines.append(str(item) + eqtypestr + str(li))
                            else:
                                missingconfiglines.append(str(item) + eqtypestr + str(data1[item]))
                        self.detailedresults += "\nThe following configuration lines are missing from " + str(nfsfile) + ":\n" + "\n".join(missingconfiglines)
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    self.compliant = False
                if not checkPerms(nfsfile, [0, 0, 420], self.logger):
                    self.detailedresults += "\nPermissions aren't correct on " \
                        + nfsfile
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    self.compliant = False
            else:
                self.detailedresults += "\n" + nfsfile + " does not exist"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                self.compliant = False

            export = "/etc/exports"
            if os.path.exists(export):
                extemp = export + ".tmp"
                data2 = {"all_squash": "",
                         "no_root_squash": "",
                         "insecure_locks": ""}
                self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", export, extemp, data2,
                                              "notpresent", "space")
                if not self.editor2.report():
                    incorrectconfiglines = []
                    if self.editor2.fixables:
                        for item in self.editor2.fixables: # no fixables being generated for items not compliant with data2 and the "notpresent" directive
                            incorrectconfiglines.append(str(item))
                        self.detailedresults += "\nThe following configuration options are insecure, in file " + str(export) + ":\n" + "\n".join(incorrectconfiglines)
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    self.compliant = False
                if not checkPerms(export, [0, 0, 420], self.logger):
                    self.detailedresults += "\n" + export + " file doesn't " + \
                        "have the correct permissions"
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    self.compliant = False
            else:
                self.detailedresults += "\n" + export + " file doesn't exist"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                self.compliant = False
            if not nfsexports:
                self.compliant = False
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def checkNFSexports(self):
        '''
        check the NFS export lines in the exports configuration file

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        @change: method first added 4/26/2016
        '''

        retval = True
        filename = "/etc/exports"
        directory = "/etc/exports.d"
        fileslist = []

        try:

            if os.path.exists(filename):

                f = open(filename, "r")
                contentlines = f.readlines()
                f.close()

                if not self.checkNFScontents(contentlines, filename):
                    retval = False

            if os.path.exists(directory):
                fileslist = [f for f in listdir(directory) if isfile(join(directory, f))]
            if fileslist:
                for f in fileslist:
                    f = open(filename, "r")
                    contentlines = f.readlines()
                    f.close()
                    if not self.checkNFScontents(contentlines, str(f)):
                        retval = False

        except Exception:
            raise
        return retval

    def checkNFScontents(self, contentlines, filename=""):
        '''
        check given list of contentlines for required nfs export formatting

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        @change: method first added 4/29/2016
        '''

        retval = True

        if not filename:
            filename = "(file name not specified)"
        if not isinstance(filename, basestring):
            filename = "(file name not specified)"

        if not isinstance(contentlines, list):
            self.logger.log(LogPriority.DEBUG, "Parameter contentlines must be of type: list!")

        if not contentlines:
            self.logger.log(LogPriority.DEBUG, "Parameter contentlines was empty!")

        try:

            if contentlines:
                for line in contentlines:
                    if re.search('^#', line):
                        continue
                    elif re.search('^\/', line):
                        # search for overly broad exports
                        broadexports = ['^\/\w+.*\s*\d{2,3}\.\d{2,3}\.0\.0\/16\b', '^\/\w+.*\s*\d{1,3}\.0\.0\.0\/8\b', '^\/\w+.*\s*.*\*.*']
                        for be in broadexports:
                            if re.search(be, line):
                                retval = False
                                self.detailedresults += "The nfs export line:\n" + str(line) + "\nin " + str(filename) + " contains an export that is overly broad."
                    else:
                        if re.search('^([^ !$`&*()+]|(\\[ !$`&*()+]))+\s*', line):
                            sline = line.split()
                            if len(sline) < 2:
                                retval = False
                                self.detailedresults += "\nThe export line:\n" + str('\"' + line.strip() + '\"') + " in " + str(filename) + " lacks a host specification."
            if not retval:
                self.detailedresults += "\n\nThere is no automatic fix action for host exports. Please ensure that each NFS export in " + str(filename) + " has a host specification.\nSee man exports for help.\n"

        except Exception:
            raise
        return retval

    def fix(self):
        '''
        Run fix actions for SecureNFS

        @return: self.rulesuccess
        @rtype: bool
        @author: dwalker
        @change: Breen Malmberg - 4/26/2016 - changed location of defaults variables in method;
                added detailedresults message if fix run while CI disabled; added formatdetailedresults update if fix called when CI disabled;
                changed return value to always be self.rulesuccess; updated self.rulesuccess based on success variable as well
        @change: Breen Malmberg - 7/11/2017 - added another service check on mac os x; no files will be created on mac if the service is not
                enabled
        '''

        self.logdispatch.log(LogPriority.DEBUG, "Entering SecureNFS.fix()...")

        success = True
        changed1, changed2 = False, False
        installed = False
        self.detailedresults = ""

        try:

            if not self.ci.getcurrvalue():
                self.detailedresults += "\nThe CI for this rule was not enabled. Nothing has been done."
                success = True
                self.formatDetailedResults("fix", success, self.detailedresults)
                self.logdispatch.log(LogPriority.DEBUG, "Exiting SecureNFS.fix()...")
                return success

            # Clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.environ.getostype() == "Mac OS X":
                nfsservice = "nfsd"
                nfsfile = "/etc/nfs.conf"
                data1 = {"nfs.lockd.port": "",
                         "nfs.lockd.tcp": "1",
                         "nfs.lockd.udp": "1"}

            elif self.ph.manager in ("yum", "zypper", "dnf"):
                nfsfile = "/etc/sysconfig/nfs"
                data1 = {"LOCKD_TCPPORT": "32803",
                         "LOCKD_UDPPORT": "32769",
                         "MOUNTD_PORT": "892",
                         "RQUOTAD_PORT": "875",
                         "STATD_PORT": "662",
                         "STATD_OUTGOING_PORT": "2020"}

                nfsservice = "nfs"
                if self.ph.manager == "zypper":
                    nfspackage = "nfs-kernel-server"
                elif self.ph.manager == "yum" or self.ph.manager == "dnf":
                    nfspackage = "nfs-utils"

            elif self.ph.manager == "apt-get":
                nfsservice = "nfs-kernel-server"
                nfspackage = "nfs-kernel-server"
                nfsfile = "/etc/services"
                data1 = {"rpc.lockd": ["32803/tcp",
                                       "32769/udp"],
                         "rpc.mountd": ["892/tcp",
                                        "892/udp"],
                         "rpc.quotad": ["875/tcp",
                                        "875/udp"],
                         "rpc.statd": ["662/tcp",
                                       "662/udp"],
                         "rpc.statd-bc": ["2020/tcp",
                                          "2020/udp"]}

            if self.environ.getostype() != "Mac OS X":
                if self.ph.manager in ("apt-get", "zypper"):
                    if not self.ph.check(nfspackage):
                        success = True
                        self.formatDetailedResults("fix", success,
                                                   self.detailedresults)
                        self.logdispatch.log(LogPriority.INFO,
                                             self.detailedresults)
                        return success

            if not os.path.exists(nfsfile):
                if createFile(nfsfile, self.logger):
                    nfstemp = nfsfile + ".tmp"
                    if self.environ.getostype() == "Mac OS X":
                        if not self.sh.auditService('/System/Library/LaunchDaemons/com.apple.nfsd.plist', serviceTarget='com.apple.nfsd'):
                            success = True
                            self.formatDetailedResults("fix", success,
                                                       self.detailedresults)
                            self.logdispatch.log(LogPriority.INFO,
                                                 self.detailedresults)
                            return success
                        self.editor1 = KVEditorStonix(self.statechglogger,
                                                      self.logger, "conf",
                                                      nfsfile, nfstemp, data1,
                                                      "present", "openeq")
                    elif self.ph.manager in ("yum", "zypper", "dnf"):
                        self.editor1 = KVEditorStonix(self.statechglogger,
                                                      self.logger, "conf",
                                                      nfsfile, nfstemp, data1,
                                                      "present", "closedeq")
                    elif self.ph.manager == "apt-get":
                        self.editor1 = KVEditorStonix(self.statechglogger,
                                                      self.logger, "conf",
                                                      nfsfile, nfstemp, data1,
                                                      "present", "space")
                    if not self.editor1.report():
                        if not self.editor1.fix():
                            success = False
                            debug = "fix for editor1 failed"
                            self.logger.log(LogPriority.DEBUG, debug)
                        else:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            self.editor1.setEventID(myid)
                            if not self.editor1.commit():
                                success = False
                                debug = "commit for editor1 failed"
                                self.logger.log(LogPriority.DEBUG, debug)
                            else:
                                changed1 = True
                    if not checkPerms(nfsfile, [0, 0, 420], self.logger):
                        if not setPerms(nfsfile, [0, 0, 420], self.logger,
                                        self.statechglogger):
                            success = False
                            debug = "Unable to set permissions on " + nfsfile
                            self.logger.log(LogPriority.DEBUG, debug)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": nfsfile}
                    self.statechglogger.recordchgevent(myid, event)
                else:
                    success = False
                    debug = "Unable to create " + nfsfile + " file"
                    self.logger.log(LogPriority.DEBUG, debug)
            else:
                if self.editor1.fixables:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor1.setEventID(myid)
                    if not self.editor1.fix():
                        success = False
                        debug = "editor1 fix failed"
                        self.logger.log(LogPriority.DEBUG, debug)
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.editor1.setEventID(myid)
                        if not self.editor1.commit():
                            success = False
                            debug = "editor1 commit failed"
                            self.logger.log(LogPriority.DEBUG, debug)
                        else:
                            changed1 = True
                if not checkPerms(nfsfile, [0, 0, 420], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(nfsfile, [0, 0, 420], self.logger,
                                    self.statechglogger, myid):
                        debug = "Unable to set permissions on " + nfsfile
                        self.logger.log(LogPriority.DEBUG, debug)

            export = "/etc/exports"
            if not os.path.exists(export):
                # mac os x will automatically enable the nfs
                # service and related ports if the file /etc/exports
                # is created
                if self.environ.getostype() == "Mac OS X":
                    if not self.sh.auditService('/System/Library/LaunchDaemons/com.apple.nfsd.plist', serviceTarget='com.apple.nfsd'):
                        success = True
                        self.formatDetailedResults("fix", success,
                                                   self.detailedresults)
                        self.logdispatch.log(LogPriority.INFO,
                                             self.detailedresults)
                        return success
                if createFile(export, self.logger):
                    extemp = export + ".tmp"
                    data2 = {"all_squash": "",
                             "no_root_squash": "",
                             "insecure_locks": ""}
                    self.editor2 = KVEditorStonix(self.statechglogger,
                                                  self.logger, "conf", export,
                                                  extemp, data2, "notpresent",
                                                  "space")
                    if not self.editor2.report():
                        if not self.editor2.fix():
                            success = False
                            debug = "fix for editor2 failed"
                            self.logger.log(LogPriority.DEBUG, debug)
                        else:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            self.editor2.setEventID(myid)
                            if not self.editor2.commit():
                                success = False
                                debug = "commit for editor2 failed"
                                self.logger.log(LogPriority.DEBUG, debug)
                            else:
                                changed2 = True
                    if not checkPerms(export, [0, 0, 420], self.logger):
                        if not setPerms(export, [0, 0, 420], self.logger,
                                        self.statechglogger):
                            success = False
                            debug = "Unable to set permissions on " + export
                            self.logger.log(LogPriority.DEBUG, debug)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": export}
                    self.statechglogger.recordchgevent(myid, event)
            else:
                if installed:
                    extemp = export + ".tmp"
                    data2 = {"all_squash": "",
                             "no_root_squash": "",
                             "insecure_locks": ""}
                    self.editor2 = KVEditorStonix(self.statechglogger,
                                                  self.logger, "conf", export,
                                                  extemp, data2, "notpresent",
                                                  "space")
                    self.editor2.report()
                if self.editor2.removeables:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor2.setEventID(myid)
                    if not self.editor2.fix():
                        success = False
                        debug = "editor2 fix failed"
                        self.logger.log(LogPriority.DEBUG, debug)
                    else:
                        if not self.editor2.commit():
                            success = False
                            debug = "editor2 commit failed"
                            self.logger.log(LogPriority.DEBUG, debug)
                        else:
                            changed2 = True
                if not checkPerms(export, [0, 0, 420], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(export, [0, 0, 420], self.logger,
                                    self.statechglogger, myid):
                        success = False
                        debug = "Unable to set permissions on " + export
                        self.logger.log(LogPriority.DEBUG, debug)

            if changed1 or changed2:
                ## CHANGE (Breen Malmberg) 1/23/2017
                # The self.sh.reloadservice() call, for SHlaunchd, will start
                # the service even if it is not already running.
                # We don't want to start THIS service if it is not
                # already running/enabled!
                # We also don't want to change this functionality at the
                # SHlaunchd class-level, because there may be other
                # instances in which we want it to do a stop and start
                # (aka a full reload), so this decision should be made at
                # the rule-level.
                ##
                if self.sh.isRunning(nfsservice, serviceTarget=nfsservice):
                    self.sh.reloadService(nfsservice, serviceTarget=nfsservice)

            self.logdispatch.log(LogPriority.DEBUG, "Exiting SecureNFS.fix()...")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return success
