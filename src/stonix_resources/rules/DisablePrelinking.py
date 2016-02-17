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
This rule disables the prelinking of executable binaries.

@author: Eric Ball
@change: 2016/02/09 eball Original implementation
'''
from __future__ import absolute_import
import os
import re
import traceback
from ..CommandHelper import CommandHelper
from ..stonixutilityfunctions import createFile, iterate, resetsecon, writeFile
from ..KVEditorStonix import KVEditorStonix
from ..rule import Rule
from ..logdispatcher import LogPriority


class DisablePrelinking(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 89
        self.rulename = "DisablePrelinking"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''This rule disables the prelinking of executable \
binaries. The prelinking feature changes binaries in an attempt to decrease \
their startup time.'''
        self.applicable = {'type': 'white',
                           'family': ['linux']}

        # Configuration item instantiation
        datatype = "bool"
        key = "DISABLEPRELINKING"
        instructions = "To disable this rule, set the value of " + \
                       "DISABLEPRELINKING to false."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.guidance = ["CCE-RHEL7-CCE-TBA 2.1.3.1.2"]
        self.iditerator = 0

        self.ch = CommandHelper(self.logger)
        if re.search("debian|ubuntu", self.environ.getostype().lower()):
            self.isDebian = True
        else:
            self.isDebian = False

    def report(self):
        try:
            if self.isDebian:
                path = "/etc/default/prelink"
            else:
                path = "/etc/sysconfig/prelink"
            self.path = path
            prelink = "/usr/sbin/prelink"
            self.compliant = True
            self.detailedresults = ""

            if os.path.exists(path):
                tmppath = path + ".tmp"
                data = {"PRELINKING": "no"}
                self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                             "conf", path, tmppath,
                                             data, "present", "closedeq")
                if not self.editor.report():
                    self.compliant = False
                    self.detailedresults += path + " does not have the " + \
                        "correct settings.\n"
            else:
                self.compliant = False
                self.detailedresults += path + " does not exist.\n"

            if os.path.exists(prelink):
                self.ch.executeCommand([prelink, "-p"])
                output = self.ch.getOutputString()
                splitout = output.split()
                try:
                    if len(splitout) > 0:
                        numPrelinks = int(splitout[0])  # Potential ValueError
                        if numPrelinks > 0:
                            self.compliant = False
                            self.detailedresults += "There are currently " + \
                                str(numPrelinks) + " prelinked binaries.\n"
                except ValueError:
                    debug = "Unexpected result from " + prelink + ". This " + \
                        "does not affect compliance."
                    self.logger.log(LogPriority.DEBUG, debug)
                    self.detailedresults += debug + "\n"

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
            path = self.path
            tmppath = path + ".tmp"
            prelinkCache = "/etc/prelink.cache"
            self.detailedresults = ""
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if not os.path.exists(path):
                if createFile(path, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation", "filepath": path}
                    self.statechglogger.recordchgevent(myid, event)
                else:
                    success = False
                    self.detailedresults += "Failed to create file: " + \
                        path + "\n"

                if writeFile(tmppath, "PRELINKING=no", self.logger):
                    os.rename(tmppath, path)
                    resetsecon(path)
                else:
                    success = False
                    self.detailedresults += "Failed to write settings " + \
                        "to file: " + path + "\n"
            elif not self.editor.report():
                if self.editor.fix():
                    if self.editor.commit():
                        self.detailedresults += "Changes successfully " + \
                            "committed to " + path + "\n"
                    else:
                        success = False
                        self.detailedresults += "Changes could not be " + \
                            "committed to " + path + "\n"
                else:
                    success = False
                    self.detailedresults += "Could not fix file " + path + "\n"

            # Although the guidance and documentation recommends using "prelink
            # -ua" command, testing has shown this command to be completely
            # unreliable. Instead, the prelink cache will be removed entirely.
            if os.path.exists(prelinkCache):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.statechglogger.recordfiledelete(prelinkCache, myid)
                os.remove(prelinkCache)

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
