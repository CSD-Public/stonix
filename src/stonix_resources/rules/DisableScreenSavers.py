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
Created on Nov 12, 2013

@author: dwalker
@change: dkennel 04/18/2014 Replaced old style CI with new
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change 2017/08/28 rsn Fixing to use new help text methods
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import readFile, writeFile, checkPerms
from ..stonixutilityfunctions import resetsecon
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from re import search
import os
import traceback


class DisableScreenSavers(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        '''Constructor'''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 246
        self.rulename = "DisableScreenSavers"
        self.mandatory = True
        self.formatDetailedResults("initialize")
        self.detailedresults = "DisableScreenSavers has not yet been run."
        datatype = 'bool'
        key = 'DISABLESCREEN'
        instructions = "To disable this rule set the value of " + \
            "DISABLESCREEN to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.guidance = ["NSA 2.3.1.3"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd']}
        self.sethelptext()

    def report(self):
        try:
            compliant = True
            self.detailedresults = ""
            self.helper = Pkghelper(self.logger, self.environ)
            config = ""
            self.paths = {"/usr/share/kde4/services/ScreenSavers/": ".desktop",
                          "/usr/share/applnk/System/ScreenSavers/": "desktop",
                          "/usr/share/applications/screensavers/": "dekstop",
                          "/usr/share/kde4/services/ScreenSavers/": "desktop",
                          "/usr/X11R6/lib/xscreensaver/": "desktop",
                          "/usr/libexec/xscreensaver/": "desktop",
                          "/usr/lib/xscreensaver/": "desktop",
                          "/usr/lib64/xscreensaver/": "desktop"}
            self.path = "/usr/lib/X11/app-defaults/XScreenSaver"
            self.badsavers = ["antspotlight", "apple2", "blitspin", "bsod",
                              "bumps", "carousel", "decayscreen", "distort",
                              "flag", "flipscreen3d", "fontglide", "gflux",
                              "glslideshow", "gltext", "jigsaw", "Kgravity",
                              "KScience", "KSlideshow", "media", "mirrorblob",
                              "noseguy", "phosphor", "photopile", "ripples",
                              "rotzoomer", "science", "slidescreen", "slip",
                              "spotlight", "starwars", "twang", "vidwhacker",
                              "xanalogtv", "xteevee", "xsublim", "zoom"]
            self.badkss = ["kscience.kss", "kslideshow.kss", "kgravity.kss"]
            if os.path.exists(self.path):
                config = readFile(self.path, self.logger)
            if config:
                if not checkPerms(self.path, [0, 0, 420], self.logger):
                    compliant = False
                for line in config:
                    if search("^\*timeout:", line):
                        line = line.split(":")
                        timeout = int(line[2])
                        if timeout > 10:
                            compliant = False
                    if search("^\*lockTimeout:", line):
                        line = line.split(":")
                        timeout = int(line[2])
                        if timeout > 5:
                            compliant = False
                    if search("^\*grabDesktopImages:", line):
                        line = line.split(":")
                        grab = str(line[1])
                        if grab != "False":
                            compliant = False
                    if search("^\*chooseRandomImages:", line):
                        line = line.split(":")
                        choose = str(line[1])
                        if choose != "True":
                            compliant = False
                    if search("^\*lock:", line):
                        line = line.split(":")
                        lock = str(line[1])
                        if lock != "True":
                            compliant = False
                for saver in self.badsavers:
                    if search(saver, config):
                        compliant = False
            for saver in self.badsavers:
                for k, v in self.paths.iteritems():
                    if os.path.exists(k + saver) or \
                       os.path.exists(k + saver + v):
                        compliant = False
            for saver in self.badkss:
                if os.path.exists('/usr/bin/' + saver):
                    compliant = False
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
        try:
            if not self.ci.getcurrvalue():
                return True
            config = ""
            if os.path.exists(self.path):
                config = readFile(self.path, self.logger)
            tmpconfig = self.path + ".tmp"
            config2 = []
            configstring = ""
            if config:
                for line in config:
                    splitline = line.split()
                    if len(splitline) >= 1:
                        if search("^\*timeout:", splitline[0]):
                            continue
                        elif search("^\*lockTimeout:", splitline[0]):
                            continue
                        elif search("^\*grabDesktopImages:", splitline[0]):
                            continue
                        elif search("^\*chooseRandomImages:", splitline[0]):
                            continue
                        elif search("^\*lock:", line):
                            continue
                        elif len(splitline) == 1 and splitline[0] not in \
                             self.badsavers:
                            config2.append(line)
                        elif len(splitline) == 2 and splitline[0] not in \
                             self.badsavers and splitline[1] not in self.badsavers:
                            config2.append(line)
                        elif len(splitline) > 2 and splitline[0] not in \
                             self.badsavers and splitline[1] not in \
                             self.badsavers and splitline[2] not in \
                             self.badsavers:
                            config2.append(line)
                        else:
                            config2.append(line)
                    else:
                        config2.append(line)
                for line in config2:
                    configstring += line
                configstring += "timeout:    0:10:00\nlockTimeout:    0:05:00\n\
                grabDesktopImages:    False\nchooseRandomImages:    True\n\
                lock:    True\n"
                if writeFile(tmpconfig, configstring, self.logger):
                    os.rename(tmpconfig, self.path)
                    os.chown(self.path, 0, 0)
                    os.chmod(self.path, 420)
                    resetsecon(self.path)
                else:
                    self.rulesuccess = False
            for saver in self.badsavers:
                for k, v in self.paths.iteritems():
                    try:
                        if os.path.exists(k + saver):
                            os.remove(k + saver)
                        elif os.path.exists(k + saver + v):
                            os.remove(k + saver + v)
                    except(OSError):
                        self.detailedresults += "The following file had " + \
                            "issues being removed:" + saver + "\n"
                        self.rulesuccess = False

            for saver in self.badkss:
                try:
                    if os.path.exists("/usr/bin/" + saver):
                        os.remove("/usr/bin/" + saver)
                except(OSError):
                    self.detailedresults += "The following file had " + \
                        "issues being removed" + saver + "\n"
                    self.rulesuccess = False
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

    def undo(self):
        '''There is no undo method for this rule since we don't ever want
        these screensaver files to exist'''
        try:
            self.detailedresults = "no undo available\n"
            self.logger.log(LogPriority.INFO, self.detailedresults)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)
