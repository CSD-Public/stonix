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
Created on Feb 12, 2013

@author: dwalker
@change: 04/18/2014 dkennel Replaced old-style CI invocation
@change: 06/03/2014 ejk added self.formatDetailedResults("initialize") to init
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/16 dkennel Updated for new isApplicable
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''

from stonixutilityfunctions import checkPerms, setPerms, readFile, writeFile
from stonixutilityfunctions import iterate, resetsecon
from rule import Rule
from logdispatcher import LogPriority
from KVEditorStonix import KVEditorStonix
import traceback
import re
import os


class PreventXListen(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 31
        self.rulename = "PreventXListen"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.guidance = ["NSA 3.6.1.3.2"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

        datatype = 'bool'
        key = 'PREVENTXLISTEN'
        instructions = "To disable this rule set the value of " + \
        "PREVENTXLISTEN to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.properties = {}
        self.iditerator = 0

###############################################################################

    def report(self):
        try:
            self.detailedresults = ""
            self.fixables1, self.fixables2 = [], []
            # self.fp1 contains a regex that needs to conform to each line in file
            self.fp1 = [["^:(.)* -nolisten tcp", "/etc/X11/xdm/Xservers", True],
                        ["^:(.)* -nolisten tcp", "/usr/X11R6/lib/X11/xdm/Xservers", True],
                        ["^:(.)* -nolisten tcp", "/etc/dt/config/Xservers", True],
                        ["^:(.)* -nolisten tcp", "/usr/dt/config/Xservers", True]]
            # self.fp2 contains regex that only needs to appear once in file
            self.fp2 = [['^command = (.)* -nolisten tcp', '/etc/X11/gdm/gdm.conf', False],
                        ['^DisallowTCP = true', '/usr/share/gdm/defaults.conf', False],
                        ['^DisallowTCP = true', '/etc/gdm/custom.conf', False],
                        ['^exec(.)* -nolisten tcp', '/etc/X11/xinit/xserverrc', False],
                        ['^ServerArgsLocal=(.)* -nolisten tcp', '/etc/kde/kdm/kdmrc', False],
                        ['^ServerArgsLocal=(.)* -nolisten tcp', '/etc/kde4/kdm/kdmrc', False],
                        ['^ServerArgsLocal=(.)* -nolisten tcp', '/usr/share/config/kdm/kdmrc', False],
                        ['DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN=NO', '/etc/sysconfig/displaymanager', False]]
            compliant = True
            for item in self.fp1:
                if os.path.exists(item[1]):
                    if not self.checkConfig(item[0], item[1], item[2]):
                        self.detailedresults += item[1] + " doesn\'t have \
correct configuration\n"
                        self.fixables1.append(item)
                        compliant = False
                    if item[1] == "/etc/X11/xdm/Xservers" or item[1] == \
                        "/usr/X11R6/lib/X11/xdm/Xservers":
                        if not checkPerms(item[1], [0, 0, 292], self.logger):
                            self.detailedresults += item[1] + " doesn\'t have \
correct permissions\n"
                            compliant = False
                    else:
                        if not checkPerms(item[1], [0, 3, 292], self.logger):
                            self.detailedresults += item[1] + " doesn\'t have \
correct permissions\n"
                            compliant = False
            for item in self.fp2:
                if os.path.exists(item[1]):
                    if not self.checkConfig(item[0], item[1], item[2]):
                        self.detailedresults += item[1] + " doesn\'t have \
correct configuration\n"
                        self.fixables2.append(item)
                    if item[1] == "/etc/X11/xinit/xserverrc":
                        if not checkPerms(item[1], [0, 0, 493], self.logger):
                            self.detailedresults += item[1] + " doesn\'t have \
correct permissions\n"
                            compliant = False
                    elif not checkPerms(item[1], [0, 0, 420], self.logger):
                        self.detailedresults += item[1] + " doesn\'t have \
correct permissions\n"
                        compliant = False
            if self.environ.getosfamily() == "solaris":
                fp3 = "/etc/X11/gdm/gdm.conf"
                keys = {"security":{"DisallowTCP":"true"}}
                if os.path.exists(fp3):
                    tmpPath = "/etc/X11/gdm/gdm.conf.tmp"
                    kvtype = "tagconf"
                    intent = "present"
                    self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                             kvtype, fp3, tmpPath, keys, intent, "closedeq")
                    if not self.editor.report():
                        self.detailedresults += "Kveditor report for solaris \
is non compliant\n"
                        compliant = False
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
    
###############################################################################

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            self.iditerator = 0

            # clear out event history so only the latest fix is recorded
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            success = True
            index = {"/etc/X11/gdm/gdm.conf": "command = /usr/X11R6/bin/X -nolisten tcp",
                     "/usr/share/gdm/defaults.conf": "DisallowTCP = true",
                     "/etc/gdm/custom.conf": "DisallowTCP = true",
                     "/etc/X11/xinit/xserverrc": "exec /usr/X11R6/bin/X -nolisten tcp",
                     "/etc/kde/kdm/kdmrc": "ServerArgsLocal = -nolisten tcp",
                     "/etc/kde4/kdm/kdmrc": "ServerArgsLocal = -nolisten tcp",
                     "/usr/share/config/kdm/kdmrc": "ServerArgsLocal = -nolisten tcp",
                     "/etc/sysconfig/displaymanager": 'DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN=NO',
                     "/etc/dt/config/Xservers": ":0   Local local_uid@console root /usr/X11/bin/Xserver :0 -nobanner -nolisten tcp",
                     "/usr/dt/config/Xservers": ":0   Local local_uid@console root /usr/X11/bin/Xserver :0 -nobanner -nolisten tcp"}
            for item in self.fp1:
                if os.path.exists(item[1]):
                    if item[1] == "/etc/X11/xdm/Xservers" or \
                       item[1] == "/usr/X11R6/lib/X11/xdm/Xservers":
                        if not checkPerms(item[1], [0, 0, 292], self.logger):
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            if not setPerms(item[1], [0, 0, 292], self.logger,
                                            self.statechglogger, myid):
                                success = False
                    else:
                        if not checkPerms(item[1], [0, 3, 292], self.logger):
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            if not setPerms(item[1], [0, 3, 292], self.logger,
                                            self.statechglogger, myid):
                                success = False
            for item in self.fp2:
                if os.path.exists(item[1]):
                    if item[1] == "/etc/X11/xinit/xserverrc":
                        if not checkPerms(item[1], [0, 0, 493], self.logger):
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            if not setPerms(item[1], [0, 0, 493], self.logger,
                                            self.statechglogger, myid):
                                success = False
                    elif not checkPerms(item[1], [0, 0, 420], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(item[1], [0, 0, 420], self.logger,
                                        self.statechglogger, myid):
                            success = False
            for item in self.fixables1:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if self.writeConfig(item[1], myid, item[0], item[2]):
                    os.chown(item[1], 0, 0)
                    os.chmod(item[1], 292)
                    resetsecon(item[1])
                else:
                    success = False
            for item in self.fixables2:
                for item2 in index:
                    if item[1] == item2:
                        item[0] = index[item2]
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if self.writeConfig(item[1], myid, item[0], item[2]):
                    if item[1] == "/etc/X11/xinit/xserverrc":
                        os.chmod(item[1], 493)
                    else:
                        os.chmod(item[1], 420)
                    os.chown(item[1], 0, 0)
                    resetsecon(item[1])
                else:
                    success = False
            if self.environ.getosfamily() == "solaris":
                fp3 = "/etc/X11/gdm/gdm.conf"
                if self.editor.fixables():
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor.setEventID(myid)
                    if self.editor.fix():
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.editor.setEventID(myid)
                        if self.editor.commit():
                            self.detailedresults += "/etc/X11/gdm/gdm.conf \
file has been fixed\n"
                            os.chown(fp3, 0, 0)
                            os.chmod(fp3, 292)
                            resetsecon(fp3)
                        else:
                            debug = "kveditor commit did not run successfully, must return"
                            self.logger.log(LogPriority.DEBUG, debug)
                            success = False
                    else:
                        debug = "kveditor fix did not run successfully, must return"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
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
    
##############################################################################

    def checkConfig(self, regex, filepath, mult):
        contents = readFile(filepath, self.logger)
        if not contents:
            debug = filepath + " contents are blank\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        if mult:
            for line in contents:
                if re.match("^#", line) or re.match(r"^\s*$", line):
                    continue
                if not re.search(regex, line.strip()):
                    return False
            return True
        else:
            for line in contents:
                if re.match("^#", line) or re.match("^\s*$", line):
                    continue
                if re.search(regex, line.strip()):
                    return True
            return False
        
##############################################################################

    def writeConfig(self, filepath, myid, regex, mult):
        tempfile = filepath + ".tmp"
        tempstring = ""
        contents = readFile(filepath, self.logger)
        if not contents:
            debug = filepath + " contents are blank\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        if mult:
            for line in contents:
                if re.match("^#", line) or re.match("^\s*$", line):
                    tempstring += line
                elif not re.search(regex, line):
                    tempstring += line.strip() + " -nolisten tcp\n"
        else:
            for line in contents:
                tempstring += line
            tempstring += regex + "\n"
        if not writeFile(tempfile, tempstring, self.logger):
            return False
        event = {"eventtype":"conf",
                 "filepath":filepath}
        self.statechglogger.recordchgevent(myid, event)
        self.statechglogger.recordfilechange(filepath, tempfile, myid)
        os.rename(tempfile, filepath)
        return True