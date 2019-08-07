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
Created on Aug 21, 2012

@author: Derek Trent Walker
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel Replaced old-style CI invocation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/16 dkennel updated for new isApplicable
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate, readFile, writeFile, checkPerms
from ..stonixutilityfunctions import setPerms, resetsecon, getUserGroupName
from ..pkghelper import Pkghelper
import os, re, pwd, grp, traceback #grp is a valid python package


class NoLegacyPlusAccts(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        '''Constructor'''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 43
        self.rulename = "NoLegacyPlusAccts"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.guidance = ["NSA 2.3.1.8"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

        #configuration item instantiation
        datatype = 'bool'
        key = 'NOLEGACYPLUSACCTS'
        instructions = "To remove possible '+' entries in the " + \
        "/etc/passwd, /etc/group, /etc/shadow and /etc/grp files ensure " + \
        "that this is set to True or Yes.  This rule should not be disabled."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.iditerator = 0

###############################################################################

    def report(self):
        '''checks to see if a plus entry exists, returns True if a plus entry
        exists and False if not


        :returns: bool
        @author: D.Walker

        '''
        try:
            self.detailedresults = ""
            compliant = True
            self.badfiles = []
            self.ph = Pkghelper(self.logger, self.environ)
            if self.environ.getostype() == "Mac OS X":
                filelist = ["/private/etc/master.passwd",
                            "/private/etc/shadow",
                            "/private/etc/passwd",
                            "/private/etc/group",
                            "/private/etc/grp"]
            else:
                filelist = ["/etc/master.passwd",
                            "/etc/shadow",
                            "/etc/passwd",
                            "/etc/group",
                            "/etc/grp"]
            counter = 0
            for fileItem in filelist:
                if os.path.exists(fileItem):
                    contents = readFile(fileItem, self.logger)
                    for line in contents:
                        if re.search("^\+", line.strip()):
                            self.badfiles.append(fileItem)
                            counter += 1
                            compliant = False
            self.detailedresults += "Found " + str(counter) + \
" plus accounts\n"
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
        '''will check if the shadow, passwd, or group file is present and
        if so remove the plus(+) account located in the file


        '''

        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""
            
            #clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            for path in self.badfiles:
                path = path.strip()
                if os.path.exists(path):
                    tempstring = ""
                    contents = readFile(path, self.logger)
                    if not contents:
                        continue
                    for line in contents:
                        if not re.search('^\+', line.strip()):
                            tempstring += line
                    if path == "/etc/master.passwd":
                        if not checkPerms(path, [0, 0, 384], self.logger):
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            setPerms(path, [0, 0, 384], self.logger,
                                                     self.statechglogger, myid)
                    elif path == "/etc/shadow":
                        #put in code to handle apt-get systems /etc/shadow file later
                        #for this file, the owner is root, but the group is shadow
                        #by default this group is 42 but may not always be that
                        if self.ph.manager == "apt-get":
                            retval = getUserGroupName("/etc/shadow")
                            if retval[0] != "root" or retval[1] != "shadow":
                                uid = pwd.getpwnam("root").pw_uid
                                gid = grp.getgrnam("shadow").gr_gid
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                setPerms(path, [uid, gid, 420], self.logger, 
                                                     self.statechglogger, myid)
                        else:
                            if not checkPerms(path, [0, 0, 256], self.logger) and \
                                      not checkPerms(path, [0, 0, 0], self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                setPerms(path, [0, 0, 256], self.logger, 
                                                         self.statechglogger, myid)
                    else:
                        if not checkPerms(path, [0, 0, 420], self.logger):
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            setPerms(path, [0, 0, 420], self.logger,
                                                     self.statechglogger, myid)
                    tmpfile = path + ".tmp"
                    if not writeFile(tmpfile, tempstring, self.logger):
                        self.rulesuccess = False
                        return
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'conf',
                             'filepath': path}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(path, tmpfile, myid)
                    os.rename(tmpfile, path)
                    if path == "/etc/master.passwd":
                        os.chown(path, 0, 0)
                        os.chmod(path, 384)
                    elif path == "/etc/shadow":
                        if self.ph.manager == "apt-get":
                            os.chown(path, uid, gid)
                            os.chmod(path, 420)
                        else:
                            os.chown(path, 0, 0)
                            os.chmod(path, 256)
                    else:
                        os.chmod(path, 420)
                    resetsecon(path)
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