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
Created on Nov 25, 2013

This class will restrict access to the root log on to console only

@author: bemalmbe
@change: dwalker 3/17/2014
@change: dkennel 04/18/2014 replaced old style CI with new style
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2014/12/15 dkennel Replaced print statements with logger debug calls
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2017/08/28 ekkehard - Added self.sethelptext()
'''



from rule import Rule
from logdispatcher import LogPriority
from stonixutilityfunctions import setPerms, resetsecon
from stonixutilityfunctions import readFile, writeFile, checkPerms, iterate
from KVEditorStonix import KVEditorStonix
from pkghelper import Pkghelper
import os
import traceback
import re


class ConsoleRootOnly(Rule):
    '''This class will restrict access to the root log on to console only
    
    @author: bemalmbe


    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 35
        self.rulename = 'ConsoleRootOnly'
        self.mandatory = True
        self.sethelptext()
        self.formatDetailedResults("initialize")
        self.guidance = ['CIS, NSA(2.3.1.1), cce3820-8, 3485-0, 4111-1']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd']}

        #configuration item instantiation
        datatype = 'bool'
        key = 'CONSOLEROOTONLY'
        instructions = "To prevent the limiting of root logon to console " + \
            "only, set the value of CONSOLEROOTONLY to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.iditerator = 0
        self.acceptable = ["console", "tty", ":[0-9]", "3270", "hvc", "hvsi",
                           "lxc/", "duart", "xvc", "vc"]

###############################################################################

    def report(self):
        '''Report whether securetty is configured to only allow local console
        log on for root


        :returns: bool
        @author: bemalmbe
        @change: dwalker - implemented applicability for apt-get like systems,
            more in depth permission checks on files, more in depth checking
            of the file and the desired contents.

        '''

        try:

            compliant = True
            self.detailedresults = ""

            # report solaris
            if self.environ.getosfamily() == 'solaris':
                compliant = self.reportsolaris()

            # report non-solaris
            else:
                self.securetty = '/etc/securetty'

                if os.path.exists(self.securetty):
                    helper = Pkghelper(self.logger, self.environ)

                    if helper.manager == "apt-get" or \
                       helper.manager == "zypper":
                        self.perms = [0, 0, 420]
                    else:
                        self.perms = [0, 0, 384]

                    if not checkPerms(self.securetty, self.perms, self.logger):
                        self.detailedresults += "Incorrect permissions on " + \
                            self.securetty + "\n"
                        compliant = False

                    contents = readFile(self.securetty, self.logger)
                    for line in contents:
                        if re.search("^#", line) or re.match('^\s*$', line):
                            continue
                        found = False
                        for item in self.acceptable:
                            if re.search("^" + item, line.strip()):
                                found = True
                                break
                        if not found:
                            self.detailedresults += "The following line is " + \
                                "not acceptable in /etc/securetty: " + line + \
                                "\n"
                            compliant = False
            self.compliant = compliant

        except(KeyboardInterrupt, SystemExit):
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

    def reportsolaris(self):
        '''because solaris has to be different


        :returns: bool
        @author bemalmbe

        '''

        # set kve arguments for reportsolaris and fixsolaris
        compliant = True
        directive = {'permitrootlogin': 'no'}
        kvpath = '/etc/ssh/sshd_config'
        kvtype = 'conf'
        kvtmppath = self.kvpath + '.stonixtmp'
        kvintent = 'present'
        kvconftype = 'space'

        if not checkPerms(kvpath, [0, 3, 420], self.logger):
            compliant = False

        self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                     kvtype, kvpath, kvtmppath, directive,
                                     kvintent, kvconftype)

        if not self.editor.report():
            compliant = False
        return compliant

###############################################################################

    def fix(self):
        '''Make config changes to securetty file (or sshd_config if solaris)
        to ensure that root can only log in via local console
        
        @author: bemalmbe
        @change: dwalker - implemented previous even deletion, more in depth
            file checking for appropriate contents along with writing any fixes
            to the file using methods found in stonixutiltyfunctions.py


        '''

        try:

            if not self.ci.getcurrvalue():
                return

            # clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)

            for event in eventlist:
                self.statechglogger.deleteentry(event)

            self.detailedresults = ""

            # fix solaris
            if self.environ.getosfamily() == 'solaris':
                self.rulesuccess = self.fixsolaris()

            # fix non-solaris
            elif os.path.exists(self.securetty):

                if not checkPerms(self.securetty, self.perms, self.logger):

                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)

                    if not setPerms(self.securetty, self.perms, self.logger,
                                    self.statechglogger, myid):
                        self.detailedresults += "Unable to set permissions " + \
                            "on: " + self.securetty + "\n"
                        self.rulesuccess = False

                contents = readFile(self.securetty, self.logger)
                tempstring = ""
                self.logger.log(LogPriority.DEBUG,
                                ['ConsoleRootOnly', 'Inside Fix'])
                for line in contents:
                    if re.search("^#", line) or re.match('^\s*$', line):
                        tempstring += line
                        continue

                    found = False
                    for item in self.acceptable:
                        self.logger.log(LogPriority.DEBUG,
                                        ['ConsoleRootOnly',
                                         'Item: ' + str(item)])
                        if re.search("^" + item, line.strip()):
                            self.logger.log(LogPriority.DEBUG,
                                            ['ConsoleRootOnly', 'Line OK'])
                            found = True
                            break

                    if found:
                        tempstring += line
                    else:
                        self.logger.log(LogPriority.DEBUG,
                                        ['ConsoleRootOnly',
                                         'Line is incorrect.'])
                        tempstring += "#" + line

                tmpfile = self.securetty + ".tmp"

                if writeFile(tmpfile, tempstring, self.logger):

                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)

                    event = {"eventtype": "conf",
                             "filepath": self.securetty}

                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.securetty,
                                                         tmpfile, myid)

                    os.rename(tmpfile, self.securetty)
                    os.chown(self.securetty, self.perms[0], self.perms[1])
                    os.chmod(self.securetty, self.perms[2])
                    resetsecon(self.securetty)

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################

    def fixsolaris(self):
        '''because solaris has to be different
        
        @author bemalmbe


        '''

        if not checkPerms(self.editor.getPath(), [0, 3, 420], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)

            if not setPerms(self.editor.getPath(), [0, 3, 420], self.logger,
                                                    self.statechglogger, myid):
                self.rulesuccess = False

        if self.editor.fixables or self.editor.removeables:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.editor.setEventID(myid)

            if not self.editor.fix():
                self.detailedresults += "Unable to run fix for kveditor\n"
                self.rulesuccess = False
                return False
            elif not self.editor.commit():
                self.detailedresults += "Unable to run commit for kveditor\n"
                self.rulesuccess = False
                return False

        return True