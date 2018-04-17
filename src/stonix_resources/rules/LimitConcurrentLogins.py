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
Created on Mar 22, 2018

@author: dwalker
'''
from __future__ import absolute_import
from ..rule import Rule
from ..stonixutilityfunctions import setPerms, checkPerms, iterate, resetsecon
from ..stonixutilityfunctions import readFile, writeFile, createFile
from ..logdispatcher import LogPriority
import traceback
import re
import os


class LimitConcurrentLogins(Rule):

    def __init__(self, config, environ, logdispatcher, statechglogger):
        Rule.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 330
        self.rulename = 'LimitConcurrentLogins'
        self.logger = logdispatcher
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rule limits the number of open terminal sessions " + \
            "for the current user\n"
        self.applicable = {'type': 'white',
                           'family': ['linux'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.12.10']}}

        # init CIs
        datatype = 'bool'
        key = 'LIMITLOGINS'
        instructions = "To disable this rule, set " + \
            "the value of LIMITLOGINS to False."
        default = False
        self.ci = self.initCi(datatype, key, instructions, default)
        
        datatype = 'string'
        key = "LOGINNUMBER"
        instructions = "The number of logins to limit to.  Default is 10."
        default = "10"
        self.cinum = self.initCi(datatype, key, instructions, default)
        
    def report(self):
        '''
        LimitConcurrentLogins.report() method to report whether system's
        concurrent logins are regulated.
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''
        try:
            self.detailedresults = ""
            compliant = True
            found = False
            self.securityfile = "/etc/security/limits.conf"
            if not os.path.exists(self.securityfile):
                self.detailedresults += self.securityfile + \
                    " doesn't exist\n"
                compliant = False
            else:
                if not checkPerms(self.securityfile, [0, 0, 420], self.logger):
                    compliant = False
                    self.detailedresults += "Permissions aren't " + \
                        "correct on " + self.securityfile + "\n"
                contents = readFile(self.securityfile, self.logger)
                for line in contents:
                    if re.match('^#', line) or re.match(r'^\s*$', line):
                        continue
                    if re.search("maxlogins", line):
                        splitline = line.split()
                        try:
                            if len(splitline) > 4:
                                continue
                            if splitline[0] != "*" or \
                                splitline[1] != "hard" or \
                                splitline[2] != "maxlogins" or \
                                splitline[3] != self.cinum.getcurrvalue():
                                compliant = False
                                self.detailedresults += "System is not " + \
                                    "configured with correct number of limiting logins\n"
                                break
                            else:
                                found = True
                        except IndexError:
                            compliant = False
                            self.detailedresults += "System is not " + \
                                "configured with correct number of limiting logins\n"
                            break
            if not found:
                self.detailedresults += "System is not " + \
                    "configured with correct number of limiting logins\n"
            if found and compliant:
                compliant = True
            else:
                compliant = False
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant
    
    def fix(self):
        '''
        LimitConcurrentLogins.fix() method to set number of concurrent logins
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if fix is successful, False if it isn't
        '''
        try:
            self.detailedresults = ""
            self.iditerator = 0
            success = True
            if not self.ci.getcurrvalue():
                self.detailedresults += 'The CI for this rule is currently disabled. Nothing will be done...\n'
                self.formatDetailedResults("fix", success, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return success
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            filecreated = False
            if not os.path.exists(self.securityfile):
                if createFile:
                    filecreated = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": self.securityfile}
                    self.statechglogger.recordchgevent(myid, event)
            contents = readFile(self.securityfile, self.logger)
            tempstring = ""
            #print "about to loop\n"
            for line in contents:
                if re.match('^#', line) or re.match(r'^\s*$', line):
                    tempstring += line
                    continue
                elif re.search("maxlogins", line):
                    splitline = line.split()
                    try:
                        if len(splitline) > 4:
                            continue
                        if splitline[0] != "*" or \
                            splitline[1] != "hard" or \
                            splitline[2] != "maxlogins" or \
                            splitline[3] != self.cinum.getcurrvalue():
                            continue
                    except IndexError:
                        continue
                else:
                    tempstring += line
            if tempstring:
                #print "tempstring: " + str(tempstring) + "\n"
                tempstring += "*\thard\tmaxlogins\t" + self.cinum.getcurrvalue() + "\n"
                #print "tempstring: " + str(tempstring) + "\n"
                tmpfile = self.securityfile + ".tmp"
                if not writeFile(tmpfile, tempstring, self.logger):
                    debug = "Unable to write changes to " + tmpfile
                    self.detailedresults += debug
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                elif not filecreated:
                    if not checkPerms(self.securityfile, [0, 0, 420], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        setPerms(self.securityfile, [0, 0, 0644], self.logger,
                             self.statechglogger, myid)
                        resetsecon(self.securityfile)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": self.securityfile}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.securityfile,
                                                         tmpfile, myid)
                    os.rename(tmpfile, self.securityfile)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    setPerms(self.securityfile, [0, 0, 420], self.logger)
                    resetsecon(self.securityfile)
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    setPerms(self.securityfile, [0, 0, 420], self.logger,
                             self.statechglogger, myid)
                    resetsecon(self.securityfile)
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