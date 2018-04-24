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

@author: Derek Walker
'''

from __future__ import absolute_import

import traceback
import re
import os

from ..rule import Rule
from ..stonixutilityfunctions import setPerms, checkPerms, iterate, resetsecon
from ..stonixutilityfunctions import readFile, writeFile, createFile
from ..logdispatcher import LogPriority


class LimitConcurrentLogins(Rule):
    '''
    '''

    def __init__(self, config, environ, logdispatcher, statechglogger):
        '''
        '''

        Rule.__init__(self, config, environ, logdispatcher, statechglogger)
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
        datatype1 = 'bool'
        key1 = 'LIMITLOGINS'
        instructions1 = "To disable this rule, set the value of LIMITLOGINS to False."
        default1 = False
        self.ci = self.initCi(datatype1, key1, instructions1, default1)
        
        datatype2 = 'string'
        key2 = "LOGINNUMBER"
        instructions2 = "The number of logins to limit to.  Default is 10."
        default2 = "10"
        self.cinum = self.initCi(datatype2, key2, instructions2, default2)
        
    def report(self):
        '''
        LimitConcurrentLogins.report() method to report whether system's
        concurrent logins are regulated.

        @return: self.compliant
        @rtype: bool

        @author: Derek Walker
        @change: 04/24/2018 - Breen Malmberg - moved all default variable initializations outside of
                try/except block so they always get set no matter what; removed all middle-man boolean
                flag assignments in favor of just setting the return variable directly; added check for
                contents in case readFile method has a problem and returns either an empty list or None;
                added detailedresults feedback for permissions issues making it clear to the user what
                is wrong in that case
                
        '''

        self.compliant = True
        self.detailedresults = ""
        found = False
        self.securityfile = "/etc/security/limits.conf"

        try:

            if not os.path.exists(self.securityfile):
                self.detailedresults += self.securityfile + " doesn't exist\n"
                self.compliant = False
            else:
                if not checkPerms(self.securityfile, [0, 0, 420], self.logger):
                    self.compliant = False
                    self.detailedresults += "Permissions are incorrect for: " + self.securityfile + "\n"

                contents = readFile(self.securityfile, self.logger)

                if not contents:
                    self.logger.log(LogPriority.DEBUG, "Unable to read file contents of: " + str(self.securityfile))
                    self.formatDetailedResults("report", self.compliant, self.detailedresults)
                    self.logger.log(LogPriority.INFO, self.detailedresults)
                    return self.compliant

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
                                self.compliant = False
                                self.detailedresults += "System is not configured with correct number of limiting logins\n"
                                break
                            else:
                                found = True
                        except IndexError:
                            self.compliant = False
                            self.detailedresults += "System is not configured with correct number of limiting logins\n"
                            break

            if not found:
                self.detailedresults += "System is not configured with correct number of limiting logins\n"
                self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.compliant
    
    def fix(self):
        '''
        Limit the number of concurrent logins to the value of LOGINNUMBER CI
        (default 10)

        @return: self.rulesuccess
        @rtype: bool

        @author: Derek Walker
        @change: 04/24/2018 - Breen Malmberg - changed the tmpfile to .stonixtmp in keeping
                with STONIX naming conventions; moved default variable assignments outside of try
                except block so they always get set/initialized, no matter what; removed unnecessary
                middle-man variable flag assignments and changed to self.rulesuccess since that is what
                gets returned; added checking to see if a file existed after the attempt is made to create
                it (since that attempt can, and was, failing); fixed an incomplete call to a method
                createFile which had nothing being passed to it, which was causing the rule to fail; changed
                the bool return flag to false if creating the file fails; moved a section of code (which was
                logic-path-success-dependent) under neath the if condition which it logically relied on; added
                default initialization of tempstring variable
        '''

        self.detailedresults = ""
        self.iditerator = 0
        self.rulesuccess = True
        filecreated = False
        tempstring = ""
        tmpfile = self.securityfile + ".stonixtmp"

        try:

            if not self.ci.getcurrvalue():
                self.detailedresults += 'The CI for this rule is currently disabled. Nothing will be done...\n'
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess

            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if not os.path.exists(self.securityfile):
                if createFile(self.securityfile, self.logger):
                    filecreated = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": self.securityfile}
                    self.statechglogger.recordchgevent(myid, event)
                    contents = readFile(self.securityfile, self.logger)
                    tempstring = ""

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
                else:
                    self.logger.log(LogPriority.DEBUG, "Unable to create file: " + str(self.securityfile))
                    self.rulesuccess = False

            if tempstring:

                tempstring += "*\thard\tmaxlogins\t" + self.cinum.getcurrvalue() + "\n"

                if not writeFile(tmpfile, tempstring, self.logger):
                    debug = "Unable to write changes to " + tmpfile
                    self.detailedresults += debug
                    self.logger.log(LogPriority.DEBUG, debug)
                    self.rulesuccess = False

                elif not filecreated:
                    if not checkPerms(self.securityfile, [0, 0, 420], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        setPerms(self.securityfile, [0, 0, 0644], self.logger, self.statechglogger, myid)
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
                    setPerms(self.securityfile, [0, 0, 420], self.logger, self.statechglogger, myid)
                    resetsecon(self.securityfile)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
