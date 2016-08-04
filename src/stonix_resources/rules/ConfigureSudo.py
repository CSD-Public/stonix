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
Created on Mar 7, 2013

@author: dwalker
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 02/14/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel Updated to use new style CI
@change: 2015/04/14 dkennel upddated to use new isApplicable
@change: 2015/09/06 Breen Malmberg, re-wrote rule
@change: 2015/10/07 eball Help text cleanup
@change: 2015/10/09 eball Fixed bad variable name in report
@change: 2016/05/09 rsn put default on Mac as admin, also
                        fixed search string and stopped removing lines.
'''
from __future__ import absolute_import

from ..stonixutilityfunctions import setPerms, checkPerms, iterate
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper

import traceback
import os
import re
import sys

class ConfigureSudo(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 56
        self.rulename = "ConfigureSudo"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = """This rule will check for proper settings for \
"wheel" (or another administrative group, if specified below) in the sudoers \
file.
If the rule is non-compliant after you have run the fix, ensure that the \
group entered in the text field exists, and that the usernames of all \
administrators who should be allowed to execute commands as root are members \
of that group. This rule will not be applicable to Solaris.
This rule does not remove any lines from the sudoers file.
***Please be aware that the default group for this rule is wheel or of on a Mac, it is admin. If you \
would like to change the group, enter the desired group in the text field \
below and hit save before running.***"""

        self.guidance = ["NSA 2.3.1.3"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}

        #configuration item instantiation
        datatype = 'string'
        key = 'GROUPNAME'
        instructions = "The group listed is the group that will be placed " + \
        "into the sudoers file with permissions to run all commands."

        if self.environ.getosfamily() == 'darwin':
            self.default = "admin"
        else:
            self.default = "wheel"

        self.ci = self.initCi(datatype, key, instructions, self.default)

        datatype2 = 'bool'
        key2 = 'CONFIGURESUDO'
        instructions2 = '''To disable this rule set the value of \
CONFIGURESUDO to False.'''
        default2 = True
        self.ci2 = self.initCi(datatype2, key2, instructions2, default2)

        self.localization()

    def localization(self):
        '''
        set up class variables, specific to OS type

        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Running localization() method...")

        self.sudoersfile = '/etc/sudoers' # default
        sudoerslocs = ['/etc/sudoers', '/private/etc/sudoers', '/usr/local/etc/sudoers']
        for loc in sudoerslocs:
            if os.path.exists(loc):
                self.sudoersfile = loc

        try:

            self.pkghelper = Pkghelper(self.logger, self.environ)

            self.searchusl = 'ALL=\(ALL\)' # default
            self.fixusl = 'ALL=(ALL)' # default
            if self.environ.getostype() == 'Mac OS X':
                self.searchusl = "ALL=\(ALL\)"
                self.fixusl = "ALL=(ALL)"
            elif self.pkghelper.manager == 'apt-get':
                self.searchusl = "ALL=\(ALL\:ALL\)"
                self.fixusl = "ALL=(ALL:ALL)"

            # set up some class variables
            self.groupname = "%{0}".format(self.ci.getcurrvalue())
            self.defaultgroupname = "%{0}".format(self.default)
            self.fixstring = '# Added by STONIX\n' + self.groupname + '\t' + self.fixusl + '\tALL\n'
            self.fixdefaultstring = '# Added by STONIX\n' + self.defaultgroupname + '\t' + self.fixusl + '\tALL\n'
            self.defaultsearchstring = '^' + self.defaultgroupname + '\s+{0}\s+ALL'.format(self.searchusl)
            self.searchstring = '^' + self.groupname + '\s+{0}\s+ALL'.format(self.searchusl)
 
        except Exception:
            raise

    def readFile(self, filepath):
        '''
        get and return contents of file filepath

        @param filepath: string full path to file to read from
        @return: contentlines
        @rtype: list
        @author: Breen Malmberg
        '''

        contentlines = []

        try:

            self.logger.log(LogPriority.DEBUG, "Running readFile() method...")
            if os.path.exists(filepath):
                f = open(filepath, 'r')
                contentlines = f.readlines()
                f.close()
            if not contentlines:
                self.detailedresults += '\nYour sudoers file appears to be completely empty. This is not a good thing.'
                self.logger.log(LogPriority.DEBUG, "The sudoers file appears to be completely empty!")

        except Exception:
            raise

        return contentlines

    def findString(self, searchstring):
        '''
        search for parameter searchstring, in self.sudoersfile

        @param searchstring: string to search for in self.sudoersfile
        @return: found
        @rtype: bool
        @author: Breen Malmberg
        '''

        found = False

        try:

            self.logger.log(LogPriority.DEBUG, "Running findString() method...")
            contentlines = self.readFile(self.sudoersfile)

            for line in contentlines:
                if re.search(searchstring, line):
                    found = True

        except Exception:
            raise

        return found

    def fixSudoers(self):
        '''
        wrapper to run fix actions for sudoers

        @param fixstring: string the string to write to the file
        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        replaced = False
        sudoerstmp = self.sudoersfile + '.stonixtmp'
        appended = False

        try:

            self.logger.log(LogPriority.DEBUG, "Running fixSudoers() method...")

            contentlines = self.readFile(self.sudoersfile)
            founddefault = False
            for line in contentlines:
                if re.match(self.defaultsearchstring, line):
                    founddefault = True
                    self.logger.log(LogPriority.INFO, "Found a valid administration group...")
                    break

            if not founddefault:
                self.logger.log(LogPriority.DEBUG, "Didn't find an appropriate administration group")
                contentlines.append('\n' + self.fixdefaultstring)
                appended = True

            found = False
            for line in contentlines:
                if re.match(self.searchstring, line):
                    found = True
                    self.logger.log(LogPriority.INFO, "Found a valid administration group...")
                    break

            if not found:
                self.logger.log(LogPriority.DEBUG, "Didn't find an appropriate administration group")
                contentlines.append('\n' + self.fixstring)
                appended = True
            f = open(sudoerstmp, 'w')
            f.writelines(contentlines)
            f.close()

            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "conf",
                     "filepath": self.sudoersfile}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(self.sudoersfile, sudoerstmp, myid)
            os.rename(sudoerstmp, self.sudoersfile)

            if not found and not appended:
                retval = False
                self.logger.log(LogPriority.DEBUG, "Contents were unable to be changed in file: " + str(self.sudoersfile))

        except Exception:
            raise

        return retval

    def report(self):
        '''
        ConfigureScreenLocking.report() method to report whether system is
        configured with a sudoers group.
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        @change: Breen Malmberg, 9/6/2015, re-wrote method
        '''

        try:

            self.detailedresults = ""
            self.compliant = True

            # set up some class variables
            self.groupname = "%{0}".format(self.ci.getcurrvalue())
            self.defaultgroupname = "%{0}".format(self.default)
            self.fixstring = '# Added by STONIX\n' + self.groupname + '\t' + self.fixusl + '\tALL\n'
            self.fixdefaultstring = '# Added by STONIX\n' + self.defaultgroupname + '\t' + self.fixusl + '\tALL\n'
            self.defaultsearchstring = '^' + self.defaultgroupname + '\s+{0}\s+ALL'.format(self.searchusl)
            self.searchstring = '^' + self.groupname + '\s+{0}\s+ALL'.format(self.searchusl)
 
            # make sure the sudoers file exists
            if not os.path.exists(self.sudoersfile):
                self.detailedresults += '\nUnable to locate the sudoers file!'
                self.logger.log(LogPriority.DEBUG, "Unable to locate the sudoers file!")
                self.compliant = False
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant
            else:
                # make sure the sudoers file contains the correct user specification configuration
                if not self.findString(self.searchstring) or not self.findString(self.defaultsearchstring):
                    self.compliant = False
                    self.detailedresults += '\nCorrect User specification line was not found in sudoers file. Should be:\n' + self.groupname + '\t' + self.fixusl + '\tALL'
                    self.logger.log(LogPriority.DEBUG, 'Correct User specification line was not found in sudoers file')

                #make sure the sudoers file has correct permissions
                if not checkPerms(self.sudoersfile, [0, 0, 288], self.logger):
                    self.compliant = False
                    self.detailedresults += '\nThe permissions and/or ownership is set incorrectly, on file: ' + str(self.sudoersfile)
                    self.logger.log(LogPriority.DEBUG, 'Permissions and/or ownership is set incorrectly on sudoers file')

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        '''
        Fix method that writes specified or default sudo group to sudoers file
        if not present from the report method
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if fix is successful, False if it isn't
        @change: Breen Malmberg, 9/6/2015, re-wrote method
        '''

        try:

            self.iditerator = 0
            fixresult = True
            self.detailedresults = ""

            if not self.ci2.getcurrvalue():
                self.detailedresults += '\nRule was not enabled, so nothing was done'
                self.logger.log(LogPriority.DEBUG, 'Rule was not enabled, so nothing was done')
                return

            #clear out event history so only the latest fix is recorded
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            self.logger.log(LogPriority.DEBUG, "Clearing event list for this rule...")
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            # run fix actions
            if not self.fixSudoers():
                fixresult = False

            #we don't record a change event for permissions
            if not setPerms(self.sudoersfile, [0, 0, 288], self.logger):
                    fixresult = False
                    self.detailedresults += '\nCould not set permissions on file: ' + str(self.sudoersfile)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixresult, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixresult
