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
@change: Breen Malmberg - 2/13/2017 - set the default group name to sudo on ubuntu and debian
        systems; set a default initialization of the group name variable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''
from __future__ import absolute_import

from ..stonixutilityfunctions import setPerms, checkPerms, iterate
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper

import traceback
import os
import re

class ConfigureSudo(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 56
        self.rulename = "ConfigureSudo"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.guidance = ["NSA 2.3.1.3"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}

        datatype2 = 'bool'
        key2 = 'CONFIGURESUDO'
        instructions2 = '''To disable this rule set the value of CONFIGURESUDO to False.'''
        default2 = True
        self.ci2 = self.initCi(datatype2, key2, instructions2, default2)

# set up CI's
        #configuration item instantiation
        datatype = 'string'
        key = 'GROUPNAME'
        instructions = "The group listed is the group that will be placed into the sudoers file with permissions to run all commands."

        # set the default group name to add to sudoers
        self.group = "wheel"
        if self.environ.getosfamily() == 'darwin':
            self.group = "admin"
        elif re.search('Ubuntu', self.environ.getostype(), re.IGNORECASE):
            self.group = "sudo"
        elif re.search('Debian', self.environ.getostype(), re.IGNORECASE):
            self.group = "sudo"
        self.ci = self.initCi(datatype, key, instructions, self.group)

        self.localization()

    def localization(self):
        '''
        set up class variables, specific to OS type

        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Running localization() method...")

        self.sudoersfile = '/etc/sudoers'
        sudoerslocs = ['/etc/sudoers', '/private/etc/sudoers', '/usr/local/etc/sudoers']
        for loc in sudoerslocs:
            if os.path.exists(loc):
                self.sudoersfile = loc
        self.sudoerstmp = self.sudoersfile + '.stonixtmp'

        try:

            self.pkghelper = Pkghelper(self.logger, self.environ)

            self.searchusl = 'ALL=\(ALL\)'
            self.fixusl = 'ALL=(ALL)'
            if self.environ.getostype() == 'Mac OS X':
                self.searchusl = "ALL=\(ALL\)"
                self.fixusl = "ALL=(ALL)"
            elif self.pkghelper.manager == 'apt-get':
                self.searchusl = "ALL=\(ALL\:ALL\)"
                self.fixusl = "ALL=(ALL:ALL)"

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
        contentlines = []

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

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        commentline = "^#.*(in|of) group.*to (run|execute)"
        existinggroup = "^\%.*" + str(self.searchusl)
        replacedexistinggroup = False
        addedgroup = False

        try:

            self.logger.log(LogPriority.DEBUG, "Running fixSudoers() method...")

            if not self.findString(self.searchstring):
                self.logger.log(LogPriority.DEBUG, "Sudoers file not configured correctly. Fixing file...")
                contentlines = self.readFile(self.sudoersfile)

# replace an existing group entry, if found
                for line in contentlines:
                    if re.search(existinggroup, line, re.IGNORECASE):
                        contentlines = [c.replace(line, self.fixstring) for c in contentlines]
                        replacedexistinggroup = True
                        addedgroup = True

# if there wasn't any existing group entry replaced, then add the new group line at the correct spot
                if not replacedexistinggroup:
                    for line in contentlines:
                        if re.search(commentline, line, re.IGNORECASE):
                            contentlines = [c.replace(line, line + self.fixstring) for c in contentlines]
                            addedgroup = True

# if we couldn't find the correct spot and didn't add the new group line, then append it to end of the file
                if not addedgroup:
                    contentlines.append(self.fixstring)
                    addedgroup = True

# if we changed any of the lines, write the new contents to the file and record the change
                if addedgroup:
                    self.logger.log(LogPriority.DEBUG, "Fixed sudoers contents. Writing the new contents to the file...")
                    f = open(self.sudoerstmp, 'w')
                    f.writelines(contentlines)
                    f.close()

                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": self.sudoersfile}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.sudoersfile, self.sudoerstmp, myid)
                    os.rename(self.sudoerstmp, self.sudoersfile)
                else:
                    self.logger.log(LogPriority.DEBUG, "Nothing changed. Nothing written to sudoers file.")

            else:
                self.logger.log(LogPriority.DEBUG, "File contents already configured correctly. Nothing was changed.")

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
            self.searchstring = ""

            # make sure we get the correct group name if the user changed the default one
            if self.group != str(self.ci.getcurrvalue()):
                self.group = self.ci.getcurrvalue()
            self.searchstring = "^\%" + str(self.group) + '\s+' + self.searchusl + '\s+ALL'

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
                if not self.findString(self.searchstring):
                    self.compliant = False
                    self.detailedresults += '\nCorrect User specification line was not found in sudoers file. Should be:\n%' + self.group + '\t' + self.fixusl + '\tALL'
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

            self.fixstring = '# Added by STONIX\n%' + self.group + '\t' + self.fixusl + '\tALL\n'

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
