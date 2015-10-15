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
Created on Aug 5, 2015

The Xinetd access control mechanism should be securely configured, if xinetd is
present.

@author: Breen malmberg
@change: 2015/10/08 eball Help text/PEP8 cleanup
'''

from __future__ import absolute_import

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..localize import XINETDALLOW
from ..stonixutilityfunctions import getOctalPerms
from ..stonixutilityfunctions import getOwnership
import traceback
import os
import re


class XinetdAccessControl(Rule):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 36
        self.rulename = 'XinetdAccessControl'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rule will securely configure the xinetd " + \
            "access control mechanism, if xinetd is present."
        self.rootrequired = True
        self.compliant = False
        self.guidance = ['']
        self.iditerator = 0
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}
        # init CIs
        datatype = 'bool'
        key = 'XinetdAccessControl'
        instructions = "To disable the configuring of the xinetd access " + \
            "control mechanism, set the value of XinetdAccessControl to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        # set up class var's
        self.setvars()

    def setvars(self):
        '''
        set the values for all the class variables to be used

        @author: Breen Malmberg
        '''

        self.confpath = '/etc/xinetd.conf'
        self.partialopt = '^only_from\s*='
        try:
            self.fullopt = '^only_from\s*=\s*' + str(XINETDALLOW)
            self.fixopt = 'only_from = ' + str(XINETDALLOW) + '\n'
        except UnboundLocalError:
            self.logger.log(LogPriority.DEBUG,
                            "NETWORK constant has not been defined in " + \
                            "localize.py, or the import failed")
        except Exception:
            raise

    def readFile(self, path):
        '''
        read the specified path's contents and return them in a list

        @param path: string the full path to the file to be read
        @return: contentlines
        @rtype: list
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "inside readFile() method")

        contentlines = []

        try:
            self.logger.log(LogPriority.DEBUG, "opening and reading file " + str(path))
            f = open(path, 'r')
            contentlines = f.readlines()
            f.close()
        except IOError:
            self.logger.log(LogPriority.DEBUG, "specified path does not exist, or insufficient permissions to access it")
            return contentlines
        self.logger.log(LogPriority.DEBUG, "finished reading file contents into contentlines. returning.")
        return contentlines

    def findopt(self, path, opt):
        '''
        search the specified path for the specified option (opt). if found, return True, else False.

        @param path: string full path to the file to be searched
        @param opt: string regex or option to search the file for
        @return: found
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "inside findopt() method")

        found = False

        self.logger.log(LogPriority.DEBUG, "getting the file contents of " + str(path))
        contentlines = self.readFile(path)

        try:
            self.logger.log(LogPriority.DEBUG, "searching for " + str(opt) + " in " + str(path))
            for line in contentlines:
                if re.search(opt, line):
                    self.logger.log(LogPriority.DEBUG, "found " + str(opt) + " in line " + str(line))
                    found = True
        except Exception:
            raise
        self.logger.log(LogPriority.DEBUG, "returning found=" + str(found))
        return found

    def replaceopt(self, path, partialopt, fullopt):
        '''
        search the specified file for the option partialopt and replace it with the option fullopt, if found.

        @param path: string full path to the file to be searched
        @param partialopt: string the regex/option text to search the file for
        @param fullopt: string the full option text to replace the found partialopt text with
        @return: replaced
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "inside replaceopt() method")

        replaced = False

        self.logger.log(LogPriority.DEBUG, "getting the file contents of " + str(path))
        contentlines = self.readFile(path)

        try:
            self.logger.log(LogPriority.DEBUG, "searching for " + str(partialopt) + " in contentlines")
            for line in contentlines:
                if re.search(partialopt, line):
                    self.logger.log(LogPriority.DEBUG, "found match in line " + str(line) + " ; replacing it with " + str(fullopt))
                    contentlines = [c.replace(line, fullopt) for c in contentlines]
                    self.logger.log(LogPriority.DEBUG, "replaced the line in contentlines")
                    self.logger.log(LogPriority.DEBUG, "opening file " + str(path) + " to write")
                    f = open(path, 'w')
                    self.logger.log(LogPriority.DEBUG, "writing contentlines to file " + str(path))
                    f.writelines(contentlines)
                    f.close()
                    self.logger.log(LogPriority.DEBUG, "done writing to file")
                    replaced = True
        except Exception:
            raise
        self.logger.log(LogPriority.DEBUG, "finished running replaceopt() method; returning replaced=" + str(replaced))
        return replaced

    def writeFile(self, path, opt):
        '''
        append the option opt to the contents of the file specified by path, and write them out to the file path

        @param path: string full path to the file to write to
        @param opt: string option text to write to the file
        @return: written
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "inside writeFile() method")

        written = False

        try:
            self.logger.log(LogPriority.DEBUG, "attempting to replace any incomplete or erroneous existing config lines")
            if not self.replaceopt(path, self.partialopt, self.fixopt):
                self.logger.log(LogPriority.DEBUG, "did not replace anything; appending config option " + str(opt) + " to contentlines")
                contentlines = self.readFile(path)
                contentlines.append(opt + '\n')
                self.logger.log(LogPriority.DEBUG, "opening file " + str(path) + " to write")
                f = open(path, 'w')
                self.logger.log(LogPriority.DEBUG, "writing contentlines to file " + str(path))
                f.writelines(contentlines)
                f.close()
                self.logger.log(LogPriority.DEBUG, "done writing to file")
                written = True
            else:
                self.logger.log(LogPriority.DEBUG, "replaced an existing incomplete or incorrect config line with the correct one. done.")
                written = True
        except Exception:
            raise
        self.logger.log(LogPriority.DEBUG, "finished running writeFile() method. returning written=" + str(written))
        return written

    def report(self):
        '''
        determine whether the xinetd configuration file contains the correct configuration settings
        determine whether the xinetd configuration file has the correct permissions set
        determine whether the xinetd configuration file has the correct ownership set

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "inside report() method for XinetdAccessControl class")

        self.compliant = True
        self.detailedresults = ""

        try:
            self.logger.log(LogPriority.DEBUG, "checking if configuration file exists at expected location " + str(self.confpath))
            if os.path.exists(self.confpath):
                self.logger.log(LogPriority.DEBUG, "configuration file found; checking for correct configuration")
                if not self.findopt(self.confpath, self.fullopt):
                    self.compliant = False
                    self.detailedresults += '\ncorrect configuration not found in ' + str(self.confpath)
                perms = getOctalPerms(self.confpath)
                self.logger.log(LogPriority.DEBUG, "checking configuration file for correct permissions")
                self.logger.log(LogPriority.DEBUG, "required perms: 644; current perms: " + str(perms))
                if perms != 644:
                    self.compliant = False
                    self.detailedresults += '\npermissions not set correctly on ' + str(self.confpath)
                ownership = getOwnership(self.confpath)
                self.logger.log(LogPriority.DEBUG, "checking configuration file for correct ownership")
                if ownership != [0, 0]:
                    self.compliant = False
                    self.detailedresults += '\nownership not set correctly on ' + str(self.confpath)
            else:
                self.detailedresults += '\nconfiguration file does not exist; xinetd not installed'
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        self.logger.log(LogPriority.DEBUG, "finished running report() method for XinetdAccessControl class\nreturning self.compliant=" + str(self.compliant))
        return self.compliant

    def fix(self):
        '''
        write correction xinetd configuration to xinetd configuration file
        ensure correct permissions set on xinetd configuration file
        ensure correct ownership set on xinetd configuration file

        @return: self.rulesuccess
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "inside fix() method for XinetdAccessControl class")

        self.rulesuccess = True
        self.detailedresults = ""

        try:
            if self.ci.getcurrvalue():
                self.logger.log(LogPriority.DEBUG, "CI is enabled; proceeding with fix actions")
                if not self.compliant:
                    self.logger.log(LogPriority.DEBUG, "config option not found; writing it to " + str(self.confpath))
                    if not self.writeFile(self.confpath, self.fixopt):
                        self.rulesuccess = False
                        self.detailedresults += '\nfailed to write configuration to ' + str(self.confpath)
                    self.logger.log(LogPriority.DEBUG, "setting permissions to 644 on " + str(self.confpath))
                    os.chmod(self.confpath, 0644)
                    self.logger.log(LogPriority.DEBUG, "setting ownership to root:root (0:0) on " + str(self.confpath))
                    os.chown(self.confpath, 0, 0)
            else:
                self.detailedresults += '\nCI is not currently enabled. fix will not be performed.'
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        self.logger.log(LogPriority.DEBUG, "finished running fix() method for XinetdAccessControl class\nreturning self.rulesuccess=" + str(self.rulesuccess))
        return self.rulesuccess
