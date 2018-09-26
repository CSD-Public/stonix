###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was  #
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
Created on April 25, 2018

Limit a system's concurrent logins to 10 (default) or the
number the end-user specifies
This is not a mandatory rule

@author: Derek Walker, Breen Malmberg
@change: 04/27/2018 - Breen Malmberg - changed config type to 'maxlogins'; fixed
        the removal of newline characters between config lines; added permissions
        checking of config file(s); changed mandatory flag to False
'''

from __future__ import absolute_import

import traceback
import re
import os

from ..rule import Rule
from ..stonixutilityfunctions import iterate, resetsecon, checkPerms
from ..logdispatcher import LogPriority


class LimitConcurrentLogins(Rule):
    '''
    Limit a system's concurrent logins to 10 (default) or the
    number the end-user specifies
    This is not a mandatory rule
    '''

    def __init__(self, config, environ, logdispatcher, statechglogger):
        '''
        '''

        Rule.__init__(self, config, environ, logdispatcher, statechglogger)
        self.rulenumber = 330
        self.rootrequired = True
        self.rulename = 'LimitConcurrentLogins'
        self.logger = logdispatcher
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.applicable = {'type': 'white',
                           'family': ['linux'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.12.10']}}
        self.conffilesdir = "/etc/security/limits.d"
        self.sethelptext()

        # init CIs
        datatype1 = 'bool'
        key1 = 'LIMITCONCURRENTLOGINS'
        instructions1 = "To enable this rule, set the value of LIMITCONCURRENTLOGINS to True."
        default1 = False
        self.ci = self.initCi(datatype1, key1, instructions1, default1)

        datatype2 = 'string'
        key2 = "MAXLOGINS"
        instructions2 = "Enter the maximum number of login sessions you wish to limit this system to. Please enter a single, positive integer."
        default2 = "10"
        self.cinum = self.initCi(datatype2, key2, instructions2, default2)

    def readFile(self, filepath):
        '''
        Read the contents of filepath into a list and return that list
        Return a blank list if either the filepath argument is not the
        correct data type, or the filepath does not exist on the operating
        system

        @param filepath: string; full path to the file to be read

        @return: contentlist
        @rtype: list

        @author: Breen Malmberg
        '''

        contentlist = []

        try:

            if not os.path.exists(filepath):
                self.detailedresults += "\nRequired configuration file: " + str(filepath) + " does not exist"
                self.logger.log(LogPriority.DEBUG, "Cannot read file. File does not exist.")
                return contentlist

            f = open(filepath, 'r')
            contentlist = f.readlines()
            f.close()

        except Exception:
            raise

        return contentlist

    def writeFile(self, path, contents):
        '''
        write given contents to a given file path
        record undo action
        return true if successful
        return false if failed

        @param path: string; full path to the file to write to
        @param contents: list; list of strings to write to file

        @return: success
        @rtype: bool

        @author: Breen Malmberg
        '''

        success = True
        tmppath = path + ".stonixtmp"

        try:

            if not contents:
                self.logger.log(LogPriority.DEBUG, "Contents was empty")
                success = False
                return success

            if not os.path.exists(os.path.abspath(os.path.join(path, os.pardir))):
                self.logger.log(LogPriority.DEBUG, "Parent directory does not exist")
                success = False
                return success

            elif os.path.exists(path):

                tf = open(tmppath, 'w')
                tf.writelines(contents)
                tf.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf",
                         "filepath": path}

                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(path, tmppath, myid)
                os.rename(tmppath, path)

            else:

                f = open(path, 'w')
                f.writelines(contents)
                f.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": path}

                self.statechglogger.recordchgevent(myid, event)

            os.chmod(path, 384)
            os.chown(path, 0, 0)
            resetsecon(path)

        except Exception:
            success = False
            raise

        return success

    def buildConfFileList(self):
        '''
        Dynamically build the list of configuration files
        we need to edit. This includes any *.conf in the
        /etc/security/limits.d/ directory and the
        /etc/security/limits.conf file if it exists
        The "limits" configuration is read as a concatenation
        of limits.conf and any *.conf files in limits.d/

        @author: Breen Malmberg
        '''

        if os.path.exists(self.conffilesdir):

            conffilelist = os.listdir(self.conffilesdir)
            if conffilelist:
                self.logger.log(LogPriority.DEBUG, "Building list of configuration files...")
                for cf in conffilelist:
                    if re.search("\.conf$", cf):
                        self.logger.log(LogPriority.DEBUG, "Adding file to list: " + cf + " ...")
                        self.conffiles.append(self.conffilesdir + "/" + cf)

    def report(self):
        '''
        LimitConcurrentLogins.report() method to report whether system's
        concurrent logins are regulated.

        @return: self.compliant
        @rtype: bool

        @author: Derek Walker, Breen Malmberg
        '''

        self.compliant = True
        self.detailedresults = ""
        self.userloginsvalue = str(self.cinum.getcurrvalue())
        self.conffiles = ["/etc/security/limits.conf"]
        self.expectedvalues = ['*', 'hard', 'maxlogins', str(self.userloginsvalue)]
        self.strcfgline = self.expectedvalues[0] + " " + self.expectedvalues[1] + " " + self.expectedvalues[2] + " " + self.expectedvalues[3]
        self.foundcorrectcfg = False
        self.foundincorrect = False

        # if a user enters an invalid value for the MAXLOGINS CI, reset the value
        # to 10 and inform the user
        if self.userloginsvalue == "":
            self.userloginsvalue = "10"
            self.logger.log(LogPriority.DEBUG, "A blank value was entered for MAXLOGINS. Resetting to default value of 10...")
        if not self.userloginsvalue.isdigit():
            self.userloginsvalue = "10"
            self.logger.log(LogPriority.DEBUG, "An invalid value was entered for MAXLOGINS. Please enter a single, positive integer. Resetting to default value of 10...")

        correctconfig = "^\s*\*\s+\hard\s+maxlogins\s+" + self.userloginsvalue

        try:

            # possibly more than 1 conf file to check
            self.buildConfFileList()

            for cf in self.conffiles:

                contentlines = self.readFile(cf)

                if contentlines:
                    for line in contentlines:
                        if re.search(correctconfig, line):
                            if not self.foundcorrectcfg:
                                self.detailedresults += "\nFound correct maxlogins config line in: " + str(cf) + "\n"
                                self.foundcorrectcfg = True

                    # we not only need to find the correct config line
                    # we also need to make sure that no incorrect config lines exist either
                    for line in contentlines:
                        if self.matchIncorrect(line, self.expectedvalues):
                            self.detailedresults += "\nFound an incorrect maxlogins config line in: " + str(cf)
                            self.detailedresults += "\nIncorrect line = " + line
                            self.foundincorrect = True

                else:
                    self.logger.log(LogPriority.DEBUG, "Configure file: " + str(cf) + " was empty/blank")

                if not checkPerms(cf, [0, 0, 0600], self.logger):
                    self.compliant = False
                    self.detailedresults += "\nIncorrect permissions on file: " + str(cf)

            if not self.foundcorrectcfg:
                self.compliant = False
                self.detailedresults += "\nDid not find the correct maxlogins config line"

            if self.foundincorrect:
                self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults('report', self.compliant, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def matchIncorrect(self, line, expectedvalues):
        '''
        find any maxlogins configuration lines which have the incorrect value(s)
        return True if an incorrect config line is found
        return False if not

        @param line: string; configuration line to check
        @param expectedvalues: list; list of correct config line parts

        @return: mismatch
        @rtype: bool

        @author: Breen Malmberg
        '''

        mismatch = False
        i = 0

        try:

            if re.search("^\s*#", line):
                return mismatch
            elif re.search("maxlogins", line, re.IGNORECASE):
                sline = line.split()
                if len(sline) != len(expectedvalues):
                    mismatch = True
                while i < len(sline):
                    if sline[i] != expectedvalues[i]:
                        mismatch = True
                    i+=1

        except IndexError:
            pass

        return mismatch

    def fix(self):
        '''
        Limit the number of concurrent logins to the value of LOGINNUMBER CI
        (default 10)

        @return: self.rulesuccess
        @rtype: bool

        @author: Derek Walker, Breen Malmberg
        '''

        self.rulesuccess = True
        self.detailedresults = ""

        self.iditerator = 0

        try:

            if self.ci.getcurrvalue():

                # iterate through list of config files
                for cf in self.conffiles:
                    contentlines = []

                    contentlines = self.readFile(cf)

                    # no limit to number of incorrect entries we can fix
                    if self.foundincorrect:
                        contentlines = self.fixIncorrect(contentlines, self.expectedvalues)

                    # we only want to append the config line once to one of the files
                    # (if it doesn't already exist somewhere else)
                    if not self.foundcorrectcfg:
                        contentlines = self.fixMissing(contentlines)
                        self.foundcorrectcfg = True

                    contentlines = self.fixDuplicates(contentlines)

                    contentlines = self.fixEOF(contentlines)

                    contentlines = self.fixHeading(cf, contentlines)

                    # fix any blank line inflation
                    contentlines = self.fixDeflate(contentlines)

                    # write all of the changes to the config file
                    if contentlines:
                        if not self.writeFile(cf, contentlines):
                            self.logger.log(LogPriority.DEBUG, "Failed to write contents to file")
                            self.rulesuccess = False
                    else:
                        self.logger.log(LogPriority.DEBUG, "Failed to write contents to file")
                        self.rulesuccess = False

            else:
                self.logger.log(LogPriority.DEBUG, "The CI for this rule was not enabled. Fix will not be performed.")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults('fix', self.rulesuccess, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def fixIncorrect(self, contentlines, expectedvalues):
        '''
        fix any existing, incorrect configuration line entries
        return the fixed results

        @param contentlines: list; list of strings to examine
        @param expectedvalues: list; list of correct config value parts

        @return: contentlines
        @rtype: list

        @author: Breen Malmberg
        '''

        # replace string slightly different than appendstring, since we
        # are replacing a current line and its newline return
        replacestring = self.strcfgline + "\n"

        for line in contentlines:
            if self.matchIncorrect(line, expectedvalues):
                contentlines = [c.replace(line, replacestring) for c in contentlines]

        return contentlines

    def fixMissing(self, contentlines=[]):
        '''
        if the contents are completely missing the configuration line
        append it and return the results

        @param contentlines: list; list of strings to examine

        @return: contentlines
        @rtype: list

        @author: Breen Malmberg
        '''

        # appendstring slightly different than replacestring, since we
        # are adding a new string plus a new newline return
        appendstring = "\n" + self.strcfgline + "\n"

        self.logger.log(LogPriority.DEBUG, "Didn't find config line. Appending it to end of config file...")
        contentlines.append(appendstring)

        return contentlines

    def fixDuplicates(self, contentlines):
        '''
        search for and remove any duplicates of the specific configuration
        line we are looking for. return the results

        @param contentlines: list; list of strings to examine
        @param expectedvalues: list; list of correct config value parts

        @return: newcontentlines
        @rtype: list

        @author: Breen Malmberg
        '''

        newcontentlines = []

        self.logger.log(LogPriority.DEBUG, "Checking for and fixing any duplicate config line entries...")

        for line in contentlines:
            if line not in newcontentlines:
                newcontentlines.append(line)

        return newcontentlines

    def fixDeflate(self, contentlines):
        '''
        remove extra blank lines to prevent file inflation

        @param contentlines: list; list of strings to examine

        @return: newcontentlines
        @rtype: list

        @author: Breen Malmberg
        '''

        i = 0
        newcontentlines = []

        # only allow a maximum of 1 full blank line between lines with actual content
        # remove all extra blank lines; keep all lines with content in them (all non-blank)
        self.logger.log(LogPriority.DEBUG, "Removing extra blank lines from file contents...")
        for line in contentlines:
            if re.search('^\s*\n$', line):
                i += 1
                if i >= 2:
                    continue
                else:
                    newcontentlines.append(line)
            else:
                newcontentlines.append(line)
                i = 0

        return newcontentlines

    def fixEOF(self, contentlines):
        '''
        move the end of file comment to the end of the file

        @param contentlines: list; list of strings to examine

        @return: contentlines
        @rtype: list

        @author: Breen Malmberg
        '''

        eofstring = "\n# End of File\n"

        for line in contentlines:
            if re.search("^\s*#\s*End\s+of\s+File", line, re.IGNORECASE):
                contentlines = [c.replace(line, "") for c in contentlines]

        contentlines.append(eofstring)

        return contentlines

    def fixHeading(self, filepath, contentlines):
        '''
        insert the file comment heading if it does not exist

        @param filepath: string; full path to the file
        @param contentlines: list; list of strings to examine

        @return: contentlines
        @rtype: list

        @author: Breen Malmberg
        '''

        foundheading = False

        for line in contentlines:
            if re.search('^\s*#\s*' + filepath, line):
                foundheading = True

        if not foundheading:
            contentlines.insert(0, '# ' + filepath + '\n\n')

        return contentlines
