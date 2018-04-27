###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was       #
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

            os.chmod(path, 0600)
            os.chown(path, 0, 0)
            resetsecon(path)

        except Exception:
            success = False
            raise

        return success

    def buildConfFileList(self):
        '''
        dynamically build the list of configuration files
        we need to edit. this includes any *.conf in the
        /etc/security/limits.d/ directory and the
        /etc/security/limits.conf file if it exists

        @author: Breen Malmberg
        '''

        if os.path.exists(self.conffilesdir):

            conffilelist = os.listdir(self.conffilesdir)
            if conffilelist:
                self.logger.log(LogPriority.DEBUG, "Building list of configuration files...")
                for cf in conffilelist:
                    if re.search("\.conf", cf):
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

        self.compliant = False
        self.detailedresults = ""
        self.userloginsvalue = str(self.cinum.getcurrvalue())
        self.conffiles = ["/etc/security/limits.conf"]
        foundcorrectcfg = False

        # if a user enters an invalid value for the MAXLOGINS CI, reset the value
        # to 10 and inform the user
        if self.userloginsvalue == "":
            self.userloginsvalue = "10"
            self.logger.log(LogPriority.DEBUG, "A blank value was entered for MAXLOGINS. Resetting to default value of 10...")
        if not self.userloginsvalue.isdigit():
            self.userloginsvalue = "10"
            self.logger.log(LogPriority.DEBUG, "An invalid value was entered for MAXLOGINS. Please enter a single, positive integer. Resetting to default value of 10...")

        matchfull = "^\*\s+\-\s+maxlogins\s+" + self.userloginsvalue
        matchincorrect = "^\*\s+.*\s+maxlogins\s+((?!" + str(self.userloginsvalue) + ").)"

        try:

            self.buildConfFileList()

            for cf in self.conffiles:

                contentlines = self.readFile(cf)
    
                if contentlines:
                    if not foundcorrectcfg:
                        for line in contentlines:
                            if re.search(matchfull, line):
                                self.detailedresults += "\nFound correct maxlogins config line in: " + str(cf)
                                self.compliant = True
                                foundcorrectcfg = True

                    # we not only need to find the correct config line
                    # we also need to make sure that no incorrect config lines exist either
                    for line in contentlines:
                        if re.search(matchincorrect, line):
                            self.compliant = False
                            self.detailedresults += "\nFound an incorrect maxlogins config line in: " + str(cf)

                if not checkPerms(cf, [0, 0, 0600], self.logger):
                    self.compliant = False
                    self.detailedresults += "\nIncorrect permissions on file: " + str(cf)

            if not foundcorrectcfg:
                self.detailedresults += "\nDid not find the correct maxlogins config line"

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults('report', self.compliant, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

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
        replacestring = "* - maxlogins " + self.userloginsvalue + "\n"
        appendstring = "\n* - maxlogins " + self.userloginsvalue
        matchincorrect = "^\*\s+.*\s+maxlogins\s+((?!" + str(self.userloginsvalue) + ").)"
        self.iditerator = 0
        contentlines = []
        wrotecorrectcfg = False

        try:

            if self.ci.getcurrvalue():

                for cf in self.conffiles:
                    replaced = False
                    appended = False
                    contentlines = []

                    contentlines = self.readFile(cf)
    
                    # file was empty. just add the config line
                    if not contentlines:
                        if not wrotecorrectcfg:
                            contentlines.append(appendstring)
                            appended = True
                    else:
    
                        for line in contentlines:
        
                            # check for partial match
                            if re.search(matchincorrect, line):
                                # if we already replaced one line with the correct config
                                # then remove any extra (duplicate) config line entries which
                                # may exist in the file's contents
                                if replaced:
                                    self.logger.log(LogPriority.DEBUG, "Found duplicate config line. Removing...")
                                    contentlines = [c.replace(line, "\n") for c in contentlines]
                                # if partial match then replace line with correct config line
                                else:
                                    self.logger.log(LogPriority.DEBUG, "Found config line, but it is incorrect. Fixing...")
                                    contentlines = [c.replace(line, replacestring) for c in contentlines]
                                    replaced = True
    
                    # if we didn't find any partial matches to replace, then
                    # append the correct config line to the end of the file
                    if not replaced:
                        if not wrotecorrectcfg:
                            self.logger.log(LogPriority.DEBUG, "Didn't find config line. Appending it to end of config file...")
                            contentlines.append(appendstring)
                            appended = True
    
                    # we only want to write if we actually changed something
                    if bool(appended or replaced):
                        if not self.writeFile(cf, contentlines):
                            self.rulesuccess = False
                        else:
                            wrotecorrectcfg = True
                    else:
                        self.logger.log(LogPriority.DEBUG, "Didn't make any changes to the file's contents")

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
