'''
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

Created on Dec 11, 2012
The SetDefaultUserUmask class sets the default user umask to 077. Also accepts
user input of alternate 027 umask.

@author: bemalmbe
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 ekkehard ci updates and ci fix method implementation
@change: 07/10/2014 rsn change assignments to comparisons and if on mac & root,
                    use 022 as the umask
@change: 08/05/2014 ekkehard added removeStonixUMASKCodeFromFile
@change: 08/25/2014 bemalmbe completely re-written
@change: 08/27/2014 bemalmbe added documentation, cleaned up some existing
        documentation
@change: 2015/04/17 dkennel updated for new isApplicable. Tuned text.
'''

from __future__ import absolute_import

import os
import re
import traceback
import shutil

from ..rule import Rule
from ..stonixutilityfunctions import iterate
from ..logdispatcher import LogPriority


class SetDefaultUserUmask(Rule):
    '''
    The SetDefaultUserUmask class sets the default user umask to 077. Also
    accepts user input of alternate 027 umask.

    For OS X documentation on this can be found at:
    http://support.apple.com/kb/HT2202
    '''

    def __init__(self, config, environ, logdispatch, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logdispatch, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logdispatch
        self.statechglogger = statechglogger
        self.rulenumber = 48
        self.rulename = 'SetDefaultUserUmask'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.helptext = "The SetDefaultUserUmask class sets the default " + \
        "user umask to 027. Also accepts user input of alternate 077 umask." + \
        " Mac OS X will have the umask set to 022 because it breaks with " + \
        "stricter settings."
        self.rootrequired = True
        self.guidance = ['CIS', 'NSA(2.3.4.4)', 'CCE-3844-8', 'CCE-4227-5',
                         'CCE-3870-3', 'CCE-4737-6']

        # set up which system types this rule will be applicable to
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}

        # decide what the default umask value should be, based on osfamily
        if self.environ.getosfamily() == 'darwin':
            defaultumask = '022'
        else:
            defaultumask = '027'

        self.ci = self.initCi("bool",
                              "SetDefaultUserUmask",
                              "To prevent stonix from setting the " + \
                              "default user umask, set the value of " + \
                              "SetDefaultUserUmask to False.",
                              True)

        # init CIs
        self.userUmask = \
        self.initCi("string", "DefaultUserUmask",
                    "Set the default user umask value. Correct format is " + \
                    "a 3-digit, 0-padded integer.", defaultumask)

        self.rootUmask = self.initCi("string", "DefaultRootUmask",
                                     "Set the default root umask value. " + \
                                     "Correct format is 3-digit, 0-padded " + \
                                     "integer. Setting this to a value " + \
                                     "more restrictive than 022 may " + \
                                     "cause issues.", "022")

        # set up list of files which need to be checked and configured
        self.rootfiles = ['/root/.bash_profile', '/root/.bashrc',
                          '/root/.cshrc', '/root/.tcshrc']

        self.filelist = ['/etc/profile', '/etc/csh.login', '/etc/csh.cshrc',
                         '/etc/bashrc', '/etc/zshrc', '/etc/login.conf',
                         '/etc/bash.bashrc']

        # this is the correct file path to use for os 10.9 as per:
        # http://support.apple.com/kb/ht2202
        self.macfile = '/etc/launchd-user.conf'

###############################################################################

    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailedresults and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return: bool
        @author: bemalmbe
        '''

        # defaults
        self.detailedresults = ""

        try:

            # decide which report method to run based on osfamily
            if self.environ.getosfamily() == 'darwin':
                self.compliant = self.reportmac()
            else:
                self.compliant = self.reportnix()

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.compliant = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def reportmac(self):
        '''
        private method for reporting compliance status of darwin based systems

        @return: bool
        @author: bemalmbe
        '''

        # defaults
        configured = False

        try:

            # check for presence of umask config line in mac config file
            if self.searchString('^umask\s*' + str(self.userUmask.getcurrvalue()),
                                 self.macfile):
                configured = True
            # report that the umask config line does not exist, if not found
            else:
                self.detailedresults += '\numask config string not found in ' + str(self.macfile)

        except Exception:
            raise

        return configured

###############################################################################

    def reportnix(self):
        '''
        private method for reporting compliance status of *nix based systems

        @return: bool
        @author: bemalmbe
        '''

        # defaults
        userlinefound = False
        rootlinefound = False
        configured = False

        try:

            # check for presence of umask config line in user files
            for item in self.filelist:
                if self.searchString('^umask\s*' + \
                                     str(self.userUmask.getcurrvalue()), item):
                    userlinefound = True

            # check for presence of umask config line in root files
            for item in self.rootfiles:
                if not os.path.exists(item):
                    self.detailedresults += '\n' + str(item) + ' config file was not found'
                if self.searchString('^umask\s*' + \
                                     str(self.rootUmask.getcurrvalue()), item):
                    rootlinefound = True

            # report which config items are not compliant in detailedresults
            if userlinefound and rootlinefound:
                configured = True
            elif not userlinefound:
                self.detailedresults += '\nuser umask config line not found'
            elif not rootlinefound:
                self.detailedresults += '\nroot umask config line not found'

        except Exception:
            raise

        return configured

###############################################################################

    def fix(self):
        '''
        The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.
        Method to set the default users umask to 077 (or 027 if specified in
        the related config file.

        @return: bool
        @author: bemalmbe
        '''

        # defaults
        self.detailedresults = ""
        self.iditerator = 0

        try:

            # if the ci is enabled/True, proceed
            if self.ci.getcurrvalue():

                # decide which fix method to run, based on osfamily
                if self.environ.getosfamily() == 'darwin':
                    self.rulesuccess = self.fixmac()
                else:
                    self.rulesuccess = self.fixnix()

            # if the ci is not enabled, or False, report this in
            # detailedresults
            else:
                self.detailedresults = str(self.ci.getkey()) + \
                " was disabled. No action was taken."

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
        return self.rulesuccess

###############################################################################

    def fixmac(self):
        '''
        private method to apply umask config changes to mac systems

        @return: bool
        @author: bemalmbe
        @change: bemalmbe 09/02/2014 - added calls to hotfix code provided by
                method removeStonixUMASKCodeFromFile()
        '''

        # defaults
        success = True

        try:

            # hotfix to remove bad code / config entries from previous version
            self.removeStonixUMASKCodeFromFile(self.rootfiles)
            self.removeStonixUMASKCodeFromFile(self.filelist)

            # append the umask config line to the mac config file
            self.configFile('umask ' + str(self.userUmask.getcurrvalue()),
                            self.macfile, 0644, [0, 0])

            # if mac config file does not exist, create it and write the
            # umask config line to it
            if not os.path.exists(self.macfile):
                f = open(self.macfile, 'w')
                f.write('umask ' + str(self.userUmask.getcurrvalue()) + '\n')
                f.close()

                # set correct permissions on newly created config file
                os.chmod(self.macfile, 0644)
                os.chown(self.macfile, 0, 0)

        except Exception:
            success = False
            raise
        return success

###############################################################################

    def fixnix(self):
        '''
        private method to apply umask config changes to *nix systems

        @return: bool
        @author: bemalmbe
        '''

        # defaults
        success = True
        rootfilefound = False

        try:

            # iterate through list of user files
            # append the umask config line to each file
            for item in self.filelist:
                if os.path.exists(item):
                    self.configFile('umask ' + \
                                    str(self.userUmask.getcurrvalue()),
                                    item, 0644, [0, 0])

            # do any of the root umask conf files exist?
            for item in self.rootfiles:
                if os.path.exists(item):
                    rootfilefound = True

            # fail-safe in case no root umask conf file exists on the OS
            if not rootfilefound:
                for item in self.rootfiles:
                    f = open(item, 'w')
                    f.write('umask ' + str(self.rootUmask.getcurrvalue()) + '\n')
                    f.close()
                    os.chmod(item, 0644)
                    os.chown(item, 0, 0)

            # iterate through list of root files
            # append umask config line to each file
            else:
                for item in self.rootfiles:
                    if os.path.exists(item):
                        self.configFile('umask ' + \
                                        str(self.rootUmask.getcurrvalue()),
                                        item, 0644, [0, 0])

        except Exception:
            success = False
            raise
        return success

###############################################################################

    def searchString(self, searchRE, filepath):
        '''
        private method for searching for a given string in a given file

        @param: searchRE - regex string to search for in given filepath
        @param: filepath - full path to the file, in which, to search
        @return: bool
        @author: bemalmbe
        '''

        # defaults
        stringfound = False

        try:

            # check if path exists, then open it and read its contents
            if os.path.exists(filepath):
                f = open(filepath, 'r')
                contentlines = f.readlines()
                f.close()

                # search for the searchRE; if found, set return val to True
                for line in contentlines:
                    if re.search(searchRE, line):
                        stringfound = True
            else:
                self.detailedresults += '\n' + str(filepath) + ' specified' + \
                ' was not found'

        except Exception:
            raise

        return stringfound

###############################################################################

    def configFile(self, configString, filepath, perms, owner):
        '''
        private method for adding a configString to a given filepath

        @param: configString - the string to add to the filepath
        @param: filepath - the full path of the file to edit
        @param: perms - 4-digit 0-padded octal permissions (integer)
        @param: owner - 2-element integer list, in format: [uid, gid]
        @author: bemalmbe
        '''

        try:

            if os.path.exists(filepath):
                tmpfile = filepath + '.stonixtmp'

                # open the file, read its contents
                f = open(filepath, 'r')
                contentlines = f.readlines()
                f.close()

                # append the config string
                contentlines.append('\n' + configString)

                # open temporary file, write new contents
                tf = open(tmpfile, 'w')
                tf.writelines(contentlines)
                tf.close()

                # create undo id and dict and save change record
                event = {'eventtype': 'conf',
                         'filepath': filepath}
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(tmpfile, filepath, myid)

                # set permission and ownership on rewritten file
                os.rename(tmpfile, filepath)
                os.chmod(filepath, perms)
                os.chown(filepath, owner[0], owner[1])

        except Exception:
            raise

###############################################################################

    def appendDetailedResults(self, message):
        '''
        '''

        self.detailedresults += '\n' + str(message) + '\n'

###############################################################################

    def removeStonixUMASKCodeFromFile(self, filelist=[]):
        '''
        Removes the STONIX sets default umask block from list
        of files presented

        @return: bool
        @author: ekkehard
        '''
        success = True
        for myfile in filelist:
            if os.path.exists(myfile):
                try:
                    rfh = open(myfile, "r")
                except Exception:
                    self.appendDetailedResults("File: " + \
                    str(myfile) + " - Open For Reading Failed - " + \
                    str(traceback.format_exc()))
                else:
                    try:
                        bakFile = "/tmp/removeUMASK-" + \
                        os.path.basename(myfile) + ".bak"
                        wfh = open(bakFile, "w")
                    except Exception:
                        self.appendDetailedResults("File: " + \
                        str(bakFile) + " Open For Writing Failed - " + \
                        str(traceback.format_exc()))
                    else:
                        startOfUMASKBlock = False
                        endOfUMASKBlock = False
                        for line in rfh:
                            if ("# This block added by STONIX sets default umask" in line):
                                startOfUMASKBlock = True
                            if startOfUMASKBlock and not endOfUMASKBlock:
                                self.logdispatch.log(LogPriority.DEBUG,
                                                     "File: " + str(myfile) + \
                                                     "; Removing Line: '" + \
                                                     line.strip() + "'")
                            else:
                                wfh.write(line)
                            if startOfUMASKBlock and "# End STONIX default umask block." in line:
                                endOfUMASKBlock = True

                        if startOfUMASKBlock and endOfUMASKBlock:
                            removedBlockSuccessfully = True
                        else:
                            removedBlockSuccessfully = False
                        rfh.close()
                        wfh.close()
#####
# Using this method as os.rename (which is used in a file "move") is not
# consistent across platforms, and this is.
                if removedBlockSuccessfully:
### delete myfile
                    os.unlink(myfile)
### copy back to real
                    shutil.copyfile(bakFile, myfile)
                    self.appendDetailedResults("File: " + str(myfile) + \
                        " - Removed STONIX sets default umask block!")
                else:
                    self.appendDetailedResults("File: " + str(myfile) + \
                        " - NO STONIX sets default umask block found in!")
### delete bak
                os.unlink(bakFile)
            else:
                self.appendDetailedResults("File: " + str(myfile) + \
                " does not exist.")
        return success
