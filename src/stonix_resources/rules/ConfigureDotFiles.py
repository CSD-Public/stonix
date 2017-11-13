###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
Created on Jul 8, 2013

A user who can modify another user's configuration files can likely execute
commands with the other user's privileges, including stealing data, destroying
files, or launching further attacks on the system. This rule ensures that no
dot files within users' home directories possess the world/other - writable
permission.

@author: Breen Malmberg
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 ekkehard Implemented isapplicable
@change: 02/27/2014 ekkehard fix self.detailedresults flow bug
@change: 04/18/2014 dkennel Updated to use new CI. Fixed bug where CI was not
checked in fix method.
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/04/30 Breen corrected mac implementation and separated mac and linux functionality
@change: 2015/10/07 eball Help text cleanup
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
'''

from __future__ import absolute_import
import os
import re
import traceback
import pwd
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import isWritable
from ..CommandHelper import CommandHelper


class ConfigureDotFiles(Rule):
    '''
    A user who can modify another user's configuration files can likely execute
    commands with the other user's privileges, including stealing data,
    destroying files, or launching further attacks on the system. This rule
    ensures that no dot files within users' home directories possess the
    world/other - writable permission.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 46
        self.rulename = 'ConfigureDotFiles'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = False
        self.compliant = False
        datatype = 'bool'
        key = 'CONFIGUREDOTFILES'
        instructions = '''To prevent dot files in user home directories from \
being made non-world-writable, set the value of ConfigureDotFiles to False.'''
        default = True
        self.ConfigureDotFiles = self.initCi(datatype, key,
                                             instructions, default)
        self.guidance = ['CIS', 'NSA 2.3.4.3', 'CCE-4561-7']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}

    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant and self.detailed results properties are
        updated to reflect the system status.

        @return self.compliant
        @rtype: boolean
        @author: Breen Malmberg
        '''

        # defaults
        dotfilelist = []
        self.compliant = True
        self.detailedresults = ""
        self.cmdhelper = CommandHelper(self.logger)

        try:

            if self.environ.getostype() == 'Mac OS X':
                dotfilelist = self.buildmacdotfilelist()
            else:
                dotfilelist = self.buildlinuxdotfilelist()

            for item in dotfilelist:
                # is item world writable?
                if isWritable(self.logger, item, 'other'):
                    self.compliant = False
                    self.detailedresults += '\nFound world writable dot file: ' \
                                            + str(item)

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
        return self.compliant

    def buildlinuxdotfilelist(self):
        '''
        build a list of linux dot files for the current user
        @return: dotfilelist
        @rtype: list
        @author: Breen Malmberg
        '''

        dotfilelist = []

        try:

            f = open('/etc/passwd', 'r')
            contentlines = f.readlines()
            f.close()

            for line in contentlines:

                line = line.split(':')

                if len(line) >= 6 and line[5] and \
                   self.environ.geteuidhome() == str(line[5]):

                    line[2] = int(line[2])
                    if line[2] >= 500 and not re.search('nfsnobody', line[0]):

                        if os.path.exists(line[5]):
                            filelist = os.listdir(line[5])
                            for i in range(len(filelist)):
                                if re.search('^\.', filelist[i]):
                                    dotfilelist.append(line[5] + '/' +
                                                       filelist[i])

        except Exception:
            raise
        return dotfilelist

    def buildmacdotfilelist(self):
        '''
        build a list of mac dot files for the current user
        @return: dotfilelist
        @rtype: list
        @author: Breen Malmberg
        '''

        dotfilelist = []
        users = []
        homedirs = []

        try:

            cmd = ["/usr/bin/dscl", ".", "-list", "/Users"]
            try:
                self.cmdhelper.executeCommand(cmd)
            except OSError as oser:
                if re.search('DSOpenDirServiceErr', str(oser)):
                    self.detailedresults += '\n' + str(oser)
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
            output = self.cmdhelper.getOutput()
            error = self.cmdhelper.getError()
            if error:
                self.detailedresults += '\nCould not get a list of user ' + \
                    'home directories. Returning empty list...'
                return dotfilelist

            if output:
                for user in output:
                    if not re.search('^_|^root|^\/$', user):
                        users.append(user.strip())
                        debug = "Adding user " + user.strip() + " to users " \
                                + "list"
                        self.logger.log(LogPriority.DEBUG, debug)

            if users:
                for user in users:
                    try:
                        currpwd = pwd.getpwnam(user)
                        homedirs.append(currpwd[5])
                    except KeyError:
                        continue

            if homedirs:
                for homedir in homedirs:
                    if self.environ.geteuidhome() == homedir:
                        filelist = os.listdir(homedir)
                        for i in range(len(filelist)):
                            if re.search('^\.', filelist[i]):
                                dotfilelist.append(homedir + '/' + filelist[i])

        except Exception:
            raise
        return dotfilelist

    def fix(self):
        '''
        remove any world writable flags from any dot files in user's home
        directory

        @author: Breen Malmberg
        '''

        # defaults
        dotfilelist = []
        self.detailedresults = ""
        self.rulesuccess = True

        if self.ConfigureDotFiles.getcurrvalue():

            try:

                if self.environ.getostype() == 'Mac OS X':
                    dotfilelist = self.buildmacdotfilelist()
                else:
                    dotfilelist = self.buildlinuxdotfilelist()

                if dotfilelist:
                    for item in dotfilelist:
                        if os.path.isfile(item):

                            try:
                                os.system('chmod o-w ' + item)
                            except (OSError, IOError):
                                self.rulesuccess = False
                                self.detailedresults += '\nCould not chmod: ' \
                                                        + str(item)

            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as err:
                self.rulesuccess = False
                self.detailedresults = self.detailedresults + "\n" + \
                    str(err) + " - " + str(traceback.format_exc())
                self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
