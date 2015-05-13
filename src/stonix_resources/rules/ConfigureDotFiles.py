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
Created on Jul 8, 2013

A user who can modify another user's configuration files can likely execute
commands with the other user's privileges, including stealing data, destroying
files, or launching further attacks on the system. This rule ensures that no
dot files within users' home directories possess the world/other - writable
permission.

@author: bemalmbe
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 ekkehard Implemented isapplicable
@change: 02/27/2014 ekkehard fix self.detailedresults flow bug
@change: 04/18/2014 dkennel Updated to use new CI. Fixed bug where CI was not
checked in fix method.
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/14 dkennel updated for new isApplicable
'''

from __future__ import absolute_import
import os
import re
import traceback
from ..rule import Rule
from ..configurationitem import ConfigurationItem
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import isWritable


class ConfigureDotFiles(Rule):
    '''
    A user who can modify another user's configuration files can likely execute 
    commands with the other user's privileges, including stealing data, destroying 
    files, or launching further attacks on the system. This rule ensures that no 
    dot files within users' home directories possess the world/other - writable 
    permission.
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
        self.helptext = '''A user who can modify another user's configuration files can likely execute 
commands with the other user's privileges, including stealing data, destroying
files, or launching further attacks on the system. This rule ensures that no
dot files within users' home directories possess the world/other - writable
permission.'''
        self.rootrequired = False
        self.compliant = False
        datatype = 'bool'
        key = 'ConfigureDotFiles'
        instructions = '''To prevent dot files in user home directories from being made non-world-writable, set the value of ConfigureDotFiles to False.'''
        default = True
        self.ConfigureDotFiles = self.initCi(datatype, key,
                                             instructions, default)
        self.guidance = ['CIS', 'NSA 2.3.4.3', 'CCE-4561-7']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.10']}}

    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return bool
        @author bemalmbe
        '''

        # defaults
        filelist = []
        dotfilelist = []
        secure = True

        try:
            self.detailedresults = ""
            f = open('/etc/passwd', 'r')
            contentlines = f.readlines()
            f.close()

            try:

                for line in contentlines:
                    line = line.split(':')
                    if len(line) > 5:
                        line[2] = int(line[2])
                        if line[2] >= 500 and not re.search('nfsnobody',
                                                            line[0]):
                            if os.path.exists(line[5]):
                                filelist = os.listdir(line[5])
                                for i in range(len(filelist)):
                                    if re.search('^\.', filelist[i]):
                                        dotfilelist.append(line[5] + "/" + \
                                                           filelist[i])

            except (KeyError, IndexError):
                self.logger.log(LogPriority.DEBUG, traceback.format_exc())

            for item in dotfilelist:
                # is item world writable?
                if isWritable(self.logger, item, 'other'):
                    secure = False

            if secure:
                self.compliant = True
            else:
                self.compliant = False

        except (KeyError, IndexError):
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                                          self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''
        The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.

        @author bemalmbe
        '''

        # defaults
        dotfilelist = []
        filelist = []
        if self.ConfigureDotFiles.getcurrvalue():
            try:
                self.detailedresults = ""
                f = open('/etc/passwd', 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:

                    line = line.split(':')

                    if line[5]:

                        line[2] = int(line[2])
                        if line[2] >= 500 and not re.search('nfsnobody', line[0]):

                            if os.path.exists(line[5]):

                                filelist = os.listdir(line[5])
                                for i in range(len(filelist)):
                                    if re.search('^\.', filelist[i]):
                                        dotfilelist.append(line[5] + "/" + filelist[i])

                                if os.getuid() in [line[2], 0]:

                                    for item in dotfilelist:
                                        if os.path.isfile(item):

                                            os.system('chmod o-w ' + item)

                                else:
                                    dotfilelist = []
                                dotfilelist = []

            except (IndexError):
                self.detailedresults = traceback.format_exc()
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception, err:
                self.rulesuccess = False
                self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
                self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                                          self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
