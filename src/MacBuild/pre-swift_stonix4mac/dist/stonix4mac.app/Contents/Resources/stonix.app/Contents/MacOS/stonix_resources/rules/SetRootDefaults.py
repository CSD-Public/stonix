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

Created on Aug 1, 2013

Set default group and home directory for root.

@author: bemalmbe
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 ekkehard ci updates and ci fix method implementation
@change: 2015/04/17 dkennel updated for new isApplicable

'''
# this rule applies to solaris only

from __future__  import absolute_import
from ..rule import Rule
from ..stonixutilityfunctions import cloneMeta
from ..configurationitem import ConfigurationItem
from ..logdispatcher import LogPriority
import os
import traceback


class SetRootDefaults(Rule):
    '''
    Set default group and home directory for root.
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
        self.rulenumber = 77
        self.rulename = 'SetRootDefaults'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.helptext = '''Set default group and home directory for root.'''
        self.rootrequired = True
        self.ci = self.initCi("bool",
                              "SetRootDefaults",
                              "To the setting of the root default " + \
                              "home directory and group, set the " + \
                              "value of SetRootDefaults to False.",
                              True)
        self.guidance = ['CIS', 'cce-4834-8']
        self.isApplicableWhiteList = ["solaris"]
        self.isApplicableBlackList = ["darwin",
                                      "linux",
                                      "freebsd"]
        self.applicable = {'type': 'white',
                           'family': ['solaris']}

    def __initializeSetRootDefaults(self):
        '''
        Private method to initialize the configurationitem object for the
        SetRootDefaults bool.

        @return configurationitem object instance
        @author bemalmbe
        '''

        conf1 = 'SetRootDefaults'
        conf1inst = '''To the setting of the root default home directory and group, set the value of SetRootDefaults to False.'''
        conf1default = True
        try:
            conf1curr = self.config.getconfvalue(self.rulename, conf1)
        except(KeyError):
            conf1curr = ''
        conf1curr = conf1curr.lower()
        if conf1curr in ['yes', 'true']:
            conf1curr = True
        elif conf1curr in ['no', 'false']:
            conf1curr = False
        else:
            conf1curr = conf1default
        try:
            conf1uc = self.config.getusercomment(self.rulename, conf1)
        except(KeyError):
            conf1uc = ''
        conf1type = 'bool'
        conf1simple = True
        setrootdefaults = ConfigurationItem(conf1, conf1default, conf1uc, conf1type, conf1inst, conf1curr, conf1simple)
        self.confitems.append(setrootdefaults)
        return setrootdefaults

###############################################################################

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
        secure = True
        found = False

        try:

            # check for root gid=0 and root homedir = /root
            f = open('/etc/passwd', 'r')
            contentlines = f.readlines()
            f.close()

            try:
                self.detailedresults = ""
                for line in contentlines:
                    line = line.split(':')
                    if line[0] == 'root':
                        found = True
                        if line[3] != '0':
                            secure = False
                        if os.path.exists('/root'):
                            if line[5] != '/root':
                                secure = False
                        else:
                            secure = False

            except (IndexError):
                print IndexError.message

            if not found:
                secure = False

            if secure:
                self.compliant = True
            else:
                self.rulesuccess = False
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
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
        Set the gid for the root account to 0. Set the home directory for the
        root account to /root

        @author bemalmbe
        '''

        try:
            self.detailedresults = ""
            if self.ci.getcurrvalue():
                # set root gid=0 and homedir = /root
                f = open('/etc/passwd', 'r')
                contentlines = f.readlines()
                f.close()

                try:

                    for line in contentlines:
                        line = line.split(':')
                        if line[0] == 'root':
                            line[3] = '0'
                        if os.path.exists('/root'):
                            line[5] = '/root'
                        else:
                            os.system('mkdir /root')
                            os.system('chmod 700 /root')
                            os.system('chown root:root /root')
                            line[5] = '/root'
                        ':'.join(line)
                except (IndexError):
                    self.logger.log(LogPriority.INFO, IndexError.message)
            else:
                self.detailedresults = str(self.ci.getkey()) + \
                " was disabled. No action was taken."

            tf = open('/etc/passwd.stonixtmp', 'w+')
            tf.writelines(contentlines)
            tf.close()
            cloneMeta(self.logger, '/etc/passwd', '/etc/passwd.stonixtmp')
            event = {'eventtype': 'conf',
                     'eventstart': self.currstate,
                     'eventend': self.targetstate,
                     'filename': '/etc/passwd'}
            myid = '0077001'
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange('/etc/passwd',
                                                 '/etc/passwd.stonixtmp',
                                                 myid)
            os.rename('/etc/passwd.stonixtmp',
                      '/etc/passwd')
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
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

    def undo(self):
        '''
        use the statechglogger to revert any file changes made by the
        fix() method.

        @author bemalmbe
        '''
        try:
            self.detailedresults = ""
            if self.currstate == 'configured':
                event = self.statechglogger.getchgevent('0077001')
                self.statechglogger.revertfilechanges(event['filename'],
                                                      '0077001')

        except (IndexError):
            self.logdispatch.log(LogPriority.DEBUG, IndexError.message)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("undo", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
