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
Created on Mar 19, 2013

Install and configure Advanced Intrusion Detection Environment (AIDE).
This rule is optional and will install and configure AIDE when it is run.

@author: bemalmbe
@change: 02/12/2014 ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel Updated for new style CI. Fixed bug where the bool
@change: 06/26/2014 dwalker tasked with figuring out installation bug, will
    be modifying rule as well
CI was not referenced in the fix and report method.
@change: 2015/04/14 dkennel updated to use new is applicable
@change: 2015/10/07 eball PEP8 cleanup
@change: 2017/08/28 ekkehard - Added self.sethelptext()
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..rule import Rule
from ..stonixutilityfunctions import readFile, writeFile, iterate, resetsecon
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..CommandHelper import CommandHelper


class ConfigureAIDE(Rule):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 110
        self.rulename = 'ConfigureAIDE'
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.guidance = ['NSA(2.1.3)', 'cce-4209-3']

        # init CIs
        datatype = 'bool'
        key = 'CONFIGUREAIDE'
        instructions = 'If you set the ConfigureAIDE variable to yes, or ' + \
            'true, ConfigureAIDE will install and set up the Advanced ' + \
            'Intrusion Detection Environment on this system.'
        default = False
        self.applicable = {'type': 'white',
                           'family': ['linux']}
        self.ci = self.initCi(datatype, key, instructions, default)

        datatype2 = 'string'
        key2 = 'AIDEJOBTIME'
        instructions2 = '''This string contains the time when the cron job for
        /usr/sbin/aide --check will run in /etc/crontab. The default value is
        05 04 * * * (which means 4:05am daily)'''
        default2 = "05 04 * * *"
        self.aidetime = self.initCi(datatype2, key2, instructions2, default2)
        pattern = "^[0-5][0-9]\s*([0-2][0-3]|[0-1][0-9])\s*(\*|(0[1-9]|[12][0-9]|3[01]))\s*(\*|[0-1][0-2])\s*(\*|0[0-6])\s*$"
        self.aidetime.setregexpattern(pattern)

    def report(self):
        '''
        Check if AIDE is installed and properly configured.
        If the config is correct then the self.compliant, self.detailed results
        and self.currstate properties are updated to reflect the system status.
        self.rulesuccess will be updated if the rule does not succeed.

        @return bool
        @author bemalmbe
        @change: dwalker - various bug fixes
        '''

        try:
            self.ph = Pkghelper(self.logger, self.environ)
            self.ch = CommandHelper(self.logger)
            self.compliant = True
            self.detailedresults = ""

            # is aide installed?
            if self.ph.check('aide'):

                # does aide exist in one of the expected paths?
                if os.path.exists('/usr/sbin/aide'):
                    aidepath = '/usr/sbin/aide'
                elif os.path.exists('/usr/bin/aide'):
                    aidepath = '/usr/bin/aide'
                # if not, do not attempt to proceed
                else:
                    self.detailedresults += "Could not locate path to " + \
                        "aide executable\n"
                    self.compliant = False

                # does the system have a crontab?
                if os.path.exists('/etc/crontab'):
                    contents = readFile("/etc/crontab", self.logger)

                    # is this system a debian distro?
                    if self.ph.manager == 'apt-get':

                        regex = self.aidetime.getcurrvalue() + " root " + \
                            aidepath + " -c /etc/aide/aide.conf --check"
                    else:
                        regex = self.aidetime.getcurrvalue() + " root " + \
                            aidepath + " --check"
                    # is the aide cron job in the crontab?
                    found = False
                    for line in contents:
                        if re.search(re.escape(regex), line.strip()):
                            found = True
                            break
                    if not found:
                        self.detailedresults += "Didn't find the aide job " + \
                            "in the crontab\n"
                        self.compliant = False
                # if the system does not have a crontab, do not attempt to
                # proceed
                else:
                    self.detailedresults += "Could not locate the system " + \
                        "crontab"
                    self.compliant = False
            else:
                self.detailedresults += "Aide is not installed\n"
                self.compliant = False
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        '''
        Attempt to install and configure AIDE.
        self.rulesuccess will be updated if the rule does not succeed.

        @author bemalmbe
        @return: bool
        @change: dwalker - various bug fixes, added event deletions in fix
        '''

        self.detailedresults = ""
        self.rulesuccess = True

        try:

            if not self.ci.getcurrvalue():
                self.detailedresults += '\nThis rule is currently not enabled, so nothing was done!'
                self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess

            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            aidepath = ''
            newaidedb = ''
            aidedb = ''

            if not self.ph.check("aide"):
                if not self.ph.checkAvailable("aide"):
                    self.detailedresults += "Unable to install Aide so this \
rule is unable to complete\n"
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                else:
                    self.ph.install("aide")
            if os.path.exists('/usr/sbin/aide'):
                aidepath = '/usr/sbin/aide'
            elif os.path.exists('/usr/bin/aide'):
                aidepath = '/usr/bin/aide'
            else:
                self.detailedresults += "Could not locate path to aide \
executable, rule cannot continue\n"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                return False
            if self.ph.manager == 'apt-get':

                self.ch.executeCommand('aideinit')

                if os.path.exists('/etc/aide/aide.conf'):

                    self.ch.executeCommand(aidepath +
                                           ' -c /etc/aide/aide.conf --check')
                else:
                    self.detailedresults += "Could not locate aide conf file\n"
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    return False
            else:
                self.ch.executeCommand(aidepath + ' --init')
                self.ch.executeCommand(aidepath + ' --check')

            if os.path.exists('/var/lib/aide/aide.db.new.gz'):
                newaidedb = '/var/lib/aide/aide.db.new.gz'
                aidedb = '/var/lib/aide/aide.db.gz'
            elif os.path.exists('/var/lib/aide/aide.db.new'):
                newaidedb = '/var/lib/aide/aide.db.new'
                aidedb = '/var/lib/aide/aide.db'
            else:
                self.detailedresults += "Could not locate aide database\n"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                return False

            os.rename(newaidedb, aidedb)
            os.chmod(aidedb, 0600)
            os.chown(aidedb, 0, 0)

            # add the aide check job to cron
            if os.path.exists('/etc/crontab'):
                tempstring = ""
                cronpath = '/etc/crontab'
                tmppath = cronpath + '.stonixtmp'
                contents = readFile(cronpath, self.logger)
                if self.ph.manager == 'apt-get':
                    regex = self.aidetime.getcurrvalue() + " root " + \
                        aidepath + " -c /etc/aide/aide.conf --check"
                else:
                    regex = self.aidetime.getcurrvalue() + " root " + \
                        aidepath + " --check"
                found = False
                for line in contents:
                    if re.search(re.escape(regex), line.strip()):
                        found = True
                        tempstring += line
                    else:
                        tempstring += line
                if not found:
                    tempstring += regex + "\n"
                if writeFile(tmppath, tempstring, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": cronpath}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(cronpath, tmppath,
                                                         myid)
                    os.rename(tmppath, cronpath)
                    os.chmod(cronpath, 384)
                    os.chown(cronpath, 0, 0)
                    resetsecon(cronpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
