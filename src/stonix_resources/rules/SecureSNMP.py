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
Created on Sep 30, 2013

The Simple Network Management Protocol allows administrators to monitor the state of network 
devices, including computers. Older versions of SNMP were well-known for weak security, 
such as plaintext transmission of the community string (used for authentication) 
and also usage of easily-guessable choices for community string. Disable SNMP if 
possible. Configure SNMP if necessary.

@author: bemalmbe
@change: 04/21/2014 ekkehard Implemented self.detailedresults flow
@change: 04/21/2014 ekkehard ci updates and ci fix method implementation
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/10/08 eball Help text cleanup
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import getOctalPerms
from ..ServiceHelper import ServiceHelper
from ..CommandHelper import CommandHelper
from ..pkghelper import Pkghelper
from ..KVEditorStonix import KVEditorStonix


class SecureSNMP(Rule):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 144
        self.rulename = 'SecureSNMP'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['NSA 3.20', 'CCE 4540-1']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}
        datatype = 'bool'
        key = 'DISABLESNMP'
        instructions = "If there is a mission-critical need for hosts at" + \
                       "this site to be remotely monitored by a SNMP " + \
                       "tool, then prevent the disabling and removal " + \
                       "of SNMP by setting the value of DisableSNMP " + \
                       "to False."
        default = True
        self.disablesnmp = self.initCi(datatype, key, instructions, default)

        datatype2 = 'bool'
        key2 = 'CONFIGURESNMP'
        instructions2 = "To configure SNMP on this system, make sure " + \
                        "you have the value for DisableSNMP set to " + \
                        "False, and set the value of ConfigureSNMP to True."
        default2 = True
        self.configuresnmp = self.initCi(datatype2, key2, instructions2,
                                         default2)

        self.snmpdconflocations = ['/etc/snmp/conf/snmpd.conf',
                                   '/etc/snmp/conf/snmp.conf',
                                   '/etc/snmp/snmpd.conf',
                                   '/etc/snmp/snmp.conf']
        self.snmpv3directives = {'defContext': 'none',
                                 'defVersion': '3',
                                 'defAuthType': 'SHA',
                                 'defSecurityLevel': 'authNoPriv'}
# add any other possible snmp configuration file paths from the environment
# variable SNMPCONFPATH
# .get does not throw keyerror but instead returns None if env doesn't exist
        snmpconfpathstring = os.environ.get('SNMPCONFPATH')

        if snmpconfpathstring:
            snmpconfpathlist = snmpconfpathstring.split()
            for path in snmpconfpathlist:
                path = str(path).strip()
                self.snmpdconflocations.append(path)

    def report(self):
        '''
        Determine which report method(s) to run and run them

        @return bool
        @author bemalmbe
        '''

        # defaults
        self.detailedresults = ""

        try:

            if self.environ.getostype() == 'Mac OS X':
                self.compliant = self.reportmac()
                self.formatDetailedResults("report", self.compliant,
                                           self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant
            compliant = True
            self.svchelper = ServiceHelper(self.environ, self.logger)
            self.pkghelper = Pkghelper(self.logger, self.environ)

            if self.disablesnmp.getcurrvalue():
                if not self.reportDisableSNMP():
                    compliant = False

            if self.configuresnmp.getcurrvalue():
                if not self.reportConfigureSNMP():
                    compliant = False

            self.compliant = compliant

        except AttributeError:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
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

    def reportmac(self):
        '''
        @author: Breen Malmberg
        '''

        configured = True

        try:

            self.cmdhelper = CommandHelper(self.logger)
            filepath = '/System/Library/LaunchDaemons/org.net-snmp.snmpd.plist'
            if not os.path.exists(filepath):
                configured = False
                self.detailedresults += '\nrequired plist configuration file not found: ' + filepath
            cmd = '/usr/bin/defaults read ' + filepath + ' Disabled'
            self.cmdhelper.executeCommand(cmd)
            output = self.cmdhelper.getOutputString()
            errout = self.cmdhelper.getErrorString()
            if errout:
                configured = False
                self.detailedresults += '\nunable to execute defaults read command, or \"Disabled\" key does not exist'
            else:
                if not re.search('^1', output):
                    configured = False
                    self.detailedresults += '\nsnmpd is not yet disabled'

        except Exception:
            raise
        return configured

    def reportDisableSNMP(self):
        '''
        Determine whether SNMP service is disabled and uninstalled

        @return bool
        @author bemalmbe
        '''

        # defaults
        secure = False
        svcenabled = False
        pkginstalled = False

        try:

            svcenabled = self.svchelper.auditservice('snmpd')

            pkginstalled = self.pkghelper.check('net-snmpd')

            if not svcenabled and not pkginstalled:
                secure = True

            return secure

        except AttributeError:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return False

    def reportConfigureSNMP(self):
        '''
        Determine whether the SNMP service is securely configured

        @return bool
        @author bemalmbe
        '''

        # defaults
        kvintent = 'present'
        kvconftype = 'conf'
        kvtype = 'space'
        secure = True

        # check to make sure perms on conf files are 640
        # check to make sure ownership of conf files is root:root
        # check to make sure conf files are not using weak or default community
        # string and that they are not using anything other than version 3
        # security model as per NSA guidance

        try:

            if self.reportDisableSNMP():
                return True

            for location in self.snmpdconflocations:
                if os.path.exists(location):
                    perms = getOctalPerms(location)
                    if perms != 640:
                        secure = False

                    kvpath = location
                    kvtmppath = location + '.stonixtmp'

                    self.kvosnmp = KVEditorStonix(self.statechglogger,
                                                  self.logger, kvtype, kvpath,
                                                  kvtmppath,
                                                  self.snmpv3directives,
                                                  kvintent, kvconftype)

                    kvosnmpretval = self.kvosnmp.report()
                    if not kvosnmpretval:
                        secure = False

                    f = open(location, 'r')
                    contentlines = f.readlines()
                    f.close()

                    for line in contentlines:
                        if re.search('^group', line):
                            line = line.split()
                            if line[2] in ['v1', 'v2', 'v2c']:
                                secure = False
                                self.detailedresults += '''You are currently using an outdated security model for your SNMP configuration. Please update to model 3.'''

                    for line in contentlines:
                        if re.search('^com2sec', line):
                            line = line.split()
                            if line[3] in ['public', 'community']:
                                secure = False
                                self.detailedresults += '''You are currently using a default or weak community string.'''

                    for line in contentlines:
                        if re.search('^access', line):
                            line = line.split()
                            if line[3] in ['any', 'v1', 'v2', 'v2c']:
                                secure = False
                                self.detailedresults += '''You are currently using an outdated security model for your SNMP configuration. Please update to model 3.'''

                            if line[4] == 'noauth':
                                secure = False
                                self.detailedresults += '''You are currently not requiring authentication for SNMP. This is an unsecure practice. Please change to authNoPriv or authPriv.'''

            return secure

        except (IndexError, OSError):
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return False

    def fix(self):
        '''
        Determine which fix method(s) to run and run them

        @author bemalmbe
        '''

        self.detailedresults = ""
        self.rulesuccess = True

        try:

            if self.environ.getostype() == 'Mac OS X':
                if self.disablesnmp.getcurrvalue() or self.configuresnmp.getcurrvalue():
                    self.rulesuccess = self.fixmac()
                    self.formatDetailedResults("fix", self.rulesuccess,
                                               self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return self.rulesuccess

            if self.disablesnmp.getcurrvalue():
                self.fixDisableSNMP()

            if self.configuresnmp.getcurrvalue():
                self.fixConfigureSNMP()

        except AttributeError:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def fixmac(self):
        '''
        @author: Breen Malmberg
        '''

        success = True

        try:

            defaults = '/usr/bin/defaults '
            operation = 'write '
            filepath = '/System/Library/LaunchDaemons/org.net-snmp.snmpd.plist '
            key = 'DISABLED'
            val = ' -bool true'

            cmd = defaults + operation + filepath + key + val

            self.cmdhelper.executeCommand(cmd)
            errout = self.cmdhelper.getErrorString()
            if errout:
                success = False
                self.detailedresults += '\ncould not set Disabled key to true in org.net-snmp.snmpd.plist'

        except Exception:
            raise
        return success

    def fixDisableSNMP(self):
        '''
        Disable the SNMP service and uninstall the package for it

        @author bemalmbe
        '''

        try:

            if not self.reportDisableSNMP():

                self.svchelper.disableservice('snmpd')

                self.pkghelper.remove('net-snmpd')

        except AttributeError:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise

    def fixConfigureSNMP(self):
        '''
        Securely configure the SNMP service. This option should be used instead
        of disabling SNMP only if there is a mission-critical need for the
        SNMP service to operate in the environment.

        @author bemalmbe
        '''

# set auth type to SHA, security model version to 3, and security level to
# authNoPriv set permissions for the SNMP conf file to 640
# change owner and group of the SNMP conf file to root and root
# admin must set up security on version 3 themselves because it is
# account-based security and they must set up their own account(s)

        try:

            myid = '0144001'

            self.kvosnmp.setEventID(myid)

            self.kvosnmp.fix()
            self.kvosnmp.commit()

            for location in self.snmpdconflocations:
                if os.path.exists(location):
                    os.chmod(location, 0640)
                    os.chown(location, 0, 0)

        except (KeyError, OSError):
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise

#     def undo(self):
#         '''
#         Undo any changes made by fix method
# 
#         @author bemalmbe
#         '''
#         try:
# 
#             event = self.statechglogger.getchgevent('0144001')
#             self.statechglogger.revertfilechanges(event['filename'], '0144001')
# 
#         except (IndexError):
#             self.logdispatch.log(LogPriority.DEBUG, IndexError.message)
#         except (KeyboardInterrupt, SystemExit):
#             # User initiated exit
#             raise
#         except Exception as err:
#             self.rulesuccess = False
#             self.detailedresults = self.detailedresults + "\n" + str(err) + \
#             " - " + str(traceback.format_exc())
#             self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
#         self.formatDetailedResults("undo", self.rulesuccess,
#                                    self.detailedresults)
#         self.logdispatch.log(LogPriority.INFO, self.detailedresults)
#         return self.rulesuccess
