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
Created on Sep 5, 2013

With this rule, you can:
        Disable the CUPS service
        Disable firewall access to CUPS service
        Configure CUPS service
        Disable Printer Browsing
        Limit Printer Browsing
        Disable Print Server Capabilities
        Set the Default Auth Type
        Setup default set of policy blocks for CUPS

@author: bemalmbe
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2014 dkennel Updated CI invocation, fixed bug where master CI
not referenced before fix.
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/10/08 eball Help text cleanup
@change: 2015/10/13 eball PEP8 cleanup
@change: 2015/10/13 eball Added feedback for report methods, and improved logic
so that a system without CUPS is compliant
'''

from __future__ import absolute_import

import os
import traceback
import re

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..ServiceHelper import ServiceHelper
from ..pkghelper import Pkghelper
from ..KVEditorStonix import KVEditorStonix
from ..stonixutilityfunctions import iterate
from ..localize import PRINTBROWSESUBNET


class SecureCUPS(Rule):
    '''
    With this rule, you can:
        Disable the CUPS service
        Disable firewall access to CUPS service
        Configure CUPS service
        Disable Printer Browsing
        Limit Printer Browsing
        Disable Print Server Capabilities
        Set the Default Auth Type
        Setup default set of policy blocks for CUPS

    @author bemalmbe
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
        self.rulenumber = 128
        self.rulename = 'SecureCUPS'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.helptext = '''With this rule, you can:
Disable the CUPS service
Disable firewall access to CUPS service
Configure CUPS service
Disable Printer Browsing
Limit Printer Browsing
Disable Print Server Capabilities
Set the Default Auth Type
Setup default set of policy blocks for CUPS'''
        self.rootrequired = True
        self.guidance = ['CCE 4420-6', 'CCE 4407-3']
        self.isApplicableWhiteList = []
        self.isApplicableBlackList = ["darwin"]
        self.applicable = {'type': 'black',
                           'family': ['darwin']}

        # init CIs
        self.SecureCUPS = self.__initializeSecureCUPS()
        self.DisableCUPS = self.__initializeDisableCUPS()
        self.DisablePrintBrowsing = self.__initializeDisablePrintBrowsing()
        self.PrintBrowseSubnet = self.__initializePrintBrowseSubnet()
        self.DisableGenericPort = self.__initializeDisableGenericPort()
        self.SetDefaultAuthType = self.__initializeSetDefaultAuthType()
        self.SetupDefaultPolicyBlocks = \
            self.__initializeSetupDefaultPolicyBlocks()

        # class variables
        self.defaultpolicyblocks = """# Restrict access to the server...
<Location />
  Order allow,deny
</Location>

# Restrict access to the admin pages...
<Location /admin>
  Order allow,deny
</Location>

# Restrict access to configuration files...
<Location /admin/conf>
  AuthType Default
  Require user @SYSTEM
  Order allow,deny
</Location>

# Set the default printer/job policies...
<Policy default>
  # Job-related operations must be done by the owner or an administrator...
  <Limit Send-Document Send-URI Hold-Job Release-Job Restart-Job Purge-Jobs \
Set-Job-Attributes Create-Job-Subscription Renew-Subscription \
Cancel-Subscription Get-Notifications Reprocess-Job Cancel-Current-Job \
Suspend-Current-Job Resume-Job CUPS-Move-Job CUPS-Get-Document>
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>

  # All administration operations require an administrator to authenticate...
  <Limit CUPS-Add-Modify-Printer CUPS-Delete-Printer CUPS-Add-Modify-Class \
CUPS-Delete-Class CUPS-Set-Default CUPS-Get-Devices>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>

  # All printer operations require a printer operator to authenticate...
  <Limit Pause-Printer Resume-Printer Enable-Printer Disable-Printer \
Pause-Printer-After-Current-Job Hold-New-Jobs Release-Held-New-Jobs \
Deactivate-Printer Activate-Printer Restart-Printer Shutdown-Printer \
Startup-Printer Promote-Job Schedule-Job-After CUPS-Accept-Jobs \
CUPS-Reject-Jobs>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>

  # Only the owner or an administrator can cancel or authenticate a job...
  <Limit Cancel-Job CUPS-Authenticate-Job>
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>

  <Limit All>
    Order deny,allow
  </Limit>
</Policy>

# Set the authenticated printer/job policies...
<Policy authenticated>
  # Job-related operations must be done by the owner or an administrator...
  <Limit Create-Job Print-Job Print-URI>
    AuthType Default
    Order deny,allow
  </Limit>

  <Limit Send-Document Send-URI Hold-Job Release-Job Restart-Job Purge-Jobs \
Set-Job-Attributes Create-Job-Subscription Renew-Subscription \
Cancel-Subscription Get-Notifications Reprocess-Job Cancel-Current-Job \
Suspend-Current-Job Resume-Job CUPS-Move-Job CUPS-Get-Document>
    AuthType Default
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>

  # All administration operations require an administrator to authenticate...
  <Limit CUPS-Add-Modify-Printer CUPS-Delete-Printer CUPS-Add-Modify-Class \
CUPS-Delete-Class CUPS-Set-Default>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>

  # All printer operations require a printer operator to authenticate...
  <Limit Pause-Printer Resume-Printer Enable-Printer Disable-Printer \
Pause-Printer-After-Current-Job Hold-New-Jobs Release-Held-New-Jobs \
Deactivate-Printer Activate-Printer Restart-Printer Shutdown-Printer \
Startup-Printer Promote-Job Schedule-Job-After CUPS-Accept-Jobs \
CUPS-Reject-Jobs>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>

  # Only the owner or an administrator can cancel or authenticate a job...
  <Limit Cancel-Job CUPS-Authenticate-Job>
    AuthType Default
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>

  <Limit All>
    Order deny,allow
  </Limit>
</Policy>"""

        self.defaultauthtype = """# Default authentication type, when \
authentication is required...
DefaultAuthType Basic"""

        self.cupsdconflocations = ['/etc/cups/cupsd.conf',
                                   '/private/etc/cups/cupsd.conf',
                                   '/usr/local/etc/cupsd.conf',
                                   '/usr/local/etc/cups/cupsd.conf']

###############################################################################

    def __initializeSetDefaultAuthType(self):
        '''
        Private method to initialize the configurationitem object for the
        SetDefaultAuthType bool.

        @return configurationitem object instance
        @author bemalmbe
        '''
        datatype = 'bool'
        key = 'SetDefaultAuthType'
        instructions = 'To prevent the defaultauthtype for cups from being \
        set to Basic, set the value of SetDefaultAuthType to False.'
        default = True
        setdefaultauthtype = self.initCi(datatype, key, instructions, default)
        return setdefaultauthtype

###############################################################################

    def __initializeSetupDefaultPolicyBlocks(self):
        '''
        Private method to initialize the configurationitem object for the
        SetupDefaultPolicyBlocks bool.

        @return configurationitem object instance
        @author bemalmbe
        '''
        datatype = 'bool'
        key = 'SetupDefaultPolicyBlocks'
        instructions = "To prevent default policy blocks for cups from \
        being defined in the cups config file, set the value of \
        SetupDefaultPolicyBlocks to False. Note that if you choose to setup \
        the default set of policy blocks you can (and probably should) edit \
        them in the cups config file afterward to customize these policies to \
        your site's particular needs."
        default = True
        setupdefaultpolicyblocks = self.initCi(datatype, key, instructions,
                                               default)
        return setupdefaultpolicyblocks

###############################################################################

    def __initializeSecureCUPS(self):
        '''
        Private method to initialize the configurationitem object for the
        SecureCUPS bool.

        @return configurationitem object instance
        @author bemalmbe
        '''
        datatype = 'bool'
        key = 'SecureCUPS'
        instructions = 'To prevent the secure configuration of CUPS, set the \
value of SecureCUPS to False.'
        default = True
        securecups = self.initCi(datatype, key, instructions, default)
        return securecups

###############################################################################

    def __initializeDisableCUPS(self):
        '''
        Private method to initialize the configurationitem object for the
        DisableCUPS bool.

        @return configurationobject item instance
        @author bemalmbe
        '''
        datatype = 'bool'
        key = 'DisableCUPS'
        instructions = 'To disable CUPS, set the value of DisableCUPS to True.'
        default = False
        disablecups = self.initCi(datatype, key, instructions, default)
        return disablecups

###############################################################################

    def __initializeDisablePrintBrowsing(self):
        '''
        Private method to initialize the configurationitem object for the
        DisablePrintBrowsing bool.

        @return configurationitem object instance
        @author bemalmbe
        '''
        datatype = 'bool'
        key = 'DisablePrintBrowsing'
        instructions = 'To disable printer browsing, set the value of \
DisablePrintBrowsing to True.'
        default = True
        disableprintbrowsing = self.initCi(datatype, key, instructions,
                                           default)
        return disableprintbrowsing

###############################################################################

    def __initializePrintBrowseSubnet(self):
        '''
        Private method to initialize the configurationitem object for the
        PrintBrowseSubnet bool.

        @return configurationitem object instance
        @author bemalmbe
        '''
        datatype = 'bool'
        key = 'PrintBrowseSubnet'
        instructions = 'To allow printer browsing on a specific subnet, set \
        the value of PrintBrowseSubnet to True. The subnet to allow printer \
        browsing for is specified in localize by setting the value of \
        PRINTBROWSESUBNET. If PRINTBROWSESUBNET is set to an empty string, \
        nothing will be written.'
        default = False
        printbrowsesubnet = self.initCi(datatype, key, instructions, default)
        return printbrowsesubnet

###############################################################################

    def __initializeDisableGenericPort(self):
        '''
        Private method to initialize the configurationitem object for the
        GenericPort bool.

        @return configurationitem object instance
        @author bemalmbe
        '''
        datatype = 'bool'
        key = 'DisableGenericPort'
        instructions = 'To prevent remote users from potentially connecting \
        to and using locally configured printers by disabling the CUPS print \
        server sharing capabilities, set the value of DisableGenericPort to \
        True.'
        default = True
        disablegenericport = self.initCi(datatype, key, instructions, default)
        return disablegenericport

###############################################################################

    def report(self):
        '''
        Reporting control logic to determine which report methods to run and \
        run them.

        @return bool
        @author bemalmbe
        '''

        # defaults
        secure = True
        self.detailedresults = ""

        # init helper objects
        self.svchelper = ServiceHelper(self.environ, self.logger)
        self.pkghelper = Pkghelper(self.logger, self.environ)

        try:

            if self.DisableCUPS.getcurrvalue():
                retval = self.reportDisableCUPS()
                if not retval:
                    secure = False

            if self.DisablePrintBrowsing.getcurrvalue():
                retval = self.reportDisablePrintBrowsing()
                if not retval:
                    secure = False

            if self.PrintBrowseSubnet.getcurrvalue() and \
               PRINTBROWSESUBNET != '':
                retval = self.reportPrintBrowseSubnet()
                if not retval:
                    secure = False
            elif self.PrintBrowseSubnet.getcurrvalue() and \
                 PRINTBROWSESUBNET == '':
                self.detailedresults += '\nThe constant PRINTBROWSESUBNET ' + \
                    'was blank. This needs to be set. This can be done in ' + \
                    'localize.py'
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                secure = False

            if self.DisableGenericPort.getcurrvalue():
                retval = self.reportDisableGenericPort()
                if not retval:
                    secure = False

            if self.SetDefaultAuthType.getcurrvalue():
                retval = self.reportDefaultAuthType()
                if not retval:
                    secure = False

            if self.SetupDefaultPolicyBlocks.getcurrvalue():
                retval = self.reportSetupDefaultPolicyBlocks()
                if not retval:
                    secure = False

            if secure:
                self.compliant = True
            else:
                self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
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

###############################################################################

    def reportDefaultAuthType(self):
        '''
        Look for a default authentication type specification in the cups config
        file.

        @return bool
        @author bemalmbe
        '''

        # defaults
        secure = True

        try:

            for location in self.cupsdconflocations:
                if os.path.exists(location):
                    f = open(location, 'r')
                    content = f.read()
                    f.close()

                    if not re.search(self.defaultauthtype, content):
                        secure = False
                        self.detailedresults += "\nDefaultAuthType not found"

            return secure

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return False

###############################################################################

    def reportSetupDefaultPolicyBlocks(self):
        '''
        Check for the existence of default policy blocks

        @return bool
        @author bemalmbe
        '''

        # defaults
        secure = True

        try:

            # Note that this checks for a DEFAULT secure configuration
            # Admin must customize after running the fix

            for location in self.cupsdconflocations:
                if os.path.exists(location):
                    f = open(location, 'r')
                    content = f.read()
                    f.close()

                    if not re.search('<Policy default>', content):
                        secure = False
                        self.detailedresults += "\n<Policy default> block " + \
                            "not found"

            return secure

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return False

###############################################################################

    def reportDisableCUPS(self):
        '''
        Check whether or not the cups service is currently configured to run.

        @return bool
        @author bemalmbe
        '''

        # defaults
        svcstatus = True
        secure = True
        retval = False

        try:

            if self.environ.getosfamily() == 'darwin':
                svcstatus = \
                    self.svchelper.auditservice('/System/Library/LaunchDaemons/org.cups.cupsd.plist',
                                                'org.cups.cupsd')
                if not svcstatus:
                    retval = True
            else:
                svcstatus = self.svchelper.auditservice('cups')

                configfilelist = ['/etc/sysconfig/iptables',
                                  '/etc/sysconfig/ip6tables']

                # search the config file(s) for the firewall exception entries
                line1 = '^-A RH-Firewall-1-INPUT -p udp -m udp --dport ' + \
                    '631 -j ACCEPT'
                line2 = '^-A RH-Firewall-1-INPUT -p tcp -m tcp --dport ' + \
                    '631 -j ACCEPT'
                for item in configfilelist:
                    if os.path.exists(item):
                        f = open(item, 'r')
                        contentlines = f.readlines()
                        f.close()

                        for line in contentlines:
                            if re.search(line1, line):
                                secure = False
                                self.detailedresults += "\n" + item + \
                                    " contains unwanted entry: " + line1
                            elif re.search(line2, line):
                                secure = False
                                self.detailedresults += "\n" + item + \
                                    " contains unwanted entry: " + line2

                if secure and not svcstatus:
                    retval = True

            return retval

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return False

###############################################################################

    def reportDisablePrintBrowsing(self):
        '''
        Check if the directives which disable printer browsing are found in
        the cups config file. If found, return True, else return False.

        @return bool
        @author bemalmbe
        '''

        # defaults
        directives = ['Browsing Off', 'BrowseAllow none']
        secure = True

        try:

            for location in self.cupsdconflocations:
                dfound = 0
                if os.path.exists(location):
                    f = open(location, 'r')
                    contentlines = f.readlines()
                    f.close()

                    for line in contentlines:
                        for directive in directives:
                            if re.search('^' + directive, line):
                                dfound += 1

                    if dfound < 2:
                        secure = False
                        self.detailedresults += "\nPrinter browsing not " + \
                            "disabled, " + location + " does not contain " + \
                            "both the necessary directives: " + str(directives)

            return secure

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return False

###############################################################################

    def reportPrintBrowseSubnet(self):
        '''
        Check the cups config file for the existence of the user-inputted
        Printer Browsing Subnet string value on the BrowseAddress config line,
        return True if found, False if not found.

        @return bool
        @author bemalmbe
        '''

        # defaults
        printbrowsesubnetstring = self.PrintBrowseSubnet.getcurrvalue()
        directives = ['BrowseDeny all', 'BrowseAllow ' +
                      printbrowsesubnetstring]
        secure = True

        try:

            if printbrowsesubnetstring != '':
                for location in self.cupsdconflocations:
                    dfound = 0
                    if os.path.exists(location):
                        f = open(location, 'r')
                        contentlines = f.readlines()
                        f.close()

                        for line in contentlines:
                            for directive in directives:
                                if re.search('^' + directive, line):
                                    dfound += 1
                        if dfound < 2:
                            secure = False
                            self.detailedresults += "\nPrinter browsing " + \
                                "subnet settings incorrect, " + location + \
                                " does not contain both the necessary " + \
                                "directives: " + str(directives)
            else:
                self.detailedresults += '\nNo value entered for print browse \
                subnet'
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                return False

            if dfound == 2:
                secure = True
            else:
                secure = False

            return secure

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return False

###############################################################################

    def reportDisableGenericPort(self):
        '''
        To prevent remote users from potentially connecting to and using
        locally configured printers, disable the CUPS print server sharing
        capabilities. To do so, limit how the server will listen for print
        jobs by removing the more generic port directive from cups config file
        and replacing it with the listen directive.

        @return bool
        @author bemalmbe
        '''

        # defaults
        port = 'Port 631'
        newport = 'Listen localhost:631'
        secure = True

        try:

            for location in self.cupsdconflocations:
                if os.path.exists(location):
                    found = 0
                    f = open(location, 'r')
                    contentlines = f.readlines()
                    f.close()

                    for line in contentlines:
                        if re.search('^' + port, line):
                            secure = False
                            self.detailedresults += "\nInsecure setting '" + \
                                port + "' found in " + location

                    for line in contentlines:
                        if re.search('^' + newport, line):
                            found += 1

                    if found < 1:
                        secure = False
                        self.detailedresults += "\nSecure port setting '" + \
                            newport + "' not found in " + location

            return secure

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return False

###############################################################################

    def fix(self):
        '''
        Control logic to determine which fix methods to run and then run them.

        @author bemalmbe
        '''

        # defaults
        self.detailedresults = ""
        self.id = 1

        try:

            if self.SecureCUPS.getcurrvalue():

                if self.DisablePrintBrowsing.getcurrvalue():
                    retval = self.reportDisablePrintBrowsing()
                    if not retval:
                        self.fixDisablePrintBrowsing()

                if self.PrintBrowseSubnet.getcurrvalue() and \
                   PRINTBROWSESUBNET != '':
                    retval = self.reportPrintBrowseSubnet()
                    if not retval:
                        self.fixPrintBrowseSubnet()

                if self.DisableGenericPort.getcurrvalue():
                    retval = self.reportDisableGenericPort()
                    if not retval:
                        self.fixDisableGenericPort()

                if self.SetDefaultAuthType.getcurrvalue():
                    retval = self.reportDefaultAuthType()
                    if not retval:
                        self.fixDefaultAuthType()

                if self.SetupDefaultPolicyBlocks.getcurrvalue():
                    retval = self.reportSetupDefaultPolicyBlocks()
                    if not retval:
                        self.fixPolicyBlocks()

            else:
                if self.DisableCUPS.getcurrvalue():
                        retval = self.reportDisableCUPS()
                        if not retval:
                            self.fixDisableCUPS()

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
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

###############################################################################

    def fixDefaultAuthType(self):
        '''
        Set the defaultauthtype to basic

        @author bemalmbe
        '''

        try:

            for location in self.cupsdconflocations:
                if os.path.exists(location):

                    templocation = location + '.stonixtmp'

                    f = open(location, 'r')
                    contentlines = f.readlines()
                    f.close()

                    contentlines.append('\n' + str(self.defaultauthtype) +
                                        '\n')

                    tf = open(location + '.stonixtmp', 'w')
                    tf.writelines(contentlines)
                    tf.close()

                    self.id += 1

                    myid = '012800' + str(self.id)
                    event = {'eventtype': 'conf',
                             'filename': location}

                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(location,
                                                         templocation, myid)

                    os.rename(location + '.stonixtmp', location)

                    os.chmod(location, 0644)
                    os.chown(location, 0, 0)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

###############################################################################

    def fixPolicyBlocks(self):
        '''
        Setup the default location access restriction and limit policy blocks

        @author bemalmbe
        '''

        try:

            for location in self.cupsdconflocations:
                if os.path.exists(location):

                    templocation = location + '.stonixtmp'

                    f = open(location, 'r')
                    content = f.read()
                    f.close()

                    # check if default policy block already exists
                    # #if it does, do nothing
                    if not re.search('<Policy default>', content):

                        content += '\n' + str(self.defaultpolicyblocks)

                        tf = open(location + '.stonixtmp', 'w')
                        tf.write(content)
                        tf.close()

                    self.id += 1

                    myid = '012800' + str(self.id)
                    event = {'eventtype': 'conf',
                             'filename': location}

                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(location,
                                                         templocation, myid)

                    os.rename(templocation, location)

                    os.chmod(location, 0644)
                    os.chown(location, 0, 0)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

###############################################################################

    def fixDisableCUPS(self):
        '''
        Disable the CUPS service.

        @author bemalmbe
        '''

        try:

            if self.environ.getosfamily() == 'darwin':
                self.svchelper.disableservice('/System/Library/LaunchDaemons/org.cups.cupsd.plist',
                                              'org.cups.cupsd')
            else:
                self.svchelper.disableservice('cups')

            for location in self.cupsdconflocations:
                if os.path.exists(location):

                    templocation = location + '.stonixtmp'

                    f = open(location, 'r')
                    contentlines = f.readlines()
                    f.close()

                    for line in contentlines:
                        if re.search('^-A RH-Firewall-1-INPUT -p udp -m udp ' +
                                     '--dport 631 -j ACCEPT', line):
                            contentlines = [c.replace(line, '')
                                            for c in contentlines]
                        elif re.search('^-A RH-Firewall-1-INPUT -p tcp -m ' +
                                       'tcp --dport 631 -j ACCEPT', line):
                            contentlines = [c.replace(line, '')
                                            for c in contentlines]

                    tf = open(location + '.stonixtmp', 'w')
                    tf.writelines(contentlines)
                    tf.close()

                    self.id += 1

                    myid = '012800' + str(self.id)
                    event = {'eventtype': 'conf',
                             'filename': location}

                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(location,
                                                         templocation, myid)

                    os.rename(templocation, location)

                    os.chmod(location, 0644)
                    os.chown(location, 0, 0)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

###############################################################################

    def fixDisablePrintBrowsing(self):
        '''
        Disable Printer Browsing completely.

        @author bemalmbe
        '''

        try:

            # defaults
            kvpath = ''
            for location in self.cupsdconflocations:
                if os.path.exists(location):
                    kvpath = location
            kvtype = 'conf'
            kvtmppath = kvpath + '.stonixtmp'
            directives = {'Browsing': 'Off',
                          'BrowseAllow': 'none'}
            kvintent = 'present'
            kvconftype = 'space'

            self.kvodpb = KVEditorStonix(self.statechglogger, self.logger,
                                         kvtype, kvpath, kvtmppath, directives,
                                         kvintent, kvconftype)
            self.kvodpb.report()
            self.kvodpb.fix()
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.kvodpb.setEventID(myid)
            self.kvodpb.commit()

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

###############################################################################

    def fixPrintBrowseSubnet(self):
        '''
        Limit Printer Browsing to a specific subnet.

        @author bemalmbe
        '''

        try:

            # defaults
            kvpath = ''
            for location in self.cupsdconflocations:
                if os.path.exists(location):
                    kvpath = location
            kvtype = 'conf'
            kvtmppath = kvpath + '.stonixtmp'
            printbrowsesubnetstring = self.PrintBrowseSubnet.getcurrvalue()
            directives = {'BrowseDeny': 'all',
                          'BrowseAllow': printbrowsesubnetstring}
            kvintent = 'present'
            kvconftype = 'space'

            self.kvopbs = KVEditorStonix(self.statechglogger, self.logger,
                                         kvtype, kvpath, kvtmppath, directives,
                                         kvintent, kvconftype)
            self.kvopbs.report()
            self.kvopbs.fix()
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.kvopbs.setEventID(myid)
            self.kvopbs.commit()

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

###############################################################################

    def fixDisableGenericPort(self):
        '''
        Remove the more generic port directive in the cupsd.conf file and
        replace it with the Listen directive.

        @author bemalmbe
        '''

        try:

            # defaults
            kvpath = ''
            for location in self.cupsdconflocations:
                if os.path.exists(location):
                    kvpath = location
            kvtype = 'conf'
            kvtmppath = kvpath + '.stonixtmp'
            directives = {'Port': '631',
                          'Listen': 'localhost:631'}
            kvintent = 'present'
            kvconftype = 'space'

            self.kvodgp = KVEditorStonix(self.statechglogger, self.logger,
                                         kvtype, kvpath, kvtmppath, directives,
                                         kvintent, kvconftype)
            self.kvodgp.report()
            self.kvodgp.fix()
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.kvodgp.setEventID(myid)
            self.kvodgp.commit()

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
