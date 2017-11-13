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
Created on Aug 31, 2016

With this rule, you can:
        Disable the CUPS service
        Secure the CUPS service
        Disable Printer Browsing
        Limit Printer Browsing
        Disable Print Server Capabilities
        Set the Default Auth Type
        Setup default set of policy blocks for CUPS

@author: Breen Malmberg
@change: Breen Malmberg - 2/8/2017 - set the default value of the self.DisableGenericPort CI to False;
        fixed a typo with the data2 dict var name for cupsdconf; KVcupsdrem will now only be processed if
        the value of the self.DisableGenericPort CI is True; added some inline comments
@change: 2017/10/23 rsn - change to new service helper interface
'''

from __future__ import absolute_import

import os
import traceback
import re

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..ServiceHelper import ServiceHelper
from ..pkghelper import Pkghelper
from ..CommandHelper import CommandHelper
from ..KVEditorStonix import KVEditorStonix
from ..localize import PRINTBROWSESUBNET
from ..stonixutilityfunctions import iterate


class SecureCUPS(Rule):
    '''
    With this rule, you can:
        Disable the CUPS service
        Configure CUPS service
        Disable Printer Browsing
        Limit Printer Browsing
        Disable Print Server Capabilities
        Set the Default Auth Type
        Setup default set of policy blocks for CUPS
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
        self.rulesuccess = True
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['CCE 4420-6', 'CCE 4407-3']
        self.applicable = {'type': 'white',
                           'family': ['darwin', 'linux']}

        # init CIs
        datatype1 = 'bool'
        key1 = 'SECURECUPS'
        instructions1 = 'To prevent to STONIX from securing the CUPS service, set the value of ' + \
        'SecureCUPS to False.'
        default1 = True
        self.SecureCUPS = self.initCi(datatype1, key1, instructions1, default1)

        datatype2 = 'bool'
        key2 = 'DISABLECUPS'
        instructions2 = 'To have STONIX completely disable the CUPS service on this system, set ' + \
        'the value of DisableCUPS to True.'
        default2 = False
        self.DisableCUPS = self.initCi(datatype2, key2, instructions2, default2)

        datatype3 = 'bool'
        key3 = 'DISABLEPRINTBROWSING'
        instructions3 = 'To prevent STONIX from disabling print browsing, set the value of ' + \
        'DisablePrintBrowsing to False. ! This option is mutually exclusive with PrintBrowseSubnet ! ' + \
        'If both PrintBrowseSubnet and DisablePrintBrowsing are checked/enabled, DisablePrintBrowsing ' + \
        'will take priority!'
        default3 = True
        self.DisablePrintBrowsing = self.initCi(datatype3, key3, instructions3, default3)

        datatype4 = 'bool'
        key4 = 'PRINTBROWSESUBNET'
        instructions4 = 'To allow printer browsing on a specific subnet, set ' + \
        'the value of PrintBrowseSubnet to True. The subnet to allow printer ' + \
        'browsing for is specified in localize by setting the value of ' + \
        'PRINTBROWSESUBNET. If PRINTBROWSESUBNET is set to an empty string, ' + \
        'nothing will be written. ! This option is mutually exclusive with DisablePrintBrowsing ! ' + \
        'If both PrintBrowseSubnet and DisablePrintBrowsing are checked/enabled, DisablePrintBrowsing ' + \
        'will take priority!'
        default4 = False
        self.PrintBrowseSubnet = self.initCi(datatype4, key4, instructions4, default4)

        datatype5 = 'bool'
        key5 = 'DISABLEGENERICPORT'
        instructions5 = 'To prevent remote users from potentially connecting ' + \
        'to and using locally configured printers by disabling the CUPS print ' + \
        'server sharing capabilities, set the value of DisableGenericPort to ' + \
        'True.'
        default5 = False
        self.DisableGenericPort = self.initCi(datatype5, key5, instructions5, default5)

        datatype6 = 'bool'
        key6 = 'SETDEFAULTAUTHTYPE'
        instructions6 = 'To prevent the defaultauthtype for cups from being ' + \
        'set to Digest, set the value of SetDefaultAuthType to False.'
        default6 = True
        self.SetDefaultAuthType = self.initCi(datatype6, key6, instructions6, default6)

        datatype7 = 'bool'
        key7 = 'SETUPDEFAULTPOLICYBLOCKS'
        instructions7 = "To prevent default policy blocks for cups from " + \
        "being defined in the cups config file, set the value of " + \
        "SetupDefaultPolicyBlocks to False. Note that if you choose to setup " + \
        "the default set of policy blocks you can (and probably should) edit " + \
        "them in the cups config file afterward to customize these policies to " + \
        "your site's particular needs."
        default7 = False
        self.SetupDefaultPolicyBlocks = self.initCi(datatype7, key7, instructions7, default7)

        self.localize()

    def localize(self):
        '''
        set various settings and variables and objects based on
        which OS is currently running

        @return: void
        @author: Breen Malmberg
        '''

        self.linux = False
        self.darwin = False

        if self.environ.getosfamily() == 'darwin':
            self.darwin = True
        if self.environ.getosfamily() == 'linux':
            self.linux = True

        self.initObjs()
        self.setVars()

    def initObjs(self):
        '''
        initialize all required class objects

        @return: void
        @author: Breen Malmberg
        '''

        if self.linux:
            self.ph = Pkghelper(self.logger, self.environ)
        if self.darwin:
            pass
        self.sh = ServiceHelper(self.environ, self.logger)
        self.serviceTarget = ""
        self.ch = CommandHelper(self.logger)

    def setVars(self):
        '''
        set all class variables depending on which
        OS is currently running

        @return: void
        @author: Breen Malmberg
        @change: Breen Malmberg - 2/8/2017 - fixed a typo with the var name of the dict
                for cupsd conf options; 
        '''

        try:

# linux config
            if self.linux:
                self.configfileperms = '0640'
                errorlog = "/var/log/cups/error_log"
                logfileperms = '0644'
                self.pkgname = "cups"
                self.svcname = "cups"
                accesslog = "/var/log/cups/access_log"

            self.cupsfilesopts = {}
            self.cupsfilesconf = ""
            self.cupsdconf = ""
            self.cupsdconfremopts = {}

# darwin config
            if self.darwin:
                accesslog = "/private/var/log/cups/access_log"
                # a value of 'strict' causes issues connecting to printers on some mac systems
                self.configfileperms = '0644'
                logfileperms = '0644'
                errorlog = "/private/var/log/cups/error_log"
                self.svclongname = "/System/Library/LaunchDaemons/org.cups.cupsd.plist"
                self.svcname = "org.cups.cupsd"

# common config
            cupsdconflocs = ['/etc/cups/cupsd.conf',
                               '/private/etc/cups/cupsd.conf']
            for loc in cupsdconflocs:
                if os.path.exists(loc):
                    self.cupsdconf = loc
            self.tmpcupsdconf = self.cupsdconf + ".stonixtmp"

            cupsfileslocs = ['/etc/cups/cups-files.conf',
                             '/private/etc/cups/cups-files.conf']
            for loc in cupsfileslocs:
                if os.path.exists(loc):
                    self.cupsfilesconf = loc
            self.tmpcupsfilesconf = self.cupsfilesconf + ".stonixtmp"

            # options for cups-files.conf
            self.cupsfilesopts["ConfigFilePerm"] = self.configfileperms
            self.cupsfilesopts["ErrorLog"] = errorlog
            self.cupsfilesopts["LogFilePerm"] = logfileperms

            # cupsd conf default configuration options
            loglevel = "warn"
            self.cupsdconfopts = {"LogLevel": loglevel}
            self.cupsdconfopts["AccessLog"] = accesslog
            self.cupsdconfopts["AccessLogLevel"] = "config"

            # cupsd conf remove these options
            if self.DisableGenericPort.getcurrvalue():
                self.cupsdconfremopts = {"Port": "631"}

            ## create kveditor objects
            if os.path.exists(self.cupsfilesconf):
                kvtype1 = "conf"
                path1 = self.cupsfilesconf
                tmpPath1 = path1 + ".stonixtmp"
                data1 = self.cupsfilesopts
                intent1 = "present"
                configType1 = "space"
                self.KVcupsfiles = KVEditorStonix(self.statechglogger, self.logger, kvtype1, path1, tmpPath1, 
                                                  data1, intent1, configType1)

            if os.path.exists(self.cupsdconf):
                kvtype2 = "conf"
                path2 = self.cupsdconf
                tmpPath2 = path2 + ".stonixtmp"
                data2 = self.cupsdconfopts
                intent2 = "present"
                configType2 = "space"
                self.KVcupsd = KVEditorStonix(self.statechglogger, self.logger, kvtype2, path2, tmpPath2,
                                              data2, intent2, configType2)

                if self.cupsdconfremopts:
                    kvtype3 = "conf"
                    path3 = self.cupsdconf
                    tmpPath3 = path3 + ".stonixtmp"
                    data3 = self.cupsdconfremopts
                    intent3 = "notpresent"
                    configType3 = "space"
                    self.KVcupsdrem = KVEditorStonix(self.statechglogger, self.logger, kvtype3, path3, tmpPath3,
                                                  data3, intent3, configType3)

            # policy blocks
            self.serveraccess = """# Restrict access to the server...
<Location />
  Encryption Required
  Order allow,deny
</Location>"""
            self.adminpagesaccess = """# Restrict access to the admin pages...
<Location /admin>
  Encryption Required
  Order allow,deny
</Location>"""
            self.configfilesaccess = """# Restrict access to configuration files...
<Location /admin/conf>
  AuthType Default
  Encryption IfRequested
  Require user @SYSTEM
  Order allow,deny
</Location>"""
            self.logfileaccess = """# Restrict access to log files...
<Location /admin/log>
  AuthType Default
  Encryption IfRequested
  Require user @SYSTEM
  Order allow,deny
</Location>"""
            self.defaultprinterpolicies = """# Set the default printer/job policies...
<Policy default>
  # Job-related operations must be done by the owner or an administrator...
  <Limit Send-Document Send-URI Hold-Job Release-Job Restart-Job Purge-Jobs Set-Job-Attributes Create-Job-Subscription Renew-Subscription Cancel-Subscription Get-Notifications Reprocess-Job Cancel-Current-Job Suspend-Current-Job Resume-Job CUPS-Move-Job>
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>

  # All administration operations require an administrator to authenticate...
  <Limit CUPS-Add-Modify-Printer CUPS-Delete-Printer CUPS-Add-Modify-Class CUPS-Delete-Class CUPS-Set-Default>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>

  # All printer operations require a printer operator to authenticate...
  <Limit Pause-Printer Resume-Printer Enable-Printer Disable-Printer Pause-Printer-After-Current-Job Hold-New-Jobs Release-Held-New-Jobs Deactivate-Printer Activate-Printer Restart-Printer Shutdown-Printer Startup-Printer Promote-Job Schedule-Job-After CUPS-Accept-Jobs CUPS-Reject-Jobs>
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
</Policy>"""

        except Exception:
            raise

    def sanityCheck(self):
        '''
        perform sanity check on the cups configuration files

        @return: sane
        @rtype: bool
        @author: Breen Malmberg
        '''

        sane = True

        sanitycheck = "/usr/sbin/cupsd -t"

        try:

            self.ch.executeCommand(sanitycheck)
            retcode = self.ch.getReturnCode()
            output = self.ch.getOutput()
            if retcode != 0:
                sane = False
                self.detailedresults += "\nError while running command: " + str(sanitycheck)
            for line in output:
                if re.search("Bad|Missing|Incorrect|Error|Wrong", line, re.IGNORECASE):
                    sane = False
                    self.detailedresults += "\n" + line

        except Exception:
            raise
        return sane

    def updateOpts(self):
        '''
        update the kveditor values for the different CIs
        based on their current user-specified values

        @return: void
        @author: Breen Malmberg
        @change: Breen Malmberg - 2/8/2017 - KVcupsdrem will now only be processed if
                self.DisableGenericPort CI is True
        '''

        try:

            if self.DisableCUPS.getcurrvalue():
                self.PrintBrowseSubnet.updatecurrvalue(False)

            if self.DisablePrintBrowsing.getcurrvalue():
                self.cupsdconfopts["Browsing"] = "Off"
                self.cupsdconfopts["BrowseAllow"] = "none"
                self.cupsdconfopts["BrowseWebIF"] = "No"
            if self.checkConsts([PRINTBROWSESUBNET]):
                if self.PrintBrowseSubnet.getcurrvalue():
                    self.cupsdconfopts["Browsing"] = "On"
                    self.cupsdconfopts["BrowseOrder"] = "allow,deny"
                    self.cupsdconfopts["BrowseDeny"] = "all"
                    self.cupsdconfopts["BrowseAllow"] = PRINTBROWSESUBNET
            else:
                self.detailedresults += "\nThe constant PRINTBROWSESUBNET is currently not defined (set to None), in localize.py. Setting the print browse subnet requires this to be defined."
            if self.DisableGenericPort.getcurrvalue():
                self.cupsdconfremopts["Port"] = "631"
            if self.SetDefaultAuthType.getcurrvalue():
                self.cupsdconfopts["DefaultAuthType"] = "Negotiate"

            # don't try to create, or update, the kv object,
            # if the file it's based on doesn't exist.
            # this would cause tracebacks in kveditor
            if os.path.exists(self.cupsfilesconf):
                kvtype1 = "conf"
                path1 = self.cupsfilesconf
                tmpPath1 = path1 + ".stonixtmp"
                data1 = self.cupsfilesopts
                intent1 = "present"
                configType1 = "space"
                self.KVcupsfiles = KVEditorStonix(self.statechglogger, self.logger, kvtype1, path1, tmpPath1, 
                                                  data1, intent1, configType1)
            else:
                self.logger.log(LogPriority.DEBUG, "Location of required configuration file cups-files.conf could not be determined")
            if os.path.exists(self.cupsdconf):
                kvtype2 = "conf"
                path2 = self.cupsdconf
                tmpPath2 = path2 + ".stonixtmp"
                data2 = self.cupsdconfopts
                intent2 = "present"
                configType2 = "space"
                self.KVcupsd = KVEditorStonix(self.statechglogger, self.logger, kvtype2, path2, tmpPath2,
                                              data2, intent2, configType2)
                if self.cupsdconfremopts:
                    kvtype3 = "conf"
                    path3 = self.cupsdconf
                    tmpPath3 = path3 + ".stonixtmp"
                    data3 = self.cupsdconfremopts
                    intent3 = "notpresent"
                    configType3 = "space"
                    self.KVcupsdrem = KVEditorStonix(self.statechglogger, self.logger, kvtype3, path3, tmpPath3,
                                                  data3, intent3, configType3)
            else:
                self.logger.log(LogPriority.DEBUG, "Location of required configuration file cupsd.conf could not be determined")

        except Exception:
            raise

    def report(self):
        '''
        run report methods/actions appropriate for the current
        OS and return compliancy status

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "\n\nREPORT()\n\n")

        # DEFAULTS
        self.detailedresults = ""
        self.compliant = True
        badopts = ["^HostNameLookups\s+Double", "^Sandboxing\s+strict", "^FatalErrors\s+config"]
        badoptsfiles = [self.cupsdconf, self.cupsfilesconf]

        try:

            # check for bad config options in files
            for f in badoptsfiles:
                if os.path.exists(f):
                    fh = open(f, 'r')
                    contentlines = fh.readlines()
                    fh.close()
                    for line in contentlines:
                        for opt in badopts:
                            if re.search(opt, line, re.IGNORECASE):
                                self.compliant = False
            # if these opts exist, then we don't want to do anything else
            ## except just remove them
            if not self.compliant:
                self.logger.log(LogPriority.DEBUG, "Bad configuration options found in cups config files. Will now remove them.")
                self.formatDetailedResults('report', self.compliant, self.detailedresults)
                return self.compliant

            if self.linux:
                if not self.ph.check(self.pkgname):
                    self.detailedresults += "\nCUPS not installed on this system. Nothing to secure."
                    self.formatDetailedResults('report', self.compliant, self.detailedresults)
                    return self.compliant

            # update kv objects with any new
            # user-specified information
            self.updateOpts()

            if self.SecureCUPS.getcurrvalue():
                # is cups secured?
                if not self.reportSecure():
                    self.compliant = False
                # make sure config syntax is correct
                if not self.sanityCheck():
                    self.compliant = False

            if self.DisableCUPS.getcurrvalue():
                # is cups disabled?
                if not self.reportDisabled():
                    self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults('report', self.compliant, self.detailedresults)
        return self.compliant

    def reportDisabled(self):
        '''
        return True if cups is disabled
        return False if cups is enabled

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            if self.linux:
                if self.sh.auditService(self.svcname, serviceTarget=self.serviceTarget):
                    retval = False
                    self.detailedresults += "\nThe " + str(self.svcname) + " service is still configured to run"
            elif self.darwin:
                if self.sh.auditService(self.svclongname, serviceTarget=self.svcname):
                    retval = False
                    self.detailedresults += "\nThe " + str(self.svcname) + " service is still configured to run"

        except Exception:
            raise
        return retval

    def checkPolicyBlocks(self):
        '''
        report on whether default policy blocks are currently set up
        in cups configuration. Note that if these already exist, we
        do not want to overwrite them as the local admin may have
        them customised to their specific environment.

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "\n\nCHECKPOLICYBLOCKS()\n\n")

        retval = True
        rootfound = False
        adminfound = False
        adminconffound = False
        defpolicyfound = False

        try:

            if os.path.exists(self.cupsdconf):
                self.logger.log(LogPriority.DEBUG, "\n\nCUPSD CONF EXISTS. OPENING FILE AND READING CONTENTS...\n\n")
                f = open(self.cupsdconf, 'r')
                contentlines = f.readlines()
                f.close()

                self.logger.log(LogPriority.DEBUG, "\n\nCONTENTS READ. CHECKING FOR POLICY BLOCKS...\n\n")
                for line in contentlines:
                    if re.search('\<Location \/\>', line, re.IGNORECASE):
                        rootfound = True
                    if re.search('\<Location \/admin\>', line, re.IGNORECASE):
                        adminfound = True
                    if re.search('\<Location \/admin\/conf\>', line, re.IGNORECASE):
                        adminconffound = True
                    if re.search('\<Policy default\>', line, re.IGNORECASE):
                        defpolicyfound = True
            else:
                self.logger.log(LogPriority.DEBUG, "\n\ncupsd.conf file does not exist. Nothing to check...\n\n")
                return retval
    
            if not rootfound:
                retval = False
                self.detailedresults += "\nCUPS Root location policy not defined"
            if not adminfound:
                retval = False
                self.detailedresults += "\nCUPS admin location policy not defined"
            if not adminconffound:
                retval = False
                self.detailedresults += "\nCUPS admin/conf location policy not defined"
            if not defpolicyfound:
                retval = False
                self.detailedresults += "\nCUPS Default Policy block not defined"

            if retval:
                self.logger.log(LogPriority.DEBUG, "\n\nALL POLICY BLOCKS OK\n\n")

        except Exception:
            raise
        return retval

    def reportSecure(self):
        '''
        run report actions common to all platforms

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        @change: Breen Malmberg - 2/8/2017 - KVcupsdrem will now only be run if 
                self.DisableGenericPort CI is True
        '''

        self.logger.log(LogPriority.DEBUG, "\n\nREPORTSECURE()\n\n")

        retval = True

        try:

            if self.SecureCUPS.getcurrvalue():

                if os.path.exists(self.cupsdconf):
                    self.KVcupsd.report()
                    if self.KVcupsd.fixables:
                        retval = False
                        self.detailedresults += "\nThe following configuration options, in " + str(self.cupsdconf) + ", are incorrect:\n" + "\n".join(self.KVcupsd.fixables)
                    if self.cupsdconfremopts:
                        self.KVcupsdrem.report()
                        if self.KVcupsdrem.removeables:
                            retval = False
                        self.detailedresults += "\nThe following configuration options, in " + str(self.cupsdconf) + ", are incorrect:\n" + "\n".join(self.KVcupsdrem.removeables)
                    if not self.checkPolicyBlocks():
                        retval = False
                else:
                    pass

                if os.path.exists(self.cupsfilesconf):
                    self.KVcupsfiles.report()
                    if self.KVcupsfiles.fixables:
                        retval = False
                        self.detailedresults += "\nThe following configuration options, in " + str(self.cupsfilesconf) + ", are incorrect:\n" + "\n".join(self.KVcupsfiles.fixables)
                else:
                    pass

            else:
                self.detailedresults += "\nNeither SecureCUPS nor DisableCUPS CI's was enabled. Nothing was done."

        except Exception:
            raise
        return retval

    def fix(self):
        '''
        run fix methods/actions appropriate for the current
        OS and return success status of fix

        @return: success
        @rtype: bool
        @author: Breen Malmberg
        '''

        # DEFAULTS
        self.detailedresults = ""
        success = True
        self.iditerator = 0
        badopts = ["^HostNameLookups\s+Double", "^Sandboxing\s+strict", "^FatalErrors\s+config"]
        badoptsfiles = [self.cupsdconf, self.cupsfilesconf]
        foundbadopts = False

        try:

            # fix bad opts; do not record state change,
            ## so that a possible revert, afterward, will
            ## not revert back to the bad state
            ## this code is a one-off for a hotfix and
            ## should probably be discontinued in some future
            ## release at some point
            for f in badoptsfiles:
                contentlines = []
                if os.path.exists(f):
                    fh = open(f, 'r')
                    contentlines = fh.readlines()
                    fh.close()
                    for line in contentlines:
                        for opt in badopts:
                            if re.search(opt, line, re.IGNORECASE):
                                foundbadopts = True
                                contentlines = [c.replace(line, '\n') for c in contentlines]
                    # finished building new contentlines; now write them for each file
                    fn = open(f, 'w')
                    fn.writelines(contentlines)
                    fn.close()
                    os.chmod(f, 0644)
            if foundbadopts:
                # do not continue with rest of fix because that would save state for this fix run
                self.logger.log(LogPriority.DEBUG, "Reloading cups service to read configuration changes...")
                if self.darwin:
                    self.sh.reloadService(self.svclongname, serviceTarget=self.svcname)
                else:
                    self.sh.reloadService(self.svcname, serviceTarget=self.serviceTarget)
                self.logger.log(LogPriority.DEBUG, "Removed bad configuration options from cups config files. Exiting...")
                self.formatDetailedResults('fix', success, self.detailedresults)
                return success


            # Are any of the CIs enabled?
            # If not, then exit, returning True
            if not self.SecureCUPS.getcurrvalue() and \
            not self.DisableCUPS.getcurrvalue():
                self.detailedresults += "\nNo CI was enabled, so nothing was done."
                self.logger.log(LogPriority.DEBUG, "SecureCUPS rule was run, but neither SecureCUPS, nor DisableCUPS CI's were enabled so nothing was done!")
                self.formatDetailedResults('fix', success, self.detailedresults)
                return success

            if self.linux and not self.ph.check("cups"):
                self.detailedresults += "\nCUPS is not installed. Nothing to do."
                self.formatDetailedResults('fix', success, self.detailedresults)
                return success

            if self.SecureCUPS.getcurrvalue():
                if not self.fixSecure():
                    success = False

            if self.DisableCUPS.getcurrvalue():
                if not self.disableCUPS():
                    success = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults('fix', success, self.detailedresults)
        return success

    def fixSecure(self):
        '''
        run fix actions common to all platforms

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        @change: Breen Malmberg - 2/8/2017 - added inline comments; changed the way KVCupsdrem
                was being handled (will not be run if there are no options to remove; aka if
                self.DisableGenericPort CI is False)
        '''

        retval = True
        pdefaultfound = False
        serveraccessfound = False
        adminaccessfound = False
        configaccessfound = False
        logfileaccessfound = False

        try:

            if os.path.exists(self.cupsdconf):

# cupsdconf add/change options
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.KVcupsd.setEventID(myid)
                if self.KVcupsd.fix():
                    if not self.KVcupsd.commit():
                        self.detailedresults += "\nCommit failed for cupsd.conf"
                        self.logger.log(LogPriority.DEBUG, "Commit failed for KVcupsd")
                        retval = False

# cupsdconf remove options
                if self.cupsdconfremopts:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.KVcupsdrem.setEventID(myid)
                    if self.KVcupsdrem.fix():
                        if not self.KVcupsdrem.commit():
                            self.detailedresults += "\nCommit failed for cupsd.conf"
                            self.logger.log(LogPriority.DEBUG, "Commit failed for KVcupsdrem")
                            retval = False

# cups-files conf add/change options
            if os.path.exists(self.cupsfilesconf):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.KVcupsfiles.setEventID(myid)
                if self.KVcupsfiles.fix():
                    if not self.KVcupsfiles.commit():
                        self.detailedresults += "\nCommit failed for cups-files.conf"
                        self.logger.log(LogPriority.DEBUG, "Commit failed for KVcupsfiles")
                        retval = False

# cupsdconf default policy blocks
# this portion cannot be handled by kveditor because of its
# xml style formatting
            if os.path.exists(self.cupsdconf):
                if self.SetupDefaultPolicyBlocks.getcurrvalue():
                    f = open(self.cupsdconf, 'r')
                    contentlines = f.readlines()
                    f.close()
                    for line in contentlines:
                        if re.search("\<Location \/\>", line, re.IGNORECASE):
                            serveraccessfound = True
                    for line in contentlines:
                        if re.search("\<Location \/admin\>", line, re.IGNORECASE):
                            adminaccessfound = True
                    for line in contentlines:
                        if re.search("\<Location \/admin\/conf\>", line, re.IGNORECASE):
                            configaccessfound = True
                    for line in contentlines:
                        if re.search("\<Location \/admin\/log\>", line, re.IGNORECASE):
                            logfileaccessfound = True
                    for line in contentlines:
                        if re.search("\<Policy default\>", line, re.IGNORECASE):
                            pdefaultfound = True
    
                    if not serveraccessfound:
                        contentlines.append("\n" + self.serveraccess + "\n")
                        self.logger.log(LogPriority.DEBUG, "\n\nroot access policy block not found. adding it...\n\n")
    
                    if not adminaccessfound:
                        contentlines.append("\n" + self.adminpagesaccess + "\n")
                        self.logger.log(LogPriority.DEBUG, "\n\nadmin access policy block not found. adding it...\n\n")
    
                    if not configaccessfound:
                        contentlines.append("\n" + self.configfilesaccess + "\n")
                        self.logger.log(LogPriority.DEBUG, "\n\nconfig access policy block not found. adding it...\n\n")
    
                    if not logfileaccessfound:
                        contentlines.append("\n" + self.logfileaccess + "\n")
                        self.logger.log(LogPriority.DEBUG, "\n\nlog file access policy block not found. adding it...\n\n")
    
                    if not pdefaultfound:
                        contentlines.append("\n" + self.defaultprinterpolicies + "\n")
                        self.logger.log(LogPriority.DEBUG, "\n\ndefault policy block not found. adding it...\n\n")
    
                    tf = open(self.tmpcupsdconf, 'w')
                    tf.writelines(contentlines)
                    tf.close()
    
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filename": self.cupsdconf}
    
                    self.statechglogger.recordfilechange(self.cupsdconf, self.tmpcupsdconf, myid)
                    self.statechglogger.recordchgevent(myid, event)
                    self.logger.log(LogPriority.DEBUG, "\n\nwriting changes to " + str(self.cupsdconf) + " file...\n\n")
                    os.rename(self.tmpcupsdconf, self.cupsdconf)
                    self.logger.log(LogPriority.DEBUG, "\n\nsetting permissions and ownership for " + str(self.cupsdconf) + " file...\n\n")
                    os.chown(self.cupsdconf, 0, 0)
                    if self.linux:
                        os.chmod(self.cupsdconf, 0640)
                    elif self.darwin:
                        os.chmod(self.cupsdconf, 0644)

            if not self.reloadCUPS():
                retval = False

        except Exception:
            raise
        return retval

    def reloadCUPS(self):
        '''
        reload the cups service to read the new configurations

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            # do not attempt to reload the service
            # if the rule is set to disable it
            if self.DisableCUPS.getcurrvalue():
                return retval

            if self.linux:
                if not self.sh.reloadService(self.svcname, serviceTarget=self.serviceTarget):
                    retval = False
                    self.detailedresults += "|nThere was a problem reloading the " + str(self.svcname) + " service"
            elif self.darwin:
                if not self.sh.reloadService(self.svclongname, serviceTarget=self.svcname):
                    retval = False
                    self.detailedresults += "|nThere was a problem reloading the " + str(self.svcname) + " service"

        except Exception:
            raise
        return retval

    def disableCUPS(self):
        '''
        disable the cups service

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            if self.linux:

                if not self.sh.disableService(self.svcname, serviceTarget=self.serviceTarget):
                    retval = False
                    self.detailedresults += "\nThere was a problem disabling the " + str(self.svcname) + " service"

            elif self.darwin:

                if not self.sh.disableService(self.svclongname, serviceTarget=self.svcname):
                    retval = False
                    self.detailedresults += "\nThere was a problem disabling the " + str(self.svcname) + " service"

        except Exception:
            raise
        return retval
