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
Created on Nov 24, 2012
This is the rule for installing puppet.

@operating system: OS X
@author: ekkehard
@change: 2014/11/24 original implementation
@change: 2015/04/15 dkennel updated for new isApplicable
'''
from __future__ import absolute_import
import traceback
import types

# The period was making python complain. Adding the correct paths to PyDev
# made this the working scenario.
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..InstallingHelper import InstallingHelper
from ..configurationitem import ConfigurationItem
from ..ServiceHelper import ServiceHelper
from ..stonixutilityfunctions import has_connection_to_server
from ..CommandHelper import CommandHelper
from ..filehelper import FileHelper
from ..IHmac import IHmac

# Link to the current version of the JAMF Casper Suite Installer
JAMFCASPERQUICKADD = "http://puppet-prod.lanl.gov/support/casper/Puppet-Stonix-quickadd.zip"
JAMFCASPERSUITESERVER = "puppet-prod.lanl.gov"


class InstallCasperSuite(Rule):
    """
    This class installs puppet on the system.
    """
    def __init__(self, config, environ, logdispatch, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logdispatch, statechglogger)
        self.rulenumber = 9
        self.rulename = 'InstallCasperSuite'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''This rule installs the JAMF Casper Suite.'''
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.10']}}
        self.js = JAMFCASPERSUITESERVER
        self.qa = JAMFCASPERQUICKADD

        self.myci = ConfigurationItem('bool')
        key = self.rulename
        self.myci.setkey(key)
        instructions = '''To disable the installation of the JAMF Casper Recon client set the InstallCasperSuite option to no or False.'''
        self.myci.setinstructions(instructions)
        default = True
        self.myci.setdefvalue(default)
        self.confitems.append(self.myci)
        self.jamf = "/usr/sbin/jamf"

# Set up CommandHelper instance
        self.ch = CommandHelper(self.logdispatch)
# Set up FileHelper instance
        self.fh = FileHelper(self.logdispatch)
        self.files = {
          "LANL Self Service":
          {"path": "/Applications/LANL Self Service.app",
          "remove": False,
          "content": None,
          "permissions": None,
          "owner": None,
          "group": None},
          "JAMF Agent":
          {"path": "/Library/LaunchAgents/com.jamfsoftware.jamf.agent.plist",
          "remove": False,
          "content": None,
          "permissions": None,
          "owner": None,
          "group": None},
          "JAMF Daemon":
          {"path": "/Library/LaunchDaemons/com.jamfsoftware.jamf.daemon.plist",
          "remove": False,
          "content": None,
          "permissions": None,
          "owner": None,
          "group": None},
          "JAMF Startup Item":
          {"path": "/Library/LaunchDaemons/com.jamfsoftware.startupItem.plist",
          "remove": False,
          "content": None,
          "permissions": None,
          "owner": None,
          "group": None}
              }
        for filelabel, fileinfo in sorted(self.files.items()):
            addfilereturn = self.fh.addFile(filelabel,
                                            fileinfo["path"],
                                            fileinfo["remove"],
                                            fileinfo["content"],
                                            fileinfo["permissions"],
                                            fileinfo["owner"],
                                            fileinfo["group"]
                                            )
# Set up service helper instance
        self.sh = ServiceHelper(self.environ, self.logdispatch)
        self.services = {"com.jamfsoftware.jamf.agent":
                         "/Library/LaunchAgents/com.jamfsoftware.jamf.agent.plist"
                         }

    def report(self):
        '''
        see if jamf -version runs, /Applications/LANL\ Self\ Service.app
        exists, and if the following four are operational:
        /Library/LaunchAgents/com.jamfsoftware.jamf.agent.plist
        /Library/LaunchDaemons/com.jamfsoftware.jamf.daemon.plist
        /Library/LaunchDaemons/com.jamfsoftware.startupItem.plist
        /Library/LaunchDaemons/com.jamfsoftware.task.1.plist
        @author: Ekkehard
        '''

        try:
            self.compliant = True
            self.detailedresults = ""
            success = True
# See if jamf command is working
            command = [self.jamf, "-version"]
            try:
                success = self.ch.executeCommand(command)
                messagestring = str(self.jamf) + " is " + \
                str(self.ch.getOutputString())
            except:
                success = False
                messagestring = str(self.jamf) + " dose not exist!"
            self.resultAppend(messagestring)
            self.logdispatch.log(LogPriority.DEBUG, messagestring)
            if not success:
                self.compliant = False
# See if all the CASPER Suite Files are in place
            success = True
            success = self.fh.evaluateFiles()
            self.resultAppend(self.fh.getFileMessage())
            self.logdispatch.log(LogPriority.DEBUG, self.fh.getFileMessage())
            if not success:
                self.compliant = False
# See if all CASPER Suite Services Are Running
            '''
            success = True
            for currentservicename, currentservice in self.services.items():
                if self.sh.auditservice(currentservice, currentservicename):
                    messagestring = "Service: auditservice('" + \
                    currentservice + "','" + currentservicename + \
                    "') = True!"
                else:
                    success = False
                    messagestring = "Service: auditservice('" + \
                    currentservice + "','" + currentservicename + \
                    "') = False!"
                self.logdispatch.log(LogPriority.DEBUG, messagestring)
                self.resultAppend(messagestring)
            if not success:
                self.compliant = False
            '''
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            self.detailedresults = self.detailedresults + \
            str(traceback.format_exc())
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                               "Exception - " + str(err) + " - " +
                               self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        '''
        Installing JAMF Casper Suite

        @author: ekkehard
        '''
        try:
            fixsuccess = False
            self.detailedresults = ""
            if not self.myci.getcurrvalue():
                self.logdispatch.log(LogPriority.INFO,
                                     str(self.rulename) + " is user disabled")
            else:
# If there network, install, else no network, log
                hasconnection = has_connection_to_server(self.logdispatch,
                                                         self.js)
                if hasconnection:
                    self.logdispatch.log(LogPriority.ERROR,
                                         "Connected to " + str(self.js))
# Set up the installation
                    installing = IHmac(self.environ,
                                       self.qa,
                                       self.logdispatch)
# Install the package
                    fixsuccess = installing.install_package_from_server()
                    if fixsuccess:
                        messagestring = str(self.qa) + \
                        " installation successful!"
                    else:
                        messagestring = str(self.qa) + \
                        " installation failed!"
                    self.detailedresults = messagestring

                    self.logdispatch.log(LogPriority.DEBUG, messagestring)

                else:
                    messagestring = "Could not connect to " + str(self.js)
                    self.detailedresults = messagestring
                    self.logdispatch.log(LogPriority.ERROR, messagestring)

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixsuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################

    def resultAppend(self, pMessage=""):
        '''
        reset the current kveditor values to their defaults.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true
        @note: kveditorName is essential
        '''
        datatype = type(pMessage)
        if datatype == types.StringType:
            if not (pMessage == ""):
                messagestring = pMessage
                if (self.detailedresults == ""):
                    self.detailedresults = messagestring
                else:
                    self.detailedresults = self.detailedresults + "\n" + \
                    messagestring
        elif datatype == types.ListType:
            if not (pMessage == []):
                for item in pMessage:
                    messagestring = item
                    if (self.detailedresults == ""):
                        self.detailedresults = messagestring
                    else:
                        self.detailedresults = self.detailedresults + "\n" + \
                        messagestring
        else:
            raise TypeError("pMessage with value" + str(pMessage) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.StringType) + \
                            " or type " + str(types.ListType) + \
                            " as expected!")
