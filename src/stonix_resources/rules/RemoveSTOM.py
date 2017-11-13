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
@copyright: 2014 Los Alamos National Security, LLC. All rights reserved
@author: ekkehard j. koch
@change: 01/06/2014 Original Implementation
@change: 02/12/2014 ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 ekkehard Implemented isapplicable
@change: 2015/04/16 dkennel updated for new isApplicable
'''
from __future__ import absolute_import
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..filehelper import FileHelper
from ..CommandHelper import CommandHelper
from ..ServiceHelper import ServiceHelper


class RemoveSTOM(Rule):
    '''
    This Mac Only rule removes all STOM Files
    @author: ekkehard j. koch
    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        Rule.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 5
        self.rulename = 'RemoveSTOM'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rules removes the old Security Tool called STOM."
        self.rootrequired = True
        self.guidance = []

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}

        self.files = {"stom2.conf": {"path": "/Library/Preferences/stom2.conf",
                                     "remove": True,
                                     "content": None,
                                     "permissions": None,
                                     "owner": None,
                                     "group": None},
                      "STOM2.app": {"path": "/Applications/STOM2.app",
                                    "remove": True,
                                     "content": None,
                                     "permissions": None,
                                     "owner": None,
                                     "group": None},
                      "gov.lanl.STOM2.user": {"path": "/Library/LaunchAgents/gov.lanl.STOM2.user.plist",
                                              "remove": True,
                                              "content": None,
                                              "permissions": None,
                                              "owner": None,
                                              "group": None},
                      "gov.lanl.STOM2": {"path": "/Library/LaunchDaemons/gov.lanl.STOM2.plist",
                                                 "remove": True,
                                                 "content": None,
                                                 "permissions": None,
                                                 "owner": None,
                                                 "group": None},
                      "gov.lanl.STOM2.airport": {"path": "/Library/LaunchDaemons/gov.lanl.STOM2.airport.plist",
                                                 "remove": True,
                                                 "content": None,
                                                 "permissions": None,
                                                 "owner": None,
                                                 "group": None},
                      "lanl_airport_off": {"path": "/usr/local/sbin/lanl_airport_off.sh",
                                                 "remove": True,
                                                 "content": None,
                                                 "permissions": None,
                                                 "owner": None,
                                                 "group": None},
                      "gov.lanl.csd.stom2.bom": {"path": "/var/db/receipts/gov.lanl.csd.stom2.bom",
                                                 "remove": True,
                                                 "content": None,
                                                 "permissions": None,
                                                 "owner": None,
                                                 "group": None},
                      "gov.lanl.csd.stom2.plist": {"path": "/var/db/receipts/gov.lanl.csd.stom2.plist",
                                                 "remove": True,
                                                 "content": None,
                                                 "permissions": None,
                                                 "owner": None,
                                                 "group": None}
                      }
        self.services = {"gov.lanl.STOM2.user":
                         "/Library/LaunchAgents/gov.lanl.STOM2.user.plist",
                         "gov.lanl.STOM2.airport":
                         "/Library/LaunchDaemons/gov.lanl.STOM2.airport.plist",
                         "gov.lanl.STOM2":
                         "/Library/LaunchDaemons/gov.lanl.STOM2.plist"
                         }
        self.fh = FileHelper(self.logdispatch, self.statechglogger)
        for filelabel, fileinfo in sorted(self.files.items()):
            addfilereturn = self.fh.addFile(filelabel,
                                            fileinfo["path"],
                                            fileinfo["remove"],
                                            fileinfo["content"],
                                            fileinfo["permissions"],
                                            fileinfo["owner"],
                                            fileinfo["group"]
                                            )
        self.ch = CommandHelper(self.logdispatch)
        self.sh = ServiceHelper(self.environ, self.logdispatch)

###############################################################################

    def report(self):
        '''
        Checks to see if any STOM Files are installed
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true if applicable false if not
        @change: 01/06/2014 Original Implementation
        '''
        try:
            self.detailedresults = ""
            self.currstate = "notconfigured"
            self.compliant = False
            serviceresults = ""
            pathresults = ""
            compliant = True
# See if any STOM Services Are Running
            for currentservicename, currentservice in self.services.items():
                if self.sh.auditservice(currentservice, currentservicename):
                    if serviceresults == "":
                        serviceresults = "('" + str(currentservicename) + \
                        "','" + str(currentservice) + "')"
                    else:
                        serviceresults = serviceresults + ", ('" + \
                        str(currentservicename) + "','" + \
                        str(currentservice) + "')"
                    message = "Service: auditservice('" + currentservice + \
                    "','" + currentservicename + "') = True!"
                    self.logdispatch.log(LogPriority.DEBUG, message)
                    compliant = False
                else:
                    message = "Service: auditservice('" + currentservice + \
                    "','" + currentservicename + "') = False!"
                    self.logdispatch.log(LogPriority.DEBUG, message)
# See if any STOM Files are present
            filecompliant = self.fh.evaluateFiles()
            pathresults = self.fh.getFileMessage()
            if not filecompliant:
                compliant = False
# Give a list of results
            if not (serviceresults == "") and not (self.detailedresults == ""):
                self.detailedresults = self.detailedresults + \
                "; List Of STOM Services that need to be turned off: " + \
                serviceresults
            elif not (serviceresults == ""):
                self.detailedresults = "List Of STOM Services that need " + \
                "to be turned off: " + serviceresults
            if not (pathresults == "") and not (self.detailedresults == ""):
                self.detailedresults = self.detailedresults + \
                "; STOM Files: " + pathresults
            elif not (pathresults == ""):
                self.detailedresults = "STOM Files: " + pathresults
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.compliant = compliant
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        '''
        Checks to see if any STOM Files are installed
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true if applicable false if not
        @change: 01/06/2014 Original Implementation
        '''
        try:
            fixed = True
            self.detailedresults = ""
            servicesDisabledSuccess = True
            servicesNotDisabled = ""
            serviceresults = ""
            pathRemovalSuccess = True
            pathresults = ""
# See if any STOM Services Are Running disable them
            if fixed:
                for currentservicename, currentservice in self.services.items():
                    if self.sh.auditservice(currentservice, currentservicename):
                        message = "Service: auditservice('" + currentservice + \
                        "','" + currentservicename + "') = True!"
                        self.logdispatch.log(LogPriority.INFO, message)
                        servicesDisabledSuccess = self.sh.disableservice(currentservice,
                                                                         currentservicename)
                        if not servicesDisabledSuccess:
                            servicesNotDisabled = currentservicename
                            break
                        else:
                            if serviceresults == "":
                                serviceresults = "('" + currentservice + \
                                "','" + currentservicename + "')"
                            else:
                                serviceresults = serviceresults + "; ('" + \
                                currentservice + "','" + currentservicename + \
                                "')"
                    else:
                        message = "Service: auditservice('" + \
                        currentservice + "','" + currentservicename + \
                        "') = False!"
                        self.logdispatch.log(LogPriority.DEBUG, message)
# See if any STOM Files are present
            # if fixed:
            pathRemovalSuccess = self.fh.fixFiles()
            pathresults = self.fh.getFileMessage()
# Did we get it all done?
            if pathRemovalSuccess and servicesDisabledSuccess:
                fixed = True
            else:
                fixed = False
# Give a list of service
            if not (serviceresults == "") and not (self.detailedresults == ""):
                self.detailedresults = self.detailedresults + \
                "; List Of STOM Services that were turned off: " + \
                serviceresults
            elif not (serviceresults == ""):
                self.detailedresults = "List Of STOM Services that were " + \
                "turned off: " + serviceresults
# Give a list of path results
            if not (pathresults == "") and not (self.detailedresults == ""):
                self.detailedresults = self.detailedresults + \
                "; STOM Files actions: " + pathresults
            elif not (pathresults == ""):
                self.detailedresults = "STOM Files actions: " + pathresults
# Serive Failures
            if not (servicesNotDisabled == "") and not (self.detailedresults == ""):
                self.detailedresults = servicesNotDisabled + \
                " could not be disabled. " + self.detailedresults
            elif not (servicesNotDisabled == ""):
                self.detailedresults = servicesNotDisabled + \
                " could not be disabled."
# Add Fix Message
            if fixed and not (self.detailedresults == ""):
                self.detailedresults = "Fix was successful! " + \
                self.detailedresults
            elif fixed:
                self.detailedresults = "STOM not present."
            elif not (fixed) and not (self.detailedresults == ""):
                self.detailedresults = "Fix failed! " + self.detailedresults
            elif not(fixed):
                self.detailedresults = "Fix failed!"
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            fixed = False
            self.rulesuccess = False
            self.detailedresults = "Error " + str(err) + " - " + \
            traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixed,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
