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
Created on Dec 10, 2013

@author: dwalker
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 03/26/2014 ekkehard convert to ruleKVEditor
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/08/26 ekkehard [artf37771] : DisableCamera(150) - NCAF & Lack of detail in Results - OS X El Capitan 10.11
@change: 2015/11/09 ekkehard - make eligible of OS X El Capitan
'''
from __future__ import absolute_import
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from ..stonixutilityfunctions import readFile, createFile, writeFile, iterate, checkPerms, setPerms

import re
import os
import traceback
import stat


class DisableCamera(Rule):
###############################################################################

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 150
        self.rulename = "DisableCamera"
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.helptext = '''This rule disables the built-in iSight camera.'''
        self.rootrequired = True
        self.guidance = ["CIS 1.2.6"]
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}
        self.plistpath = "/Library/LaunchDaemons/stonixDisableCamera.plist"
        self.logger = logger
        self.created = False
        # configuration item instantiation
        datatype = 'bool'
        key = 'DISABLECAMERA'
        instructions = "To disable this rule set the value of " + \
            "DISABLECAMERA to False."
        default = False
        self.ci = self.initCi(datatype, key, instructions,  default)
        self.plist = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>gov.lanl.stonix.disablecamera</string>
    <key>Program</key>
    <string>
        <string>/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix_resources/stonixBootSecurityMac</string>
    </string>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>'''

    def report(self):
        '''
        report the compliancy status of this rule

        @return: self.compliant
        @rtype: boolean
        @author: Breen Malmberg
        '''
        try:
            self.detailedresults = ""
            compliant = True
            self.cmdhelper = CommandHelper(self.logdispatch)
            cmd = ["/usr/sbin/kextstat"]
            cameradriver = "com.apple.driver.AppleCameraInterface"
            if not os.path.exists(self.plistpath):
                self.detailedresults += "Required plist file doesn't exist\n"
                compliant = False
            elif not checkPerms(self.plistpath, [0, 0, 436], self.logger):
                self.detailedresults += "Plist file doesn't have the " + \
                    "correct permissions\n"
                compliant = False
            if self.cmdhelper.executeCommand(cmd):
                found = False
                output = self.cmdhelper.getOutput()
                error = self.cmdhelper.getError()
                if output:
                    for line in output:
                        if re.search(cameradriver, line):
                            found = True
                            break
                    if found:
                        self.detailedresults += "The camera is not disabled\n"
                        compliant = False
                elif error:
                    self.detailedresults += "There was an error running " + \
                        "kextstat command.  Unable to determine whether " + \
                        "the camera is disabled or enabled\n"
                    compliant = False
            self.compliant = compliant
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

    def fix(self):
        '''
        remove read access from key files to disable the isight camera functionality

        @return: success
        @rtype: boolean
        @author: Breen Malmberg
        '''
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            success = True
            tmpfile = self.plistpath + ".tmp"
            if os.path.exists(self.plistpath):
                if not checkPerms(self.plistpath, [0, 0, 436], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.plistpath, [0, 0, 436], self.logger,
                                    self.statechglogger, myid):
                        debug = "Unable to set the permissions on " + \
                            self.plistpath + " file\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                contents = readFile(self.plistpath, self.logger)
                contentstring = ""
                for line in contents:
                    contentstring += line
                if not re.search(self.plist, contentstring):
                    if writeFile(tmpfile, self.plist, self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "conf",
                                 "filepath": self.plistpath}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(self.logpath, tmpfile, myid)
                    else:
                        debug = "Unable to write the plist file\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
            else:
                if createFile(self.plistpath):
                    if writeFile(tmpfile, self.plist, self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "creation",
                                 "filepath": self.plistpath}
                        self.statechglogger.recordchgevent(myid, event)
                    else:
                        debug = "Unable to write the plist file\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                else:
                    debug = "Unable to create the plist file\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
            cmd = ["/sbin/kextunload", "-b", "com.apple.driver.AppleCameraInterface"]
            if self.cmdhelper.executeCommand(cmd):
                retval = self.cmdhelper.getReturnCode()
                if retval != 0:
                    debug = "kextunload command unable to " + \
                        "run successfully.  Unable to disable camera\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
            else:
                debug = "kextunload command unable to " + \
                    "run successfully.  Unable to disable camera\n"
                self.logger.log(LogPriority.DEBUG, debug)
                success = False
            self.rulesuccess = success
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
