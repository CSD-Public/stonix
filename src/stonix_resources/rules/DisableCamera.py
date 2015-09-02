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
'''
from __future__ import absolute_import
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper

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
        self.mandatory = True
        self.helptext = '''This rule disables the built-in iSight camera.'''
        self.rootrequired = True
        self.guidance = ["CIS 1.2.6"]
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.10']}}

    def isreadable(self, path):
        '''
        detect and return whether a specified file is readable (by anyone)

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = False

        try:

            statlist = [stat.S_IROTH,
                        stat.S_IRUSR,
                        stat.S_IRGRP]
            readabledict = {}

            if os.path.exists(path):
                perms = os.stat(path)
                for s in statlist:
                    readabledict[path + str(s)] = bool(perms.st_mode & s)

            if readabledict:
                for item in readabledict:
                    if readabledict[item] == True:
                        retval = True

        except Exception:
            raise
        return retval

    def report(self):
        '''
        report the compliancy status of this rule

        @return: self.compliant
        @rtype: boolean
        @author: Breen Malmberg
        '''

        self.detailedresults = ""
        self.compliant = True
        self.pathlist = ['/System/Library/QuickTime/QuickTimeUSBVDCDigitizer.component/Contents/MacOS/QuickTimeUSBVDCDigitizer',
                         '/System/Library/PrivateFrameworks/CoreMediaIOServicesPrivate.framework/Versions/A/Resources/VDC.plugin/Contents/MacOS/VDC',
                         '/System/Library/PrivateFrameworks/CoreMediaIOServices.framework/Versions/A/Resources/VDC.plugin/Contents/MacOS/VDC',
                         '/System/Library/Frameworks/CoreMediaIO.framework/Versions/A/Resources/VDC.plugin/Contents/MacOS/VDC',
                         '/Library/CoreMediaIO/Plug-Ins/DAL/AppleCamera.plugin/Contents/MacOS/AppleCamera']
        self.cmdhelper = CommandHelper(self.logdispatch)

        try:

            for path in self.pathlist:
                if self.isreadable(path):
                    self.compliant = False
                    self.detailedresults += '\nfile: ' + str(path) + ' is still readable'

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

        self.detailedresults = ""
        success = True
        cmd = "chmod a-r "

        try:

            for path in self.pathlist:
                if os.path.exists(path):
                    self.cmdhelper.executeCommand(cmd + path)
                    error = self.cmdhelper.getErrorString()
                    if error:
                        success = False
                        self.detailedresults += '\nthere was an error running command: ' + cmd + path

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return success
