#!/usr/bin/env python
'''
Created on Oct 4, 2012

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

@author: dkennel
@change: 2015/10/15 eball Updated deprecated unittest methods, added
    cron.service for openSUSE and Debian 8 compatibility
'''
import os
import time
import unittest
from src.stonix_resources.environment import Environment
from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.stonix_resources.ServiceHelper import ServiceHelper


class zzzTestFrameworkServiceHelper(unittest.TestCase):

    def setUp(self):
        self.enviro = Environment()
        self.enviro.setdebugmode(False)
        self.logger = LogDispatcher(self.enviro)
        self.mysh = ServiceHelper(self.enviro, self.logger)
        self.myservice = 'crond'
        self.myservicename = ""
        if self.enviro.getosfamily() == 'darwin':
            self.myservice = "/System/Library/PrivateFrameworks/CalendarAgent.framework/Executables/CalendarAgent"
            self.myservicename = "com.apple.CalendarAgent"
        elif self.enviro.getosfamily() == 'solaris':
            self.myservice = 'svc:/system/cron:default'
        elif self.enviro.getosfamily() == 'freebsd':
            self.myservice = 'cron'
        elif os.path.exists('/usr/lib/systemd/system/cron.service'):
            self.myservice = 'cron.service'
        elif os.path.exists('/usr/lib/systemd/system/crond.service'):
            self.myservice = 'crond.service'
        elif os.path.exists('/etc/init.d/vixie-cron'):
            self.myservice = 'vixie-cron'
        elif os.path.exists('/etc/init.d/cron'):
            self.myservice = 'cron'

    def tearDown(self):
        pass

    def testListServices(self):
        svcslist = self.mysh.listservices()
        self.assertTrue(len(svcslist) > 0)

    def testDisableEnable(self):
        self.mysh.disableservice(self.myservice)
        auditresult = self.mysh.auditservice(self.myservice,
                                             self.myservicename)
        self.assertFalse(auditresult,
                         "Service not disabled or return from audit not valid")
        time.sleep(3)
        self.assertFalse(self.mysh.isrunning(self.myservice,
                                             self.myservicename),
                         "Service is still running or return from isrunning not valid")
        self.mysh.enableservice(self.myservice)
        self.assertTrue(self.mysh.auditservice(self.myservice,
                                               self.myservicename),
                        "Service not enabled or return from audit not valid")
        time.sleep(3)
        self.assertTrue(self.mysh.isrunning(self.myservice,
                                            self.myservicename),
                        "Service is not running or return from isrunning not valid")

    def testReloadService(self):
        self.assertTrue(self.mysh.reloadservice(self.myservice,
                                                self.myservicename),
                        'Service reload returned false')

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
