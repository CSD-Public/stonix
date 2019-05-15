#!/usr/bin/env python
###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
#                                                                             #
###############################################################################


"""
Created on Oct 4, 2012

@author: David Kennel
@change: 2015/10/15 Eric Ball Updated deprecated unittest methods, added
    cron.service for openSUSE and Debian 8 compatibility
@change: roy - adding sys.path.append for both test framework and individual
               test runs.
@change: 2017/10/23 Roy Nielsen - Adding asserts, and grooming for the second generation
               service helper
@change: 2018/06/27 Breen Malmberg - removed code to get currently logged-in user as it
        was relying on OS commands which no longer work and the code itself was not being
        used anywhere in this test anyway
@change: 2019/04/09 Breen Malmberg - unit test refactor
"""

import os
import sys
import time
import unittest

sys.path.append("../../../..")
from src.stonix_resources.environment import Environment
from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.stonix_resources.ServiceHelper import ServiceHelper


class zzzTestFrameworkServiceHelper(unittest.TestCase):
    '''Class docs'''

    def setUp(self):
        '''initialize and set class variables and objects'''

        self.environ = Environment()
        self.environ.setdebugmode(True)
        self.logger = LogDispatcher(self.environ)
        self.mysh = ServiceHelper(self.environ, self.logger)

        # set service name
        self.myservice = 'crond'
        self.myservicename = ""
        if self.environ.getosfamily() == 'darwin':
            self.myservice = "/Library/LaunchDaemons/gov.lanl.stonix.report.plist"
            self.myservicename = "gov.lanl.stonix.report"
        elif self.environ.getosfamily() == 'solaris':
            self.myservice = 'svc:/system/cron:default'
        elif self.environ.getosfamily() == 'freebsd':
            self.myservice = 'cron'
        elif os.path.exists('/usr/lib/systemd/system/cron.service'):
            self.myservice = 'cron.service'
        elif os.path.exists('/usr/lib/systemd/system/crond.service'):
            self.myservice = 'crond.service'
        elif os.path.exists('/etc/init.d/vixie-cron'):
            self.myservice = 'vixie-cron'
        elif os.path.exists('/etc/init.d/cron'):
            self.myservice = 'cron'

        if self.environ.getosfamily() == "darwin":
            self.service = self.myservice, self.myservicename
        else:
            self.service = [self.myservice]

        # store system initial state
        self.orig_enabled = self.mysh.auditService(*self.service)

    def tearDown(self):
        '''restore system initial state'''

        if self.orig_enabled:
            self.mysh.enableService(*self.service)
        else:
            self.mysh.disableService(*self.service)

    def testListServices(self):
        '''test listing of services'''

        services = self.mysh.listServices()

        self.assertGreater(len(services), 0)
        self.assertIsInstance(services, list)

    def testDisable(self):
        '''test disabling a service from initial state:
        enabled


        '''

        # make sure service is started, so stopping it will be a valid test of the function
        if not self.mysh.auditService(*self.service):
            self.mysh.enableService(*self.service)

        disabled = self.mysh.disableService(*self.service)
        self.assertTrue(disabled)

    def testEnable(self):
        '''test enabling a service from initial state:
        disabled


        '''

        # make sure service is stopped, so starting it will be a valid test of the function
        if self.mysh.auditService(*self.service):
            self.mysh.disableService(*self.service)

        enabled = self.mysh.enableService(*self.service)
        self.assertTrue(enabled)

    def testReloadService(self):
        '''test reloading a service from both initial states:
        enabled
        disabled


        '''

        self.mysh.disableService(*self.service)
        reloaded1 = self.mysh.reloadService(*self.service)
        self.assertTrue(reloaded1)

        self.mysh.enableService(*self.service)
        reloaded2 = self.mysh.reloadService(*self.service)
        self.assertTrue(reloaded2)

    def testIsRunning(self):
        '''test status checking to see if a service
        is running
        (start and stop not implemented in all helpers)


        '''

        if self.mysh.startService(*self.service):
            self.assertTrue(self.mysh.isRunning(*self.service))

        if self.mysh.stopService(*self.service):
            self.assertFalse(self.mysh.isRunning(*self.service))

if __name__ == "__main__":
    unittest.main()
