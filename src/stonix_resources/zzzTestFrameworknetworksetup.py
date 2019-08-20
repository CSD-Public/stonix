#!/usr/bin/env python3
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

'''
Created on May 13, 2015


@author: ekkehard
@change: 2015-05-13 ekkehard - original implementation
'''
import unittest
from . import environment
from . import logdispatcher
from . import networksetup


class zzzTestFrameworknetworksetup(unittest.TestCase):

    def setUp(self):
        # create sample test files
        env = environment.Environment()
        logger = logdispatcher.LogDispatcher(env)
        self.ns = networksetup()

    def tearDown(self):
        pass

    def testGetLocation(self):
        location = self.ns.getLocation()
        self.assertTrue( location == "" )

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()