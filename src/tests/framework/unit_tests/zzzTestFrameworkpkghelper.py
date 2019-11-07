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
Created on Jul 31, 2012


@author: dwalker
@change: 2015/10/26 eball Refactored test to make it functional on all systems
    and to be less error-prone.
@change: 2016-02-10 roy - adding sys.path.append for both test framework and
                          individual test runs.
@change: 2016/07/15 eball Added feedback to assertions
'''
import sys
import unittest

sys.path.append("../../../..")
import src.stonix_resources.pkghelper as pkghelper
from src.tests.lib.logdispatcher_lite import LogDispatcher
import src.stonix_resources.environment as environment


class zzzTestFrameworkpkghelper(unittest.TestCase):

    def setUp(self):
        self.enviro = environment.Environment()
        self.logger = LogDispatcher(self.enviro)
        self.helper = pkghelper.Pkghelper(self.logger, self.enviro)
        self.pkg = "zsh"

    def tearDown(self):
        pass

    def testPkgHelper(self):
        if self.helper.check(self.pkg):
            self.assertTrue(self.helper.remove(self.pkg),
                            "Could not remove " + self.pkg)
            self.assertFalse(self.helper.check(self.pkg),
                             self.pkg + " still found after pkghelper.remove")

            self.assertTrue(self.helper.install(self.pkg),
                            "Could not install " + self.pkg)
            self.assertTrue(self.helper.check(self.pkg),
                            self.pkg + " not found after pkghelper.install")
        else:
            self.assertTrue(self.helper.install(self.pkg),
                            "Could not install " + self.pkg)
            self.assertTrue(self.helper.check(self.pkg),
                            self.pkg + " not found after pkghelper.install")

            self.assertTrue(self.helper.remove(self.pkg),
                            "Could not remove " + self.pkg)
            self.assertFalse(self.helper.check(self.pkg),
                             self.pkg + " still found after pkghelper.remove")

if __name__ == "__main__":
    unittest.main()
