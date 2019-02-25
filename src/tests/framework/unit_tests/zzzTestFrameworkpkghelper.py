#!/usr/bin/python
'''
Created on Jul 31, 2012

###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
