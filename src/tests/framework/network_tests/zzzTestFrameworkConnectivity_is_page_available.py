#!/usr/bin/python
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

import re
import sys
import unittest
from src.stonix_resources.localize import PROXY

# for importing support libraries
sys.path.append("../../../..")

from src.stonix_resources.Connectivity import Connectivity
from connectivity_test_data import test_case_data_is_page_available
from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.stonix_resources.environment import Environment


def name_test_template(*args):
    """
    decorator for monkeypatching
    """
    def foo(self):
        self.assert_value(*args)
    return foo


class test_Connectivity_is_page_available(unittest.TestCase):

    def setUp(self):
        self.environ = Environment()
        self.logdispatcher = LogDispatcher(self.environ)
        self.skip = False
        if self.environ.getosfamily() == "linux" or re.search("foo.bar", PROXY):
            # If we can do this the easy way with Python > 2.7, do that. If
            # not, set the skip flag
            if hasattr(unittest, "SkipTest"):
                self.skipTest("Proxy is set to a fake value. " +
                              "Skipping connectivity test.")
            else:
                self.skip = True
        if not self.skip:
            self.conn = Connectivity(self.logdispatcher, use_proxy=True)

    def assert_value(self, expected, test_iteration, site, page):
        if not self.skip:
            if expected:
                self.assertTrue(self.conn.is_site_available(site, page),
                                "Could not reach page " + page + " at site " +
                                site)
            else:
                self.assertFalse(self.conn.is_site_available(site, page),
                                 "Found page " + page + " at site " +
                                 site)


for behavior, test_cases in test_case_data_is_page_available.items():
    for test_case_data in test_cases:
        expected, test_iteration, site, page = test_case_data
        my_test_name = "test_{0}_{2}_{1}".format(test_iteration, str(expected),
                                                 str(behavior))
        my_test_case = name_test_template(*test_case_data)
        setattr(test_Connectivity_is_page_available, my_test_name,
                my_test_case)
