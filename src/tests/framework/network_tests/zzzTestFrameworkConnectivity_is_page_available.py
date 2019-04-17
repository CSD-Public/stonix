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

#!/usr/bin/python

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

@unittest.skipIf(PROXY == None, "Proxy is not set. Skipping connectivity test.")
class test_Connectivity_is_page_available(unittest.TestCase):

    def setUp(self):
        '''
        '''

        self.environ = Environment()
        self.logdispatcher = LogDispatcher(self.environ)
        self.conn = Connectivity(self.logdispatcher, use_proxy=True)

    def assert_value(self, expected, test_iteration, site, page):
        '''
        '''

        if expected:
            self.assertTrue(self.conn.is_site_available(site, page), "Could not reach page " + page + " at site " + site)
        else:
            self.assertFalse(self.conn.is_site_available(site, page), "Found page " + page + " at site " + site)

for behavior, test_cases in test_case_data_is_page_available.items():
    for test_case_data in test_cases:
        expected, test_iteration, site, page = test_case_data
        my_test_name = "test_{0}_{2}_{1}".format(test_iteration, str(expected),
                                                 str(behavior))
        my_test_case = name_test_template(*test_case_data)
        setattr(test_Connectivity_is_page_available, my_test_name,
                my_test_case)
