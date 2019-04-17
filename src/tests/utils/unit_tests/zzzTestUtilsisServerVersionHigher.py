#!/usr/bin/python
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

To run this test:

Only requries unittest.

The controller will need to be modified (path environment variable) to make
unittest work (python -m unittest -v <testname, without filename extension>)

@author: Roy Nielsen
"""
import sys
import unittest

from src.tests.lib.logdispatcher_lite import LogPriority
from src.stonix_resources.stonixutilityfunctions import isServerVersionHigher \
                                                     as isServerVersionHigher
###############################
# Import Mocks for testing
######
from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.tests.lib.environment_mac_mock import Environment

###############################

#            ("expected_result", "version", "server_version", "comment"),
version_test_case_data = \
{ "needs_upgrading_true": [(True, "1.0.0", "0.9.9.9", "one"),
             (True, "1.0.0.0", "1.9.9.9", "two"),
             (True, "0.1.0.0", "0.9.0.0a", "four"),
             (True, "0.9.0.0", "0.9.9.9", "five"),
             (True, "1.0.0.0", "1.0.0.1", "seven"),
             (True, "1.0.0.0", "1.0.1.0", "eight"),
             (True, "1.0.0.0", "1.1.0.0", "nine"),
             (True, "1.0.0", "1.0.0.1", "ten"),
             (True, "1.0.0", "1.0.1.0", "eleven"),
             (True, "1.0.0", "1.1.0.0", "twelve"),
             (True, "1.0.0.0", "1.0.1", "thirteen"),
             (True, "1.0.0.0", "1.1.0", "fourteen"),
             (True, "1.0.0.0", "1.1.1", "fifteen"),
             (True, "1.0.0.0", "1.10.1", "sixteen"),
             (True, "1.1.9.0", "1.1.11", "seventeen"),
             (True, "0.8.9.1", "0.8.10.0", "eighteen"),
             (True, "0.8.12.7", "0.8.12.20", "nineteen"),
             (True, "0.8.12.100", "0.8.13.0", "twenty"),
             (True, "0.8.12.100 ", "0.8.13.0", "twentyone"),
             (True, "0.8.12.100\n", "0.8.13.0", "twentytwo"),
             (True, "0.8.12.65", "0.8.13.0", "twentythree"),
             (True, "0.8.12.65", "0.8.13", "twentyfour"),
             (True, "0.8.12", "0.8.13.0", "twentyfive"),
             ],
  "needs_upgrading_false": [(False, "1.0.0", "1.0.0", "thirty"),
             (False, "1.0.1", "1.0.0", "thirtyone"),
             (False, "1.1.0", "1.0.0", "thirtytwo"),
             (False, "2.1.0", "1.0.0", "thirtythree"),
             ],
}

def version_test_template(*args):
    """
    template for monkeypatching
    """
    def foo(self):
        self.assert_version_check(*args)
    return foo


class zzzTestUtilsisServerVersionHigher(unittest.TestCase) :
    """
    Attempt to do a pytest friendly test
    """
    #def setUp(self):
    #    self.environment = Environment()
    #    self.logger = LogDispatcher(self.environment)
        
    def assert_version_check(self, expected_result, version, server_version, comment):
        """
        for assessing the version comparison
        """
        self.assertEquals(expected_result, isServerVersionHigher(version, server_version))


for behavior, test_cases in version_test_case_data.iteritems():
    for case in test_cases:
        (expected_result, version, server_version, comment) = case
        test_name = "test_{0}_{1}_{2}_{3}".format(behavior, version, server_version, comment)
        version_test_case = version_test_template(expected_result, version, server_version, comment)
        setattr(zzzTestUtilsisServerVersionHigher, test_name, version_test_case)

