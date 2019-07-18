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
@note: This test is not set up to use proxies.
@author: Roy Nielsen
@change 2016/02/10 roy Added sys.path.append for being able to unit test this
                       file as well as with the test harness.
"""
import re
import sys
import unittest

### for importing support libraries
sys.path.append("../../../..")

from src.stonix_resources.Connectivity import Connectivity
from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.stonix_resources.environment import Environment

from .connectivity_test_data import test_case_data_site_socket_online

def name_test_template_one(*args):
    '''decorator for monkeypatching

    :param *args: 

    '''
    def foo(self):
        self.assert_value(*args)
    return foo 

class test_Connectivity_is_site_socket_online(unittest.TestCase):

    def setUp(self):
        self.environ = Environment()
        self.logdispatcher = LogDispatcher(self.environ)
        self.conn = Connectivity(self.logdispatcher)

    def assert_value(self, test_iteration, pass_or_not, host):

        if pass_or_not:
            self.assertTrue(self.conn.is_site_socket_online(host))
        else:
            self.assertFalse(self.conn.is_site_socket_online(host))


for behavior, test_cases in list(test_case_data_site_socket_online.items()):
    for test_case_data in test_cases:
        test_iteration, pass_or_not, host = test_case_data
        my_test_name = "test_{0}_{1}".format(test_iteration, str(pass_or_not))
        my_test_case = name_test_template_one(*test_case_data)
        setattr(test_Connectivity_is_site_socket_online, my_test_name, my_test_case)

