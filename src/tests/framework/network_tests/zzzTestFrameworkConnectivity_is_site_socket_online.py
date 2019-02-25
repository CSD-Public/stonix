#!/usr/bin/python
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

from connectivity_test_data import test_case_data_site_socket_online

def name_test_template_one(*args):
    """ 
    decorator for monkeypatching
    """
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


for behavior, test_cases in test_case_data_site_socket_online.items():
    for test_case_data in test_cases:
        test_iteration, pass_or_not, host = test_case_data
        my_test_name = "test_{0}_{1}".format(test_iteration, str(pass_or_not))
        my_test_case = name_test_template_one(*test_case_data)
        setattr(test_Connectivity_is_site_socket_online, my_test_name, my_test_case)

