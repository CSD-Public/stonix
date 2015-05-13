"""

Please Note!

This test is not set up to use proxies, so if you need
to use a proxy server, all the valid_connections
tests  will fail.

"""



import re
import sys
import unittest
from mock import *

### for importing support libraries
sys.path.append("..")

from Connectivity import Connectivity
from test_data import test_case_data_is_page_available

from Connectivity import Connectivity
from logdispatcher_mock import LogDispatcher
from environment_mac_mock import Environment

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
        self.conn = Connectivity(self.logdispatcher)

    def assert_value(self, expected, test_iteration, site, page):

        if expected:
            self.assertTrue(self.conn.is_site_available(site, page))
        else:
            self.assertFalse(self.conn.is_site_available(site, page))


for behavior, test_cases in test_case_data_is_page_available.items():
    for test_case_data in test_cases:
        expected, test_iteration, site, page = test_case_data
        my_test_name = "test_{0}_{2}_{1}".format(test_iteration, str(expected), str(behavior))
        my_test_case = name_test_template(*test_case_data)
        setattr(test_Connectivity_is_page_available, my_test_name, my_test_case)

