#!/usr/bin/env python
'''
Created on February 21, 2018

###############################################################################
#                                                                             #
# Copyright 2018.  Los Alamos National Security, LLC. This material was       #
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

@author: rsn
'''
import re
import sys
import unittest

from datetime import datetime

sys.path.append("../../../..")

from src.stonix_resources.environment import Environment
from src.stonix_resources.SHlaunchdTwo import SHlaunchdTwo
from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.tests.lib.logdispatcher_lite import LogPriority as lp
from src.tests.framework.unit_tests.SHlaunchdTwoData import service_path_test_data
from src.tests.framework.unit_tests.SHlaunchdTwoData import name_from_service_test_data
from src.tests.framework.unit_tests.SHlaunchdTwoData import target_valid_test_data

if sys.platform == 'darwin':


    class zzzTestFrameworkSHlaunchdTwoHelperMethods(unittest.TestCase):
        '''
        Test the launchd version 2 service helper.

        @author: Roy Nielsen
        '''
        @classmethod
        def setUpClass(self):
            '''
            Test initializer
            '''
            self.environ = Environment()
            self.environ.setdebugmode(True)

            # Start timer in miliseconds
            self.test_start_time = datetime.now()

            self.logger = LogDispatcher(self.environ)

            self.sh = SHlaunchdTwo(self.environ, self.logger)

            self.logger.log(lp.DEBUG, "test " + __file__ + " initialized...")

        def test_isValidServicePath(self):
            '''
            '''
            for test_key, test_values in service_path_test_data.iteritems():
                if re.match("^valid_service_paths", test_key):
                    for test_item in test_values:
                        self.assertTrue(self.sh.isValidServicePath(test_item),
                                        "Invalid service path: " +
                                        str(test_item))
                if re.match("^invalid_service_paths", test_key):
                    for test_item in test_values:
                        self.assertFalse(self.sh.isValidServicePath(test_item),
                                         "Valid service path: " +
                                         str(test_item))

        def test_getServiceNameFromService(self):
            '''
            '''
            for test_key, test_values in name_from_service_test_data.iteritems():
                if re.match("^valid_service_plists", test_key):
                    for test_item in test_values:
                        self.assertTrue(self.sh.isValidServicePath(test_item),
                                        "Invalid service plist: " +
                                        str(test_item))
                if re.match("^invalid_service_plists", test_key):
                    for test_item in test_values:
                        self.assertFalse(self.sh.isValidServicePath(test_item),
                                         "Valid service plist: " +
                                         str(test_item))

        def test_targetValid(self):
            '''
            '''
            for test_key, test_values in target_valid_test_data.iteritems():
                if re.match("^valid_service_plists", test_key):
                    for test_item in test_values:
                        params = {test_item[1]['serviceName'][0]:
                                  test_item[1]['serviceName'][1]}
                        self.assertTrue(self.sh.targetValid(test_item[0],
                                                            **params),
                                        "Target data: " +
                                        str(test_item) +
                                        " is not valid.")
                if re.match("^invalid_service_plists", test_key):
                    for test_item in test_values:
                        params = {test_item[1]['serviceName'][0]:
                                  test_item[1]['serviceName'][1]}
                        self.assertFalse(self.sh.targetValid(test_item[0],
                                                             **params),
                                         "Target data: " +
                                         str(test_item) +
                                         " is good!")

        @classmethod
        def tearDownClass(self):
            '''
            Test destructor
            '''
            #####
            # capture end time
            test_end_time = datetime.now()

            #####
            # Calculate and log how long it took...
            test_time = (test_end_time - self.test_start_time)

            self.logger.log(lp.DEBUG, self.__module__ +
                            " took " + str(test_time) +
                            " time to complete...")


    if __name__ == '__main__':
        unittest.main()

