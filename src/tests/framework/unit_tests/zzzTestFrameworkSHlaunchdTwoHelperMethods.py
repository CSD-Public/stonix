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
Created on February 21, 2018


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
        '''Test the launchd version 2 service helper.
        
        @author: Roy Nielsen


        '''
        @classmethod
        def setUpClass(self):
            '''Test initializer'''
            self.environ = Environment()
            self.environ.setdebugmode(True)

            # Start timer in miliseconds
            self.test_start_time = datetime.now()

            self.logger = LogDispatcher(self.environ)
            self.logger.initializeLogs()

            self.sh = SHlaunchdTwo(self.environ, self.logger)

            self.logger.log(lp.DEBUG, "test " + __file__ + " initialized...")

        def test_isValidServicePath(self):
            ''' '''
            for test_key, test_values in list(service_path_test_data.items()):
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
            ''' '''
            for test_key, test_values in list(name_from_service_test_data.items()):
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
            ''' '''
            for test_key, test_values in list(target_valid_test_data.items()):
                if re.match("^valid_target_data", test_key):
                    for test_item in test_values:
                        params = {test_item[1]['serviceName'][0]:
                                  test_item[1]['serviceName'][1]}
                        self.assertEqual(self.sh.targetValid(test_item[0],
                                                             **params),
                                         test_item[2],
                                         "Target data: " +
                                         str(test_item) +
                                         " is not valid.")
                if re.match("^invalid_target_data", test_key):
                    for test_item in test_values:
                        params = {test_item[1]['serviceName'][0]:
                                  test_item[1]['serviceName'][1]}
                        self.assertNotEqual(self.sh.targetValid(test_item[0],
                                                                **params),
                                            test_item[2],
                                            "Target data: " +
                                            str(test_item) +
                                            " is good!")

        @classmethod
        def tearDownClass(self):
            '''Test destructor'''
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

