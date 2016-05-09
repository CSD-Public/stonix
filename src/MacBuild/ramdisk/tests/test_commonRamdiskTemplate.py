#!/usr/bin/python -u
"""
CommonRamdiskTemplate test.

@author: Roy Nielsen
"""
from __future__ import absolute_import
#--- Native python libraries
import re
import os
import sys
import time
import unittest
import tempfile
import ctypes as C
from datetime import datetime

#--- non-native python libraries in this source tree
from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp

from lib.libHelperExceptions import NotValidForThisOS

#####
# Load OS specific Ramdisks
if sys.platform.startswith("darwin"):
    #####
    # For Mac
    from macRamdisk import RamDisk, detach
elif sys.platform.startswith("linux"):
    #####
    # For Linux
    from linuxTmpfsRamdisk import RamDisk, unmount

class test_commonRamdiskTemplate(unittest.TestCase):
    """
    """

    @classmethod
    def setUpClass(self):
        """
        Runs once before any tests start
        """
        # Start timer in miliseconds
        self.test_start_time = datetime.now()

    ##################################

    def setUp(self):
        """
        This method runs before each test run.

        @author: Roy Nielsen
        """
        pass

###############################################################################
##### Method Tests

    ##################################

    def test_init(self):
        """
        """
        pass

    ##################################

    def test_get_data(self):
        """
        """
        pass


###############################################################################
##### Functional Tests

    ##################################


###############################################################################
##### unittest Tear down
    @classmethod
    def tearDownClass(self):
        """
        Final cleanup actions...
        """
        self.logger = CyLogger()
        #####
        # capture end time
        test_end_time = datetime.now()

        #####
        # Calculate and log how long it took...
        test_time = (test_end_time - self.test_start_time)

        self.logger.log(lp.INFO, self.__module__ + " took " + str(test_time) + " time to complete...")

###############################################################################
