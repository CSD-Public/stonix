#!/usr/bin/python -u
"""
Test for the RamdiskFactory

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
from tests.genericTestUtilities import GenericTestUtilities

#####
# Load OS specific Ramdisks
if sys.platform.startswith("darwin"):
    #####
    # For Mac
    from macRamdisk import RamDisk, unmount
elif sys.platform.startswith("linux"):
    #####
    # For Linux
    from linuxTmpfsRamdisk import RamDisk, unmount

class test_ramdiskFactory(unittest.TestCase, GenericTestUtilities):
    """
    """

    @classmethod
    def setUpClass(self):
        """
        Initializer
        """
        unittest.SkipTest("Tests need to be written...")
        # Start timer in miliseconds
        self.test_start_time = datetime.now()

        self.logger = CyLogger()

        self.libcPath = None # initial initialization

        #####
        # If we don't have a supported platform, skip this test.
        if not sys.platform.startswith("darwin") and \
           not sys.platform.startswith("linux"):
            raise unittest.SkipTest("This is not valid on this OS")
        raise unittest.SkipTest("Not a supported tests....")

    def setUp(self):
        """
        This method runs before each test run.

        @author: Roy Nielsen
        """
        pass

###############################################################################
##### Method Tests

    ##################################

    def test_ramdiskFactoryFirstTest(self):
        """
        """
        pass

    ##################################

    def test_ramdiskFactorySecondTest(self):
        """
        """
        pass

###############################################################################
##### Functional Tests

###############################################################################
##### unittest Tear down
    @classmethod
    def tearDownClass(self):
        """
        disconnect ramdisk
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
