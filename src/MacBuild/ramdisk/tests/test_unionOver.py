#!/usr/bin/python -u
"""
Test unionfs functionality. 

as of 3/15/2016, only the Mac OS X platform is supported.

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
from tests.genericRamdiskTest import GenericRamdiskTest
from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp
from lib.libHelperExceptions import NotValidForThisOS

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

class test_unionOver(GenericRamdiskTest):
    """
    Test unionfs functionality of ramdisks

    @author: Roy Nielsen
    """

    @classmethod
    def setUpClassInstanceSpecifics(self):
        """
        Initializer
        """
        raise unittest.SkipTest("Needs appropriate tests written")

        #####
        # If we don't have a supported platform, skip this test.
        if not sys.platform.startswith("darwin"):
            raise unittest.SkipTest("This is not valid on this OS")
        self.getLibc()
     


    def setUp(self):
        """
        This method runs before each test case.

        @author: Roy Nielsen
        """
        pass


###############################################################################
##### Method Tests

    ##################################

    def test_unionOverFirstTest(self):
        """
        """
        pass

    ##################################

    def test_unionOverSecondTest(self):
        """
        """
        pass

###############################################################################
##### unittest Tear down
    @classmethod
    def tearDownClassInstanceSpecifics(self):
        """
        disconnect ramdisk
        """
        pass

###############################################################################
