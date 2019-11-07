#!/usr/bin/env python3 -u
"""

@author: Roy Nielsen
"""

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
    from macRamdisk import RamDisk, detach, unmount
elif sys.platform.startswith("linux"):
    #####
    # For Linux
    from linuxTmpfsRamdisk import RamDisk, unmount

@unittest.skipUnless(sys.platform.startswith("darwin"), "This test is not valid on this OS")
class test_macRamdisk(GenericRamdiskTest):
    ''' '''

    @classmethod
    def setUpInstanceSpecifics(self):
        '''Initializer'''

        self.getLibc()

    ##################################

    def setUp(self):
        '''This method runs before each test run.
        
        @author: Roy Nielsen


        '''
        #self.getLibc()
        pass

###############################################################################
##### Method Tests

    ##################################

    def test_macRamdiskFirstTest(self):
        ''' '''
        pass

    ##################################

    def test_macRamdiskSecondTest(self):
        ''' '''
        pass

###############################################################################
##### unittest Tear down
    @classmethod
    def tearDownInstanceSpecifics(self):
        '''disconnect ramdisk'''
        pass

###############################################################################
