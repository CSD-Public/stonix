#!/usr/bin/python -u
"""
Test unionfs functionality. 

as of 3/15/2016, only the Mac OS X platform is supported.

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
    from macRamdisk import RamDisk, unmount
elif sys.platform.startswith("linux"):
    #####
    # For Linux
    from linuxTmpfsRamdisk import RamDisk, unmount

@unittest.skip("Needs appropriate tests written...")
class test_unionOver(GenericRamdiskTest):
    '''Test unionfs functionality of ramdisks
    
    @author: Roy Nielsen


    '''

    @classmethod
    def setUpClassInstanceSpecifics(self):
        '''Initializer'''

        self.getLibc()

    def setUp(self):
        '''This method runs before each test case.
        
        @author: Roy Nielsen


        '''
        pass


###############################################################################
##### Method Tests

    ##################################

    def test_unionOverFirstTest(self):
        ''' '''
        pass

    ##################################

    def test_unionOverSecondTest(self):
        ''' '''
        pass

###############################################################################
##### unittest Tear down
    @classmethod
    def tearDownClassInstanceSpecifics(self):
        '''disconnect ramdisk'''
        pass

###############################################################################
