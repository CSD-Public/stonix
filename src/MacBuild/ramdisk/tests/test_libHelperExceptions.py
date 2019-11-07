#!/usr/bin/env python3 -u
"""
Test the helper exceptions.

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

@unittest.skip("Tests need to be written...")
class test_libHelperExceptions(unittest.TestCase):
    ''' '''

    @classmethod
    def setUpClass(self):
        '''Initializer'''

        # Start timer in miliseconds
        self.test_start_time = datetime.now()

        self.logger = CyLogger()

        self.libcPath = None # initial initialization


    def setUp(self):
        '''This method runs before each test run.
        
        @author: Roy Nielsen


        '''
        self.libcPath = None # initial initialization
        #####
        # setting up to call ctypes to do a filesystem sync
        if sys.platform.startswith("darwin"):
            #####
            # For Mac
            self.libc = C.CDLL("/usr/lib/libc.dylib")
        elif sys.platform.startswith("linux"):
            #####
            # For Linux
            self.findLinuxLibC()
            self.libc = C.CDLL(self.libcPath)
        else:
            self.libc = self._pass()



###############################################################################
##### Helper Classes

    def setMessageLevel(self, msg_lvl="normal"):
        '''Set the logging level to what is passed in.

        :param msg_lvl:  (Default value = "normal")

        '''
        self.message_level = msg_lvl

    def findLinuxLibC(self):
        '''Find Linux Libc library...
        
        @author: Roy Nielsen


        '''
        possible_paths = ["/lib/x86_64-linux-gnu/libc.so.6",
                          "/lib/i386-linux-gnu/libc.so.6"]
        for path in possible_paths:

            if os.path.exists(path):
                self.libcPath = path
                break

    def _pass(self):
        '''Filler if a library didn't load properly'''
        pass

###############################################################################
##### Method Tests

    ##################################

    def test_init(self):
        ''' '''
        pass

    ##################################

###############################################################################
##### Functional Tests

    ##################################

###############################################################################
##### unittest Tear down
    @classmethod
    def tearDownClass(self):
        '''disconnect ramdisk'''
        logger = CyLogger()
        #####
        # capture end time
        test_end_time = datetime.now()

        #####
        # Calculate and log how long it took...
        test_time = (test_end_time - self.test_start_time)

        logger.log(lp.INFO, self.__module__ + " took " + str(test_time) + \
                  " time to complete...")

###############################################################################
