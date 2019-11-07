#!/usr/bin/env python3 -u
"""
Template for future generic ramdisk test.

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

sys.path.append("../")

#--- non-native python libraries in this source tree
from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp
from lib.libHelperExceptions import NotValidForThisOS
from tests.genericRamdiskTest import GenericRamdiskTest

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

@unittest.skipUnless(sys.platform.startswith("darwin"|"linux"), "This is not valid on this OS")
class test_ramdisk(GenericRamdiskTest):
    ''' '''

    @classmethod
    def setUpClass(self):
        '''Initializer'''
        # Start timer in miliseconds
        self.test_start_time = datetime.now()

        #self.message_level = "debug"
        self.message_level = "debug"

        self.libcPath = None # initial initialization

        self.subdirs = ["two", "three" "one/four"]

        """
        Set up a ramdisk and use that random location as a root to test the
        filesystem functionality of what is being tested.
        """
        #Calculate size of ramdisk to make for this unit test.
        size_in_mb = 1800
        ramdisk_size = size = size_in_mb
        self.mnt_pnt_requested = ""

        self.logger = CyLogger()

        self.success = False
        self.mountPoint = False
        self.ramdiskDev = False
        self.mnt_pnt_requested = False

        # get a ramdisk of appropriate size, with a secure random mountpoint
        self.my_ramdisk = RamDisk(str(ramdisk_size),
                                  self.mnt_pnt_requested,
                                  self.message_level)
        (self.success, self.mountPoint, self.ramdiskDev) = self.my_ramdisk.getData()
        if self.success:
            self.logger.log(lp.INFO, "::::::::Ramdisk Mount Point: " + str(self.mountPoint))
            self.logger.log(lp.INFO, "::::::::Ramdisk Device     : " + str(self.ramdiskDev))

        else:
            raise IOError("Cannot get a ramdisk for some reason. . .")

        #####
        # Create a temp location on disk to run benchmark tests against
        self.fs_dir = tempfile.mkdtemp()

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
##### Helper Methods


###############################################################################
##### Method Tests

    ##################################

    def test_init(self):
        ''' '''
        pass

    ##################################

    def test_get_data(self):
        ''' '''
        pass

    ##################################

    def test_getRandomizedMountpoint(self):
        ''' '''
        pass

    ##################################

    def test_create(self):
        ''' '''
        pass

    ##################################

    def test_mount(self):
        ''' '''
        pass

    ##################################

    def test_attach(self):
        ''' '''
        pass

    ##################################

    def test_remove_journal(self):
        ''' '''
        pass

    ##################################

    def test_unmount(self):
        ''' '''
        pass

    ##################################

    def test_eject(self):
        ''' '''
        pass

    ##################################

    def test_format(self):
        ''' '''
        pass

    ##################################

    def test_partition(self):
        ''' '''
        pass

    ##################################

    def test_isMemoryAvailable(self):
        ''' '''
        pass

    ##################################

    def test_runcmd(self):
        ''' '''
        pass

    ##################################

    def test_getDevice(self):
        ''' '''
        pass

    ##################################

    def test_setDevice(self):
        ''' '''
        pass

    ##################################

    def test_getVersion(self):
        ''' '''
        pass

    ##################################

    def test_detach(self):
        ''' '''
        pass

###############################################################################
##### Functional Tests

    ##################################

    def test_files_n_dirs(self):
        '''Should work when files exist in ramdisk.'''
        # Do file setup for this test
        for subdir in self.subdirs:
            dirpath = self.mountPoint + "/" + subdir
            self.logger.log(lp.DEBUG, "DIRPATH: : " + str(dirpath))
            self.mkdirs(dirpath)
            self.touch(dirpath + "/" + "test")

        # Do the tests
        for subdir in self.subdirs:
            # CANNOT use os.path.join this way.  os.path.join cannot deal with
            # absolute directories.  May work with mounting ramdisk in local
            # relative directories.
            self.assertTrue(os.path.exists(self.mountPoint + "/" + subdir + "/" +  "test"))

    ##################################

    def test_four_file_sizes(self):
        '''Test file creation of various sizes, ramdisk vs. filesystem'''
        #####
        # Clean up the ramdisk
        self.my_ramdisk._format()
        #####
        # 100Mb file size
        oneHundred = 100
        #####
        # 100Mb file size
        twoHundred = 200
        #####
        # 500Mb file size
        fiveHundred = 500
        #####
        # 1Gb file size
        oneGig = 1000

        my_fs_array = [oneHundred, twoHundred, fiveHundred, oneGig]
        time.sleep(1)
        for file_size in my_fs_array:
            self.logger.log(lp.DEBUG, "testfile size: " + str(file_size))
            #####
            # Create filesystem file and capture the time it takes...
            fs_time = self.mkfile(os.path.join(self.fs_dir, "testfile"), file_size)
            self.logger.log(lp.DEBUG, "fs_time: " + str(fs_time))
            time.sleep(1)

            #####
            # get the time it takes to create the file in ramdisk...
            ram_time = self.mkfile(os.path.join(self.mountPoint, "testfile"), file_size)
            self.logger.log(lp.DEBUG, "ram_time: " + str(ram_time))
            time.sleep(1)

            speed = fs_time - ram_time
            self.logger.log(lp.DEBUG, "ramdisk: " + str(speed) + " faster...")

            self.assertTrue((fs_time - ram_time).days>-1)


    def test_many_small_files_creation(self):
        ''' '''
        #####
        # Clean up the ramdisk
        self.my_ramdisk._format()
        #####
        #
        ramdisk_starttime = datetime.now()
        for i in range(1000):
            self.mkfile(os.path.join(self.mountPoint, "testfile" + str(i)), 1)
        ramdisk_endtime = datetime.now()

        rtime = ramdisk_endtime - ramdisk_starttime

        fs_starttime = datetime.now()
        for i in range(1000):
            self.mkfile(os.path.join(self.fs_dir, "testfile" + str(i)), 1)
        fsdisk_endtime = datetime.now()

        fstime = fsdisk_endtime - fs_starttime

        self.assertTrue((fstime - rtime).days > -11)

###############################################################################
##### unittest Tear down
    @classmethod
    def tearDownClass(self):
        '''disconnect ramdisk'''
        if self.my_ramdisk.unmount():
            self.logger.log(lp.INFO, r"Successfully detached disk: " + \
                       str(self.my_ramdisk.mntPoint).strip())
        else:
            self.logger.log(lp.WARNING, r"Couldn't detach disk: " + \
                       str(self.my_ramdisk.myRamdiskDev).strip() + \
                       " : mntpnt: " + str(self.my_ramdisk.mntPoint))
            raise Exception(r"Cannot eject disk: " + \
                            str(self.my_ramdisk.myRamdiskDev).strip() + \
                            " : mntpnt: " + str(self.my_ramdisk.mntPoint))
        #####
        # capture end time
        test_end_time = datetime.now()

        #####
        # Calculate and log how long it took...
        test_time = (test_end_time - self.test_start_time)

        self.logger.log(lp.INFO, self.__module__ + " took " + str(test_time) + \
                  " time to complete...")

###############################################################################
