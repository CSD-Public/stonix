"""
Generic ramdisk test, with helper functions. Inherited by other tests.

@author: Roy Nielsen
"""
#--- Native python libraries

import os
import re
import sys
import tempfile
import unittest
import ctypes
from datetime import datetime
#sys.path.append("../")
#--- non-native python libraries in this source tree
from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp
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

class GenericRamdiskTest(unittest.TestCase, GenericTestUtilities):
    '''Holds helper methods.  DO NOT create an init
    
    Inspiration for using classmethod:
    http://simeonfranklin.com/testing2.pdf
    
    @author: Roy Nielsen


    '''
    @classmethod
    def setUpClass(self):
        ''' '''
        #self.getLibc()
        self.subdirs = ["two", "three" "one/four"]
        self.logger = CyLogger()
        self.logger.log(lp.CRITICAL, "Logger initialized............................")

        """
        Set up a ramdisk and use that random location as a root to test the
        filesystem functionality of what is being tested.
        """
        #Calculate size of ramdisk to make for this unit test.
        size_in_mb = 1800
        ramdisk_size = size = size_in_mb
        self.mnt_pnt_requested = ""

        self.success = False
        self.mountPoint = False
        self.ramdiskDev = False
        self.mnt_pnt_requested = False

        # get a ramdisk of appropriate size, with a secure random mountpoint
        self.my_ramdisk = RamDisk(size=str(ramdisk_size), logger=self.logger)
        (self.success, self.mountPoint, self.ramdiskDev) = self.my_ramdisk.getData()

        self.mount = self.mountPoint

        self.logger.log(lp.INFO, "::::::::Ramdisk Mount Point: " + str(self.mountPoint))
        self.logger.log(lp.INFO, "::::::::Ramdisk Device     : " + str(self.ramdiskDev))

        if not self.success:
            raise IOError("Cannot get a ramdisk for some reason. . .")

        #####
        # Create a temp location on disk to run benchmark tests against
        self.fs_dir = tempfile.mkdtemp()

        # Start timer in miliseconds
        self.test_start_time = datetime.now()

        self.setUpInstanceSpecifics()

    @classmethod
    def setUpInstanceSpecifics(self):
        '''Call the child class setUpClass initializer, if possible..
        
        Here to be over-ridden by a child class.
        
        @author: Roy Nielsen


        '''
        pass

    ################################################
    ##### Helper Methods

    def _unloadRamdisk(self):
        ''' '''
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
            self.assertTrue(os.path.exists(self.mountPoint + "/" + subdir + "/" +  "test"), "Problem with ramdisk...")

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

        for file_size in my_fs_array:
            self.logger.log(lp.INFO, "testfile size: " + str(file_size))
            #####
            # Create filesystem file and capture the time it takes...
            fs_time = self.mkfile(os.path.join(self.fs_dir, "testfile"), file_size)
            self.logger.log(lp.INFO, "fs_time: " + str(fs_time))

            #####
            # get the time it takes to create the file in ramdisk...
            ram_time = self.mkfile(os.path.join(self.mountPoint, "testfile"), file_size)
            self.logger.log(lp.INFO, "ram_time: " + str(ram_time))

            speed = fs_time - ram_time
            self.logger.log(lp.INFO, "ramdisk: " + str(speed) + " faster...")

            self.assertTrue((fs_time - ram_time).days > -1, "Problem with ramdisk...")

    ##################################

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

        self.assertTrue((fstime - rtime).days > -1, "Problem with ramdisk...")

    ##################################

    @classmethod
    def tearDownInstanceSpecifics(self):
        '''Skeleton method in case a child class wants/needs to override it.
        
        @author: Roy Nielsen


        '''
        pass

    @classmethod
    def tearDownClass(self):
        ''' '''
        self.tearDownInstanceSpecifics()
        if unmount(self.mount):
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
