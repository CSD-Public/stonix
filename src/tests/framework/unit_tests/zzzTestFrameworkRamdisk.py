#!/usr/bin/python -u

import re
import os
import sys
import time
import unittest
import tempfile
import ctypes as C
from datetime import datetime

from src.MacBuild.macRamdisk import RamDisk, detach 
from src.stonix_resources.environment import Environment
from src.tests.lib.logdispatcher_lite import LogDispatcher, LogPriority

class zzzTestFrameworkRamdisk(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        """
        Initializer
        """
        self.environ = Environment()
        if self.environ.getosfamiliy() != "macosx":
            myos = self.environ.getosfamiliy()
            raise self.SkipTest("RamDisk does not support this OS" + \
                                " family: " + str(myos))
        
        self.logger = LogDispatcher(self.environ)

        #####
        # setting up to call ctypes to do a filesystem sync 
        if self.environ.getosfamily() == "redhat" :
            self.libc = C.CDLL("/lib/libc.so.6")
        elif self.environ.getosfamily() == "macosx" :
            self.libc = C.CDLL("/usr/lib/libc.dylib")
        else:
            self.libc = None

        self.subdirs = ["two", "three" "one/four"]

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

        self.logger.log(LogPriority.DEBUG, "::::::::Ramdisk Mount Point: " + str(self.mountPoint))
        self.logger.log(LogPriority.DEBUG, "::::::::Ramdisk Device     : " + str(self.ramdiskDev))

        if self.environ.getosfamily().lower() == "darwin":
            
            # import appropriate ramdisk library
            #from src.MacBuild.macRamdisk import Ramdisk, detach 

            # get a ramdisk of appropriate size, with a secure random mountpoint
            my_ramdisk = RamDisk(str(ramdisk_size), self.mnt_pnt_requested)
            
            (self.success, self.mountPoint, self.ramdiskDev) = \
            my_ramdisk.get_data()
            
        else:
            self.logger.log(LogPriority.INFO, "Not applicable to this OS")
            self.success = False

        if not self.success:
            raise "Cannot get a ramdisk for some reason. . ."
        
        #####
        # Create a temp location on disk to run benchmark tests against
        self.fs_dir = tempfile.mkdtemp()
        

###############################################################################
##### Helper Classes

    def touch(self, fname=""):
        """
        Python implementation of the touch command..
        
        inspiration: http://stackoverflow.com/questions/1158076/implement-touch-using-python
        
        @author: Roy Nielsen
        """
        if re.match("^\s*$", str(fname)):
            self.logger.log(LogPriority.DEBUG, "Cannot touch a file without a filename....")
        else :
            try:
                os.utime(fname, None)
            except:
                try :
                    open(fname, 'a').close()
                except Exception, err:
                    self.logger.log(LogPriority.INFO,"Cannot open to touch: " + str(fname))


    def mkdirs(self, path="") :
        """
        A function to do an equivalent of "mkdir -p"
        """
        if not path :
            self.logger.log(LogPriority.INFO,"Bad path...")
        else :
            if not os.path.exists(str(path)):
                try:
                    os.makedirs(str(path))
                except OSError as err1:
                    self.logger.log(LogPriority.INFO,"OSError exception attempting to create directory: " + str(path))
                    self.logger.log(LogPriority.INFO,"Exception: " + str(err1))
                except Exception, err2 :
                    self.logger.log(LogPriority.INFO,"Unexpected Exception trying to makedirs: " + str(err2))


    def mkfile(self, file_path="", file_size=0, pattern="rand", block_size=512, mode=0o777):
        """
        Create a file with "file_path" and "file_size".  To be used in 
        file creation benchmarking - filesystem vs ramdisk.

        @parameter: file_path - Full path to the file to create
        @parameter: file_size - Size of the file to create, in Mba
        @parameter: pattern - "rand": write a random pattern
                              "0xXX": where XX is a hex value for a byte
        @parameter: block_size - size of blocks to write in bytes
        @parameter: mode - file mode, default 0o777

        @returns: time in miliseconds the write took

        @author: Roy Nielsen
        """
        total_time = 0
        if file_path and file_size:
            try:
                self.libc.sync()
            except:
                pass
            tmpfile_path = os.path.join(file_path, "testfile")
            self.logger.log(LogPriority.DEBUG,"Writing to: " + tmpfile_path)
            try:
                # Get the number of blocks to create
                blocks = file_size/block_size

                # Start timer in miliseconds
                start_time = datetime.now()

                # do low level file access...
                tmpfile = os.open(tmpfile_path, os.O_WRONLY | os.O_CREAT, mode)

                # do file writes...
                for i in range(blocks):
                    tmp_buffer = os.urandom(block_size)
                    os.write(tmpfile, str(tmp_buffer))
                    os.fsync(tmpfile)
                os.close(tmpfile)

                # capture end time
                end_time = datetime.now()
            except Exception, err:
                self.logger.log(LogPriority.INFO,"Exception trying to write temp file for benchmarking...")
                self.logger.log(LogPriority.INFO,"Exception thrown: " + str(err))
                total_time = 0
            else:
                total_time = end_time - start_time
                os.unlink(tmpfile_path)
                try:
                    self.libc.sync()
                except:
                    pass
        return total_time
 
###############################################################################
##### Tests
        
    ##################################

    def test_files_n_dirs(self):
        """
        Should work when files exist in ramdisk.
        """
        # Do file setup for this test
        for subdir in self.subdirs:
            dirpath = self.mountPoint + "/" + subdir
            self.logger.log(LogPriority.DEBUG,"DIRPATH: : " + str(dirpath))
            self.mkdirs(dirpath)
            self.touch(dirpath + "/" + "test")

        # Do the tests
        for subdir in self.subdirs:
            # CANNOT use os.path.join this way.  os.path.join cannot deal with
            # absolute directories.  May work with mounting ramdisk in local
            # relative directories.
            self.assertTrue(os.path.exists(self.mountPoint + "/" + subdir + "/" +  "test"))

    ##################################

    def test_fs_compare(self):
        """
        Test filesystem access vs ramdisk access, of various sizes
        """
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
            #####
            # Create filesystem file and capture the time it takes...
            fs_time = self.mkfile(self.fs_dir, file_size)
            self.logger.log(LogPriority.DEBUG,"fs_time: " + str(fs_time))
            time.sleep(1)

            #####
            # get the time it takes to create the file in ramdisk...
            ram_time = self.mkfile(self.mountPoint, file_size)
            self.logger.log(LogPriority.DEBUG,"ram_time: " + str(ram_time))
            time.sleep(1)

            speed = fs_time - ram_time
            self.logger.log(LogPriority.DEBUG,"ramdisk: " + str(speed) + " faster...")

            self.assertTrue(((fs_time - ram_time).days>-1))


###############################################################################
##### unittest Tear down
    @classmethod
    def tearDownClass(self):
        """
        disconnect ramdisk
        """
        if detach(self.ramdiskDev):
            self.logger.log(LogPriority.DEBUG, "Successfully detached disk: " + str(self.ramdiskDev).strip())
        else:
            self.logger.log(LogPriority.INFO, "Couldn't detach disk: " + str(self.ramdiskDev).strip() + " : mntpnt: " + str(self.mntPoint))
            raise Exception("Cannot eject disk: " + str(self.ramdiskDev).strip() + " : mntpnt: " + str(self.mntPoint))
        
###############################################################################
