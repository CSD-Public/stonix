"""
Generic class based Yutilities for ramdisk testing...

@author: Roy Nielsen
"""
#--- Native python libraries
from __future__ import absolute_import
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

class GenericTestUtilities(object):
    '''Generic class based Yutilities for ramdisk testing...
    
    @author: Roy Nielsen


    '''
    def __init__(self):
        """
        Initialization Method...
        """
        self.logger = CyLogger()
        
        self.getLibc()
    ################################################
    ##### Helper Methods
    @classmethod
    def getLibc(self):
        ''' '''
        self.osFamily = sys.platform.lower()

        if self.osFamily and  self.osFamily.startswith("darwin"):
            #####
            # For Mac
            try:
                self.libc = ctypes.CDLL("/usr/lib/libc.dylib")
            except:
                raise Exception("DAMN IT JIM!!!")
            else:
                print "Loading Mac dylib......................................"
        elif self.osFamily and  self.osFamily.startswith("linux"):
            #####
            # For Linux
            possible_paths = ["/lib/x86_64-linux-gnu/libc.so.6",
                              "/lib/i386-linux-gnu/libc.so.6",
                              "/usr/lib64/libc.so.6"]
            for path in possible_paths:

                if os.path.exists(path):
                    self.libcPath = path
                    self.libc = ctypes.CDLL(self.libcPath)
                    print "     Found libc!!!"
                    break
        else:
            self.libc = self._pass()

        try:
            self.libc.sync()
            print":::::Syncing..............."
        except:
            raise Exception("..............................Cannot Sync.")

        print "OS Family: " + str(self.osFamily)

    ################################################

    def findLinuxLibC(self):
        '''Find Linux Libc library...
        
        @author: Roy Nielsen


        '''
        possible_paths = ["/lib/x86_64-linux-gnu/libc.so.6",
                          "/lib/i386-linux-gnu/libc.so.6"]
        for path in possible_paths:

            if os.path.exists(path):
                self.libcPath = path
                self.libc = ctypes.CDLL(self.libcPath)
                break

    ################################################
    @classmethod
    def _pass(self):
        '''Filler if a library didn't load properly'''
        pass

    ################################################

    def touch(self, fname="", message_level="normal"):
        '''Python implementation of the touch command..
        
        @author: Roy Nielsen

        :param fname:  (Default value = "")
        :param message_level:  (Default value = "normal")

        '''
        if re.match("^\s*$", str(fname)):
            self.logger.log(lp.WARNING, "Cannot touch a file without a filename....")
        else:
            try:
                os.utime(fname, None)
            except:
                try:
                    open(fname, 'a').close()
                except Exception, err:
                    self.logger.log(lp.WARNING, "Cannot open to touch: " + str(fname))

    ################################################

    def mkdirs(self, path=""):
        '''A function to do an equivalent of "mkdir -p"

        :param path:  (Default value = "")

        '''
        if not path:
            self.logger.log(lp.WARNING, "Bad path...")
        else:
            if not os.path.exists(str(path)):
                try:
                    os.makedirs(str(path))
                except OSError as err1:
                    self.logger.log(lp.WARNING, "OSError exception attempting to create directory: " + str(path))
                    self.logger.log(lp.WARNING, "Exception: " + str(err1))
                except Exception, err2:
                    self.logger.log(lp.WARNING, "Unexpected Exception trying to makedirs: " + str(err2))

    ################################################

    def mkfile(self, file_path="", file_size=0, pattern="rand", block_size=512, mode=0o777):
        '''Create a file with "file_path" and "file_size".  To be used in
        file creation benchmarking - filesystem vs ramdisk.

        :param eter: file_path - Full path to the file to create
        :param eter: file_size - Size of the file to create, in Mba
        :param eter: pattern - "rand": write a random pattern
                              "0xXX": where XX is a hex value for a byte
        :param eter: block_size - size of blocks to write in bytes
        :param eter: mode - file mode, default 0o777
        :param file_path:  (Default value = "")
        :param file_size:  (Default value = 0)
        :param pattern:  (Default value = "rand")
        :param block_size:  (Default value = 512)
        :param mode:  (Default value = 0o777)
        :returns: s: time in miliseconds the write took
        
        @author: Roy Nielsen

        '''
        total_time = 0
        if file_path and file_size:
            self.libc.sync()
            file_size = file_size * 1024 * 1024
            if os.path.isdir(file_path):
                tmpfile_path = os.path.join(file_path, "testfile")
            else:
                tmpfile_path = file_path
            self.logger.log(lp.DEBUG, "Writing to: " + tmpfile_path)
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
                self.libc.sync()
                os.close(tmpfile)
                self.libc.sync()
                os.unlink(tmpfile_path)
                self.libc.sync()

                # capture end time
                end_time = datetime.now()
            except Exception, err:
                self.logger.log(lp.WARNING, "Exception trying to write temp file for "  + \
                                "benchmarking...")
                self.logger.log(lp.WARNING, "Exception thrown: " + str(err))
                total_time = 0
            else:
                total_time = end_time - start_time
        return total_time
