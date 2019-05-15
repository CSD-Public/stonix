"""
Template for creating a linux "loop" ramdisk.  Dangerous as the "loop" disk
will continue to dynamically grow until it is out of memory (virtual included)

@author: Roy Nielsen
"""
#--- Native python libraries
import os
import re
import sys
import unittest
from tempfile import mkdtemp

#--- non-native python libraries in this source tree
from lib.run_commands import RunWith
from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp
from commonRamdiskTemplate import RamDiskTemplate
from commonRamdiskTemplate import RamDiskTemplate

###############################################################################

class RamDisk(RamDiskTemplate):
    ''' '''
    def __init__(self, size=0, mountpoint="", logger=False):
        """
        """
        RamDiskTemplate.__init__(self, size, mountpoint, logger)
        self.module_version = '20160224.032043.009191'
        if not sys.platform.startswith("linux"):
            raise self.NotValidForThisOS("This ramdisk is only viable for a Linux.")
        raise self.NotValidForThisOS("Not yet implemented......")
        print "#=====================================#"
        print "# Not yet implemented...              #"
        print "#=====================================#"

    ###########################################################################

    def __create(self) :
        """
        Create a ramdisk device

        Must be over-ridden to provide OS/method specific ramdisk creation

        @author: Roy Nielsen
        """
        success = False
        return success

    ###########################################################################

    def __mount(self) :
        """
        Mount the disk

        @author: Roy Nielsen
        """
        success = False
        return success

    ###########################################################################

    def __remove_journal(self) :
        """
        Having a journal in ramdisk makes very little sense.  Remove the journal
        after creating the ramdisk device

        Must be over-ridden to provide OS/Method specific functionality

        @author: Roy Nielsen
        """
        success = False
        return success

    ###########################################################################

    def unmount(self) :
        '''Unmount the disk - same functionality as __eject on the mac
        
        Must be over-ridden to provide OS/Method specific functionality
        
        @author: Roy Nielsen


        '''
        success = False
        return success

    ###########################################################################

    def _format(self) :
        '''Format the ramdisk
        
        Must be over-ridden to provide OS/Method specific functionality
        
        @author: Roy Nielsen


        '''
        success = False
        return success

    ###########################################################################

    def __isMemoryAvailable(self) :
        """
        Check to make sure there is plenty of memory of the size passed in
        before creating the ramdisk

        Must be over-ridden to provide OS/Method specific functionality

        @author: Roy Nielsen
        """
        #mem_free = psutil.phymem_usage()[2]

        #print "Memory free = " + str(mem_free)
        success = False
        return success

    ###########################################################################

    def getDevice(self):
        '''Getter for the device name the ramdisk is using
        
        Must be over-ridden to provide OS/Method specific functionality
        
        @author: Roy Nielsen


        '''
        return self.myRamdiskDev

    ###########################################################################

    def setDevice(self, device=None):
        '''Setter for the device so it can be ejected.
        
        Must be over-ridden to provide OS/Method specific functionality
        
        @author: Roy Nielsen

        :param device:  (Default value = None)

        '''
        success = False
        return success

    ###########################################################################

    def getVersion(self):
        '''Getter for the version of the ramdisk
        
        Must be over-ridden to provide OS/Method specific functionality
        
        @author: Roy Nielsen


        '''
        success = False
        return success

###############################################################################


def unmount(device=" ", message_level="normal"):
    '''Eject the ramdisk
    
    Must be over-ridden to provide OS/Method specific functionality
    
    @author: Roy Nielsen

    :param device:  (Default value = " ")
    :param message_level:  (Default value = "normal")

    '''
    success = False
    return success

