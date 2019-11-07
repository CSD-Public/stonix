"""
Factory for creating ramdisks.

@note: may be of more use in the tests/testFramework, or example directories

@author: Roy Nielsen
"""
#--- Native python libraries
import re
from tempfile import mkdtemp
from subprocess import Popen, PIPE, STDOUT

#--- non-native python libraries in this source tree
from .lib.loggers import Logger
from .lib.loggers import LogPriority as lp
from .lib.run_commands import RunWith
from .lib.libHelperFunctions import getOsFamily

def BadRamdiskTypeException(Exception):
    '''Custom Exception

    :param Exception: 

    '''
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

def OSNotValidForRamdiskHelper(Exception):
    '''Custom Exception

    :param Exception: 

    '''
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class RamDiskFactory(object):
    '''Retrieve and OS specific ramdisk, and provide an interface to manage it.
    
    Keeps a reference to a list of ramdisks.  When calling getRamdisk(new), if
    "new" is true, the method will add the ramdisk to the list of ramdisks.

    :param eter: message_level: Level of logging a person wishes to log at.
                              see logMessage in the log_message module.
    
    @method: getRamdisk: Will return either a new ramdisk, or make the
                         self.activeRamdisk the ramdisk with the name of the
                         passed in mountpoint (if found).  Otherwise, the
                         self.activeRamdisk is initialized to None.
    
    @method getModuleVersion: gets the version of this module.
    
    @method unmountActiveRamdisk: Unmounts the active ramdisk.
    
    @method unmountRamdisk: Unmounts the mountpoint that is passed in.
    
    @author: Roy Nielsen

    '''
    def __init__(self, logger=None):
        """
        Identify OS and instantiate an instance of a ramdisk
        """
        self.module_version = '20160224.203258.288119'

        self.size = 0
        self.mountpoint = None
        self.ramdiskType = None
        if not logger:
            self.logger = Logger()
        else:
            self.logger = logger
        self.activeRamdisk = None
        self.ramdisks = []
        self.validRamdiskTypes = ["loop", "tmpfs"]
        self.validOSFamilies = ["macos", "linux"]

        self.myosfamily = getOsFamily()

        if not self.myosfamily in self.validOSFamilies:
            raise OSNotValidForRamdiskHelper("Needs to be MacOS or Linux...")

    ############################################################################
    
    def getRamdisk(self, size=0, mountpoint="", ramdiskType=""):
        '''Getter for the ramdisk instance.
        
        @var: ramdisks - a list of ramdisks this factory has created

        :param size:  (Default value = 0)
        :param mountpoint:  (Default value = "")
        :param ramdiskType:  (Default value = "")

        '''
        if not ramdiskType in self.validRamdiskTypes:
            raise BadRamdiskTypeException("Not a valid ramdisk type")
    
        if size and mountpoint and ramdiskType:
            #####
            # Determine OS and ramdisk type, create ramdisk accordingly
            if self.myosfamily == "darwin":
                #####
                # Found MacOS
                from .macRamdisk import RamDisk
                self.activeRamdisk = RamDisk(size, mountpoint, self.logger)

            elif self.myosfamily == "linux" and ramdiskType == "loop":
                #####
                # Found Linux with a loopback ramdisk request
                from .linuxLoopRamdisk import RamDisk
                self.activeRamdisk = RamDisk(mountpoint, self.logger)

            elif self.myosfamily == "linux" and ramdiskType == "tmpfs":
                #####
                # Found Linux with a tmpfs ramdisk request.
                from .linuxTmpfsRamdisk import RamDisk
                self.activeRamdisk = RamDisk(size, mountpoint, self.logger)

            else:
                #####
                # Bad method input parameters...
                self.activeRamdisk = None

            #####
            # Append the newly assigned self.activeRamdisk to the self.ramdisks
            # list
            self.ramdisks.append(self.activeRamdisk)

        elif not size and mountpoint:
            #####
            # Look for the ramdisk with "mountpoint" and return that instance.
            for ramdisk in self.ramdisks:
                if re.match("^%s$"%mountpoint, ramdisk.getMountPoint()):
                    self.activeRamdisk = ramdisk
                    break

        return self.activeRamdisk

    ############################################################################

    def getModuleVersion(self):
        '''Getter for the version of this  module.
        
        @author: Roy Nielsen


        '''
        return self.module_version

    ############################################################################

    def unmountActiveRamdisk(self):
        '''Eject the currently active ramdisk in the Factory.


        :returns: success - successful = True, unsuccessful = False
        
        @author: Roy Nielsen

        '''
        success = False

        success = self.activeRamdisk.unmount(self.logger)

        return success

    ############################################################################

    def unmountRamdisk(self, mountpoint=""):
        '''Eject the ramdisk in the list with the passed in mountpoint.

        :param mountpoint: the mountpoint to eject. (Default value = "")
        :returns: True if successful, False if not successful
        
        @author: Roy Nielsen

        '''
        success = False
        if mountpoint:
            for ramdisk in self.ramdisks:
                if re.match("^%s$"%mountpoint, ramdisk.getMountPoint()):
                    self.activeRamdisk = ramdisk
                    success = self.unmountActiveRamdisk()
                    break

        return success

    ############################################################################

    ############################################################################

    ############################################################################

