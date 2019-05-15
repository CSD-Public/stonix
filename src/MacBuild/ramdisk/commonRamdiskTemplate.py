"""
Template for the ramdisk classes

@author: Roy Nielsen
"""
#--- Native python libraries
from tempfile import mkdtemp

#--- non-native python libraries in this source tree
from lib.loggers import LogPriority as lp
from lib.loggers import CyLogger

###############################################################################

class RamDiskTemplate(object):
    ''' '''
    def __init__(self, size=0, mountpoint=False, logger=False):
        """
        """
        #####
        # Version/timestamp is
        # <YYYY><MM><DD>.<HH><MM><SS>.<microseconds>
        # in UTC time
        self.module_version = '20160224.032043.009191'
        if not logger:
            self.logger = CyLogger()
            self.logger.log(lp.INFO, "Logger: " + str(self.logger))
        else:
            self.logger = logger
            self.logger.log(lp.INFO, "Logger: " + str(self.logger))
        self.diskSize = size
        self.success = False
        self.myRamdiskDev = None
        if not mountpoint:
            self.getRandomizedMountpoint()
        else:
            self.mntPoint = mountpoint

        self.logger.log(lp.DEBUG, "disk size: " + str(self.diskSize))
        self.logger.log(lp.DEBUG, "volume name: " + str(self.mntPoint))

    ###########################################################################

    def getData(self):
        '''Getter for mount data, and if the mounting of a ramdisk was successful'''
        return (self.success, str(self.mntPoint), str(self.myRamdiskDev))

    ###########################################################################

    def printData(self):
        '''Getter for mount data, and if the mounting of a ramdisk was successful.
        Also prints to the data to the console


        '''
        print "Success: " + str(self.success)
        print "Mount point: " + str(self.mntPoint)
        print "Device: " + str(self.myRamdiskDev)
        return (self.success, str(self.mntPoint), str(self.myRamdiskDev))

    ###########################################################################

    def logData(self):
        '''Getter for mount data, and if the mounting of a ramdisk was successful
        Also logs the data.


        '''
        self.logger.log(lp.INFO, "Success: " + str(self.success))
        self.logger.log(lp.INFO, "Mount point: " + str(self.mntPoint))
        self.logger.log(lp.INFO, "Device: " + str(self.myRamdiskDev))
        return (self.success, str(self.mntPoint), str(self.myRamdiskDev))

    ###########################################################################

    def getRandomizedMountpoint(self) :
        '''Create a randomized (secure) mount point - per python's implementation
        of mkdtemp - a way to make an unguessable directory on the system
        
        @author: Roy Nielsen


        '''
        success = False
        try :
            self.mntPoint = mkdtemp()
        except Exception, err :
            self.logger.log(lp.WARNING, "Exception trying to create temporary directory")
            raise err
        else :
            success = True
            self.logger.log(lp.WARNING, "Success: " + str(success) + " in get_randomizedMountpoint: " + str(self.mntPoint))
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

    def getDevice(self):
        '''Getter for the device name the ramdisk is using
        
        Must be over-ridden to provide OS/Method specific functionality
        
        @author: Roy Nielsen


        '''
        return self.myRamdiskDev

    ###########################################################################

    def getMountPoint(self):
        '''Getter for the mount point name the ramdisk is using
        
        Must be over-ridden to provide OS/Method specific functionality
        
        @author: Roy Nielsen


        '''
        return self.mntPoint

    ###########################################################################

    def setDevice(self, device=None):
        '''Setter for the device so it can be ejected.
        
        Must be over-ridden to provide OS/Method specific functionality
        
        @author: Roy Nielsen

        :param device:  (Default value = None)

        '''
        self.myRamdiskDev = device

    ###########################################################################

    def getVersion(self):
        '''Getter for the version of the ramdisk
        
        Must be over-ridden to provide OS/Method specific functionality
        
        @author: Roy Nielsen


        '''
        return self.module_version

    ###########################################################################

    class NotValidForThisOS(Exception):
        '''Meant for being thrown when an action/class being run/instanciated is not
        applicable for the running operating system.
        
        @author: Roy Nielsen


        '''
        def __init__(self, *args, **kwargs):
            Exception.__init__(self, *args, **kwargs)

    ###########################################################################

    class BadRamdiskArguments(Exception):
        '''Meant for being thrown when an invalid values are passed in as arguments
        to class instanciation or class methods.
        
        @author: Roy Nielsen


        '''
        def __init__(self, *args, **kwargs):
            Exception.__init__(self, *args, **kwargs)

###############################################################################


def detach(device=None, message_level="normal"):
    '''Eject the ramdisk
    
    Must be over-ridden to provide OS/Method specific functionality
    
    @author: Roy Nielsen

    :param device:  (Default value = None)
    :param message_level:  (Default value = "normal")

    '''
    success = False
    return success

