"""
Mac ramdisk + unionfs implementation

@Notes:  Below are the initial notes for creating a ramdisk on the Mac

Things we need to modularize:
* create
* mount
* unmount
* detach?
* format (newfs_hfs vs. diskutil)
* randomize mountpoint
* turn off journaling, for faster access
* unionfs setup

Maybe function, or other module
* Find available memory,
  - Linux - just read /proc
  - Mac - Use top's "unused" so it doesn't try to use swap
          swap would defeat the purpose.

Maybe function, method  or other module
* rsync from spinning disk to ram disk

@author: Roy Nielsen
"""
#--- Native python libraries
import os
import re
import shutil
from subprocess import Popen, PIPE

#--- non-native python libraries in this source tree
from .commonRamdiskTemplate import RamDiskTemplate
from .lib.run_commands import RunWith
from .lib.loggers import CyLogger
from .lib.loggers import LogPriority as lp
from .lib.libHelperFunctions import getOsFamily
from .lib.libHelperExceptions import NotValidForThisOS

###############################################################################

class RamDisk(RamDiskTemplate) :
    '''Class to manage a ramdisk
    
    utilizes commands I've used to manage ramdisks
    
    Size passed in must be passed in as 1Mb chunks


    '''
    def __init__(self, size=0, mountpoint="", logger=False) :
        """
        Constructor
        """
        super(RamDisk, self).__init__(size, mountpoint, logger)

        if not getOsFamily() == "darwin":
            raise NotValidForThisOS("This ramdisk is only viable for a MacOS.")

        self.module_version = '20160225.125554.540679'

        #####
        # Initialize the RunWith helper for executing shelled out commands.
        self.runWith = RunWith(self.logger)

        #####
        # Calculating the size of ramdisk in 1Mb chunks
        self.diskSize = str(int(float(size)) * 1024 * 1024 / 512)

        self.hdiutil = "/usr/bin/hdiutil"
        self.diskutil = "/usr/sbin/diskutil"

        #####
        # Just /dev/disk<#>
        self.myRamdiskDev = ""

        #####
        # should take the form of /dev/disk2s1, where disk 2 is the assigned
        # disk and s1 is the slice, or partition number.  While just /dev/disk2
        # is good for some things, others will need the full path to the
        # device, such as formatting the disk.
        self.devPartition = ""

        #####
        # Indicate if the ramdisk is "mounted" in the Mac sense - attached,
        # but not mounted.
        self.mounted = False

        success = False

        #####
        # Passed in disk size must have a non-default value
        if not self.diskSize == 0 :
            success  = True
        #####
        # Checking to see if memory is availalbe...
        if not self.__isMemoryAvailable() :
            self.logger.log(lp.DEBUG, "Physical memory not available to create ramdisk.")
            success = False
        else:
            success = True

        if success :

            #####
            # If a mountpoint is passed in, use that, otherwise, set up for a
            # random mountpoint.
            if mountpoint:
                self.logger.log(lp.INFO, "\n\n\n\tMOUNTPOINT: " + str(mountpoint) + "\n\n\n")
                self.mntPoint = mountpoint
                #####
                # eventually have checking to make sure that directory
                # doesn't already exist, and have data in it.
            else :
                #####
                # If a mountpoint is not passed in, create a randomized
                # mount point.
                self.logger.log(lp.DEBUG, "Attempting to acquire a radomized mount " + \
                           "point. . .")
                if not self.getRandomizedMountpoint() :
                    success = False

            #####
            # The Mac has a more complicated method of managing ramdisks...
            if success:
                #####
                # Attempt to create the ramdisk
                if not self.__create():
                    success = False
                    self.logger.log(lp.WARNING, "Create appears to have failed..")
                else:
                    #####
                    # Ramdisk created, try mounting it.
                    if not self.__mount():
                        success = False
                        self.logger.log(lp.WARNING, "Mount appears to have failed..")
                    else:
                        #####
                        # Filessystem journal will only slow the ramdisk down...
                        # No need to keep it as when the journal is unmounted
                        # all memory is de-allocated making it impossible to do
                        # forensics on the volume.
                        if not self.__remove_journal():
                            success = False
                            self.logger.log(lp.WARNING, "Remove journal " + \
                                            "appears to have failed..")

        self.success = success
        if success:
            self.logger.log(lp.INFO, "Mount point: " + str(self.mntPoint))
            self.logger.log(lp.INFO, "Device: " + str(self.myRamdiskDev))
        self.logger.log(lp.INFO, "Success: " + str(self.success))
            

    ###########################################################################

    def __create(self) :
        """
        Create a ramdisk device

        @author: Roy Nielsen
        """
        retval = None
        reterr = None
        success = False
        #####
        # Create the ramdisk and attach it to a device.
        cmd = [self.hdiutil, "attach", "-nomount", "ram://" + self.diskSize]
        self.runWith.setCommand(cmd)
        self.runWith.communicate()
        retval, reterr, retcode = self.runWith.getNlogReturns()

        if reterr:
            success = False
            raise Exception("Error trying to create ramdisk(" + \
                            str(reterr).strip() + ")")
        else:
            self.myRamdiskDev = retval.strip()
            self.logger.log(lp.DEBUG, "Device: \"" + str(self.myRamdiskDev) + "\"")
            success = True
        self.logger.log(lp.DEBUG, "Success: " + str(success) + " in __create")
        return success

    ###########################################################################

    def getData(self):
        '''Getter for mount data, and if the mounting of a ramdisk was successful
        
        Does not print or log the data.
        
        @author: Roy Nielsen


        '''
        return (self.success, str(self.mntPoint), str(self.myRamdiskDev))

    ###########################################################################

    def getNlogData(self):
        '''Getter for mount data, and if the mounting of a ramdisk was successful
        
        Also logs the data.
        
        @author: Roy Nielsen


        '''
        self.logger.log(lp.INFO, "Success: " + str(self.success))
        self.logger.log(lp.INFO, "Mount point: " + str(self.mntPoint))
        self.logger.log(lp.INFO, "Device: " + str(self.myRamdiskDev))
        return (self.success, str(self.mntPoint), str(self.myRamdiskDev))

    ###########################################################################

    def getNprintData(self):
        '''Getter for mount data, and if the mounting of a ramdisk was successful'''
        print(("Success: " + str(self.success)))
        print(("Mount point: " + str(self.mntPoint)))
        print(("Device: " + str(self.myRamdiskDev)))
        return (self.success, str(self.mntPoint), str(self.myRamdiskDev))

    ###########################################################################

    def __mount(self) :
        """
        Mount the disk - for the Mac, just run self.__attach

        @author: Roy Nielsen
        """
        success = False
        success = self.__attach()
        if success:
            self.mounted = True
        return success

    ###########################################################################

    def __attach(self):
        """
        Attach the device so it can be formatted

        @author: Roy Nielsen
        """
        success = False
        #####
        # Attempt to partition the disk.
        if self.__partition():
            success = True
            #####
            # eraseVolume format name device
            if self.mntPoint:
                #####
                # "Mac" unmount (not eject)
                cmd = [self.diskutil, "unmount", self.myRamdiskDev + "s1"]
                self.runWith.setCommand(cmd)
                self.runWith.communicate()
                retval, reterr, retcode = self.runWith.getNlogReturns()

                if not reterr:
                    success = True

                if success:
                    #####
                    # remount to self.mntPoint
                    cmd = [self.diskutil, "mount", "-mountPoint",
                           self.mntPoint, self.devPartition]
                    self.runWith.setCommand(cmd)
                    self.runWith.communicate()
                    retval, reterr, retcode = self.runWith.getNlogReturns()

                    if not reterr:
                        success = True
            self.runWith.getNlogReturns()
            self.getData()
            self.logger.log(lp.DEBUG, "Success: " + str(success) + " in __mount")
        return success

    ###########################################################################

    def __remove_journal(self) :
        """
        Having a journal in ramdisk makes very little sense.  Remove the journal
        after creating the ramdisk device

        cmd = ["/usr/sbin/diskutil", "disableJournal", "force", myRamdiskDev]

        using "force" doesn't work on a mounted filesystem, without it, the
        command will work on a mounted file system

        @author: Roy Nielsen
        """
        success = False
        cmd = [self.diskutil, "disableJournal", self.myRamdiskDev + "s1"]
        self.runWith.setCommand(cmd)
        self.runWith.communicate()
        retval, reterr, retcode = self.runWith.getNlogReturns()
        if not reterr:
            success = True
        self.logger.log(lp.DEBUG, "Success: " + str(success) + " in __remove_journal")
        return success

    ###########################################################################

    def unionOver(self, target="", fstype="hfs", nosuid=None, noowners=True,
                        noatime=None, nobrowse=None):
        '''Use unionfs to mount a ramdisk on top of a location already on the
        filesystem.

        :param eter: target - where to lay the ramdisk on top of, ie the lower
                             filesystem layer.
        :param eter: nosuid - from the mount manpage: "Do not allow
                             set-user-identifier bits to take effect.
        :param eter: fstype - What supported filesystem to use.
        :param eter: noowners - From the mount manpage: "Ignore the ownership
                               field for the entire volume.  This causes all
                               objects to appear as owned by user ID 99 and
                               group ID 99.  User ID 99 is interpreted as
                               the current effective user ID, while group
                               99 is used directly and translates to "unknown".
        :param eter: noatime - from the mount manpage: "Do not update the file
                              access time when reading from a file.  This
                              option is useful on file systems where there are
                              large numbers of files and performance is more
                              critical than updating the file access time
                              (which is rarely ever important).
        :param eter: nobrowse - from the mount manpage: "This option indicates
                               that the mount point should not be visible via
                               the GUI (i.e., appear on the Desktop as a
                               separate volume).
        
        @author: Roy Nielsen
        :param target:  (Default value = "")
        :param fstype:  (Default value = "hfs")
        :param nosuid:  (Default value = None)
        :param noowners:  (Default value = True)
        :param noatime:  (Default value = None)
        :param nobrowse:  (Default value = None)

        '''
        success = False

        #####
        # If the ramdisk is mounted, unmount it (not eject...)
        if self.mounted:
            self._unmount()

        #####
        # Create the target directory if it doesn't exist yet...
        if not os.path.isdir(target):
            if os.path.isfile(target):
                shutil.move(target, target + ".bak")
            os.makedirs(target)

        #####
        # Put together the command if the base options are given
        if fstype and self.devPartition:
            #####
            # Compile the options
            options = "union"
            if nosuid:
                options = options + ",nosuid"
            if noowners:
                options = options + ",noowners"
            if noatime:
                options = options + ",noatime"
            if nobrowse:
                options = options + ",nobrowse"
            #####
            # Put the command together.
            cmd = ["/sbin/mount", "-t", str(fstype), "-o", options,
                   self.devPartition, target]

            #####
            # Run the command
            self.runWith.setCommand(cmd)
            self.runWith.communicate()
            retval, reterr, retcode = self.runWith.getNlogReturns()
            if not reterr:
                success = True

        return success

    ###########################################################################

    def unmount(self) :
        '''Unmount the disk - same functionality as __eject on the mac
        
        @author: Roy Nielsen


        '''
        success = False
        if self.eject() :
            success = True
        self.logger.log(lp.DEBUG, "Success: " + str(success) + " in unmount")
        return success

    ###########################################################################

    def detach(self) :
        '''Unmount the disk - same functionality as __eject on the mac
        
        @author: Roy Nielsen


        '''
        success = False
        if self.eject() :
            success = True
        self.logger.log(lp.DEBUG, "Success: " + str(success) + " in detach")
        return success

    ###########################################################################

    def _unmount(self) :
        '''Unmount in the Mac sense - ie, the device is still accessible.
        
        @author: Roy Nielsen


        '''
        success = False
        cmd = [self.diskutil, "unmount", self.devPartition]
        self.runWith.setCommand(cmd)
        self.runWith.communicate()
        retval, reterr, retcode = self.runWith.getNlogReturns()
        if not reterr:
            success = True
        return success

    ###########################################################################

    def _mount(self) :
        '''Mount in the Mac sense - ie, mount an already accessible device to
        a mount point.
        
        @author: Roy Nielsen


        '''
        success = False
        cmd = [self.diskutil, "mount", "-mountPoint", self.mntPoint, self.devPartition]
        self.runWith.setCommand(cmd)
        self.runWith.communicate()
        retval, reterr, retcode = self.runWith.getNlogReturns()
        if not reterr:
            success = True
        return success

    ###########################################################################

    def eject(self) :
        '''Eject the ramdisk
        
        Detach (on the mac) is a better solution than unmount and eject
        separately.. Besides unmounting the disk, it also stops any processes
        related to the mntPoint
        
        @author: Roy Nielsen


        '''
        success = False
        cmd = [self.hdiutil, "detach", self.myRamdiskDev]
        self.runWith.setCommand(cmd)
        self.runWith.communicate()
        retval, reterr, retcode = self.runWith.getNlogReturns()
        if not reterr:
            success = True
        self.runWith.getNlogReturns()

        return success

    ###########################################################################

    def _format(self) :
        '''Format the ramdisk
        
        @author: Roy Nielsen


        '''
        success = False
        #####
        # Unmount (in the mac sense - the device should still be accessible)
        # Cannot format the drive unless only the device is accessible.
        success = self._unmount()
        #####
        # Format the disk (partition)
        cmd = ["/sbin/newfs_hfs", "-v", "ramdisk", self.devPartition]
        self.runWith.setCommand(cmd)
        self.runWith.communicate()
        retval, reterr, retcode = self.runWith.getNlogReturns()
        if not reterr:
            success = True
        #####
        # Re-mount the disk
        self._mount()
        return success

    ###########################################################################

    def __partition(self) :
        """
        Partition the ramdisk (mac specific)

        @author: Roy Nielsen
        """
        success=False
        size = str(int(float(self.diskSize))/(2*1024))
        cmd = [self.diskutil, "partitionDisk", self.myRamdiskDev, str(1),
               "MBR", "HFS+", "ramdisk", str(size) + "M"]
        self.runWith.setCommand(cmd)
        self.runWith.communicate()
        retval, reterr, retcode = self.runWith.getNlogReturns()
        if not reterr:
            success = True
        if success:
            #####
            # Need to get the partition device out of the output to assign to
            # self.devPartition
            for line in retval.split("\n"):
                if re.match("^Initialized (\S+)\s+", line):
                    linematch = re.match("Initialized\s+(\S+)", line)
                    rdevPartition = linematch.group(1)
                    self.devPartition = re.sub("rdisk", "disk", rdevPartition)
                    break

        self.runWith.getNlogReturns()

        return success

    ###########################################################################

    def __isMemoryAvailable(self) :
        """
        Check to make sure there is plenty of memory of the size passed in
        before creating the ramdisk

        Best method to do this on the Mac is to get the output of "top -l 1"
        and re.search("unused\.$", line)

        @author: Roy Nielsen
        """
        #mem_free = psutil.phymem_usage()[2]

        #print "Memory free = " + str(mem_free)
        success = False
        found = False
        almost_size = 0
        size = 0
        self.free = 0
        line = ""
        freeMagnitude = None

        #####
        # Set up and run the command
        cmd = ["/usr/bin/top", "-l", "1"]

        proc = Popen(cmd, stdout=PIPE, stderr=PIPE)

        while True:
            line = proc.stdout.readline().strip()
            #####
            # Split on spaces
            line = line.split()
            #####
            # Get the last item in the list
            found = line[-1]
            almost_size = line[:-1]
            size = almost_size[-1].decode('utf-8')

            found = found.strip()
            #almost_size = almost_size.strip()
            size = size.strip()

            self.logger.log(lp.INFO, "size: " + str(size))
            self.logger.log(lp.INFO, "found: " + str(found))

            if re.search("unused", found.decode('utf-8')) or re.search("free", found.decode('utf-8')):
                #####
                # Found the data we wanted, stop the search.
                break
        proc.kill()

        #####
        # Find the numerical value and magnitute of the ramdisk
        if size:
            sizeCompile = re.compile("(\d+)(\w+)")

            split_size = sizeCompile.search(size)
            freeNumber = split_size.group(1)
            freeMagnitude = split_size.group(2)

            if re.match("^\d+$", freeNumber.strip()):
                if re.match("^\w$", freeMagnitude.strip()):
                    if freeMagnitude:
                        #####
                        # Calculate the size of the free memory in Megabytes
                        if re.search("G", freeMagnitude.strip()):
                            self.free = 1024 * int(freeNumber)
                            self.free = str(self.free)
                        elif re.search("M", freeMagnitude.strip()):
                            self.free = freeNumber
        self.logger.log(lp.DEBUG, "free: " + str(self.free))
        self.logger.log(lp.DEBUG, "Size requested: " + str(self.diskSize))
        if int(self.free) > int(float(self.diskSize))/(2*1024):
            success = True
        print((str(self.free)))
        print((str(success)))
        return success

    ###########################################################################

    def getDevice(self):
        '''Getter for the device name the ramdisk is using
        
        @author: Roy Nielsen


        '''
        return self.myRamdiskDev

    ###########################################################################

    def setDevice(self, device=None):
        '''Setter for the device so it can be ejected.
        
        @author: Roy Nielsen

        :param device:  (Default value = None)

        '''
        if device:
            self.myRamdiskDev = device
        else:
            raise Exception("Problem trying to set the device..")

    ###########################################################################

    def getVersion(self):
        '''Getter for the version of the ramdisk
        
        @author: Roy Nielsen


        '''
        return self.module_version


###############################################################################

def unmount(device=" ", logger=False):
    '''On the Mac, call detach.
    
    @author: Roy Nielsen

    :param device:  (Default value = " ")
    :param logger:  (Default value = False)

    '''
    detach(device, logger)

###############################################################################

def detach(device=" ", logger=False):
    '''Eject the ramdisk
    Detach (on the mac) is a better solution than unmount and eject
    separately.. Besides unmounting the disk, it also stops any processes
    related to the mntPoint
    
    @author: Roy Nielsen

    :param device:  (Default value = " ")
    :param logger:  (Default value = False)

    '''
    success = False
    if not logger:
        logger = CyLogger()
    else:
        logger = logger
    myRunWith = RunWith(logger)
    if not re.match("^\s*$", device):
        cmd = ["/usr/bin/hdiutil", "detach", device]
        myRunWith.setCommand(cmd)
        myRunWith.communicate()
        retval, reterr, retcode = myRunWith.getNlogReturns()
        if not reterr:
            success = True

        myRunWith.getNlogReturns()
    else:
        raise Exception("Cannot eject a device with an empty name..")
    return success
