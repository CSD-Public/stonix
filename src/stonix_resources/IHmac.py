"""
###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
# produced under U.S. Government contract DE-AC52-06NA25396 for Los Alamos    #
# National Laboratory (LANL), which is operated by Los Alamos National        #
# Security, LLC for the U.S. Department of Energy. The U.S. Government has    #
# rights to use, reproduce, and distribute this software.  NEITHER THE        #
# GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY, LLC MAKES ANY WARRANTY,        #
# EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.  #
# If software is modified to produce derivative works, such modified software #
# should be clearly marked, so as not to confuse it with the version          #
# available from LANL.                                                        #
#                                                                             #
# Additionally, this program is free software; you can redistribute it and/or #
# modify it under the terms of the GNU General Public License as published by #
# the Free Software Foundation; either version 2 of the License, or (at your  #
# option) any later version. Accordingly, this program is distributed in the  #
# hope that it will be useful, but WITHOUT ANY WARRANTY; without even the     #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    #
# See the GNU General Public License for more details.                        #
#                                                                             #
###############################################################################

Created November 2, 2011
The installing class holds Mac specific methods for installing a package,
intended for use to selfupdate a script.

@operatingsystem: Mac OS X
@author: Roy Nielsen
@change: 2015/11/23 eball Replaced Popen with CommandHelper, removed sys.exit
"""
import re
import os
import grp
import pwd
import shutil
from CommandHelper import CommandHelper
from InstallingHelper import InstallingHelper
from logdispatcher import LogPriority
from stonixutilityfunctions import isServerVersionHigher


class IHmac(InstallingHelper) :
    """
    This class holds Mac specific methods for installing software.

    The end goal is to provide the selfupdate mechanism so a program
    can update itself.

    @author: Roy Nielsen

    """
    def __init__(self, environ, url, logger):
        """
        """
        self.url = url
        self.logger = logger
        self.ch = CommandHelper(self.logger)
        if re.match("^\s*$", self.url):
            self.logger.log(LogPriority.WARNING, "Empty URL passed to IHmac")

        InstallingHelper.__init__(self, environ, url, self.logger)

    def install_package_from_server(self):
        """
        This function references generic methods from the InstallingHelper
        class to download an archived .pkg or .mpkg file, check md5sum of
        the file against the md5 on the server, unarchive the file and
        install the package. It will remove the temporary directory that
        the file was downloaded and unarchived to when the install is
        complete.

        local vars:
        tmp_dir = the temporary directory that is created for the downloaded
                  file, and to unarchive it into.
        self.sig_match = A variable that tells if the signature of the
                         downloaded file and the server string match.  Set
                         in the download_and_prepare method of the parent
                         class
        pkg_extension = for verifying that the package extension is either
                        ".pkg" or ".mpkg"
        self.package_name = the name of the package to be downloaded, without
                            the archive extension.  Set in the InstallingHelper
                            class.

        @author: Roy Nielsen

        """
        # Download and unarchive the package to a temporary directory, with
        # md5 checking.
        success = False
        tmp_dir = self.download_and_prepare()

        if not self.sig_match:
            self.logger.log(LogPriority.ERROR,
                            "Signatures didn't match.")
        else:
            # Check if it's a pkg or mpkg
            pkg_extension = self.find_package_extension(tmp_dir)

            if re.match("^\.pkg$", pkg_extension) or \
               re.match("^\.mpkg$", pkg_extension):

                # set up the install package command string

                cmd = ["/usr/bin/sudo", "/usr/sbin/installer", "-verboseR",
                       "-pkg", tmp_dir + "/" + self.package_name +
                       pkg_extension, "-target", "/"]
                self.ch.executeCommand(cmd)
                self.logger.log(LogPriority.DEBUG,
                                self.ch.getOutputString())
                if self.ch.getReturnCode() == 0:
                    success = True

                # remove the temporary directory where the archive was
                # downloaded and unarchived.
                try:
                    shutil.rmtree(tmp_dir)
                except Exception, err:
                    self.logger.log(LogPriority.ERROR,
                                    "Exception: " + str(err))
                    success = False
            else:
                self.logger.log(LogPriority.ERROR, "Valid package extension " +
                                "not found, cannot install: " + tmp_dir + "/" +
                                self.package_name + pkg_extension)

        return success

    def copy_install_from_server(self, src="", dest=".", isdir=True, mode=0755,
                                 owner="root", group="admin"):
        """
        Copies a directory tree, or contents of a directory to "dest"
        destination.

        @param: src - the source directory to copy from (not the absolute
                      path, the path that resides inside the archive that
                      is to be unloaded)
        @param: dest - the destination to copy to
        @param: isdir - do we recursively copy the source directory, or the 
                        files inside the source directory (not including
                        recursive directories)
        @param: mode - the mode of the destination directory (it is assumed
                       that the files/tree inside that directory have the
                       correct permissions) - only valid if isdir=True
        @param: owner - the owner of the destination directory (it is assumed
                       that the files/tree inside that directory have the
                       correct permissions) - only valid if isdir=True
        @param: group - the group of the destination directory (it is assumed
                       that the files/tree inside that directory have the
                       correct permissions) - only valid if isdir=True

        local vars:
        tmp_dir = the temporary directory that is created for the downloaded
                  file, and to unarchive it into.
        self.sig_match = A variable that tells if the signature of the
                         downloaded file and the server string match.  Set
                         in the download_and_prepare method of the parent
                         class

        @author: Roy Nielsen

        """
        # Download and unarchive the files/directory to a temporary directory, 
        # with md5 checking.
        tmp_dir = self.download_and_prepare()

        if re.match("^\s*$", tmp_dir) :
            tmp_dir = "."
        
        src_path = tmp_dir + "/" + src

        self.logger.log(LogPriority.DEBUG,  
                        "New src_path: " + src_path)

        # if integrity ok, 
        if not self.sig_match :
            self.logger.log(LogPriority.ERROR, 
                            "Signatures didn't match, not copying...")
            raise
        else:
            if isdir:
                try:
                    shutil.copytree(src_path, dest)
                except Exception, err:
                    self.logger.log(LogPriority.ERROR, 
                                    "Unable to recursively copy dir: " + src_path + " error: " + str(err))
                    raise
                else :
                    # try to chmod the directory (not recursively)
                    try :
                        os.chmod(dest, mode)
                    except OSError, err :
                        self.logger.log(LogPriority.ERROR, 
                                        "Unable to change mode: " + str(err))
                        raise
                    
                    # UID & GID needed to chown the directory
                    uid = 0
                    gid = 80
                    try :
                        uid = pwd.getpwnam(owner)[2]
                    except KeyError, err :
                        self.logger.log(LogPriority.DEBUG, 
                                        "Error: " + str(err))
                        raise
                    try :
                        gid = grp.getgrnam(group)[2]
                    except KeyError, err :
                        self.logger.log(LogPriority.DEBUG, 
                                        "Error: " + str(err))
                        raise
                    # Can only chown if uid & gid are int's
                    if ((type(uid) == type(int())) and (type(gid) == type(int()))) :
                        try :
                            os.chown(dest, uid, gid)
                        except OSError, err :
                            self.logger.log(LogPriority.DEBUG, 
                                            "Error: " + str(err))
            else :
                try :
                    dir_list = os.listdir(src_path)
                except OSError, err :
                    self.logger.log(LogPriority.ERROR, 
                                    "Error listing files from: " + src_path + " error: " + str(err))
                    raise
                else :
                    for myfile in dir_list :
                        try :
                            shutil.copy2(myfile, dest)
                        except Exception, err :
                            self.logger.log(LogPriority.DEBUG, 
                                            "Error copying file: " + myfile + " error: " + str(err))
                            raise


    def find_package_extension(self, pkg_dir="."):
        """
        Find a valid install package extension for the Mac
        
        @param: pkg_dir - directory the package should be in
        
        @returns: pkg_extension - return if it is a pkg, mpkg or 
                                  neither (in which case an empty string)
                                  
        @author: Roy Nielsen

        """
        if os.path.exists(pkg_dir + "/" + self.package_name + ".pkg"):
            pkg_extension = ".pkg"
        elif os.path.exists(pkg_dir + "/" + self.package_name + ".mpkg"):
            pkg_extension = ".mpkg"
        else:
            pkg_extension = ""
        
        return pkg_extension


    def selfupdate(self, version) :
        """
        The crowning jewel of the installing class -- a method to check
        the passed in (local program) version string and compare it to a 
        version string on the server & if the passed in version is less
        than the server version, it will call either the install_package_from_server
        or copy_install_from_server method to install the updated version.
        
        @params: version - a string that contains: "X.Y.Z" where X is the 
                           major version and Y is the mid version and Z is 
                           the minor version of the file.  If using 
                           optionparser, one can use the parser.get_version() 
                           method to get that string (defined in the 
                           OptionParser class instantiation).
        
        local variables:
        update - Whether or not to update the software
        server_version - the version found on the server <package>.version.txt
        vers_num - a string containing the version
        prog - a string containing the program name
        vers_major - the major version of the software (X above)
        vers_minor - the minor version of the software (Y above)
        server_vers_num - string containing the version found on the server
        svr_vers_major - the major version of the software (X above)
        svr_vers_minor - the minor version of the software (Y above)
        
        @author: Roy Nielsen

        """
        update = False

        server_version = self.get_string_from_url(self.base_url + "/" + self.package_name + ".version.txt")

        update = isServerVersionHigher(version, server_version)
        
        if update :
            self.logger.log(LogPriority.DEBUG, 
                             "Current version is less than the version on the server, attempting to update")
            # set url, or use set url
            self.install_package_from_server()

