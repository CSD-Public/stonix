'''
###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
Created on Nov 24, 2015

@author: rsn, dwalker
'''
import os
import re
import hashlib
import urllib2
import shutil
import plistlib
import tempfile
import traceback
import ctypes as C

from localize import MACREPOROOT
from logdispatcher import LogPriority
from CommandHelper import CommandHelper
from Connectivity import Connectivity
from ssl import SSLError


class NoRepoException(Exception):
    """
    Custom Exception
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class InvalidURL(Exception):
    """
    Custom Exception
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class NotApplicableToThisOS(Exception):
    """
    Custom Exception
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class MacPkgr(object):

    def __init__(self, environ, logger):
        '''
        Mac package manager based on other stonix package managers.

        Uses the stonix IHmac and InstallingHelper Libraries.  They can
        install .zip, .tar, .tar.gz, .pkg and .mpkg files via an http or
        https URL

        @parameter: Instanciated stonix Environment object
        @parameter: Instanciated stonix LogDispatcher object
        @parameter: Takes an https link as a repository.

        @method: installpackage(package) - install a package
        @method: removepackage(package) - remove a package
        @method: checkInstall(package) - is the package installed?
        @method: checkAvailable(package) - is it available on the repository?
        @method: getInstall(package) -
        @method: getRemove(package) -

        # Methods specific to Mac.
        @method: findDomain(package) - see docstring

        @note: Uses the stonix IHmac and InstallingHelper Libraries.  They can
               install .zip, .tar, .tar.gz, .pkg and .mpkg files via an http or
               https URL

        @note: WARNING: To use checkInstall or removepackage, this package
               manager converts all of the plists in the /var/db/receipts
               directory to text, then converts they all back to binary when it
               is done performing a reverse lookup to find if a specific
               package is installed. I would love to use Greg Neagle's
               FoundationPlist.py, but licenses are not compatible.
        @change: Breen Malmberg - 2/28/2017 - Made the missing macreporoot message more
                clear and helpful; added logic to also check if it is 'None'
        '''

        self.environ = environ

        self.osfamily = self.environ.getosfamily()
        if not re.match("^darwin$", self.osfamily.strip()):
            return

        #####
        # setting up to call ctypes to do a filesystem sync
        if self.environ.getosfamily() == "darwin":
            self.libc = C.CDLL("/usr/lib/libc.dylib")
        else:
            self.libc = None

        self.logger = logger
        self.detailedresults = ""
        self.pkgUrl = ""
        self.reporoot = ""
        if not MACREPOROOT:
            raise NoRepoException("Please ensure that the constant, MACREPOROOT, is properly defined in localize.py and is not set to 'None'")
        elif MACREPOROOT == None:
            raise NoRepoException("Please ensure that the constant, MACREPOROOT, is properly defined in localize.py and is not set to 'None'")
        else:
            self.reporoot = MACREPOROOT
        self.dotmd5 = True
        self.logger.log(LogPriority.DEBUG,
                        "Done initializing MacPkgr class...")
        self.ch = CommandHelper(self.logger)
        self.connection = Connectivity(self.logger)

    ###########################################################################

    def installPackage(self, package):
        '''
        Install a package. Return a bool indicating success or failure.

        @param string package : Path to the package past the REPOROOT

        IE. package would be: QuickAdd.Stonix.pkg rather than:
            https://jss.lanl.gov/CasperShare/QuickAdd.Stonix.pkg
            \_____________________________/ \________________/
                            |                        |
                        REPOROOT                  package

        Where REPOROOT is initialized in the class __init__, and package is
        passed in to this method

        This assumes that all packages installed via an instance of this class
        will be retrieved from the same REPOROOT.  If you need to use another
        REPOROOT, please use another instance of this class.

        @return success
        @rtype: bool
        @author: dwalker, Roy Nielsen
        @change: Breen Malmberg - 2/28/2017 - added logic to handle case where
                self.reporoot is undefined; added logging; minor doc string edit
        '''

        success = False

        if not self.reporoot:
            self.logger.log(LogPriority.WARNING, "No MacRepoRoot defined! Unable to determine package URL!")
            return success

        try:

            self.package = package
            #####
            # Create a class variable that houses the whole URL
            if self.reporoot.endswith("/"):
                self.pkgUrl = self.reporoot + self.package
            else:
                self.pkgUrl = self.reporoot + "/" + self.package
            message = "self.pkgUrl: " + str(self.pkgUrl)
            self.logger.log(LogPriority.DEBUG, message)

            if re.search("://", self.pkgUrl):
                if self.connection.isPageAvailable(self.pkgUrl):
                    #####
                    # Download into a temporary directory
                    success = self.downloadPackage()
                    if success:
                        #####
                        # Apple operating systems have a lazy attitude towards
                        # writing to disk - the package doesn't get fully
                        # written to disk until the following method is called.
                        # Otherwise when the downloaded package is further
                        # manipulated, (uncompressed or installed) the
                        # downloaded file is not there.  There may be other
                        # ways to get python to do the filesystem sync...
                        try:
                            self.libc.sync()
                        except:
                            pass
                        #####
                        # Make sure the md5 of the file matches that of the
                        # server
                        if self.checkMd5():
                            #####
                            # unarchive if necessary
                            compressed = [".tar", ".tar.gz", ".tgz",
                                          ".tar.bz", ".tbz", ".zip"]
                            for extension in compressed:
                                if self.tmpLocalPkg.endswith(extension):
                                    self.unArchive()
                                try:
                                    self.libc.sync()
                                except:
                                    pass
                            #####
                            # The unArchive renames self.tmpLocalPkg to the
                            # actual software to install that is inside the
                            # package.
                            #
                            # install - if extension is .app, copy to the
                            #           /Applications folder, otherwise if it
                            #           is a .pkg or .mpkg use the installer
                            #           command
                            if self.tmpLocalPkg.endswith(".app"):
                                success = self.copyInstall()

                            elif self.tmpLocalPkg.endswith(".pkg") or \
                                 self.tmpLocalPkg.endswith(".mpkg"):
                                success = self.installPkg()
            else:
                #####
                # Otherwise the repository is on a mounted filesystem
                self.logger.log(LogPriority.DEBUG, "Looking for a local " +
                                                   "filesystem repo...")
                self.tmpLocalPkg = self.reporoot + self.package

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
            raise err
        if success:
            try:
                self.libc.sync()
            except:
                pass
        return success

    ###########################################################################

    def getPkgUrl(self):
        """
        Setter for the class varialbe pkgUrl

        @author: Roy Nielsen
        """
        return self.pkgUrl

    ###########################################################################

    def setPkgUrl(self, pkgUrl=""):
        """
        Setter for the class varialbe pkgUrl

        @author: Roy Nielsen
        """
        self.pkgUrl = pkgUrl

    ###########################################################################

    def removePackage(self, package="", install_root="/"):
        '''
        Remove a package domain. Return a bool indicating success or failure.
        Not yet implemented...

        Will use pkgutil to determine domain, then delete files in receipt..

        @param string package : Name of the package to be removed, must be
            recognizable to the underlying package manager.

        @return bool :
        @author: rsn
        '''
        success = False
        self.package = package
        try:
            self.logger.log(LogPriority.DEBUG, "Package: " + str(package))
            domain = None
            domain = self.findDomain(package)
            self.logger.log(LogPriority.DEBUG,
                            "removePackage - Domain: " + domain)
            if domain:
                cmd_one = ["/usr/sbin/pkgutil",
                           "--only-files",
                           "--files",
                           domain]
                cmd_two = ["/usr/sbin/pkgutil",
                           "--only-dirs",
                           "--files",
                           domain]

                #####
                # Use the pkgutil command to get a list of files in the package
                # receipt
                count = 0
                self.ch.executeCommand(cmd_one)
                files2remove = self.ch.getOutputString().split("\n")
                print "Files to remove: " + str(files2remove)
                self.logger.log(LogPriority.DEBUG, files2remove)
                if str(self.ch.getReturnCode()) == str(0):
                    for file in files2remove:
                        if file:
                            try:
                                #####
                                # Make sure "/" is prepended to the file as
                                # pkgutil does not report the first "/" in the
                                # file path
                                os.remove(install_root + file)
                                count = count + 1
                            except OSError, err:
                                self.logger.log(LogPriority.DEBUG,
                                                "Error trying to remove: " +
                                                str(file))
                                self.logger.log(LogPriority.DEBUG,
                                                "With Exception: " +
                                                str(err))
                        else:
                            #####
                            # Potentially empty filename in the list, need to
                            # bump the count to match.
                            count = count + 1

                    #####
                    # Directory list will include directories such as /usr
                    # and /usr/local... Sucess is obtained only if all of
                    # the files (not directories) are deleted.
                    if count == len(files2remove):
                        success = True
                    else:
                        self.logger.log(LogPriority.WARNING,
                                        "Count: " + str(count))
                        self.logger.log(LogPriority.WARNING,
                                        "Files removed: " +
                                        str(len(files2remove)))

                    #####
                    # Use the pkgutil command to get a list of directories
                    # in the package receipt
                    self.ch.executeCommand(cmd_two)
                    dirs2remove = self.ch.getOutputString().split("\n")
                    #####
                    # Reverse list as list is generated with parents first
                    # rather than children first.
                    dirs2remove.reverse()
                    self.logger.log(LogPriority.DEBUG, dirs2remove)
                    if str(self.ch.getReturnCode()) == str(0):
                        for dir in dirs2remove:
                            if dir:
                                try:
                                    #####
                                    # Make sure "/" is prepended to the directory
                                    # tree as pkgutil does not report the first "/"
                                    # in the file path
                                    os.rmdir(install_root + dir)
                                    #####
                                    # We don't care if any of the child directories
                                    # still have files, as directories such as
                                    # /usr/bin, /usr/local/bin are reported by
                                    # pkgutil in the directory listing, which is
                                    # why we use os.rmdir rather than shutil.rmtree
                                    # and we don't report on the success or failure
                                    # of removing directories.
                                except OSError, err:
                                    self.logger.log(LogPriority.DEBUG,
                                                    "Error trying to remove: "
                                                    + str(dir))
                                    self.logger.log(LogPriority.DEBUG,
                                                    "With Exception: " +
                                                    str(err))
                                    pass

                        #####
                        # Make the system package database "forget" the package
                        # was installed.
                        cmd_three = ["/usr/sbin/pkgutil", "--forget", domain]
                        self.ch.executeCommand(cmd_three)
                        if re.match("^%s$" %
                                    str(self.ch.getReturnCode()).strip(),
                                    str(0)):
                            success = True
                else:
                    self.logger.log(LogPriority.DEBUG, "Page: \"" +
                                    str(package) + "\" Not found")

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        if success:
            try:
                self.libc.sync()
            except:
                pass
        print "Remove Package success: " + str(success)
        return success

    ###########################################################################

    def checkInstall(self, package):
        '''
        Check the installation status of a package. Return a bool; True if
        the package is installed.

        Use pkgutil to determine if package has been installed or not.

        @param string package : Name of the package whose installation status
            is to be checked, must be recognizable to the underlying package
            manager.

        @return bool :
        @author: rsn
        '''
        success = False
        self.package = package
        try:
            #####
            # Perform a reverse lookup to get the domain...
            domain = self.findDomain(package)
            self.logger.log(LogPriority.DEBUG, "Domain: " + str(domain))
            if domain:
                success = True
                self.logger.log(LogPriority.DEBUG,
                                "Domain: " + str(domain) + " found")

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)

        return success

    ###########################################################################

    def checkAvailable(self, package):
        """
        Check if a package is available at the "reporoot"

        @return: success
        @rtype: bool
        @author: Roy Nielsen
        @change: Breen Malmberg - 2/28/2017 - added logic to handle case where
                self.reporoot is undefined; added logging; minor doc string edit
        """

        success = False
        self.package = package

        if not self.reporoot:
            self.logger.log(LogPriority.WARNING, "No MacRepoRoot defined! Unable to determine package URL!")
            return success

        try:

            self.logger.log(LogPriority.DEBUG, "Checking if: " +
                            str(package)) + " is available on the server..."
            self.logger.log(LogPriority.DEBUG, "From repo: " +
                            str(self.reporoot))

            self.pkgUrl = self.reporoot + "/" + package

            # If there network, install, else no network, log
            if self.connection.isPageAvailable(self.pkgUrl):
                self.logger.log(LogPriority.DEBUG, "There is a connection to" +
                                                   " the server...")
                #####
                # Download the file
                self.downloadPackage()

                #####
                # Perform a md5 checksum - if there is a match, return
                # success = True
                if self.checkMd5():
                    success = True
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)

        return success

    ###########################################################################

    def getInstall(self, package):
        return self.installPackage(package)

    ###########################################################################

    def getRemove(self, package):
        return self.removePackage(package)

    ###########################################################################

    def findDomain(self, pkg=""):
        """
        Go through the package receipts database to find a package, and return
        a domain.  Apple stores package information in "domain" format, rather
        than a package name format. Accessing the package name means we need to
        look through all the ".plist" files in /var/db/receipts to find the
        package name, then we can return the domain so that can be used for
        package management.

        Install package receipts can be found in /var/db/receipts.

        A domain is the filename in the receipts database without the ".plist"
        or ".bom".

        An example is org.macports.MacPorts

        @parameters: pkg - the name of the install package that we need the
                     domain for.
        @returns: domains - the first domain in a possible list of domains.

        @author: Roy Nielsen
        """
        try:
            self.logger.log(LogPriority.DEBUG, "Looking for: " + str(pkg))
            path = "/var/db/receipts/"
            files = []
            domain = ""
            for name in os.listdir(path):
                if os.path.isfile(os.path.join(path, name)) and \
                   os.path.isfile(os.path.join(path, name)) and \
                   name.endswith(".plist"):
                    files.append(name)

            unwrap = "/usr/bin/plutil -convert xml1 /var/db/receipts/*.plist"
            wrap = "/usr/bin/plutil -convert binary1 /var/db/receipts/*.plist"

            self.ch.executeCommand(unwrap)

            if not re.match("^%s$" % str(self.ch.getReturnCode()), str(0)):
                #####
                # Unwrap command didn't work... return None
                domain = None
            else:
                try:
                    self.libc.sync()
                except:
                    pass
                #####
                # Unwrap command worked, process the receipt plists
                for afile in files:
                    if re.match("^\..+.plist", afile):
                        continue
                    self.logger.log(LogPriority.DEBUG, "afile: " + str(afile))
                    #####
                    # Get the path without the plist file extension.
                    afile_path = os.path.join(path, afile)
                    #####
                    # Make sure we have a valid file on the filesystem
                    if os.path.isfile(afile_path):
                        try:
                            plist = plistlib.readPlist(afile_path)
                        except Exception, err:
                            self.logger.log(LogPriority.DEBUG, "Exception " +
                                                               "trying to use" +
                                                               " plistlib: " +
                                                               str(err))
                            raise err
                        else:
                            if re.match("^%s$" % plist['PackageFileName'],
                                        pkg):
                                #####
                                # Find the first instance of the
                                # PackageFileName without the .plist.
                                domain = ".".join(afile.split(".")[:-1])
                                break
                #####
                # Make the plists binary again...
                self.ch.executeCommand(wrap)

                #####
                # Log the domain...
                self.logger.log(LogPriority.DEBUG, "Domain: " + str(domain))
            print "findDomain: " + str(domain)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)

        return domain

    ###########################################################################

    def downloadPackage(self):
        """
        Download the package in the self.package URL to a temporary directory
        created by tempfile.mkdtemp.  Does not checked for a cached file.

        @Note: path to downloaded file will be in the self.tmpLocalPkg variable
               for use by other class methods.

        @author: Roy Nielsen
        """
        success = False
        urlfile = None
        try:
            self.tmpDir = ""
            if self.pkgUrl:
                #####
                # Make a temporary directory to download the package
                try:
                    self.tmpDir = tempfile.mkdtemp()
                    self.logger.log(LogPriority.DEBUG, "tmpDir: " +
                                                       str(self.tmpDir))
                except Exception, err:
                    message = "Problem creating temporary directory: " + \
                              str(err)
                    self.logger.log(LogPriority.WARNING, message)
                    raise err
                else:
                    #####
                    # First try to open the URL
                    if self.connection.isPageAvailable(self.pkgUrl):
                        urlfile = urllib2.urlopen(self.pkgUrl, timeout=10)
                        #####
                        # Get just the package name out of the "package" url
                        urlList = self.pkgUrl.split("/")
                        self.pkgName = urlList[-1]
                        self.tmpLocalPkg = os.path.join(self.tmpDir,
                                                        self.pkgName)
                        try:
                            #####
                            # Next try to open a file for writing the local file
                            f = open(str(self.tmpLocalPkg).strip(), "w")
                        except IOError, err:
                            message = "Error opening file - err: " + str(err)
                            self.logger.log(LogPriority.INFO, message)
                            raise err
                        except Exception, err:
                            message = "Generic exception opening file - err: " + \
                                      str(err)
                            self.logger.log(LogPriority.INFO, message)
                            raise err
                        else:
                            self.logger.log(LogPriority.DEBUG,
                                            "..................")
                            #####
                            # take data out of the url stream and put it in the
                            # file a chunk at a time - more sane for large files
                            chunk = 16 * 1024 * 1024
                            counter = 0
                            while 1:
                                try:
                                    if urlfile:
                                        data = urlfile.read(chunk)
                                        if not data:
                                            message = "Done reading file: " + \
                                                      self.pkgUrl
                                            self.logger.log(LogPriority.DEBUG,
                                                            message)
                                            break
                                        f.write(data)
                                        message = "Read " + str(len(data)) + \
                                            " bytes"
                                        self.logger.log(LogPriority.DEBUG,
                                                        message)
                                    else:
                                        raise IOError("What file???")
                                except (OSError or IOError), err:
                                    #####
                                    # Catch in case we run out of space on the
                                    # local system during the download process
                                    message = "IO error: " + str(err)
                                    self.logger.log(LogPriority.INFO, message)
                                    raise err
                                except SSLError:
                                    # This will catch timeouts. Due to a bug in
                                    # the urlfile object, it will sometimes not
                                    # read, and will need to be recreated. The
                                    # counter ensures that if the error is not
                                    # a simple timeout, it will not get stuck
                                    # in an infinite loop.
                                    counter += 1
                                    if counter > 3:
                                        raise
                                    self.logger.log(LogPriority.DEBUG,
                                                    "Connection timed out. " +
                                                    "Creating new urlfile " +
                                                    "object.")
                                    urlfile = urllib2.urlopen(self.pkgUrl,
                                                              timeout=10)
                                else:
                                    success = True
                            f.close()
                        urlfile.close()
                    else:
                        message = "Error opening the URL: " + str(self.pkgUrl)
                        self.logger.log(LogPriority.DEBUG, message)
            else:
                message = "Need a valid package url. Can't download nothing..."
                self.logger.log(LogPriority.DEBUG, message)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)
        return success

    ###########################################################################

    def checkMd5(self):
        """
        Validate that the MD5 of the file is the same as the one on the server,
        for consistency's sake, ie we got a good download.

        Takes an MD5 of the local file, then appends it to the filename with a
        ".", then does a request and getreqpose and checks for a "200 in the
        response.status field.

        .<filename>.<UPPER-md5sum>

        Specific to the Casper server for Macs.  If you want to override this
        method for another OS, subclass this class, or rewrite the function.

        @author: Roy Nielsen
        """
        success = False
        try:
            hashSuccess, myhash = self.getDownloadedFileMd5sum()
            if hashSuccess and myhash:
                #####
                # Generate the name of the hash using the generated md5
                hashname = "." + self.package + \
                           "." + str(myhash).upper().strip()

                message = "Hashname: " + str(hashname).strip()
                self.logger.log(LogPriority.DEBUG, message)

                #####
                # Generate a web link to the hash file
                hashUrlList = self.pkgUrl.split("/")
                del hashUrlList[-1]
                hashUrlList.append(str(hashname))
                self.hashUrl = "/".join(hashUrlList)

                self.logger.log(LogPriority.DEBUG, "Page: " + self.hashUrl)

                if self.connection.isPageAvailable(self.hashUrl):
                    success = True
                    message = "Found url: " + str(self.hashUrl)
                else:
                    message = "Did NOT find url: " + str(self.hashUrl)
                self.logger.log(LogPriority, message)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)

        return success

    ###########################################################################

    def getDownloadedFileMd5sum(self):
        """
        Get the md5sum of a file on the local filesystem.  Calculate the data
        in chunks in case of large files.

        @param: filename - filename to check integrity of

        @returns: retval - the md5sum of the file, or -1 if unsuccessful in
                           getting the md5sum

        @author: Roy Nielsen
        """
        success = False
        try:
            retval = None
            try:
                if os.path.exists(self.tmpLocalPkg):
                    fh = open(self.tmpLocalPkg, 'r')
                else:
                    raise Exception("Cannot open a non-existing file...")
            except Exception, err:
                message = "Cannot open file: " + self.tmpLocalPkg + \
                    " for reading."
                self.logger.log(LogPriority.WARNING, message)
                self.logger.log(LogPriority.WARNING, "Exception : " + str(err))
                success = False
                retval = '0'
            else:
                chunk = 16 * 1024 * 1024
                m = hashlib.md5()
                while True:
                    data = fh.read(chunk)
                    if not data:
                        break
                    m.update(data)
                retval = m.hexdigest()

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)
        else:
            success = True

        return success, str(retval).strip()

    ###########################################################################

    def unArchive(self):
        """
        Unarchive tar, tar.gz, tgz, tar.bz, and zip files.  Using tarfile and
        zipfile libraries

        @Note: Will look for the first "*.app" or "*.pkg", and use that as the
               self.tmpLocalPkg that the rest of the class will use to try to
               install.  This way the compressed file can be named something
               different than the actual package to install.  This means that
               the compressed package can be named generically and a specified
               version is in the compressed file.

               Caution - This means when removing the package means you need to
               know the name of the package inside the compressed file to
               remove the installed file.

        @author: Roy Nielsen
        """
        try:
            retval = 0
            ##############################################
            # Check if the file is a tar file of some sort
            inTarList = False
            tars = ["tar", "tgz", "tar.gz", "tbz", "tar.bz"]
            for extension in tars:
                if filename.endswith(extension):
                    inTarList = True

            if re.match("^\s*$", filename):
                self.logger.log(LogPriority.DEBUG,
                                "Emtpy archive name, cannot uncompress.")
                retval = -1
            elif inTarList:
                import tarfile
                try:
                    #####
                    # Open the tar file to prepare for extraction
                    tar = tarfile.open(filename)
                    try:
                        message = "file: " + filename + ", dest: " + destination
                        self.logger.log(LogPriority.DEBUG, message)
                        #####
                        # Extract the tarball at the "destination" location
                        tar.extractall(destination)
                    except (OSError | IOError), err:
                        message = "Error extracting archive: " + str(err)
                        self.logger.log(LogPriority.WARNING, message)
                        raise err
                except Exception, err:
                    message = "Error opening archive: " + str(err)
                    self.logger.log(LogPriority.DEBUG, message)
                    raise err
                else:
                    tar.close()
                    retval = 0

            elif filename.endswith("zip"):
                ###############################################
                # Process if it a zip file.
                #
                # partial reference at:
                # http://stackoverflow.com/questions/279945/set-permissions-on-a-compressed-file-in-python
                import zipfile
                #####
                # create a zipfile object, method for python 2.5:
                # http://docs.python.org/release/2.5.2/lib/module-zipfile.html
                # Use this type of method as without it the unzipped
                # permissions aren't what they are supposed to be.
                uzfile = zipfile.ZipFile(filename, "r")
                if zipfile.is_zipfile(filename):
                    #####
                    # if the file is a zipfile
                    #
                    # list the files inside the zipfile
                    # for internal_filename in uzfile.namelist():
                    for ifilename in uzfile.filelist:
                        perm = ((ifilename.external_attr >> 16L) & 0777)
                        internal_filename = ifilename.filename
                        message = "extracting file: " + str(internal_filename)
                        self.logger.log(LogPriority.DEBUG, message)
                        #####
                        # Process directories first
                        if internal_filename.endswith("/"):
                            #####
                            # if a directory is found, create it (zipfile
                            # doesn't)
                            try:
                                os.makedirs(os.path.join(destination,
                                                         internal_filename.strip("/")),
                                            perm)
                            except OSError, err:
                                message = "Error making directory: " + str(err)
                                self.logger.log(LogPriority.DEBUG, message)
                                raise err
                            else:
                                continue
                        #####
                        # Now process if it is not a directoy
                        try:
                            contents = uzfile.read(internal_filename)
                        except RuntimeError, err:
                            #####
                            # Calling read() on a closed ZipFile will raise a
                            # RuntimeError
                            self.logger.log(LogPriority.DEBUG,
                                            ["InstallingHelper.un_archive",
                                             "Called read on a closed ZipFile: "
                                             + str(err)])
                            raise err
                        else:
                            try:
                                #####
                                # using os.open as regular open doesn't give
                                # the ability to set permissions on a file.
                                unzip_file = os.path.join(destination,
                                                          internal_filename)
                                target = os.open(unzip_file,
                                                 os.O_CREAT | os.O_WRONLY,
                                                 perm)
                                try:
                                    #####
                                    # when an exception is thrown in the try block, the
                                    # execution immediately passes to the finally block
                                    # After all the statements in the finally block are
                                    # executed, the exception is raised again and is 
                                    # handled in the except statements if present in
                                    # the next higher layer of the try-except statement
                                    os.write(target, contents)
                                finally:
                                    os.close(target)
                            except OSError, err:
                                message = "Error opening file for writing: " + \
                                          str(err)
                                self.logger.log(LogPriority.WARNING, message)
                                raise err
                    uzfile.close()
                    if not retval < -1:
                        # if there was not an error creating a directory as
                        # part of the unarchive process
                        retval = 0
                else:
                    # Not a zipfile based on the file's "magic number"
                    self.logger.log(LogPriority.DEBUG,
                                    ["InstallingHelper.un_archive",
                                     "file: " + filename +
                                     " is not a zipfile."])
                    retval = -1
            #####
            # Find the first item in the directory that is a .app | .pkg | .mpkg
            # Use that as the self.tmpLocalPkg that the rest of the class will
            # use to try to install.  This way the compressed file can be
            # named something different than the actual package to install.
            # This means that the compressed package can be named generically
            # and a specified version is in the compressed file.
            # Caution - This means when removing the package means you need
            # to know the name of the package inside the compressed file to
            # remove the installed file.
            dirlist = os.listdir(self.tmpDir)
            for myfile in dirlist:
                if re.search(".app", myfile) or \
                   re.search(".pkg", myfile) or \
                   re.search(".mpkg", myfile):
                    self.tmpLocalPkg = self.tmpDir + "/" + str(myfile)
                    break

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)

        return retval

    ###########################################################################

    def copyInstall(self, dest="/Applications", isdir=True, mode=0775,
                    owner="root", group="admin"):
        """
        Copies a directory tree, or contents of a directory to "dest"
        destination.

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
        self.tmpDir = the temporary directory that is created for the
                      downloaded file, and to unarchive it into.
        self.sig_match = A variable that tells if the signature of the
                         downloaded file and the server string match.  Set
                         in the download_and_prepare method of the parent
                         class

        @author: Roy Nielsen
        """
        try:
            if re.match("^\s*$", self.tmpDir):
                self.tmpDir = "."

            src_path = self.tmpDir + "/" + self.pkgName

            self.logger.log(LogPriority.DEBUG, "New src_path: " + src_path)

            if isdir:
                try:
                    shutil.copytree(src_path, dest)
                except Exception, err:
                    message = "Unable to recursively copy dir: " + src_path + \
                              " error: " + str(err)
                    self.logger.log(LogPriority.ERROR, message)
                    raise Exception(message)
                else:
                    success = True
                    #####
                    # try to chmod the directory (not recursively)
                    try:
                        os.chmod(dest, mode)
                    except OSError, err:
                        success = False
                        message = "Unable to change mode: " + str(err)
                        self.logger.log(LogPriority.ERROR, message)
                        raise Exception(message)
                    #####
                    # UID & GID needed to chown the directory
                    uid = 0
                    gid = 80
                    try:
                        uid = pwd.getpwnam(owner)[2]
                    except KeyError, err:
                        success = False
                        message = "Error: " + str(err)
                        self.logger.log(LogPriority.DEBUG, message)
                        raise Exception(message)
                    try:
                        gid = grp.getgrnam(group)[2]
                    except KeyError, err:
                        success = False
                        message = "Error: " + str(err)
                        self.logger.log(LogPriority.DEBUG, message)
                        raise Exception(message)
                    #####
                    # Can only chown if uid & gid are int's
                    if ((type(uid) == type(int())) and
                        (type(gid) == type(int()))):
                        try:
                            os.chown(dest, uid, gid)
                        except OSError, err:
                            success = False
                            message = "Error: " + str(err)
                            self.logger.log(LogPriority.DEBUG, message)
                            raise Exception(message)
            else:
                try:
                    dir_list = os.listdir(src_path)
                except OSError, err:
                    message = "Error listing files from: " + src_path + \
                              " error: " + str(err)
                    self.logger.log(LogPriority.ERROR, message)
                    raise Exception(message)
                else:
                    for myfile in dir_list:
                        try:
                            shutil.copy2(myfile, dest)
                        except Exception, err:
                            message = "Error copying file: " + myfile + \
                                      " error: " + str(err)
                            self.logger.log(LogPriority.DEBUG, message)
                            raise
                        else:
                            success = True
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)

        return success

    ##########################################################################

    def installPkg(self):
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
        success = False
        try:
            #####
            # Check if it's a pkg or mpkg
            if self.tmpLocalPkg.endswith(".pkg") or \
               self.tmpLocalPkg.endswith(".mpkg"):
                #####
                # set up the install package command string
                cmd = ["/usr/bin/sudo", "/usr/sbin/installer", "-verboseR",
                       "-pkg", self.tmpLocalPkg, "-target", "/"]
                self.ch.executeCommand(cmd)
                self.logger.log(LogPriority.DEBUG,
                                self.ch.getOutputString())
                if self.ch.getReturnCode() == 0:
                    success = True
                    #####
                    # remove the temporary directory where the archive was
                    # downloaded and unarchived.
                    try:
                        shutil.rmtree(self.tmpDir)
                    except Exception, err:
                        self.logger.log(LogPriority.ERROR,
                                        "Exception: " + str(err))
                        raise err
                    else:
                        success = True
            else:
                self.logger.log(LogPriority.ERROR, "Valid package " +
                                "extension not found, cannot install:" +
                                " " + self.tmpLocalPkg)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)

        return success
