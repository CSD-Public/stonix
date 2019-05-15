###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
#                                                                             #
###############################################################################

"""
Created November 2, 2011

The installing class holds generic python methods for installing a package,
intended for use to selfupdate a script.

@operatingsystem: Only specifics - md5 hashing specific to both python version 
                  and OS.

@author: Roy Nielsen

"""
import os.path
import re
import sys
import tempfile
import urllib2
from subprocess import Popen, PIPE

from logdispatcher import LogPriority
from stonixutilityfunctions import set_no_proxy

class InstallingHelper(object) :
    '''Generic class using python native calls to download, check md5sums
    and unarchive files found on the server.
    
    @author: Roy Nielsen


    '''
    
    def __init__(self, environ, url, logger) :
        """
        Initialization method
        """
        self.environ = environ
        self.url = url
        self.logger = logger
        if re.match("^\s*$", self.url):
            self.logger.log(LogPriority.ERROR, "Cannot use this class " +
                            "without a URL to the archive " +
                            "file you wish to download and install")
        
        self.find_file_name()
        self.find_package_name()
        self.find_base_url()

    def un_archive(self, filename="", destination=".") :
        '''Unarchive tar, tar.gz, tgz, tar.bz, and zip files.  Using tarfile and
        zipfile libraries -- can't use shutil, as that functionality is 2.7 and
        beyond

        :param filename:  (Default value = "")
        :param destination:  (Default value = ".")

        '''
        retval = 0
        if re.match("^\s*$", filename) :
            self.logger.log(LogPriority.DEBUG, \
                            "Emtpy archive name, cannot uncompress.")
            retval = -1
        elif filename.endswith("tar") or \
             filename.endswith("tgz") or \
             filename.endswith("tar.gz") or \
             filename.endswith("tbz") or \
             filename.endswith("tar.bz") :
            import tarfile
            try :
                tar = tarfile.open(filename)
                try :
                    self.logger.log(LogPriority.DEBUG, 
                                    ["InstallingHelper.un_archive",
                                    "file: " + filename + ", dest: " + destination])
                    tar.extractall(destination)
                except (OSError|IOError), err :
                    self.logger.log(LogPriority.WARNING, 
                                    ["InstallingHelper.un_archive",
                                    "Error extracting archive: " + str(err)])
                    retval = -2
            except Exception, err :
                self.logger.log(LogPriority.DEBUG, 
                                    ["InstallingHelper.un_archive",
                                "Error opening archive: " + str(err)])
                retval = -3
            else :
                tar.close()
                retval = 0

        elif filename.endswith("zip") :
            # partial reference at: http://stackoverflow.com/questions/279945/set-permissions-on-a-compressed-file-in-python
            import zipfile
            # create a zipfile object, method for python 2.5:
            # http://docs.python.org/release/2.5.2/lib/module-zipfile.html
            # Use this type of method as without it the unzipped permissions
            # aren't what they are supposed to be.
            uzfile = zipfile.ZipFile(filename, "r")
            if zipfile.is_zipfile(filename) :
                # if the file is a zipfile
            
                #list the files inside the zipfile
                #for internal_filename in uzfile.namelist():
                for ifilename in uzfile.filelist :
                    perm = ((ifilename.external_attr >> 16L) & 0777)
                    internal_filename = ifilename.filename
                    self.logger.log(LogPriority.DEBUG, 
                                    ["InstallingHelper.un_archive",
                                    "extracting file: " + internal_filename])
                    if internal_filename.endswith("/") :
                        # if a directory is found, create it (zipfile doesn't)
                        try :
                            os.makedirs(os.path.join(destination, internal_filename.strip("/")), perm)
                        except OSError, err :
                            self.logger.log(LogPriority.DEBUG, 
                                            ["InstallingHelper.un_archive",
                                            "Error making directory: " + str(err)])
                            retval = -2
                            break
                        else :
                            continue
                    try :
                        contents = uzfile.read(internal_filename)
                    except RuntimeError, err :
                        # Calling read() on a closed ZipFile will raise a 
                        # RuntimeError
                        self.logger.log(LogPriority.DEBUG, 
                                    ["InstallingHelper.un_archive",
                                        "Called read on a closed ZipFile: " + str(err)])
                        retval = -3
                        break
                    else :
                        try :
                            # using os.open as regular open doesn't give the 
                            # ability to set permissions on a file.
                            target = os.open(os.path.join(destination, internal_filename), os.O_CREAT | os.O_WRONLY , perm)
                            try :
                                # when an exception is thrown in the try block, the
                                # execution immediately passes to the finally block
                                # After all the statements in the finally block are
                                # executed, the exception is raised again and is 
                                # handled in the except statements if present in
                                # the next higher layer of the try-except statement
                                os.write(target, contents)
                            finally :
                                os.close(target)
                        except OSError, err :
                            self.logger.log(LogPriority.WARNING, 
                                            ["InstallingHelper.un_archive",
                                            "Error opening file for writing: " + str(err)])
                            retval = -4
                            break

                uzfile.close()
                if not retval < -1 :
                    # if there was not an error creating a directory as part of
                    # the unarchive process
                    retval = 0
            else :
                # Not a zipfile based on the file's "magic number"
                self.logger.log(LogPriority.DEBUG, 
                                    ["InstallingHelper.un_archive",
                                "file: " + filename + " is not a zipfile."])
                retval = -1

        return retval
    
    def download_and_save_file(self, fpath="") :
        '''Download a file from "url" to "fpath" location, a "chunk" at a time,
        so we don't get a memory filling problem.

        :param fpath:  (Default value = "")

        '''
        if not re.match("^$", self.url) or not re.match("^$", fpath) :

            set_no_proxy()

            # first try to open the URL
            try :
                urlfile = urllib2.urlopen(self.url)
            except Exception , err:
                self.logger.log(LogPriority.DEBUG, 
                                ["InstallingHelper.download_and_save_file",
                                 "Error: " + str(err)])
            else :
                try :
                    # Next try to open the file for writing
                    f = open(fpath, "w")
                except IOError, err :
                    self.logger.log(LogPriority.INFO, 
                                    ["InstallingHelper.download_and_save_file",
                                    "Error opening file - err: " + str(err)])
                except Exception, err :
                    self.logger.log(LogPriority.INFO, 
                                    ["InstallingHelper.download_and_save_file",
                                    "Generic exception opening file - err: " + str(err)])
                else :
                    # take data out of the url stream and put it in the file
                    # a chunk at a time
                    chunk = 16 * 1024 * 1024
                    while 1 :
                        data = urlfile.read(chunk)
                        if not data :
                            self.logger.log(LogPriority.DEBUG, 
                                            ["InstallingHelper.download_and_save_file",
                                            "Done reading file: " + self.url])
                            break
                        f.write(data)
                        self.logger.log(LogPriority.DEBUG, 
                                        ["InstallingHelper.download_and_save_file",
                                        "Read " + str(len(data)) + " bytes"])
                    f.close()
                urlfile.close()
        else :
            print "Need both a URL and full path filename... try again."    
    
    
    def download_and_prepare(self):
        '''Download and unarchive a file into a temporary directory.


        :returns: s: tmp_dir - the path where the archive was downloaded to
                  tmp_name - name of the downloaded archive, including the
                             tmp_dir
        
        @author: Roy Nielsen

        '''
    
        if re.match("^\s*$", self.url) or re.match("^\s*$", self.package_name) :
            self.logger.log(LogPriority.DEBUG, 
                            ["InstallingHelper.download_and_prepare",
                            "sent empty URL: \"" + self.url + "\" or name: \"" + \
                            self.package_name + "\" to download_and_prepare..."])
            tmp_name = ""
            tmp_dir = ""
        else :
    
            try :
                tmp_dir = tempfile.mkdtemp(prefix=self.package_name, dir="/tmp")
            except Exception, err :
                self.logger.log(LogPriority.WARNING, 
                                ["InstallingHelper.download_and_prepare",
                                "mkdtemp exception: " + str(err)])
                self.sig_match = False
            else :
                self.logger.log(LogPriority.DEBUG, 
                                ["InstallingHelper.download_and_prepare",
                                 "tmp_dir: " + tmp_dir])

            tmp_name = tmp_dir + "/" + self.file_name

            self.download_and_save_file(tmp_name)    

            self.logger.log(LogPriority.DEBUG, 
                            ["InstallingHelper.download_and_prepare",
                            "md5 file: " + self.base_url + "/" + \
                            self.package_name + ".md5.txt"])

            tmp_sig = self.get_string_from_url(self.base_url + "/" + \
                                               self.package_name + \
                                               ".md5.txt")
            if re.match("^\s*$", tmp_sig) :
                tmp_sig = self.get_string_from_url(self.base_url + "/" + \
                                                   self.package_name.lower() + \
                                                   ".md5.txt")

            if not self.check_md5(tmp_sig, tmp_name) :
                self.logger.log(LogPriority.WARNING, 
                                ["InstallingHelper.download_and_prepare",
                                "md5: " + str(tmp_sig) + " and file: " + \
                                tmp_name + " don't match"])
                self.sig_match = False
            else :
                self.logger.log(LogPriority.DEBUG,
                                ["InstallingHelper.download_and_prepare",
                                "md5: " + str(tmp_sig) + " and file: " + \
                                tmp_name + " match"])
                self.sig_match = True
                un_arch_complete = self.un_archive(tmp_name, tmp_dir)
                if  un_arch_complete == 0 :
                    self.logger.log(LogPriority.DEBUG,
                                    ["InstallingHelper.download_and_prepare",
                                     "un_archive returned 0"])
                elif un_arch_complete == -1 :
                    self.logger.log(LogPriority.DEBUG, 
                                    ["InstallingHelper.download_and_prepare",
                                    "un_archive returned -1"])
                else:
                    self.logger.log(LogPriority.DEBUG, 
                                    ["InstallingHelper.download_and_prepare",
                                    "un_archive returned code: " + \
                                    str(un_arch_complete)])
        self.logger.log(LogPriority.DEBUG, 
                        ["InstallingHelper.download_and_prepare",
                        "Returning: " + tmp_dir + \
                        " from download_and_prepare()"])
        return tmp_dir

    def get_string_from_url(self, url=""):
        '''Read a string from a url (file) on the server.
        
        Purpose: to read a file on the server that contains the md5sum of a file
        that we are going to download for file integrity.

        :param url:  (Default value = "")
        :returns: s: string returned by the url
        
        @author: Roy Nielsen

        '''
        server_string = ""

        set_no_proxy()

        if not re.match("^\s*$", url):
            set_no_proxy()

            try:
                f = urllib2.urlopen(url)
            except IOError, err:
                self.logger.log(LogPriority.INFO,
                                ["InstallingHelper.get_string_from_url",
                                 "IOError, " + url + " : " + str(err)])
            else:
                server_string = f.read()
                f.close()

        return server_string.strip()

    def get_file_md5sum(self, filename=""):
        '''Get the md5sum of a file on the local filesystem.  Calculate the data
        in chunks in case of large files.

        :param filename:  (Default value = "")
        :returns: s: retval - the md5sum of the file, or -1 if unsuccessful in
                           getting the md5sum
        
        @author: Roy Nielsen

        '''
        import hashlib

        retval = -1

        try :
            fh = open(filename, 'r')
        except Exception, err :
            self.logger.log(LogPriority.WARNING, 
                            ["InstallingHelper.get_file_md5sum",
                            "Cannot open file: " + filename + " for reading."])
            self.logger.log(LogPriority.WARNING, 
                            ["InstallingHelper.get_file_md5sum",
                             "Exception : " + str(err)])
        else :
            chunk = 16 * 1024 * 1024
            m = hashlib.md5()
            while True :
                data = fh.read(chunk)
                if not data :
                    break
                m.update(data)
            retval = m.hexdigest()

        return str(retval).strip()


    def get_file_old_md5sum(self, filename="") :
        '''Get the md5 sum of the file for versions of python less than
        2.5 - specifically Solaris 10.  Easy to add other systems
        by setting the cmd with the correct command to get the md5 sum on
        that OS.

        :param filename: name of the file to acquire the md5 hash for (Default value = "")
        :returns: s: retval - the md5sum of the file, or -1 if unsuccessful in
                           getting the md5sum
        
        @author Roy Nielsen

        '''
        retval = -1
        myretval = ""
        cmd = []
        
        if self.environ.getosfamily() == "solaris" :
            cmd = ["/usr/sfw/bin/openssl", "md5", filename]
        
        try :
            myretval = Popen(cmd, stdout=PIPE, stderr=PIPE).communicate()[0]
        except Exception, err :
            self.logger.log(LogPriority.WARNING,
                            ["InstallingHelper.get_file_old_md5sum",
                             "Error executing command: " + str(cmd)])
            self.logger.log(LogPriority.WARNING,
                            ["InstallingHelper.get_file_old_md5sum",
                             "Exception: " + str(err)])
        else :
            retval = myretval.split()[1].strip()
    
        return retval


    def check_md5(self, signature="", filename="") :
        '''Check if the md5 is a match with the filename passed in.

        :param signature:  (Default value = "")
        :param filename:  (Default value = "")
        :returns: s: retval - -1 for mismatch
                            0 for match
        
        @author: Roy Nielsen

        '''
        pat = re.compile(str(signature))        
        
        if sys.hexversion < 0x02050000 :
            # If the python version running this script is less than 2.5
            hash_from_file = self.get_file_old_md5sum(filename)
        else :
            # If the python running this script is 2.5 or above
            hash_from_file = self.get_file_md5sum(filename)
        
        if pat.match(str(hash_from_file)) :
            retval = True
        else :
            retval = False

        return retval


    def check_extension(self):
        '''Check the url for a valid archive extension
        
        @author: Roy Nielsen


        '''
        retval = True
        if self.url.endswith("tar.gz") :
            self.extension = "tar.gz"
        elif self.url.endswith("tgz") :
            self.extension = "tgz"
        elif self.url.endswith("tar.bz") :
            self.extension = "tar.bz"
        elif self.url.endswith("tbz") :
            self.extension = "tbz"
        elif self.url.endswith("zip") :
            self.extension = "zip"
        elif self.url.endswith("txt") :
            self.extension = "txt"
        elif self.url.endswith("tar") :
            self.extension = "tar"
        else:
            retval = False

        if retval:
            self.logger.log(LogPriority.DEBUG,
                            ["InstallingHelper.check_extension",
                             "extension = " + self.extension])
        else:
            self.logger.log(LogPriority.DEBUG,
                            ["InstallingHelper.check_extension",
                             "Archive extension not found, returning False"])

        return retval

    def find_package_name(self):
        '''Get the name of the package without an archive extension
        
        @author: Roy Nielsen


        '''
        self.package_name = ""
        filename = re.compile("(\S*)\.(tar|tar.gz|tgz|tar.bz|tbz|zip|txt|pkg)\s*$")

        name_list = self.url.split("/")
        for name in name_list:

            try:
                package_name = filename.match(name.strip())
                if package_name:
                    self.package_name = package_name.group(1).strip()

            except AttributeError, err:
                self.package_name = ""
                self.logger.log(LogPriority.WARNING,
                                ["InstallingHelper.find_package_name",
                                 "AttributeError: " + str(err)])

        # the name of the archive file should be the last item in the above
        # list, if a match is not found, or is empty, exit.
        if re.match("^\s*$", self.package_name):
            self.logger.log(LogPriority.INFO,
                            ["InstallingHelper.find_package_name",
                             "Need a valid url pointing to an archive file."])
        else:
            self.logger.log(LogPriority.DEBUG,
                            ["InstallingHelper.find_package_name",
                             "package_name = " + self.package_name])

    def find_file_name(self):
        '''Get the name of the file to download, from the url string
        
        @author: Roy Nielsen


        '''
        self.file_name = ""

        name_list = self.url.split("/")
        for name in name_list:
            self.file_name = name
        # the name of the archive file should be the last item in the above
        # list, if it is empty, then exit.
        if re.match("^\s*$", self.file_name):
            self.logger.log(LogPriority.INFO,
                            ["InstallingHelper.find_file_name",
                             "Need a valid url pointing to an archive file."])
        else:
            self.logger.log(LogPriority.DEBUG,
                            ["InstallingHelper.find_file_name",
                             "file_name = " + self.file_name])

    def find_base_url(self):
        '''Get the base url, without the file_name
        
        @author: Roy Nielsen


        '''
        self.base_url = ""
        i = 0

        name_list = self.url.split("/")
        for name in name_list:
            i = i + 1
            if i >= len(name_list):
                break
            elif i == 1:
                self.base_url = name
                continue

            self.base_url = self.base_url + "/" + name

        self.logger.log(LogPriority.DEBUG,
                        ["InstallingHelper.find_base_url",
                         "base_url = " + self.base_url])

    def download_and_unarchive(self) :
        '''Download and unarchive the package to be delivered.
        
        @author: Roy Nielsen


        '''
        # take name and create tmpdir
        # create string with tmpdir and filename
        # download and check integrity
            # download file
            # check md5

        (tmp_name, tmp_dir) = self.download_and_prepare()

        # if integrity ok, 
        if re.match("^\s*$", tmp_name) or re.match("^\s*$", tmp_dir) :
            self.logger.log(LogPriority.WARNING, 
                            ["InstallingHelper.download_and_unarchive",
                            "Cannot install: \"" + tmp_name + "\" to: \"" + \
                            tmp_dir + "\""])
        else :
             # if archive, unarchive
            self.un_archive(tmp_name, tmp_dir)

