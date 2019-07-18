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

'''

A class that helps out with evaluation and fixing of files

@author: ekkehard j. koch
@change: 10/21/2013 ekkehard Original Implemantation
@note: This is only design for unix base file system
'''
import grp
import os
import pwd
import re
import shutil
import stat
import traceback
import types
from .CommandHelper import CommandHelper
from .logdispatcher import LogPriority
from .stonixutilityfunctions import writeFile, resetsecon


class FileHelper(object):
    '''FileHelper is class that helps with execution files permission, owner,
    content, and/or removal
    @note: copy, move, and trash of files will be implemented in the future
    @author: ekkehard


    '''

# initialize attributes
    def __init__(self, logdispatcher, statechglogger):
# By Default Use OSs default directory mode to create directories in
# createfile_path
        self.defaultDirectoryMode = ""
# By Default do not remove empty parent directories
        self.defaultRemoveEmptyParentDirectories = False
        self.logdispatcher = logdispatcher
        self.statechglogger = statechglogger
        self.ch = CommandHelper(self.logdispatcher)
        self.removeAllFiles()

###############################################################################

    def getDefaultDirectoryMode(self):
        return self.defaultDirectoryMode

###############################################################################

    def getDefaultRemoveEmptyParentDirectories(self):
        return self.defaultRemoveEmptyParentDirectories

###############################################################################

    def getFileContent(self):
        return self.file_content

###############################################################################

    def getFileLabel(self):
        return self.file_label

###############################################################################

    def getFileMessage(self):
        return self.file_messages

###############################################################################

    def getFileOwner(self):
        return self.file_owner

###############################################################################

    def getFilePath(self):
        return self.file_path

###############################################################################

    def getFilePermissions(self):
        return self.file_permissions

###############################################################################

    def getFileRemove(self):
        return self.file_remove

###############################################################################

    def setDefaultDirectoryMode(self, defaultDirectoryMode):
        self.defaultDirectoryMode = defaultDirectoryMode
        return self.defaultDirectoryMode

###############################################################################

    def setDefaultRemoveEmptyParentDirectories(self, defaultRemoveEmptyParentDirectories):
        self.defaultRemoveEmptyParentDirectories = defaultRemoveEmptyParentDirectories
        return self.defaultRemoveEmptyParentDirectories

###############################################################################

    def setFileContent(self, file_content):
        if file_content == None:
            self.file_content = file_content
            message = "File content was set to '" + str(self.file_content) + \
            "'!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        else:
            self.file_content = file_content
            message = "File content was set to '" + str(self.file_content) + \
            "'!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        return self.file_content

###############################################################################

    def setFileEventID(self, file_eventid):
        if file_eventid == None:
            self.file_eventid = file_eventid
            message = "File eventid was set to '" + str(self.file_eventid) + \
            "'!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        else:
            self.file_eventid = file_eventid
            message = "File eventid was set to '" + str(self.file_eventid) + \
            "'!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        return self.file_eventid

###############################################################################

    def setFileGroup(self, file_group):
        file_group_name = None
        file_group_id = None
        if file_group == None:
            self.file_group = file_group
            message = "File group was set to " + str(self.file_group) + "!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        else:
            datatype = type(file_group)
            if datatype == bytes:
                try:
                    file_group_name = file_group
                    file_group_id = grp.getgrnam(file_group_name).gr_gid
                    self.file_group = file_group_id
                    message = "File group Name='" + str(file_group_name) + \
                    "' gid='" + str(file_group_id) + "' was of type '" + \
                    str(datatype) + "' converted to gid '" + \
                    str(self.file_group) + "'!"
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                except Exception as err:
                    self.file_group = None
                    message = str(err) + \
                    " No valid gid could be found for file group of '" + \
                    str(file_group) + "' of type '" + str(datatype) + \
                    "'! File group set to '" + str(self.file_group) + "'."
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                    raise
            elif datatype == int:
                try:
                    file_group_id = file_group
                    file_group_name = grp.getgrgid(file_group_id).gr_name
                    self.file_group = file_group_id
                    message = "File group gid '" + str(file_group_id) + \
                    "' was of type '" + str(datatype) + \
                    "' is a valid gid with the name of '" + \
                    str(file_group_name) + "'! File group set to '" + \
                    str(self.file_owner) + "'."
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                except Exception as err:
                    self.file_group = None
                    message = str(err) + \
                    " No valid name could be found for file group of gid '" + \
                    str(file_group_id) + "' of type '" + str(datatype) + \
                    "'! File group set to '" + str(self.file_group) + "'."
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                    raise
            else:
                self.file_owner = None
                message = "Invalid file group of '" + str(file_group) + \
                "' is of an unrecognized type of '" + str(datatype) + \
                "'! File owner set to '" + str(self.file_group) + "'."
                self.logdispatcher.log(LogPriority.DEBUG, message)
        return self.file_group

###############################################################################

    def setFileLabel(self, file_label):
        self.file_label = file_label.strip()
        return self.file_label

###############################################################################

    def setFileOwner(self, file_owner):
        if file_owner == None:
            self.file_owner = file_owner
            message = "File owner was set to '" + str(self.file_owner) + "'!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        else:
            datatype = type(file_owner)
            if datatype == bytes:
                try:
                    file_owner_name = file_owner
                    file_owner_id = pwd.getpwnam(file_owner_name).pw_uid
                    self.file_owner = file_owner_id
                    message = "File owner Name='" + str(file_owner_name) + \
                    "' uid='" + str(file_owner_id) + "' was of type '" + \
                    str(datatype) + "' converted to uid '" + \
                    str(self.file_owner) + "'!"
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                except Exception as err:
                    self.file_owner = None
                    message = str(err) + \
                    " No valid uid could be found for file owner of '" + \
                    str(file_owner_name) + "' of type '" + str(datatype) + \
                    "'! File owner set to '" + str(self.file_owner) + "'."
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                    raise
            elif datatype == int:
                try:
                    file_owner_id = file_owner
                    file_owner_name = pwd.getpwuid(file_owner_id).pw_name
                    self.file_owner = file_owner_id
                    message = "File owner uid '" + str(file_owner_id) + \
                    "' was of type '" + str(datatype) + \
                    "' is a valid uid with the name of '" + \
                    str(file_owner_name) + "'! File owner set to '" + \
                    str(self.file_owner) + "'."
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                except Exception as err:
                    self.file_group = None
                    message = str(err) + \
                    " No valid name could be found for file owner with " + \
                    "uid '" + str(file_owner_id) + "' of type '" + \
                    str(datatype) + "'! File owner set to '" + \
                    str(self.file_owner) + "'."
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                    raise
                self.file_owner = file_owner
                message = "File owner '" + str(file_owner) + \
                "' was of type '" + str(datatype) + "' converted to uid '" + \
                str(self.file_owner) + "'!"
                self.logdispatcher.log(LogPriority.DEBUG, message)
            else:
                self.file_owner = None
                message = "Invalid file owner of '" + str(file_owner) + \
                "' is of an unrecognized type of '" + str(datatype) + \
                "'! File owner set to '" + str(self.file_owner) + "'."
                self.logdispatcher.log(LogPriority.DEBUG, message)
        return self.file_owner

###############################################################################

    def setFilePath(self, file_path):
        self.file_path = file_path.strip()
        if self.file_path == "":
            self.file_path_non_blank = False
        else:
            self.file_path_non_blank = True
        return self.file_path

###############################################################################

    def setFilePermissions(self, file_permissions):
        if file_permissions == None:
            self.file_permissions = file_permissions
            message = "File Permission were set to '" + \
            str(self.file_permissions) + "'!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        else:
            datatype = type(file_permissions)
            if datatype == bytes:
                try:
                    self.file_permissions = int(file_permissions, 8)
                    message = "File permission '" + str(file_permissions) + \
                    "' were of type '" + str(datatype) + \
                    "' is and assumed to be octal string and where " + \
                    "changed to int " + str(self.file_permissions) + "'!"
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                except Exception as err:
                    self.file_permissions = None
                    message = str(err) + " No valid file permissions " + \
                    "couldbe found for file permissions with of '" + \
                    str(file_permissions) + "' of type '" + str(datatype) + \
                    "'! File permissions set to '" + \
                    str(self.file_permissions) + "'."
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                    raise
            elif datatype == int:
                self.file_permissions = file_permissions
                message = "File permission of '" + str(file_permissions) + \
                "' were of type '" + str(datatype) + \
                "'. The value is int " + str(self.file_permissions) + "'!"
                self.logdispatcher.log(LogPriority.DEBUG, message)
            else:
                self.file_permissions = None
                message = "Invalid File permission of '" + \
                str(file_permissions) + "' is of an unrecognized type of '" + \
                str(datatype) + "'! File Permissions set to '" + \
                str(self.file_permissions) + "'."
                self.logdispatcher.log(LogPriority.DEBUG, message)
        return self.file_permissions

###############################################################################

    def setFileRemove(self, file_remove):
        self.file_remove = file_remove
        return self.file_remove

###############################################################################

    def addFile(self, file_label, file_path="", file_remove=False,
                file_content=None, file_permissions=None, file_owner=None,
                file_group=None, file_eventid=None):
        '''set the current file helper values and adds the new file to the
        dictionary
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param file_label: string - needs to be non blank
        :param file_path: string - The full path to the file (blank by default)
        :param file_content: string - The content that should be in the file
                             (blank by default)
        :param file_owner: string - The file_owner the file should have
                           (blank by default)
        :param file_permissions: string - The permission the file should have
                                          (blank by default)
        :param file_remove:  (Default value = False)
        :param file_group:  (Default value = None)
        :param file_eventid:  (Default value = None)
        :returns: pointer to the configuration item
        @note: file_label is essential

        '''
        success = self.saveFileHelperValues()
        self.resetFileHelperValues()
        if file_label == "":
            success = False
        else:
            self.setFileLabel(file_label)
            self.setFilePath(file_path)
            self.setFileRemove(file_remove)
            self.setFileContent(file_content)
            self.setFilePermissions(file_permissions)
            self.setFileOwner(file_owner)
            self.setFileGroup(file_group)
            self.setFileEventID(file_eventid)
            success = self.saveFileHelperValues()
            if success:
                message = "['" + str(self.file_label) + "','" + \
                str(self.file_path) + "','" + str(self.file_remove) + "','" + \
                str(self.file_content) + "','" + str(self.file_permissions) + \
                "','" + str(self.file_owner) + "','" + str(self.file_group) + \
                "','" + str(file_eventid) + "'] successful."
                self.logdispatcher.log(LogPriority.DEBUG, message)
        return success

###############################################################################

    def updateFile(self, file_label, file_path="", file_remove=False,
                    file_content=None, file_permissions=None,
                    file_owner=None, file_group=None):
        success = self.saveFileHelperValues()
        if file_label == "":
            success = False
        else:
            self.getFileHelperValues(file_label)
            self.setFilePath(file_path)
            self.setFileRemove(file_remove)
            self.setFileContent(file_content)
            self.setFilePermissions(file_permissions)
            self.setFileOwner(file_owner)
            self.setFileGroup(file_group)
            success = self.saveFileHelperValues()
            if success:
                message = "['" + str(self.file_label) + "','" + \
                str(self.file_path) + "','" + str(self.file_remove) + "','" + \
                str(self.file_content) + "','" + str(self.file_permissions) + \
                "','" + str(self.file_owner) + "','" + str(self.file_group) + \
                "'] successful."
                self.logdispatcher.log(LogPriority.DEBUG, message)
        return success

###############################################################################

    def removeAllFiles(self):
        self.filedictionary = {}
        self.resetFileHelperValues()
        return True

###############################################################################

    def evaluateFiles(self):
        '''Evaluaate all files that have been added with addfile.
        @author: ekkehard j. koch

        :param self: essential if you override this definition

        '''
        evaluteAll = True
        evaluate = True
        message = ""
# Get all the keys in the file dictionary
        keys = sorted(self.filedictionary.keys())
# Iterate through all the keys
        for key in keys:
# Load object value
            self.getFileHelperValues(key)
# Evaluate file
            evaluate = self.evaluateFile()
            if evaluate == False:
                if message == "":
                    message = self.getFileMessage()
                else:
                    message = message + '''
''' + self.getFileMessage()
                evaluteAll = False
        self.resetFileMessage()
        self.appendToFileMessage(message)
        return evaluteAll

###############################################################################

    def fixFiles(self):
        '''Fixes all files that have been added with addfile.
        @author: ekkehard j. koch

        :param self: essential if you override this definition

        '''
        fixAll = True
        message = ""
        keys = sorted(self.filedictionary.keys())
        for key in keys:
            self.getFileHelperValues(key)
            fixed = self.fixFile()
            if fixed == False:
                if message == "":
                    message = self.getFileMessage()
                else:
                    message = message + '''
''' + self.getFileMessage()
                fixAll = False
        self.resetFileMessage()
        self.appendToFileMessage(message)
        return fixAll

###############################################################################

    def evaluateFile(self):
        '''evalueate the currently loaded file in the object.
        @author: ekkehard j. koch

        :param self: essential if you override this definition

        '''
        evaluationMatch = True
        self.evaluationReset()
#check if the file have the correct permissions set
        self.file_path_needs_to_be_created = self.evaluateFileCreation(not(self.file_remove))
        if self.file_path_needs_to_be_created:
            evaluationMatch = False
#check if the file have the correct permissions set
        self.file_path_needs_to_be_deleted = self.evaluateFileRemoval(self.file_remove)
        if self.file_path_needs_to_be_deleted:
            evaluationMatch = False
#check if the file has the correct owner set
        self.file_permissions_matches = self.evaluateFilePermission(self.getFilePermissions())
        if not self.file_permissions_matches:
            evaluationMatch = False
#check if the file has the correct owner set
        self.file_owner_matches = self.evaluateFileOwnerGroup(self.getFileOwner())
        if not self.file_owner_matches:
            evaluationMatch = False
#check if file has proper content
        self.file_content_matches = self.evaluateFileContent(self.getFileContent())
        if not self.file_content_matches:
            evaluationMatch = False
        return evaluationMatch

###############################################################################

    def fixFile(self):
        '''This is the standard fix routine for a rule. It goes
        though all # the KVEditors and atempts to fix everything. If it
        succeeds it returns true
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        @note: kveditorName is essential

        '''
        fixFileSuccess = True
        self.evaluateFile()
        success = True
# if file does not exist but should create it
        if success and self.file_path_needs_to_be_created:
            success = self.createFilePath(self.getFilePath(),
                                          not(self.file_remove))
            if not success:
                fixFileSuccess = False
# if file exists and needs to be removed remove it
        if success and self.file_path_needs_to_be_deleted:
            success = self.removeFilePath(self.getFilePath(),
                                          self.file_remove)
            if not success:
                fixFileSuccess = False
# if file owner/group are messed up fix them
        if success and not self.file_owner_matches:
            success = self.fixFileOwnerGroup(self.getFilePath(),
                                             self.getFileOwner(),
                                             self.getFileGroup(),
                                             True)
            if not success:
                fixFileSuccess = False
# if file permissions are messed up fix them
        if success and not self.file_permissions_matches:
            success = self.fixFilePermissions(self.getFilePath(),
                                              self.getFilePermissions(),
                                              True)
            if not success:
                fixFileSuccess = False
# if file contents are incorrect fix them
        if success and not self.file_content_matches:
            success = self.fixFileContent(self.getFilePath(),
                                          self.getFileContent(),
                                          True)
            if not success:
                fixFileSuccess = False

###############################################################################

    def evaluateFilePermission(self, desired_file_permissions=None):
        evaluationMatch = True
        if not desired_file_permissions == None:
            desired_file_permissions_masked = desired_file_permissions & 0o7777
            file_path = self.getFilePath()
            if not (file_path == ""):
#check if the file exists
                if os.path.exists(file_path):
                    permissions_masked = os.stat(file_path).st_mode & 0o7777
                    if not permissions_masked == desired_file_permissions_masked:
                        message = "for " + self.filePrefix() + \
                        " file permissions should be " + \
                        str(desired_file_permissions_masked) + \
                        " but are " + str(permissions_masked) + "!"
                        self.appendToFileMessage(message)
                        self.logdispatcher.log(LogPriority.DEBUG, message)
                        evaluationMatch = False
                else:
                    message = self.filePrefix() + " does not exist!"
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                    evaluationMatch = False
            else:
                message = "file_path is blank!"
                self.logdispatcher.log(LogPriority.DEBUG, message)
        return evaluationMatch

###############################################################################

    def evaluateFileOwnerGroup(self, desired_file_owner=None,
                               desired_file_group=None):
        evaluationMatch = True
        if not desired_file_owner == None and not desired_file_group == None:
            file_path = self.getFilePath()
            if not (file_path == ""):
#check if the file exists
                if os.path.exists(file_path):
                    if not desired_file_owner == None:
                        owner = stat(file_path).st_uid
                        if not owner == desired_file_owner:
                            message = "for file " + str(self.getFilePath()) + \
                            " file owner should be " + \
                            str(desired_file_owner) + " but is " + \
                            str(owner) + "!"
                            self.appendToFileMessage(message)
                            self.logdispatcher.log(LogPriority.DEBUG, message)
                            evaluationMatch = False
                    if not desired_file_group == None:
                        group = stat(file_path).st_gid
                        if not group == desired_file_group:
                            message = "for file " + str(self.getFilePath()) + \
                            " file group should be " + \
                            str(desired_file_group) + " but is " + \
                            str(group) + "!"
                            self.appendToFileMessage(message)
                            self.logdispatcher.log(LogPriority.DEBUG, message)
                            evaluationMatch = False
                else:
                    evaluationMatch = False
        return evaluationMatch

###############################################################################

    def evaluateFileContent(self, desiredfile_content=None):
        evaluationMatch = True
        if not desiredfile_content == None:
            if not (self.getFilePath() == ""):
#check if the file exists
                if os.path.exists(self.getFilePath()):
                    filehandle = open(str(self.getFilePath()), 'r')
                    contents = filehandle.read()
                    filehandle.close()
                    if not re.search(re.escape(desiredfile_content), contents):
                        self.file_content_matches = False
                        message = "for " + self.filePrefix() + \
                        " file content is not as desired!"
                        self.appendToFileMessage(message)
                        self.logdispatcher.log(LogPriority.DEBUG, message)
                        evaluationMatch = False
                else:
                    evaluationMatch = False
            else:
                evaluationMatch = False
        return evaluationMatch

###############################################################################

    def evaluateFileCreation(self, shouldbecreated=True):
        evaluationMatch = False
        if not (self.getFilePath() == ""):
#check if the file exists
            if not os.path.exists(self.getFilePath()):
                if shouldbecreated:
                    message = "file " + self.filePrefix() + \
                    " needs to be created!"
                    self.appendToFileMessage(message)
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                    evaluationMatch = True
            else:
                evaluationMatch = False
        return evaluationMatch

###############################################################################

    def evaluateFileRemoval(self, souldberemoved=True):
        evaluationMatch = False
        if not (self.getFilePath() == ""):
#check if the file exists
            if os.path.exists(self.getFilePath()):
                if souldberemoved:
                    message = "file " + self.filePrefix() + \
                    " needs to be removed!"
                    self.appendToFileMessage(message)
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                    evaluationMatch = True
            else:
                evaluationMatch = False
        return evaluationMatch

###############################################################################

    def removeFilePath(self, file_path="", shouldI=True):
        '''remove file_path. Only operates on absolute non blank links, files, and
        directories on UNIX file systems
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param file_path: string - The full path to the file (blank by default)
        :param shouldI: boolean - The content that should be in the file
                                  (True by default)
        :returns: boolean - (True if file_path removal worked,
                           False if it does not)
        @note: This will not work on Windows systems

        '''
        success = True
        directory = os.path.dirname(file_path)
        removaltype = ""
# blank path
        if success and file_path == "":
            success = False
            message = "file_path is empty is not an absolute path!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        if success and not (os.path.isabs(file_path)):
            success = False
            message = "'" + str(file_path) + "' is not an absolute path!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
# check if the file exists
        if success and not os.path.exists(file_path):
            success = True
            message = "'" + str(file_path) + "' does not exist!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        elif success:
            if success and os.path.islink(file_path):
                removaltype = "os.remove"
            elif success and os.path.isdir(file_path):
                removaltype = "shutil.rmtree"
            elif success and os.path.isfile(file_path):
                removaltype = "os.remove"
# Now let's remove the file_path
        if success and not removaltype == "" and not shouldI:
            message = "Would have removed directory via " + str(removaltype) + \
                "(" + file_path + ")"
            self.logdispatcher.log(LogPriority.DEBUG, message)
            success = False
        elif success and removaltype == "shutil.rmtree":
            try:
                shutil.rmtree(file_path)
                message = "removed " + file_path + " via " + removaltype + \
                "(" + file_path + ")."
                self.logdispatcher.log(LogPriority.DEBUG, message)
            except Exception as err:
                success = False
                message = removaltype + "('" + file_path + \
                "') failed with Error (" + str(err) + ") - " + \
                traceback.format_exc()
                self.logdispatcher.log(LogPriority.DEBUG, message)
                raise
        elif success and removaltype == "os.remove":
            try:
                if self.file_eventid:
                    debug = "EventID for " + file_path + ": " + \
                        str(self.file_eventid)
                    self.logdispatcher.log(LogPriority.DEBUG, debug)
                    deleteId = self.file_eventid + "d"
                    event = {"eventtype": "deletion",
                             "filepath": file_path}
                    self.statechglogger.recordfiledelete(file_path, deleteId)
                    self.statechglogger.recordchgevent(deleteId, event)
                os.remove(file_path)
                message = "removed " + file_path + " via " + removaltype + \
                "('" + file_path + "')."
                self.logdispatcher.log(LogPriority.DEBUG, message)
            except Exception as err:
                success = False
                message = removaltype + "('" + file_path + \
                "') failed with Error (" + str(err) + ") - " + \
                traceback.format_exc()
                self.logdispatcher.log(LogPriority.DEBUG, message)
                raise
        else:
            success = False
            message = "removaltype = '" + str(removaltype) + \
            "'. Could not figure out how to remove '" + file_path + "'."
            self.logdispatcher.log(LogPriority.DEBUG, message)
        if success:
            removeEmptyDirectory = self.defaultRemoveEmptyParentDirectories
            try:
                if removeEmptyDirectory and not os.listdir(directory):
                    os.rmdir(directory)
                    message = "removed " + directory + " via os.rmdir(" + \
                    directory + ")."
                    self.logdispatcher.log(LogPriority.DEBUG, message)
                    directory = os.path.dirname(directory)
            except Exception as err:
                message = "os.rmdir('" + directory + \
                "'). failed with Error (" + str(err) + ")."
                self.logdispatcher.log(LogPriority.DEBUG, message)
                raise
        return success

###############################################################################

    def createFilePath(self, file_path="", shouldI=True):
        '''remove file_path. Only operates on absolute non blank links, files, and
        directories on UNIX file systems
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param file_path: string - The full path to the file (blank by default)
        :param shouldI: boolean - The content that should be in the file
                                  (True by default)
        :returns: boolean - (True if file_path removal worked,
                           False if it does not)
        @note: This will not work on Windows systems

        '''
        success = True
        creationtype = ""
        directory = os.path.dirname(file_path)
# blank path
        if success and file_path == "":
            success = False
            message = "file_path is empty is not an absolute path!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
# we can only deal with absolute paths
        if success and not (os.path.isabs(file_path)):
            success = False
            message = "'" + str(file_path) + "' is not an absolute path!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
# if the directory does not exist create it
        if success and not os.path.exists(directory):
            message = "directory '" + str(directory) + "' for file_path '" + \
            str(file_path) + "'does not exist!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
            try:
                if self.defaultDirectoryMode == "":
                    os.makedirs(directory)
                    message = "successfully created directory '" + \
                    str(directory) + "' via os.makedirs('" + directory + "')."
                else:
                    os.makedirs(directory, self.defaultDirectoryMode)
                    message = "successfully created directory '" + \
                    str(directory) + "' via os.makedirs('" + directory + \
                    "'," + str(self.defaultDirectoryMode) + ")."
                self.logdispatcher.log(LogPriority.DEBUG, message)
            except Exception as err:
                success = False
                message = "os.makedirs('" + directory + "'," + \
                str(self.defaultDirectoryMode) + "). failed with Error '" + \
                str(err) + "' - " + traceback.format_exc()
                self.logdispatcher.log(LogPriority.DEBUG, message)
                raise
# check if the file exists
        if success and not os.path.exists(file_path):
            creationtype = "open"
        elif success:
            creationtype = "os.utime"
# Now let's remove the file_path
        if success and not creationtype == "" and not shouldI:
            if creationtype == "open":
                message = "Would created file via " + str(creationtype) + \
                "(" + file_path + ",'w').close."
                self.logdispatcher.log(LogPriority.DEBUG, message)
            elif creationtype == "os.utime":
                message = "Would created file via " + str(creationtype) + \
                "(" + file_path + ", None)."
                self.logdispatcher.log(LogPriority.DEBUG, message)
            else:
                message = "Would not have know how to handle " + \
                str(creationtype) + "."
                self.logdispatcher.log(LogPriority.DEBUG, message)
            success = False
        elif success and creationtype == "open":
            try:
                open(file_path, 'w').close()
                if self.file_eventid:
                    createId = self.file_eventid + "c"
                    event = {"eventtype": "creation",
                             "filepath": file_path}
                    self.statechglogger.recordchgevent(createId, event)
                message = "Successfully created file '" + file_path + \
                    "' via " + creationtype + "(" + file_path + ",'w').close."
                self.logdispatcher.log(LogPriority.DEBUG, message)
            except Exception as err:
                success = False
                message = creationtype + "(" + file_path + \
                ", 'w').close failed with Error '" + str(err) + "' - " + \
                traceback.format_exc()
                self.logdispatcher.log(LogPriority.DEBUG, message)
                raise
        elif success and creationtype == "os.utime":
            try:
                os.utime(file_path, None)
                message = "successfully created file '" + file_path + \
                "' via " + creationtype + "(" + file_path + ", None)."
                self.logdispatcher.log(LogPriority.DEBUG, message)
            except Exception as err:
                success = False
                message = creationtype + "(" + str(file_path) + \
                ", None) failed with Error '" + str(err) + "' - " + \
                traceback.format_exc()
                self.logdispatcher.log(LogPriority.DEBUG, message)
                raise
        else:
            success = False
            message = "Could not figure out how to remove " + file_path + "."
            self.logdispatcher.log(LogPriority.DEBUG, message)
        return success

###############################################################################

    def fixFilePermissions(self, file_path="", file_permissions=None,
                           shouldI=True):
        '''fix file permissions. Only operates on absolute non blank links, files,
        and directories on UNIX file systems
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param file_path: string - The full path to the file (blank by default)
        :param shouldI: boolean - The content that should be in the file
                                  (True by default)
        :param file_permissions:  (Default value = None)
        :returns: boolean - (True if file_path removal worked,
                           False if it does not)
        @note: This will not work on Windows systems

        '''
        success = True
        file_permissions_fixed = False
# blank path
        if success and file_path == "":
            success = False
            file_permissions_fixed = True
            message = "file_path is empty!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        if success:
            if not os.path.exists(file_path):
                success = False
                file_permissions_fixed = True
                message = "file path '" + str(file_path) + "' does not exist!"
                self.logdispatcher.log(LogPriority.DEBUG, message)
        if success and file_permissions is None:
            success = False
            file_permissions_fixed = True
            message = "file_permissions are default value of '" + \
                str(file_permissions) + "'! no action taken"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        if success:
            file_permissions_masked = file_permissions & 0o7777
            if not file_permissions == file_permissions_masked:
                message = "file_permissions of " + str(file_permissions) + \
                    " were masked to " + str(file_permissions_masked) + "!"
                self.logdispatcher.log(LogPriority.DEBUG, message)
        if success:
            try:
                if shouldI:
                    statdata = os.stat(file_path)
                    owner = statdata.st_uid
                    group = statdata.st_gid
                    mode = stat.S_IMODE(statdata.st_mode)
                    os.chmod(file_path, file_permissions_masked)
                    if self.file_eventid:
                        permId = self.file_eventid + "p"
                        event = {"eventtype": "perm",
                                 "filepath": file_path,
                                 "startstate": [owner, group, mode],
                                 "endstate": [owner, group,
                                              file_permissions_masked]}
                        self.statechglogger.recordchgevent(permId,
                                                           event)
                    message = "File Permissions for '" + file_path + \
                        "' were successfully updated to '" + \
                        str(file_permissions_masked) + "'"
                    file_permissions_fixed = True
                else:
                    message = "File Permissions for '" + file_path + \
                        "' should be fixed to '" + str(file_permissions_masked) + \
                        "' but shouldI was set to '" + str(shouldI) + "'!"
                    file_permissions_fixed = False
                self.appendToFileMessage(message)
                self.logdispatcher.log(LogPriority.DEBUG, message)
            except Exception as err:
                success = False
                message = "os.chmod('" + file_path + "'," + \
                    str(file_permissions_masked) + "). failed with Error '" + \
                    str(err) + "' - " + traceback.format_exc()
                self.appendToFileMessage(message)
                self.logdispatcher.log(LogPriority.DEBUG, message)
                raise
        return file_permissions_fixed

###############################################################################

    def fixFileOwnerGroup(self, file_path="", file_owner=None, file_group=None,
                          shouldI=True):
        '''fix file owner & group. Only operates on absolute non blank links,
        files, and directories on UNIX file systems
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param file_path: string - The full path to the file (blank by default)
        :param shouldI: boolean - The content that should be in the file
                                  (True by default)
        :param file_owner:  (Default value = None)
        :param file_group:  (Default value = None)
        :returns: boolean - (True if file_path removal worked,
                           False if it does not)
        @note: This will not work on Windows systems

        '''
        success = True
        file_owner_fixed = False
        file_group_fixed = False
# blank path
        if success and file_path == "":
            success = False
            file_owner_fixed = True
            file_group_fixed = True
            message = "file_path is empty is not an absolute path!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        if success:
            if not os.path.exists(file_path):
                success = False
                file_owner_fixed = True
                file_group_fixed = True
                message = "file path '" + str(file_path) + "' does not exist!"
                self.logdispatcher.log(LogPriority.DEBUG, message)
        if success and file_owner == None and file_group == None:
            success = False
            file_owner_fixed = True
            file_group_fixed = True
            message = "file owner and file goup are at default values of " + \
            "owner='" + str(file_owner) + "' group='" + str(file_group) + \
            "'! no action taken"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        if success and file_owner == None:
            file_owner_fixed = True
            file_owner = -1
            message = "file owner is at default values of owner='" + \
            str(file_owner) + "'! no action taken"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        if success and file_group == None:
            file_group_fixed = True
            file_group = -1
            message = "file goup are at default value of group='" + \
            str(file_group) + "'! no action taken"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        if success and (not file_owner_fixed or not file_group_fixed):
            try:
                if shouldI:
                    os.chown(file_path, file_owner, file_group)
                    message = "File owner and file group for '" + file_path + \
                    "' were successfully updated to owner='" + \
                    str(file_owner) + "' group='" + str(file_group) + "'!"
                    file_owner_fixed = True
                    file_group_fixed = True
                else:
                    message = "File owner and file group for '" + file_path + \
                    "' should updated to owner='" + str(file_owner) + \
                    "' group='" + str(file_group) + \
                    "'! But shouldI is set to '" + str(shouldI)
                    file_owner_fixed = False
                    file_group_fixed = False
                self.appendToFileMessage(message)
                self.logdispatcher.log(LogPriority.DEBUG, message)
            except Exception as err:
                success = False
                file_owner_fixed = False
                file_group_fixed = False
                message = "os.chown('" + str(file_path) + "'," + \
                str(file_owner) + "','" + str(file_group) + \
                "'). failed with Error '" + str(err) + "' - " + \
                traceback.format_exc()
                self.appendToFileMessage(message)
                self.logdispatcher.log(LogPriority.DEBUG, message)
                raise
        return file_owner_fixed or file_group_fixed

###############################################################################

    def fixFileContent(self, file_path="", file_content=None, shouldI=True):
        success = True
        file_content_fixed = False
        if success and file_path == "":
            success = False
            file_content_fixed = True
            message = "file_path is empty is not an absolute path!"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        if success:
            if not os.path.exists(file_path):
                success = False
                file_content_fixed = True
                message = "file path '" + str(file_path) + "' does not exist!"
                self.logdispatcher.log(LogPriority.DEBUG, message)
        if success and file_content is None:
            file_content_fixed = True
            message = "File content is at default values of content='" + \
                str(file_content) + "'! No action taken"
            self.logdispatcher.log(LogPriority.DEBUG, message)
        if success:
            if not shouldI:
                file_content_fixed = False
                success = False
        if success and not file_content_fixed:
            try:
                if shouldI:
                    tmpfile = file_path + ".stonixtmp"
                    if writeFile(tmpfile, file_content, self.logdispatcher) \
                       and self.file_eventid:
                        createId = self.file_eventid + "c"
                        event = {'eventtype': 'conf',
                                 'filepath': file_path}
                        self.statechglogger.recordchgevent(createId,
                                                           event)
                        self.statechglogger.recordfilechange(file_path,
                                                             tmpfile,
                                                             createId)
                        os.rename(tmpfile, file_path)
                        perms = self.getFilePermissions()
                        if perms is not None:
                            os.chmod(file_path, perms)
                        resetsecon(file_path)
                        message = "File content for '" + file_path + \
                            "' were successfully updated to content='" + \
                            str(file_content) + "'!"
                        file_content_fixed = True
                    else:
                        message = "Could not write new contents to " + tmpfile
                        file_content_fixed = False
                else:
                    message = "File content for '" + file_path + \
                        "' should updated to content='" + str(file_content) + \
                        "'! But shouldI is set to '" + str(shouldI) + "'"
                    file_content_fixed = False
                self.appendToFileMessage(message)
                self.logdispatcher.log(LogPriority.DEBUG, message)
            except Exception as err:
                success = False
                file_content_fixed = False
                message = "Error writing new contents to " + str(file_path) + \
                    ". Failed with error '" + str(err) + "' - " + \
                    traceback.format_exc()
                self.appendToFileMessage(message)
                self.logdispatcher.log(LogPriority.DEBUG, message)
                raise
        return file_content_fixed

###############################################################################

    def getFileHelperValues(self, file_label):
        '''gets a kveditor by name and loads it into the current kveditor values
        of the object.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param file_label: string - required kveditorname
        :returns: boolean - true

        '''
        self.saveFileHelperValues()
        self.file_label = file_label
        item = self.filedictionary[self.file_label]
        if not (item == None):
            self.file_path = item["file_path"]
            self.file_path_backup =  item["file_path_backup"]
            self.file_remove = item["file_remove"]
            self.file_path_not_evaluated = item["file_path_not_evaluated"]
            self.file_path_non_blank = item["file_path_non_blank"]
            self.file_path_needs_to_be_created = item["file_path_needs_to_be_created"]
            self.file_path_needs_to_be_deleted = item["file_path_needs_to_be_deleted"]
            self.file_path_exists = item["file_path_exists"]
            self.file_content = item["file_content"]
            self.file_content_matches = item["file_content_matches"]
            self.file_permissions = item["file_permissions"]
            self.file_permissions_matches = item["file_permissions_matches"]
            self.file_owner = item["file_owner"]
            self.file_owner_matches = item["file_owner_matches"]
            self.file_group = item["file_group"]
            self.file_group_matches = item["file_group_matches"]
            self.file_messages = item["file_messages"]
            self.file_eventid = item["file_eventid"]
        else:
            self.resetFileHelperValues()
        return True

###############################################################################

    def saveFileHelperValues(self):
        '''saves the current kveditor values into the dictionary.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param file_label: string - required kveditorname
        :returns: boolean - true

        '''
        if not (self.file_label == ""):
            item = {"file_path": self.file_path,
                    "file_path_backup": self.file_path_backup,
                    "file_remove": self.file_remove,
                    "file_path_not_evaluated": self.file_path_not_evaluated,
                    "file_path_non_blank": self.file_path_non_blank,
                    "file_path_needs_to_be_created":
                    self.file_path_needs_to_be_created,
                    "file_path_needs_to_be_deleted":
                    self.file_path_needs_to_be_deleted,
                    "file_path_exists": self.file_path_exists,
                    "file_content": self.file_content,
                    "file_content_matches": self.file_content_matches,
                    "file_permissions": self.file_permissions,
                    "file_permissions_matches": self.file_permissions_matches,
                    "file_owner": self.file_owner,
                    "file_owner_matches": self.file_owner_matches,
                    "file_group": self.file_group,
                    "file_group_matches": self.file_group_matches,
                    "file_messages": self.file_messages,
                    "file_eventid": self.file_eventid}
            self.filedictionary[self.file_label] = item
        else:
            self.resetFileHelperValues()
        return True

###############################################################################

    def resetFileHelperValues(self):
        '''reset the current file values to their defaults.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :returns: boolean - true

        '''
        self.file_label = ""
        self.file_path = ""
        self.file_path_backup = ""
        self.file_content = None
        self.file_permissions = None
        self.file_owner = None
        self.file_group = None
        self.file_remove = False
        self.file_eventid = None
        self.evaluationReset()
        return True

###############################################################################

    def evaluationReset(self):
        self.file_path_not_evaluated = True
        self.file_path_non_blank = True
        self.file_path_needs_to_be_created = True
        self.file_path_needs_to_be_deleted = True
        self.file_path_exists = True
        self.file_content_matches = True
        self.file_permissions_matches = True
        self.file_owner_matches = True
        self.file_group_matches = True
        self.file_messages = ""
        return True

###############################################################################

    def appendToFileMessage(self, message):
        if self.file_messages == "":
            self.file_messages = message
        else:
            self.file_messages = self.file_messages + '''
''' + message
        return True

###############################################################################

    def resetFileMessage(self):
        self.file_messages = ""
        return True

###############################################################################

    def filePrefix(self):
        prefix = "('" + str(self.file_label) + "','" + str(self.file_path) + \
        "')"
        return prefix
