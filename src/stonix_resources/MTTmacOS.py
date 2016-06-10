'''
###############################################################################
#                                                                             #
# Copyright 2016.  Los Alamos National Security, LLC. This material was       #
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

@author: ekkehard
@change: 2016/06/10 original implementation
'''

from __future__ import unicode_literals
from ctypes import cdll, byref, Structure, c_char, c_char_p
from ctypes.util import find_library
from .compat import binary_type

Foundation = cdll.LoadLibrary(find_library('Foundation'))
CoreServices = cdll.LoadLibrary(find_library('CoreServices'))

GetMacOSStatusCommentString = Foundation.GetMacOSStatusCommentString
GetMacOSStatusCommentString.restype = c_char_p
FSPathMakeRefWithOptions = CoreServices.FSPathMakeRefWithOptions
FSMoveObjectToTrashSync = CoreServices.FSMoveObjectToTrashSync

kFSPathMakeRefDefaultOptions = 0
kFSPathMakeRefDoNotFollowLeafSymlink = 0x01

kFSFileOperationDefaultOptions = 0
kFSFileOperationOverwrite = 0x01
kFSFileOperationSkipSourcePermissionErrors = 0x02
kFSFileOperationDoNotMoveAcrossVolumes = 0x04
kFSFileOperationSkipPreflight = 0x08

class FSRef(Structure):
    _fields_ = [('hidden', c_char * 80)]

class MTTmacOS(object):

    def __init__(self, logdispatcher):
        self.logdispatcher = logdispatcher
        self.filepathlist = []
        self.fp = FSRef()
        self.encoding = 'utf-8'

    def appendFilePath(self, filepath):
        if not filepath == "":
            if not isinstance(filepath, binary_type):
                filepath = filepath.encode(self.encoding)
            self.filepathlist.append(filepath)
        return self.filepathlist

    def getFilePaths(self):
        return self.filepathlist

    def resetFilePaths(self):
        self.filepathlist = []
        return self.filepathlist
    
    def setFilePaths(self, filepaths):
        self.resetFilePaths()
        for filepath in filepaths:
            self.appendFilePath(filepath)
        
    def Send(self, filepaths):
        success = True
        self.setFilePaths(filepaths)
        if not self.filepathlist == []:
            for filepath in self.filepathlist:
                options = kFSPathMakeRefDoNotFollowLeafSymlink
                operationResults = FSPathMakeRefWithOptions(filepath, options, byref(self.fp), None)
                self.checkOperationResults(operationResults)
                options = kFSFileOperationDefaultOptions
                operationResults = FSMoveObjectToTrashSync(byref(self.fp), None, options)
                self.checkOperationResults(operationResults)
        return success

    def checkOperationResults(self, operationResults):
        if operationResults:
            msg = GetMacOSStatusCommentString(operationResults).decode(self.encoding)
            raise OSError(msg)
    