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
import MTTmacOS

class MoveToTrash(object):
    '''
    MoveToTrash is a factory object that implements moving files and folders 
    to the trash for all supported operating systems

    @author: ekkehard
    '''

    def __init__(self, environment, logdispatcher):
        '''
        The ServiceHelper needs to receive the STONIX environment and
        logdispatcher objects as parameters to init.

        @param environment: STONIX environment object
        @param logdispatcher: STONIX logdispather object
        '''
        self.environ = environment
        self.logdispatcher = logdispatcher
        if self.environ.getostype() == "Mac OS X":
            self.MTTObject = MTTmacOS.MTTmacOS(self.logdispatcher)
        else:
            self.MTTObject = None

    def appendFilePath(self, filepath):
        filepathlist = []
        if not self.MTTObject == None:
            filepathlist = self.MTTObject.appendFilePath(filepath)
        return filepathlist

    def getFilePaths(self):
        filepathlist = []
        if not self.MTTObject == None:
            filepathlist = self.MTTObject.getFilePaths()
        return filepathlist

    def resetFilePaths(self):
        filepathlist = []
        if not self.MTTObject == None:
            filepathlist = self.MTTObject.resetFilePaths()
        return filepathlist
    
    def setFilePaths(self, filepaths):
        filepathlist = []
        if not self.MTTObject == None:
            filepathlist = self.MTTObject.setFilePaths(filepaths)
        return filepathlist

    def Send(self, filepaths):
        success = True
        if not self.MTTObject == None:
            success = self.MTTObject.Send(filepaths)
        return success
