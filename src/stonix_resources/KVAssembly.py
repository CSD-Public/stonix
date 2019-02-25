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
Created on Apr 8, 2013

@author: dwalker,ekkehard
'''


class KVAssembly(object):

    def __init__(self):
        self.path = ""
        self.tmpPath = ""
        self.value = ""
        self.data = None

    def commit(self):
        pass

    def getvalue(self):
        return self.value

    def setPath(self, path):
        self.path = path
        return self.path

    def setTmpPath(self, tmpPath):
        self.tmppath = tmpPath
        return self.tmppath

    def update(self, data):
        self.data = data
        pass

    def validate(self, data):
        self.value = ""
        self.data = data
        pass

    def updatedata(self, data):
        self.data = data
        pass
