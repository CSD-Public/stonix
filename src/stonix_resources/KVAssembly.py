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
