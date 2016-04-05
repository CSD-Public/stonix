"""
Helper functions, OS agnostic

@author: Roy Nielsen
"""
from __future__ import absolute_import
#--- Native python libraries
import os
import sys
import ctypes
from subprocess import Popen, STDOUT, PIPE

#--- non-native python libraries in this source tree
from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp

def getOsFamily():
    """
    Get the os name from the "uname -s" command

    @author: Roy Nielsen
    """

    operatingsystemfamily = sys.platform

    return operatingsystemfamily

##############################################################################
