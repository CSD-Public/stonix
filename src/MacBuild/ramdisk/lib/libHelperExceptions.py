"""
Class for ramdisk management specific creations

Should be OS agnostic

@author: Roy Nielsen
"""
from __future__ import absolute_import

class UnsupportedOSError(Exception):
    """
    Meant for being thrown when an action/class being run/instanciated is not
    applicable for the running operating system.

    @author: Roy Nielsen
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class NotValidForThisOS(Exception):
    """
    Meant for being thrown when an action/class being run/instanciated is not
    applicable for the running operating system.

    @author: Roy Nielsen
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class SystemToolNotAvailable(Exception):
    """
    Meant for being thrown when a system command is not available for
    use by the library.

    @author: Roy Nielsen
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class NotEnoughMemoryError(Exception):
    """
    Thrown when there is not enough memory for this operation.

    @author: Roy Nielsen
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

def NotACyLoggerError(BaseException):
    """
    Custom Exception
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

