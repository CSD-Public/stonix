"""
Custom exceptions with the potential of
being used in multiple locations.

"""

class UnsupportedOsError(Exception):
    """ 
    Meant for being thrown when an action/class being run/instanciated is not
    applicable for the running operating system.

    @author: Roy Nielsen
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


