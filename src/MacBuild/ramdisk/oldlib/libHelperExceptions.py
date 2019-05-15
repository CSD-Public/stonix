"""
Class for ramdisk management specific creations

Should be OS agnostic

@author: Roy Nielsen
"""

class NotValidForThisOS(Exception):
    '''Meant for being thrown when an action/class being run/instanciated is not
    applicable for the running operating system.
    
    @author: Roy Nielsen


    '''
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

