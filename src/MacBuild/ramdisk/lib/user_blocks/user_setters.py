import re

from ..Environment import Environment
from ..CheckApplicable import CheckApplicable
from ..loggers import LogPriority as lp

class UserSetters(object):
    '''
    '''
    def __init__(self, *args, **kwargs):
        '''
        Initialization method
        '''
        self.logger = logger
        #####
        # Set values to validate use of the correct information in the class.
        self.macApplicable = {'type': 'white', 'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}
        self.nixApplicable = {'type': 'white', 'family': ['linux', 'solaris', 'freebsd']}

    def getUserObject(self, directoryIdentifier="local"):
        '''
        Return an appropriate setter, either matching a user directory or 
        OS or both.
        
        @param: directoryIdentifier - Where to look for user info.  Initial only
                                      on the local system.  Later LDAP and AD
                                      directory support may be added.

        @author: Roy Nielsen
        '''
        self.userSetters = None
        #####
        # Validate expected required input        
        if isinstance(directoryIdentifier, basestring) and \
           re.match("^local$", directoryIdentifier):

            #####
            # Check for macOS and instanciate appropriate setter
            chkApp.setApplicable(macApplicable)
            if chkApp.isapplicable():
                #####
                # macOS specific imports
                from .local_macos_setters import LocalMacosSetters
                self.userSetters = LocalMacosSetters(self.loggers)

            chkApp.setApplicable(nixApplicable)                
            if chkApp.isapplicable():
                from .local_nix_setters import LocalNixSetters
                self.userSetters = LocalNixSetters(self.loggers)
                
        return self.userSetters
