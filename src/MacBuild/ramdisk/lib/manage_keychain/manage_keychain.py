"""
Factory object for acquiring the right keychain manager

@note: Defined interface methods work somewhat like generic decorators that have
       a preprocess and postprocess step.

@note: If the generic interface doesn't have enough functionality, the
       factory has a method to return the specific keychain manager.

@author: Roy Nielsen
"""
from __future__ import absolute_import
import sys
import inspect

from ..loggers import LogPriority as lp
from ..libHelperExceptions import UnsupportedOSError

class ManageKeychain(object):
    """
    Factory object for acquiring the right keychain manager
    
    @note: Defined interface methods work somewhat like generic decorators that have
           a preprocess and postprocess step.
    
    @note: If the generic interface doesn't have enough functionality, the
           factory has a method to return the specific keychain manager.
    
    @author: Roy Nielsen
    """

    #----------------------------------------------------------------------

    def __init__(self, logger=False):
        """
        Class initialization method
        """
        #####
        # Set up logging
        self.logger = logger
        self.logger.log(lp.INFO, "Logger: " + str(self.logger))

        if sys.platform.lower() == "darwin":
            self.logger.log(lp.DEBUG, "Loading Mac keychain manager...")
            from .macos_keychain import MacOSKeychain
            self.keychainMgr = MacOSKeychain(logDispatcher=self.logger)
        else:
            raise UnsupportedOSError("This operating system is not supported...")

    #----------------------------------------------------------------------
    # helper Methods
    #----------------------------------------------------------------------
    def getSpecificManager(self):
        """
        Getter to acqure the specific keychain manager
        """
        return self.keychainMgr

    #----------------------------------------------------------------------

    def __calledBy(self):
        """
        Log the caller of the method that calls this method
        
        @author: Roy Nielsen
        """
        try:
            filename = inspect.stack()[2][1]
            functionName = str(inspect.stack()[2][3])
            lineNumber = str(inspect.stack()[2][2])
        except Exception, err:
            raise err
        else:
            self.logger.log(lp.DEBUG, "called by: " + \
                                      filename + ": " + \
                                      functionName + " (" + \
                                      lineNumber + ")")

    #----------------------------------------------------------------------

    def setUser(self, *args, **kwargs):
        """
        Setter for the user property of the concrete class.
        
        @author: Roy Nielsen
        """
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.keychainMgr.setUser(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success        

    #----------------------------------------------------------------------
    # Defined Interface methods
    #----------------------------------------------------------------------

    def lockKeychain(self, *args, **kwargs):
        """
        Unlock the defined keychain
        
        @author: Roy Nielsen
        """
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.keychainMgr.unlockKeychain(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def unlockKeychain(self, *args, **kwargs):
        """
        Unlock the defined keychain
        
        @author: Roy Nielsen
        """
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.keychainMgr.unlockKeychain(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def changeKeychainPassword(self, *args, **kwargs):
        """
        Change a keychain password
        
        @author: Roy Nielsen
        """
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.keychainMgr.changeKeychainPassword(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def deleteKeychain(self, *args, **kwargs):
        """
        Delete keychain
        
        @author: Roy Nielsen
        """
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.keychainMgr.deleteKeychain(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def createKeychain(self, *args, **kwargs):
        """
        Create a keychain.
        
        @author: Roy Nielsen
        """
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.logger.log(lp.DEBUG, "called by: " + inspect.stack()[1][1] + ": " + str(inspect.stack()[1][3]) + " (" + str(inspect.stack()[1][2]) + ")")
        #####
        # Call factory created object's mirror method
        success = self.keychainMgr.createKeychain(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success
