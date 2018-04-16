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
import traceback

from ..loggers import LogPriority as lp
from ..loggers import CyLogger
from ..libHelperExceptions import UnsupportedOSError, NotACyLoggerError

class ManageKeychain(object):
    """
    Factory object for acquiring the right keychain manager
    
    @note: Defined interface methods work somewhat like generic decorators that have
           a preprocess and postprocess step.
    
    @note: If the generic interface doesn't have enough functionality, the
           factory has a method to return the specific keychain manager.

    @note: Methods may return a bool, list or dictionary depending on the 
           concrete implementation of the keychain manager for a specific
           OS or application.

    @author: Roy Nielsen
    """

    #----------------------------------------------------------------------

    def __init__(self, logger):
        """
        Class initialization method
        """
        #####
        # Set up logging
        if isinstance(logger, CyLogger):
            self.logger = logger
        else:
            raise NotACyLoggerError("Passed in value for logger is invalid, try again.")

        self.logger.log(lp.INFO, "Logger: " + str(self.logger))

        if sys.platform.lower() == "darwin":
            self.logger.log(lp.DEBUG, "Loading Mac keychain manager...")
            from ..manage_keychain.macos_keychain import MacOSKeychain
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
            self.logger.log(lp.WARNING, traceback.format_exc())
            self.logger.log(lp.WARNING, str(err))
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

    def listKeychain(self, *args, **kwargs):
        """
        Display or manipulate the keychain search list.

        @author: Roy Nielsen
        """
        success = False

        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()

        #####
        # Call factory created object's mirror method
        success, output = self.keychainMgr.listKeychains(*args, **kwargs)

        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

    #----------------------------------------------------------------------

    def defaultKeychain(self, *args, **kwargs):
        """
        Display or set the default keychain.
        
        @author: Roy Nielsen
        """
        success = False

        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()

        #####
        # Call factory created object's mirror method
        success, output = self.keychainMgr.defaultKeychain(*args, **kwargs)

        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

    #----------------------------------------------------------------------

    def loginKeychain(self, *args, **kwargs):
        '''
        Display or set the login keychain.
        
        @author: Roy Nielsen
        '''
        success = False

        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()

        #####
        # Call factory created object's mirror method
        success, output = self.keychainMgr.loginKeychain(*args, **kwargs)

        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

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
        success, output = self.keychainMgr.createKeychain(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

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
        success, output = self.keychainMgr.deleteKeychain(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

    def lockKeychain(self, *args, **kwargs):
        """
        Unlock the defined keychain
        
        @author: Roy Nielsen
        """
        success = False
        output = ''
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success, output = self.keychainMgr.unlockKeychain(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

    #----------------------------------------------------------------------

    def unlockKeychain(self, *args, **kwargs):
        """
        Unlock the defined keychain
        
        @author: Roy Nielsen
        """
        success = False
        output = ''
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success, output = self.keychainMgr.unlockKeychain(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

    #----------------------------------------------------------------------

    def changeKeychainPassword(self, *args, **kwargs):
        """
        Change a keychain password
        
        @author: Roy Nielsen
        """
        success = False
        output = ''
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success, output = self.keychainMgr.changeKeychainPassword(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

    #----------------------------------------------------------------------

    def showKeychainInfo(self, keychain, *args, **kwargs):
        '''
        Show the settings for a keychain.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success, output = self.keychainMgr.showKeychainInfo(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

    #----------------------------------------------------------------------

    def dumpKeychain(self, *args, **kwargs):
        '''
        Dump the contents of one or more keychains.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success, output = self.keychainMgr.dumpKeychain(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

    #----------------------------------------------------------------------

    def findCertificate(self, *args, **kwargs):
        '''
        Find a certificate item.
        
        @author: Roy Nielsen
        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success, output = self.keychainMgr.findCertificate(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

    #----------------------------------------------------------------------

    def findIdentity(self, *args, **kwargs):
        '''
        Find an identity (certificate + private key).
        
        @author: Roy Nielsen
        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success, output = self.keychainMgr.findIdentity(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output

    #----------------------------------------------------------------------

    def error(self, *args, **kwargs):
        '''
        Display descrip6tive message for the given error code(s).
        
        @author: Roy Nielsen
        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success, output = self.keychainMgr.error(*args, **kwargs)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, output
