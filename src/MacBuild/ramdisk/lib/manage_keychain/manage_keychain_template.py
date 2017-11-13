"""
Interface or template class for the individual ManageKeychain 
implementations

For usage of *args and **kwargs, see:
https://pythontips.com/2013/08/04/args-and-kwargs-in-python-explained/
http://lmgtfy.com/?q=python+*args+**kwargs

@author: Roy Nielsen
"""
class ManageKeychainTemplate(object):
    """
    """
    def __init__(self, **kwargs):
        """
        Initialization Method
        
        @author: Roy Nielsen
        """
        if 'logDispatcher' not in kwargs:
            raise ValueError("Variable 'logger' a required parameter for " + str(self.__class__.__name__))
        else:
            self.logger = kwargs.get('logDispatcher')
    
    def listKeychains(self):
        '''
        Display or manipulate the keychain search list.
        
        @author: Roy Nielsen
        '''
        success = False
        self.logger.log("listKeychains method not yet implemented.")
        return success

    def defaultKeychain(self):
        '''
        Display or set the default keychain.
        
        @author: Roy Nielsen
        '''
        success = False
        self.logger.log("defaultKeychain method not yet implemented.")
        return success

    def loginKeychain(self):
        '''
        Display or set the login keychain.
        
        @author: Roy Nielsen
        '''
        success = False
        self.logger.log("loginKeychain method not yet implemented.")
        return success

    def createKeychain(self, *args, **kwargs):
        """
        Create a keychain.
        
        @author: Roy Nielsen
        """
        success = False
        self.logger.log("createKeychain method not yet implemented.")
        return success

    def deleteKeychain(self, *args, **kwargs):
        """
        Delete keychains and remove them from the search list.
        
        @author: Roy Nielsen
        """
        success = False
        self.logger.log("deleteKeychain method not yet implemented.")
        return success

    def lockKeychain(self, *args, **kwargs):
        """
        Unlock the defined keychain
        
        @author: Roy Nielsen
        """
        success = False
        self.logger.log("lockKeychain method not yet implemented.")
        return success

    def unlockKeychain(self, *args, **kwargs):
        """
        Unlock the defined keychain
        
        @author: Roy Nielsen
        """
        success = False
        self.logger.log("unlockKeychain method not yet implemented.")
        return success

    def changeKeychainPassword(self, *args, **kwargs):
        """
        Change a keychain password
        
        @author: Roy Nielsen
        """
        success = False
        self.logger.log("changeKeychainPassword method not yet implemented.")
        return success

    def showKeychainInfo(self, keychain, *args, **kwargs):
        '''
        Show the settings for a keychain.

        @author: Roy Nielsen
        '''
        success = False
        self.logger.log("showKeychainInfo method not yet implemented.")
        return success

    def dumpKeychain(self, *args, **kwargs):
        '''
        Dump the contents of one or more keychains.

        @author: Roy Nielsen
        '''
        success = False
        self.logger.log("dumpKeychain method not yet implemented.")
        return success

    def findCertificate(self, *args, **kwargs):
        '''
        Find a certificate item.

        @author: Roy Nielsen
        '''
        success = False
        self.logger.log("findCertificate method not yet implemented.")
        return success

    def findIdentity(self, *args, **kwargs):
        '''
        Find an identity (certificate + private key).

        @author: Roy Nielsen
        '''
        success = False
        self.logger.log("findIdentity method not yet implemented.")
        return success

    def error(self, *args, **kwargs):
        '''
        Display descrip6tive message for the given error code(s).

        @author: Roy Nielsen
        '''
        success = False
        self.logger.log("error method not yet implemented.")
        return success
