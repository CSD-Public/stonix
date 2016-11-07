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
        pass
    
    def lockKeychain(self, *args, **kwargs):
        """
        Unlock the defined keychain
        
        @author: Roy Nielsen
        """
        pass

    def unlockKeychain(self, *args, **kwargs):
        """
        Unlock the defined keychain
        
        @author: Roy Nielsen
        """
        pass

    def changeKeychainPassword(self, *args, **kwargs):
        """
        Change a keychain password
        
        @author: Roy Nielsen
        """
        pass

    def deleteKeychain(self, *args, **kwargs):
        """
        Delete keychain
        
        @author: Roy Nielsen
        """
        pass

    def createKeychain(self, *args, **kwargs):
        """
        Create a keychain.
        
        @author: Roy Nielsen
        """
        pass
