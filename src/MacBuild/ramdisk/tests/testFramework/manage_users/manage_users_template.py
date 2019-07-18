"""
Cross platform user creation and management

Created for testing cross user testing for the ramdisk project, specifically
unionfs functionality.

@author: Roy Nielsen
"""


class ManagerUsersTemplate(object):
    '''Class to manage user properties.
    
    @author: Roy Nielsen


    '''
    def __init__(self, logger, userName="", userShell="/bin/bash",
                       userComment="", userUid=10000, userPriGid=20,
                       userHomeDir="/tmp"):
        pass

    def setUserName(self):
        ''' '''
        pass

    def setUserShell(self, user="", shell=""):
        '''

        :param user:  (Default value = "")
        :param shell:  (Default value = "")

        '''
        pass

    def setUserComment(self, user="", comment=""):
        '''

        :param user:  (Default value = "")
        :param comment:  (Default value = "")

        '''
        pass

    def setUserUid(self, user="", uid=""):
        '''

        :param user:  (Default value = "")
        :param uid:  (Default value = "")

        '''
        pass

    def setUserPriGid(self, user="", priGid=""):
        '''

        :param user:  (Default value = "")
        :param priGid:  (Default value = "")

        '''
        pass

    def setUserHomeDir(self, user="", userHome = ""):
        '''

        :param user:  (Default value = "")
        :param userHome:  (Default value = "")

        '''
        pass

    def addUserToGroup(self, user="", group=""):
        '''

        :param user:  (Default value = "")
        :param group:  (Default value = "")

        '''
        pass

    def setUserPassword(self, user="", password=""):
        '''

        :param user:  (Default value = "")
        :param password:  (Default value = "")

        '''
        pass

