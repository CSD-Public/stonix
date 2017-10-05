'''
###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
# produced under U.S. Government contract DE-AC52-06NA25396 for Los Alamos    #
# National Laboratory (LANL), which is operated by Los Alamos National        #
# Security, LLC for the U.S. Department of Energy. The U.S. Government has    #
# rights to use, reproduce, and distribute this software.  NEITHER THE        #
# GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY, LLC MAKES ANY WARRANTY,        #
# EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.  #
# If software is modified to produce derivative works, such modified software #
# should be clearly marked, so as not to confuse it with the version          #
# available from LANL.                                                        #
#                                                                             #
# Additionally, this program is free software; you can redistribute it and/or #
# modify it under the terms of the GNU General Public License as published by #
# the Free Software Foundation; either version 2 of the License, or (at your  #
# option) any later version. Accordingly, this program is distributed in the  #
# hope that it will be useful, but WITHOUT ANY WARRANTY; without even the     #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    #
# See the GNU General Public License for more details.                        #
#                                                                             #
###############################################################################
Created on November 3, 2016

@author: rsn

Note: Each concrete helper will inherit this class, which will be the default 
      behavior of all service helpers.
'''
from __builtin__ import False

class ServiceHelperTemplate(object):
    '''
    The ServiceHelper class serves as an abstraction layer between rules that
    need to manipulate services and the actual implementation of changing
    service status on various operating systems.

    @Note: Interface methods abstracted to allow for different parameter
           lists for different helpers.  This moves the requirement for 
           input validation the the concrete helpers.

    @author: dkennel
    '''

    def __init__(self, environment, logdispatcher):
        '''
        The ServiceHelper needs to receive the STONIX environment and
        logdispatcher objects as parameters to init.

        @param environment: STONIX environment object
        '''
        self.environ = environment
        self.logdispatcher = logdispatcher

    #----------------------------------------------------------------------
    # helper Methods
    #----------------------------------------------------------------------

    def getHelper(self):
        """
        Getter to acqure the currently specified service helper
        """
        return self

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

    def setService(self, *args, **kwargs):
        '''
        Update the name of the service being worked with.

        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This service helper not yet in production.')
        self.__calledBy()
        return False

    #----------------------------------------------------------------------
    # Standard interface to the service helper.
    #----------------------------------------------------------------------

    def disableService(self, service, *args, **kwargs):
        '''
        Disables the service and terminates it if it is running.

        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        return False

    #----------------------------------------------------------------------

    def enableService(self, service, *args, **kwargs):
        '''
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        return False

    #----------------------------------------------------------------------

    def auditService(self, service, *args, **kwargs):
        '''
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @return: Bool, True if the service is configured to run
        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        return False

    #----------------------------------------------------------------------

    def isRunning(self, service, *args, **kwargs):
        '''
        Check to see if a service is currently running. The enable service uses
        this so that we're not trying to start a service that is already
        running.

        @return: bool, True if the service is already running
        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        return False

    #----------------------------------------------------------------------

    def reloadService(self, service, *args, **kwargs):
        '''
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active. This method ignores services that do not return true when
        self.isrunning() is called. The assumption being that this method is
        being called due to a change in a conf file, and a service that isn't
        currently running will pick up the change when (if) it is started.

        @return: bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        return False

    #----------------------------------------------------------------------

    def listServices(self):
        '''
        List the services installed on the system.

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        return False

    #----------------------------------------------------------------------

    def kill(self, process, *args, **kwargs):
        '''
        Kills a process with a unix signal.

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        return False

    #----------------------------------------------------------------------

    def start(self, service, *args, **kwargs):
        '''
        Start a service installed on the system.

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        return False

    #----------------------------------------------------------------------

    def stop(self, service, *args, **kwargs):
        '''
        Stop a service installed on the system.

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        return False

    #----------------------------------------------------------------------

    def restart(self, service, *args, **kwargs):
        '''
        Restart a service installed on the system.

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        return False

