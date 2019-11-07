###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
#                                                                             #
###############################################################################

'''
Created on November 3, 2016

@author: rsn

Note: Each concrete helper will inherit this class, which will be the default 
      behavior of all service helpers.
'''
import inspect

from stonix_resources.logdispatcher import LogPriority


class MethodNotImplementedError(Exception):
    '''Meant for being thrown in the template, for when a class that
    inherits ServiceHelperTemplate does not implement a method, this


    :raises author: Roy Nielsen

    '''
    def __init__(self, *args, **kwargs):
        super(MethodNotImplementedError, self).__init__(self, *args, **kwargs)


class ServiceHelperTemplate(object):
    '''The ServiceHelper class serves as an abstraction layer between rules that
    need to manipulate services and the actual implementation of changing
    service status on various operating systems.
    
    @Note: Interface methods abstracted to allow for different parameter
           lists for different helpers.  This moves the requirement for
           input validation the the concrete helpers.
    
    @author: dkennel


    '''

    def __init__(self, environment, logger):
        '''
        The ServiceHelper needs to receive the STONIX environment and
        logdispatcher objects as parameters to init.

        @param environment: STONIX environment object
        '''
        self.environ = environment
        self.logdispatcher = logger

    #----------------------------------------------------------------------
    # helper Methods
    #----------------------------------------------------------------------

    def getHelper(self):
        '''Getter to acqure the currently specified service helper'''
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
        except Exception as err:
            raise err
        else:
            self.logdispatcher.log(LogPriority.DEBUG, "called by: " + \
                                      filename + ": " + \
                                      functionName + " (" + \
                                      lineNumber + ")")

    #----------------------------------------------------------------------

    def setService(self, service, **kwargs):
        '''Update the name of the service being worked with.

        :param service: 
        :param **kwargs: 
        :returns: Bool indicating success status

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This service helper not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    #----------------------------------------------------------------------
    # Standard interface to the service helper.
    #----------------------------------------------------------------------

    def disableService(self, service, **kwargs):
        '''Disables the service and terminates it if it is running.

        :param service: 
        :param **kwargs: 
        :returns: Bool indicating success status

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    #----------------------------------------------------------------------

    def enableService(self, service, **kwargs):
        '''Enables a service and starts it if it is not running as long as we are
        not in install mode

        :param service: 
        :param **kwargs: 
        :returns: Bool indicating success status

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    #----------------------------------------------------------------------

    def auditService(self, service, **kwargs):
        '''Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        :param service: 
        :param **kwargs: 
        :returns: Bool, True if the service is configured to run

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    #----------------------------------------------------------------------

    def isRunning(self, service, **kwargs):
        '''Check to see if a service is currently running. The enable service uses
        this so that we're not trying to start a service that is already
        running.

        :param service: 
        :param **kwargs: 
        :returns: bool, True if the service is already running

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    #----------------------------------------------------------------------

    def reloadService(self, service, **kwargs):
        '''Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active. This method ignores services that do not return true when
        self.isrunning() is called. The assumption being that this method is
        being called due to a change in a conf file, and a service that isn't
        currently running will pick up the change when (if) it is started.

        :param service: 
        :param **kwargs: 
        :returns: bool indicating success status

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    #----------------------------------------------------------------------

    def listServices(self, **kwargs):
        '''List the services installed on the system.

        :param **kwargs: 
        :returns: list of strings

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    #----------------------------------------------------------------------

    def start(self, service, *args, **kwargs):
        '''Start a service installed on the system.

        :param service: 
        :param *args: 
        :param **kwargs: 
        :returns: list of strings

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    #----------------------------------------------------------------------

    def stop(self, service, *args, **kwargs):
        '''Stop a service installed on the system.

        :param service: 
        :param *args: 
        :param **kwargs: 
        :returns: list of strings

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    def getStartCommand(self, service):
        '''retrieve the start command.  Mostly used by event recording

        :param service: 
        :returns: string - start command

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    def getStopCommand(self, service):
        '''retrieve the stop command.  Mostly used by event recording

        :param service: 
        :returns: string - stop command
        @author: dwalker

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    def getEnableCommand(self, service):
        '''retrieve the enable command.  Mostly used by event recording

        :param service: 
        :returns: string - enable command
        @author: dwalker

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError

    def getDisableCommand(self, service):
        '''retrieve the start command.  Mostly used by event recording

        :param service: 
        :returns: string - disable command
        @author: dwalker

        '''
        self.logdispatcher.log(LogPriority.INFO,
                               '--This method not yet in production.')
        self.__calledBy()
        raise MethodNotImplementedError