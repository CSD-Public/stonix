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
'''
import os
import types
from launchctl import LaunchCtl
from logdispatcher import LogPriority as lp
from ServiceHelperTemplate import ServiceHelperTemplate

class ServiceHelper(ServiceHelperTemplate):
    '''
    This concrete service helper serves as an interface between operating system
    specific code and the generic service helper class factory.

    @author: rsn
    '''
    def __init__(self, environment, logdispatcher):
        '''
        The ServiceHelper needs to receive the STONIX environment and
        logdispatcher objects as parameters to init.

        @param environment: STONIX environment object
        '''
        super(ServiceHelper, self).__init__(self, environment, logdispatcher)
        self.environ = environment
        self.logger = logdispatcher
        self.lCtl = LaunchCtl(logdispatcher)

    #----------------------------------------------------------------------
    # helper Methods
    #----------------------------------------------------------------------

    def setService(self, *args, **kwargs):
        '''
        Update the name of the service being worked with.

        @return: Bool indicating success status
        '''
        return False, "Not implemented"

    def getLaunchCtl(self):
        '''
        Return the instance of the LaunchCtl class for use outside this context.

        @author: Roy Nielsen
        '''
        return self.lCtl

    #----------------------------------------------------------------------
    # Standard interface to the service helper.
    #----------------------------------------------------------------------

    def disableService(self, domainTarget=None, **kwargs):
        '''
        Disables the service and terminates it if it is running.

        @return: Bool indicating success status
        '''
        success = False

        if 'servicePath' not in kwargs:
            raise ValueError("Variable 'servicePath' a required parameter for " + str(self.__class__.__name__))
        else:
            servicePath = kwargs.get('servicePath')

        if 'serviceTarget' not in kwargs:
            raise ValueError("Variable 'serviceTarget' a required parameter for " + str(self.__class__.__name__))
        else:
            serviceTarget = kwargs.get('serviceTarget')

        successOne = self.lCtl.disable(serviceTarget)
        successTwo = self.lCtl.bootOut(domainTarget, servicePath)

        if successOne and successTwo:
            success = True

        return success

    #----------------------------------------------------------------------

    def enableService(self, domainTarget=None, **kwargs):
        '''
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @return: Bool indicating success status
        '''
        success = False

        if 'servicePath' not in kwargs:
            raise ValueError("Variable 'servicePath' a required parameter for " + str(self.__class__.__name__))
        else:
            servicePath = kwargs.get('servicePath')

        if 'serviceTarget' not in kwargs:
            raise ValueError("Variable 'serviceTarget' a required parameter for " + str(self.__class__.__name__))
        else:
            serviceTarget = kwargs.get('serviceTarget')

        if 'options' not in kwargs:
            options = ""
        else:
            options = kwargs.get('options')

        successOne = self.lCtl.bootStrap(domainTarget, servicePath)
        successTwo = self.lCtl.enable(serviceTarget)
        successThree = self.lCtl.kickStart(serviceTarget, options)

        if successOne and successTwo and successThree:
            success = True

        return success

    #----------------------------------------------------------------------

    def auditService(self, serviceTarget):
        '''
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @return: Bool, True if the service is configured to run
                 Data, Information about the process, if running
        '''
        success = False

        success, data = self.lCtl.printTarget(serviceTarget)

        return success, data

    #----------------------------------------------------------------------

    def isRunning(self, serviceTarget):
        '''
        Check to see if a service is currently running. The enable service uses
        this so that we're not trying to start a service that is already
        running.

        @Note: This concrete method implementation is the samd as the auditService
               method

        @return: bool, True if the service is already running
        '''
        success = False
        data = None

        success, data = self.lCtl.printTarget(serviceTarget)

        return success, data

    #----------------------------------------------------------------------

    def reloadService(self, serviceTarget, **kwargs):
        '''
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active. This method ignores services that do not return true when
        self.isrunning() is called. The assumption being that this method is
        being called due to a change in a conf file, and a service that isn't
        currently running will pick up the change when (if) it is started.

        @return: bool indicating success status
        '''
        success = False

        if 'options' not in kwargs:
            options = "-k"
        else:
            options = kwargs.get('options')

        success = self.lCtl.kickStart(serviceTarget, options)

        return success

    #----------------------------------------------------------------------

    def listServices(self, **kwargs):
        '''
        List the services in a specified domain per the launchctl man page

        @return: list of strings
        '''
        success = False
        data = None

        if 'domainTarget' not in kwargs:
            domainTarget = ""
        else:
            domainTarget = kwargs.get('domainTarget')

        data = self.lCtl.printTarget(domainTarget)

        return data
