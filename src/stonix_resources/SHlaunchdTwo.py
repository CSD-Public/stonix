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

Second generation service helper.

@author: rsn
'''
import os
import time
import types
from launchctl import LaunchCtl
from logdispatcher import LogPriority as lp
from ServiceHelperTemplate import ServiceHelperTemplate
from stonixutilityfunctions import reportStack

class SHlaunchdTwo(ServiceHelperTemplate):
    '''
    This concrete service helper serves as an interface between operating system
    specific code and the generic service helper class factory.

    @author: rsn
    '''
    def __init__(self, **kwargs):
        '''
        The ServiceHelper needs to receive the STONIX environment and
        logdispatcher objects as parameters to init.

        @param environment: STONIX environment object
        '''
        super(SHlaunchdTwo, self).__init__(**kwargs)
        self.environ = kwargs.get("environment")
        self.logger = kwargs.get("logdispatcher")
        self.lCtl = LaunchCtl(self.logger)

    #----------------------------------------------------------------------
    # helper Methods
    #----------------------------------------------------------------------

    def targetValid(self, **kwargs):
        '''
        Validate a service or domain target, possibly via servicename or
        serviceName.
        
        @author: Roy Nielsen
        '''
        target = False
        if 'servicename' in kwargs:
            target = kwargs.get('servicename')
        if 'serviceName' in kwargs:
            target = kwargs.get('serviceName')
        elif 'serviceTarget' in kwargs:
            target = kwargs.get('serviceTarget')
        elif 'domainTarget' in kwargs:
            target = kwargs.get('domainTarget')
        elif 'serviceTarget' in kwargs:
            target = kwargs.get('servicetarget')
        elif 'domainTarget' in kwargs:
            target = kwargs.get('domaintarget')
        else:
            raise ValueError(reportStack(2) + "One of 'servicename', " + \
                             "'serviceName', 'serviceTarget'" + \
                             ", 'domainTarget', 'servicetarget', " + \
                             "'domaintarget' are required for this method.")
        return target

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

    def disableService(self, service=None, **kwargs):
        '''
        Disables the service and terminates it if it is running.

        @param: service: full path to the plist file used to manage
                         the service.
        @param: serviceName|serviceTarget|domainTarget can be used 
                interchangably via key value pair in kwargs.  See 
                description below for details on this variable.
                
               system/[service-name]
                  Targets the system domain or a service within the system
                  domain. The system domain manages the root Mach bootstrap
                  and is considered a privileged execution context.
                  Anyone may read or query the system domain, but root privileges
                  are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with UID 501,
                domain-target is gui/501/, service-name is com.apple.example,
                and service-target is gui/501/com.apple.example.

        @return: Bool indicating success status
        '''
        success = False

        target = self.targetValid(**kwargs)
        if target:
            successTwo = self.lCtl.bootOut(target, service)
            successOne = self.lCtl.disable(target)

            if successOne and successTwo:
                success = True

        return success

    #----------------------------------------------------------------------

    def enableService(self, service, **kwargs):
        '''
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @param: service - full path to the service to enable, eg:
                          /System/Library/LaunchDaemons/tftp.plist
        @param: servicename - the 'domainTarget' or 'serviceTarget', eg:

                system/[service-name]
                  Targets the system domain or a service within the system
                  domain. The system domain manages the root Mach bootstrap
                  and is considered a privileged execution context.
                  Anyone may read or query the system domain, but root privileges
                  are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with UID 501,
                domain-target is gui/501/, service-name is com.apple.example,
                and service-target is gui/501/com.apple.example.

        @return: Bool indicating success status
        '''
        success = False
        successOne = False
        successTwo = False

        target = self.targetValid(**kwargs)
        if target:
        
            if 'options' not in kwargs:
                options = ""
            else:
                options = kwargs.get('options')
    
            successOne = self.lCtl.enable(target)
            time.sleep(3)
            successTwo = self.lCtl.bootStrap(service, target)
            #successThree = self.lCtl.kickStart(serviceTarget, options)
    
            if successOne and successTwo: # and successTwo and successThree:
                success = True
            else:
                #raise ValueError("Problem enabling service: " + serviceTarget + " one=" + str(successOne) + ", two=" + str(successTwo) + " three: " + str(successThree))
                raise ValueError("Problem enabling service: " + target + " one=" + str(successOne) + ", two=" + str(successTwo))

        return success

    #----------------------------------------------------------------------

    def auditService(self, service, **kwargs):
        '''
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @param: service: full path to the plist file used to manage
                         the service.
        @param: serviceName|serviceTarget|domainTarget can be used 
                interchangably via key value pair in kwargs.  See 
                description below for details on this variable.
                
               system/[service-name]
                  Targets the system domain or a service within the system
                  domain. The system domain manages the root Mach bootstrap
                  and is considered a privileged execution context.
                  Anyone may read or query the system domain, but root privileges
                  are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with UID 501,
                domain-target is gui/501/, service-name is com.apple.example,
                and service-target is gui/501/com.apple.example.

        @return: Bool, True if the service is configured to run
                 Data, Information about the process, if running
        '''
        success = False

        target = self.targetValid(**kwargs)
        if target:
            success, data = self.lCtl.printTarget(target)

        return success

    #----------------------------------------------------------------------

    def isRunning(self, service, **kwargs):
        '''
        Check to see if a service is currently running. The enable service uses
        this so that we're not trying to start a service that is already
        running.

        @param: service: full path to the plist file used to manage
                         the service.
        @param: serviceName|serviceTarget|domainTarget can be used 
                interchangably via key value pair in kwargs.  See 
                description below for details on this variable.
                
               system/[service-name]
                  Targets the system domain or a service within the system
                  domain. The system domain manages the root Mach bootstrap
                  and is considered a privileged execution context.
                  Anyone may read or query the system domain, but root privileges
                  are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with UID 501,
                domain-target is gui/501/, service-name is com.apple.example,
                and service-target is gui/501/com.apple.example.

        @Note: This concrete method implementation is the same as the auditService
               method

        @return: bool, True if the service is already running
        '''
        success = False
        data = None

        target = self.targetValid(**kwargs)
        if target:
            success, data = self.lCtl.printTarget(target)

        return success

    #----------------------------------------------------------------------

    def reloadService(self, service, **kwargs):
        '''
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active. This method ignores services that do not return true when
        self.isrunning() is called. The assumption being that this method is
        being called due to a change in a conf file, and a service that isn't
        currently running will pick up the change when (if) it is started.

        @param: service: full path to the plist file used to manage
                         the service.
        @param: serviceName|serviceTarget|domainTarget can be used 
                interchangably via key value pair in kwargs.  See 
                description below for details on this variable.
                
               system/[service-name]
                  Targets the system domain or a service within the system
                  domain. The system domain manages the root Mach bootstrap
                  and is considered a privileged execution context.
                  Anyone may read or query the system domain, but root privileges
                  are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with UID 501,
                domain-target is gui/501/, service-name is com.apple.example,
                and service-target is gui/501/com.apple.example.

        @return: bool indicating success status
        '''
        success = False
        target = self.targetValid(**kwargs)
        if target:

            if 'options' not in kwargs:
                options = "-k"
            else:
                options = kwargs.get('options')
    
            success = self.lCtl.kickStart(target, options)

        return success

    #----------------------------------------------------------------------

    def listServices(self, **kwargs):
        '''
        List the services in a specified domain per the launchctl man page

        @return: list of strings
        '''
        success = False
        data = None

        data = self.lCtl.list()

        return data
