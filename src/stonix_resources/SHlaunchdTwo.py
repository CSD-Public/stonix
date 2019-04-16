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

Second generation service helper.

@author: Roy Nielsen
'''

import os
import re
import pwd

from plistlib import readPlist
from launchctl import LaunchCtl
from logdispatcher import LogPriority as lp
from ServiceHelperTemplate import ServiceHelperTemplate
from stonixutilityfunctions import reportStack, findUserLoggedIn


class SHlaunchdTwo(ServiceHelperTemplate):
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
        super(SHlaunchdTwo, self).__init__(environment, logdispatcher)
        #self.environ = kwargs.get("environment")
        #self.logger = kwargs.get("logdispatcher")
        self.environ = environment
        self.logger = logdispatcher
        self.lCtl = LaunchCtl(self.logger)

    # ----------------------------------------------------------------------
    # helper Methods
    # ----------------------------------------------------------------------

    def isValidServicePath(self, service):
        '''
        Check to make sure the path to the service is a valid character string.

        @param: service - Full path to a LaunchAgent or LaunchDaemon.

        @returns: True - path follows normal service path conventions
                  False - does not follow service path convention.

        @author: Roy Nielsen
        '''
        valid = False

        if isinstance(service, basestring) and service and \
           (re.search("LaunchAgent", service) or
            re.search("LaunchDaemon", service)) and \
           re.match("^/[A-Za-z]+[A-Za-z0-9_\-/\.]*$", service) and \
           os.path.exists(service):
            valid = True

        return valid

    def getServiceNameFromService(self, service):
        '''
        Determine the target from the full path to the service.  If it is a
        LaunchAgent, it is in the loaded user space.  If it is a LaunchDaemon,
        it is in the loaded System space.

        Future work: Look inside the plist to see if the service is set to run
                     as a specific user.

        NOTE: This has not been tested with a user logged in via ssh.  It
              only applies to the user logged in to the GUI.

        @param: service - Full path to a service to examine.

        @returns: The target to be used for this service.

        @author: Roy Nielsen
        '''
        serviceName = None

        if not isinstance(service, basestring) or not service or \
           not self.isValidServicePath(service):
            return serviceName

        servicePlist = readPlist(service)
        serviceName = servicePlist["Label"]
        serviceName = serviceName.strip()

        return serviceName

    # ----------------------------------------------------------------------

    def targetValid(self, service, **kwargs):
        '''
        Validate a service or domain target, possibly via
        servicename|serviceName|servicetarget|serviceTarget|domaintarget|domainTarget.

        @return: the value of one of the above as "target", in the order
                found below.

        @author: Roy Nielsen
        '''
        serviceName = False
        if 'servicename' in kwargs:
            serviceName = kwargs.get('servicename')
        elif 'serviceName' in kwargs:
            serviceName = kwargs.get('serviceName')
        elif 'servicetarget' in kwargs:
            serviceName = kwargs.get('servicetarget')
        elif 'serviceTarget' in kwargs:
            serviceName = kwargs.get('serviceTarget')
        elif 'domaintarget' in kwargs:
            serviceName = kwargs.get('domaintarget')
        elif 'domainTarget' in kwargs:
            serviceName = kwargs.get('domainTarget')
        else:
            self.logger.log(lp.DEBUG, reportStack(2) +
                            "Either the service (full " +
                            "path to the service) or One of 'servicename', " +
                            "'serviceName', 'serviceTarget'" +
                            ", 'domainTarget', 'servicetarget', " +
                            "'domaintarget' are expected for this method.")

        if not isinstance(serviceName, basestring) or not serviceName or \
           not re.match("^[A-Za-z]+[A-Za-z0-9_\-\.]*$", serviceName):
            serviceName = self.getServiceNameFromService(service)

        user = False
        userUid = False
        target = ""
        if serviceName:
            if 'LaunchDaemon' in service:
                target = 'system/' + serviceName
            if 'LaunchAgent' in service:
                user = findUserLoggedIn(self.logger)
                if user:
                    userUid = pwd.getpwnam(user).pw_uid
                if userUid:
                    target = 'gui/' + str(userUid) + '/' + serviceName

                target = target.strip()
        return target

    # ----------------------------------------------------------------------

    def getLaunchCtl(self):
        '''
        Return the instance of the LaunchCtl class for use outside this
        context.

        @author: Roy Nielsen
        '''
        return self.lCtl

    # ----------------------------------------------------------------------
    # Standard interface to the service helper.
    # ----------------------------------------------------------------------

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
                  Anyone may read or query the system domain, but root
                  privileges are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with
                UID 501, domain-target is gui/501/, service-name is
                com.apple.example, and service-target is
                gui/501/com.apple.example.

        @return: Bool indicating success status
        '''
        success = False
        domain = ''

        target = self.targetValid(service, **kwargs)
        if target:
            #targetName = target.split('/')[1]
            domainList = target.split("/")[:-1]
            if len(domainList) > 1:
                domain = "/".join(domainList)
            else:
                domain = domainList[0]

            if self.isRunning(service, **kwargs):
                successTwo = self.lCtl.bootOut(domain, service)
            else:
                successTwo = True

            if successTwo:
                successOne = self.lCtl.disable(target)
            else:
                successOne = True

            if successOne and successTwo:
                success = True

            else:
                if self.isRunning(service, **kwargs):
                    success = self.lCtl.bootOut(domain, service)
                else:
                    success = True

        return success

    # ----------------------------------------------------------------------

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
                  Anyone may read or query the system domain, but root
                  privileges are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with
                UID 501, domain-target is gui/501/, service-name is
                com.apple.example, and service-target is
                gui/501/com.apple.example.

        @return: Bool indicating success status
        '''
        success = False
        successOne = False
        successTwo = False

        target = self.targetValid(service, **kwargs)
        if target:
            '''
            if 'options' not in kwargs:
                options = ""
            else:
                options = kwargs.get('options')
            '''
            successOne = self.lCtl.enable(target, service)

            domainList = target.split("/")[:-1]
            if len(domainList) > 1:
                domain = "/".join(domainList)
            else:
                domain = domainList[0]

            successTwo = self.lCtl.bootStrap(domain, service)

            if successOne and successTwo:
                success = True
            else:
                success = False
                self.logger.log(lp.DEBUG,
                                "Problem enabling service: " + target +
                                " one=" + str(successOne) +
                                ", two=" + str(successTwo))

        return success

    # ----------------------------------------------------------------------

    def auditService(self, service, **kwargs):
        '''
        check if the target is a valid file and format
        if so, check if the file is a service that is running
        if running, return True
        if not running, return False

        @param: service: full path to the plist file used to manage
                         the service.
        @param: serviceName|serviceTarget|domainTarget can be used
                interchangeably via key value pair in kwargs.  See
                description below for details on this variable.

               system/[service-name]
                  Targets the system domain or a service within the system
                  domain. The system domain manages the root Mach bootstrap
                  and is considered a privileged execution context.
                  Anyone may read or query the system domain, but root
                  privileges are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with
                UID 501, domain-target is gui/501/, service-name is
                com.apple.example, and service-target is
                gui/501/com.apple.example.

        @return: success
        @rtype: bool
        @author: Roy Nielsen
        '''

        success = False
        successOne = False
        successTwo = False
        successThree = False
        stderr = False

        self.logger.log(lp.DEBUG, "Is the target service in a valid format?")
        target = self.targetValid(service, **kwargs)

        if target:
            self.logger.log(lp.DEBUG, "Yes, it is in a valid format")

            # added for potential use in the foundDisabled re.search string (dynamic string building)
            try:
                domainTarget = target.split('/')[:-1]
            except KeyError:
                return success

            self.logger.log(lp.DEBUG, "Is the target service a file?")
            successOne = os.path.isfile(service)
            if successOne:
                self.logger.log(lp.DEBUG, "Yes, it is a file")
            else:
                self.logger.log(lp.DEBUG, "No, it is not a file")

            self.logger.log(lp.DEBUG, "Is the target service either a Launch Agent or Launch Daemon?")
            if re.search("LaunchAgents", service):
                successTwo = True
                self.logger.log(lp.DEBUG, "Yes, it is a Launch Agent")
            if re.search("LaunchDaemons", service):
                successTwo = True
                self.logger.log(lp.DEBUG, "Yes, it is a Launch Daemon")
            if not successTwo:
                self.logger.log(lp.DEBUG, "No, it is neither a Launch Agent nor a Launch Daemon")

            #####
            # Find just the service name.
            try:
                serviceName = target.split('/')[-1]
            except KeyError:
                return success
            #####
            # Look for the serviceName to be running
            try:
                success, _, stderr, _ = self.lCtl.list(serviceName)
            except KeyError:
                pass
            else:
                #####
                # Launchctl command workd, parsing output to see if it is running
                foundDisabled = False
                if stderr:
                    for line in stderr:
                        if re.search("Could not find service .+ in domain for system",
                                     line, re.IGNORECASE):
                            if re.search("%s"%serviceName, line):
                                foundDisabled = True
                                break

                self.logger.log(lp.DEBUG, "Is the service currently enabled?")
                if not foundDisabled:
                    #####
                    # Service is currently enabled.
                    successThree = True
                    self.logger.log(lp.DEBUG, "Yes, the service is currently enabled")
                else:
                    self.logger.log(lp.DEBUG, "No, the service is currently disabled")

            if successOne and successTwo and successThree:
                success = True
            else:
                success = False

        else:
            self.logger.log(lp.DEBUG, "No, the target service is not a valid format")

        return success

    # ----------------------------------------------------------------------

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
                  Anyone may read or query the system domain, but root
                  privileges are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with
                UID 501, domain-target is gui/501/, service-name is
                com.apple.example, and service-target is
                gui/501/com.apple.example.

        @Note: This concrete method implementation is the same as the
               auditService method

        @return: bool, True if the service is already running
        '''
        serviceRunning = False
        data = None

        target = self.targetValid(service, **kwargs)
        if target:
            label = target.split("/")[-1]
            _, data, error, _ = self.lCtl.list(label)
            if error:
                for line in error:
                    if re.search("Could not find service .+ in domain for system",
                                 line, re.IGNORECASE):
                        if re.search("%s"%label, line):
                            serviceRunning = False
                            break
                    else:
                        serviceRunning = True
            else:
                serviceRunning = True
            self.logger.log(lp.DEBUG, str(data))
        return serviceRunning

    # ----------------------------------------------------------------------

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
                  Anyone may read or query the system domain, but root
                  privileges are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with
                UID 501, domain-target is gui/501/, service-name is
                com.apple.example, and service-target is
                gui/501/com.apple.example.

        @return: bool indicating success status
        '''
        success = False
        target = self.targetValid(service, **kwargs)
        if target:

            if 'options' not in kwargs:
                options = "-k"
            else:
                options = kwargs.get('options')

            success = self.lCtl.kickStart(target, options)

        return success

    # ----------------------------------------------------------------------

    def listServices(self):
        '''
        List the services in a specified domain per the launchctl man page

        @return: list of strings
        '''
        success, data, reterr, _ = self.lCtl.list()

        if success and data and not reterr:
            self.logger.log(lp.DEBUG, str(data))
        else:
            self.logger.log(lp.DEBUG, "No data found...")

        return data
