'''
###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
This object encapsulates the /bin/launchctl command for Service Helper

@author: ekkehard
@change: 2012-10-31 - ekkehard - original implementation
@change: 2014-03-31 - ekkehard - took out -w option and converted to cmd list
@change: 2014-11-24 - ekkehard - added OS X Yosemite 10.10 support
@change: 2017-01-20 - Breen Malmberg - changed name of var self.findstring to
        self.noservicemsgs
@change: 2017/01/31 - Breen Malmberg - clarified the difference between auditservice
        and isrunning methods in the documentation; clarified the nature of the
        two parameters in each of those methods in the doc strings as well;
        fixed a logic error in auditservice()
@change: 2017/10/23 - rsn - switching service helper call interfaces to
        service helper second generation, not second generation
        functionality
'''

import re
import CommandHelper
from logdispatcher import LogPriority
from ServiceHelperTemplate import ServiceHelperTemplate
from stonixutilityfunctions import reportStack


class SHlaunchd(ServiceHelperTemplate):
    '''
    SHlaunchd is the Service Helper for systems using the launchd command to
    configure services. (Apple's OS X 10.6, 10.7, 10.8, 10.9, 10.10, etc.)
    '''

    def __init__(self, environment, logdispatcher):
        '''
        Constructor
        '''
        super(SHlaunchd, self).__init__(environment, logdispatcher)
        self.environment = environment
        self.logdispatcher = logdispatcher
        self.launchd = "/bin/launchctl"
        self.defaults = "/usr/bin/defaults"
# NOTE: This needs to be updated with new OS X after Yosemite
        self.noservicemsgs = ["Could not find service ",
                           "launchctl list returned unknown response"]
        self.ch = CommandHelper.CommandHelper(logdispatcher)

    def targetValid(self, service, **kwargs):
        '''
        Validate a service or domain target, possibly via 
        servicename|serviceName|servicetarget|serviceTarget|domaintarget|domainTarget.

        @return: the value of one of the above as "target", in the order
                found below.

        @author: Roy Nielsen
        '''
        target = False
        if service:
            pass
        if 'servicename' in kwargs:
            target = kwargs.get('servicename')
        elif 'serviceName' in kwargs:
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
            raise ValueError(reportStack(2) + "Either the service (full " +
                             "path to the service) or One of 'servicename', " +
                             "'serviceName', 'serviceTarget'" +
                             ", 'domainTarget', 'servicetarget', " +
                             "'domaintarget' are required for this method.")

        return target

    def disableService(self, service, **kwargs):
        '''
        Disables the service and terminates it if it is running.

        @return: servicesuccess
        @rtype: bool
        @param service string: Name of the service to be disabled
        @param serviceTarget string: Short Name of the service to be disabled
        @author: ???
        @change: Breen Malmberg - 1/20/2017 - minor doc string edit; try/except
        '''

        servicesuccess = False

        serviceTarget = self.targetValid(service, **kwargs)
        if serviceTarget:

            command = [self.launchd, 'unload', service]

            try:

                self.logdispatcher.log(LogPriority.DEBUG, "command = '" + \
                                       str(command) + "'")
                if self.ch.executeCommand(command):
                    if self.ch.findInOutput('nothing found to load'):
                        self.logdispatcher.log(LogPriority.DEBUG,
                                               "Disable of " + str(service) + \
                                               " failed!")
                    else:
                        self.logdispatcher.log(LogPriority.DEBUG,
                                               "Disable of " + str(service) + \
                                               " succeded!")
                        servicesuccess = True
            except Exception:
                raise
        return servicesuccess

    def enableService(self, service, **kwargs):
        '''
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @param service string: Name of the service to be enabled
        @param serviceTarget string: Short Name of the service to be enabled
        @return: Bool indicating success status
        '''
        serviceTarget = self.targetValid(service, **kwargs)
        if serviceTarget:
            try:
                servicesuccess = False
                servicecompleted = False

                command = [self.launchd, 'load', service]
                lastcommand = command
                servicesuccess = self.ch.executeCommand(command)
                if servicesuccess:
                    commandOutput = self.ch.getErrorOutput()
                    stringToFind = 'nothing found to load'
                    foundInOutput = self.ch.findInOutput(stringToFind)
                    if foundInOutput:
                        servicecompleted = False
                    else:
                        servicecompleted = True
                if servicesuccess and not servicecompleted:
                    command = [self.launchd, 'load', "-w", service]
                    lastcommand = command
                    servicesuccess = self.ch.executeCommand(command)
                if servicesuccess and not servicecompleted:
                    commandOutput = self.ch.getErrorOutput()
                    stringToFind = 'nothing found to load'
                    foundInOutput = self.ch.findInOutput(stringToFind)
                    if foundInOutput:
                        servicecompleted = True
                        self.logdispatcher.log(LogPriority.ERROR,
                                                   "(" + str(service) + "," + \
                                                   str(serviceTarget) + ") " + \
                                                   str(command) + \
                                                   " output = '" + \
                                                   str(commandOutput) + \
                                                   "' failed!")
                    else:
                        servicecompleted = True
                        self.logdispatcher.log(LogPriority.ERROR,
                                                   "(" + str(service) + "," + \
                                                   str(serviceTarget) + ") " + \
                                                   " had to issue " +\
                                                   str(command) + \
                                                   " output = '" + \
                                                   str(commandOutput) + \
                                                   "' to fix -w issue!")
                if not servicesuccess:
                    raise ValueError("self.ch.executeCommand(" + \
                                     str(lastcommand) + ") Failed!")
                return servicesuccess

            except Exception:
                raise
            return False

    def auditService(self, service, **kwargs):
        '''
        Use launchctl to determine if a given service is configured
        to run (aka currently loaded). Return True if so. Return
        False if not.

        @return: isloaded
        @rtype: bool
        @param service string: Full path to the plist of the service to run
                ex: /System/Library/LaunchDaemons/com.apple.someservice.plist
        @param serviceTarget: string; label of service in launchd (can be different
                from filename of service plist)
        @author: ???
        @change: 2014-11-24 - ekkehard - remove -x option no supported in
        OS X Yosemite 10.10
        @change: Breen Malmberg - 1/20/2017 - minor doc string edit; minor
                refactor; logging
        @change: Breen Malmberg - 1/31/2017 - doc string edit; minor refactor
        @change: Breen Malmberg - 5/11/2017 - doc string edit to explain that
                serviceTarget can be different from the filename in service
        '''

        self.logdispatcher.log(LogPriority.DEBUG, "Entering SHlaunchd.auditservice()...")

        isloaded = True
        command = [self.launchd, "list"]
        found = False

        serviceTarget = self.targetValid(service, **kwargs)
        if serviceTarget:
            try:

                self.ch.executeCommand(command)
                retcode = self.ch.getReturnCode()

                if retcode != 0:
                    self.logdispatcher.log(LogPriority.DEBUG, "Command failed: " + str(command) + " with return code: " + str(retcode))

                cmdoutput = self.ch.getOutput()

                # is there any output at all?
                if not cmdoutput:
                    isloaded = False
                    self.logdispatcher.log(LogPriority.INFO, "There was no output from command: " + str(command))

                # did we even find the service in the output at all?
                for line in cmdoutput:
                    if re.search(service, line, re.IGNORECASE):
                        found = True
                    if re.search(serviceTarget, line, re.IGNORECASE):
                        found = True

                # did we get any messages specifically stating the
                # specified service is not loaded or not configured
                # to run?
                for line in cmdoutput:
                    if re.search(self.noservicemsgs[0], line, re.IGNORECASE):
                        isloaded = False
                    elif re.search(self.noservicemsgs[1], line, re.IGNORECASE):
                        isloaded = False

                # if it wasn't found at all, it's not configured to run
                if not found:
                    isloaded = False

                # log whether it's running or not
                if isloaded:
                    self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " is loaded")
                else:
                    self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " is NOT loaded")

                self.logdispatcher.log(LogPriority.DEBUG, "Exiting SHlaunchd.auditservice()...")

            except Exception:
                raise
        return isloaded

    def isRunning(self, service, **kwargs):
        '''
        Use launchctl to determine if the given service is currnetly
        running or not. Return True if it is. Return False if it is not.

        @return: isrunning
        @rtype: bool
        @param service string: Name of the service to be checked
        @param serviceTarget string: Short Name of the service to be checked
        @author: ???
        @change: 2014-12-22 - ekkehard - remove -x option no supported in
        OS X Yosemite 10.10
        @change: Breen Malmberg - 1/20/2017 - minor doc string edit; minor
                refactor; logging
        '''

        self.logdispatcher.log(LogPriority.DEBUG, "Entering SHlaunchd.isrunning()...")

        isrunning = True
        command = [self.launchd, "list"]
        found = False

        serviceTarget = self.targetValid(service, **kwargs)
        if serviceTarget:
            try:

                self.ch.executeCommand(command)
                retcode = self.ch.getReturnCode()

                if retcode != 0:
                    self.logdispatcher.log(LogPriority.DEBUG, "Command failed: " + str(command) + " with return code: " + str(retcode))

                cmdoutput = self.ch.getOutput()

                # is there any output at all?
                if not cmdoutput:
                    isrunning = False
                    self.logdispatcher.log(LogPriority.INFO, "There was no output from command: " + str(command))

                # did we even find the service in the output at all?
                for line in cmdoutput:
                    if re.search(service, line, re.IGNORECASE):
                        found = True
                    if re.search(serviceTarget, line, re.IGNORECASE):
                        found = True

                # if found, is it configured to run or not?
                # did we get any messages specifically stating the
                # specified service is not loaded or not configured
                # to run?
                for line in cmdoutput:
                    if re.search(serviceTarget, line, re.IGNORECASE):
                        sline = line.split()
                        if re.search('\-', sline[0], re.IGNORECASE):
                            isrunning = False
                    elif re.search(self.noservicemsgs[0], line, re.IGNORECASE):
                        isrunning = False
                    elif re.search(self.noservicemsgs[1], line, re.IGNORECASE):
                        isrunning = False

                # if it wasn't found at all, it's not configured to run
                if not found:
                    isrunning = False

                # log whether it's running or not
                if isrunning:
                    self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " is running")
                else:
                    self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " is NOT running")

                self.logdispatcher.log(LogPriority.DEBUG, "Exiting SHlaunchd.isrunning()...")

            except Exception:
                raise
        return isrunning

    def reloadService(self, service, **kwargs):
        '''
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active.

        @return: reloadsuccess
        @rtype: bool
        @param: service - servicelong string: Name of the service to be reloaded
        @param: serviceTarget - serviceshort string: Short Name of the service to be reloaded

        @author: Breen Malmberg
        @change: Breen Malmberg - 1/20/2017 - minor doc string edit; refactor;
                try/except; logging
        @change: Breen Malmberg - 2/9/2017 - complete refactor of method, will use
                load and unload commands instead of stop and start job commands
                (stop and start are not used on newer versions of mac os x), but
                load and unload still work on all currently supported versions (10.10,
                10.11, 10.12); kept the additional parameter for backwards compatibility
                even though it is now unused in this method; parameter order maintained
        '''

        self.logdispatcher.log(LogPriority.DEBUG, "Entering SHlaunchd.reloadservice()...")

        serviceTarget = self.targetValid(service, **kwargs)
        if serviceTarget:
            servicelong = service
            reloadsuccess = True
            unloadcmd = [self.launchd, "unload", servicelong]
            loadcmd = [self.launchd, "load", servicelong]
            errmsg = ""
            errmsg2 = ""

            try:

                self.ch.executeCommand(unloadcmd)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    reloadsuccess = False
                    errmsg = self.ch.getErrorString()
                    self.logdispatcher.log(LogPriority.DEBUG, "Command: " + str(unloadcmd) + " failed with error code: " + str(retcode))
                    self.logdispatcher.log(LogPriority.DEBUG, "\n" + errmsg)
                else:
                    self.logdispatcher.log(LogPriority.DEBUG, "Command: " + str(unloadcmd) + " was run successfully")

                self.ch.executeCommand(loadcmd)
                retcode2 = self.ch.getReturnCode()
                if retcode2 != 0:
                    reloadsuccess = False
                    errmsg2 = self.ch.getErrorString()
                    self.logdispatcher.log(LogPriority.DEBUG, "Command: " + str(loadcmd) + " failed with error code: " + str(retcode2))
                    self.logdispatcher.log(LogPriority.DEBUG, "\n" + errmsg2)
                else:
                    self.logdispatcher.log(LogPriority.DEBUG, "Command: " + str(loadcmd) + " was run successfully")

                self.logdispatcher.log(LogPriority.DEBUG, "Exiting SHlaunchd.reloadservice()...")

            except Exception:
                raise
        return reloadsuccess

    def listServices(self):
        '''
        Return a list containing strings that are service names.

        @return: list
        '''
        servicelist = []
        command = [self.launchd, 'list']
        if self.ch.executeCommand(command):
            servicelist = self.ch.getOutputGroup("\S+\s+\S+\s+(\S+)", 1)
        self.logdispatcher.log(LogPriority.DEBUG, '-- END = ' + \
                               str(servicelist))
        return servicelist

    def startService(self, service, **kwargs):
        '''
        start a service.

        @param service string: Name of the service to be started
        @param serviceTarget string: Short Name of the service to be started
        @return: bool indicating success
        '''
        servicesuccess = False
        serviceTarget = self.targetValid(service, **kwargs)
        if serviceTarget:

            if self.isRunning(service, serviceTarget=serviceTarget):
                servicesuccess = True
            else:
                command = [self.launchd, 'start', 'job', serviceTarget]
                if self.ch.executeCommand(command):
                    if self.ch.getReturnCode == 0:
                        servicesuccess = True

            self.logdispatcher.log(LogPriority.DEBUG,
                                   '(' + service + ', ' + serviceTarget + \
                                   ') = ' + str(servicesuccess))

        return servicesuccess

    def stopService(self, service, **kwargs):
        '''
        stop a service.

        @param: service string: Name of the service to be stopped
        @param: serviceTarget string: Short Name of the service to be stopped
        @return: bool indicating success
        '''
        servicesuccess = True
        serviceTarget = self.targetValid(service, **kwargs)
        if serviceTarget:

            if self.isRunning(service, serviceTarget=serviceTarget):
                command = [self.launchd, 'stop', 'job ', serviceTarget]
                if self.ch.executeCommand(command):
                    if self.ch.getReturnCode == 0:
                        servicesuccess = True
            else:
                servicesuccess = True

            self.logdispatcher.log(LogPriority.DEBUG,
                                   '(' + service + ', ' + serviceTarget + \
                                   ') = ' + str(servicesuccess))

        return servicesuccess
