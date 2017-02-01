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
'''

import re
import CommandHelper
from logdispatcher import LogPriority


class SHlaunchd(object):
    '''
    SHlaunchd is the Service Helper for systems using the launchd command to
    configure services. (Apple's OS X 10.6, 10.7, 10.8, 10.9, 10.10, etc.)
    '''

    def __init__(self, environment, logdispatcher):
        '''
        Constructor
        '''
        self.environment = environment
        self.logdispatcher = logdispatcher
        self.launchd = "/bin/launchctl"
        self.defaults = "/usr/bin/defaults"
# NOTE: This needs to be updated with new OS X after Yosemite
        self.noservicemsgs = ["Could not find service ",
                           "launchctl list returned unknown response"]
        self.ch = CommandHelper.CommandHelper(logdispatcher)

    def disableservice(self, service, servicename):
        '''
        Disables the service and terminates it if it is running.

        @return: servicesuccess
        @rtype: bool
        @param service string: Name of the service to be disabled
        @param servicename string: Short Name of the service to be disabled
        @author: ???
        @change: Breen Malmberg - 1/20/2017 - minor doc string edit; try/except
        '''

        servicesuccess = True
        command = [self.launchd, 'unload', service]

        try:

            self.logdispatcher.log(LogPriority.DEBUG, "command = '" + \
                                   str(command) + "'")
            if self.ch.executeCommand(command):
                if self.ch.findInOutput('nothing found to load'):
                    servicesuccess = False
                    self.logdispatcher.log(LogPriority.DEBUG,
                                           "Disable of " + str(service) + \
                                           " failed!")
                else:
                    self.logdispatcher.log(LogPriority.DEBUG,
                                           "Disable of " + str(service) + \
                                           " succeded!")
        except Exception:
            raise
        return servicesuccess

    def enableservice(self, service, servicename):
        '''
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @param service string: Name of the service to be enabled
        @param servicename string: Short Name of the service to be enabled
        @return: Bool indicating success status
        '''

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
                                               str(servicename) + ") " + \
                                               str(command) + \
                                               " output = '" + \
                                               str(commandOutput) + \
                                               "' failed!")
                else:
                    servicecompleted = True
                    self.logdispatcher.log(LogPriority.ERROR,
                                               "(" + str(service) + "," + \
                                               str(servicename) + ") " + \
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

    def auditservice(self, service, servicename):
        '''
        Use launchctl to determine if a given service is configured
        to run (aka currently loaded). Return True if so. Return
        False if not.

        @return: isloaded
        @rtype: bool
        @param service string: Full path to the plist of the service to run
                ex: /System/Library/LaunchDaemons/com.apple.someservice.plist
        @param servicename string: Name of service without full path or the '.plist'
                ex: com.apple.someservice
        @author: ???
        @change: 2014-11-24 - ekkehard - remove -x option no supported in
        OS X Yosemite 10.10
        @change: Breen Malmberg - 1/20/2017 - minor doc string edit; minor
                refactor; logging
        @change: Breen Malmberg - 1/31/2017 - doc string edit; minor refactor
        '''

        self.logdispatcher.log(LogPriority.DEBUG, "Entering SHlaunchd.auditservice()...")

        isloaded = True
        command = [self.launchd, "list"]
        found = False

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
                if re.search(servicename, line, re.IGNORECASE):
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

    def isrunning(self, service, servicename):
        '''
        Use launchctl to determine if the given service is currnetly
        running or not. Return True if it is. Return False if it is not.

        @return: isrunning
        @rtype: bool
        @param service string: Name of the service to be checked
        @param servicename string: Short Name of the service to be checked
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
                if re.search(servicename, line, re.IGNORECASE):
                    found = True

            # if found, is it configured to run or not?
            # did we get any messages specifically stating the
            # specified service is not loaded or not configured
            # to run?
            for line in cmdoutput:
                if re.search(servicename, line, re.IGNORECASE):
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

    def reloadservice(self, service, servicename):
        '''
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active.

        @return: servicesuccess
        @rtype: bool
        @param service string: Name of the service to be reloaded
        @param servicename string: Short Name of the service to be reloaded
        @author: ???
        @change: Breen Malmberg - 1/20/2017 - minor doc string edit; refactor;
                try/except; logging
        '''

        self.logdispatcher.log(LogPriority.DEBUG, "Entering SHlaunchd.reloadservice()...")

        servicesuccess = False
        startsuccess = True
        stopsuccess = True
        isrunning = False

        try:

            if self.isrunning(service, servicename):
                self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " is running")
                isrunning = True
            else:
                self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " is NOT running")
    
            if isrunning:

                self.logdispatcher.log(LogPriority.INFO, "Stopping " + str(service) + " service...")
                if not self.stopservice(service, servicename):
                    stopsuccess = False

                if stopsuccess:
                    self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " successfully stopped")
                    self.logdispatcher.log(LogPriority.INFO, "Starting " + str(service) + " service...")
                    startsuccess = self.startservice(service, servicename)
            else:
                self.logdispatcher.log(LogPriority.INFO, "Starting " + str(service) + " service...")
                startsuccess = self.startservice(service, servicename)

            if startsuccess:
                self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " successfully started")
    
            servicesuccess = startsuccess and stopsuccess
    
            if servicesuccess:
                self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " successfully reloaded")
            else:
                self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " failed to reload")

            self.logdispatcher.log(LogPriority.DEBUG, "Exiting SHlaunchd.reloadservice()...")

        except Exception:
            raise
        return servicesuccess

    def listservices(self):
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

    def startservice(self, service, servicename):
        '''
        start a service.

        @param service string: Name of the service to be started
        @param servicename string: Short Name of the service to be started
        @return: bool indicating success
        '''
        servicesuccess = True
        if self.isrunning(service, servicename):
            servicesuccess = True
        else:
            command = [self.launchd, 'start', 'job', servicename]
            if self.ch.executeCommand(command):
                if self.ch.getReturnCode == 0:
                    servicesuccess = True

        self.logdispatcher.log(LogPriority.DEBUG,
                               '(' + service + ', ' + servicename + \
                               ') = ' + str(servicesuccess))

        return servicesuccess

    def stopservice(self, service, servicename):
        '''
        stop a service.

        @param service string: Name of the service to be stopped
        @param servicename string: Short Name of the service to be stopped
        @return: bool indicating success
        '''
        servicesuccess = True
        if self.isrunning(service, servicename):
            command = [self.launchd, 'stop', 'job ', servicename]
            if self.ch.executeCommand(command):
                if self.ch.getReturnCode == 0:
                    servicesuccess = True
        else:
            servicesuccess = True

        self.logdispatcher.log(LogPriority.DEBUG,
                               '(' + service + ', ' + servicename + \
                               ') = ' + str(servicesuccess))

        return servicesuccess
