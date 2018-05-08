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
'''

import CommandHelper
import re
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
        self.findstring = ["Could not find service ",
                           "launchctl list returned unknown response"]
        self.ch = CommandHelper.CommandHelper(logdispatcher)

    def disableservice(self, service, servicename):
        '''
        Disables the service and terminates it if it is running.

        @param service string: Name of the service to be disabled
        @param servicename string: Short Name of the service to be disabled
        @return: Bool indicating success status
        '''
        servicesuccess = True
        command = [self.launchd, 'unload', service]
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
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @param service string: Name of the service to be audited
        @param servicename string: Short Name of the service to be audited
        @return: Bool, True if the service is configured to run
        @change: 2014-11-24 - ekkehard - remove -x option no supported in
        OS X Yosemite 10.10
        '''
        try:
            servicesuccess = True
            command = [self.launchd, "list", servicename]
            self.logdispatcher.log(LogPriority.DEBUG, "command = '" + \
                                   str(command) + "'")
            if self.ch.executeCommand(command):
                if self.ch.getErrorOutput() == []:
                    servicesuccess = False
                    self.logdispatcher.log(LogPriority.DEBUG,
                                   'Blank output (' + service + ', ' + \
                                    servicename + \
                                    ')!')
                elif self.ch.findInOutput(self.findstring[0]) or self.ch.findInOutput(self.findstring[1]):
                    servicesuccess = False
                    self.logdispatcher.log(LogPriority.DEBUG,
                                           'Cannot Find service ' + \
                                           service + ', ' + \
                                           servicename + \
                                           ') Output is ' + \
                                           str(self.ch.getErrorOutput()) + \
                                           "!")
                else:
                    self.logdispatcher.log(LogPriority.DEBUG,
                                   'Found (' + service + ', ' + \
                                    servicename + \
                                    ') Output is ' + \
                                    str(self.ch.getErrorOutput()) + "!")
            self.logdispatcher.log(LogPriority.DEBUG,
                                   '(' + service + ', ' + \
                                    servicename + \
                                    ') = ' + str(servicesuccess))
            return servicesuccess
        except Exception:
            raise

    def isrunning(self, service, servicename):
        '''
        Check to see if a service is currently running.

        @param service string: Name of the service to be checked
        @param servicename string: Short Name of the service to be checked
        @return: bool, True if the service is already running
        @change: 2014-12-22 - ekkehard - remove -x option no supported in
        OS X Yosemite 10.10
        '''
        try:
            servicesuccess = True
            command = [self.launchd, "list", servicename]
            self.logdispatcher.log(LogPriority.DEBUG, "command = '" + \
                                   str(command) + "'")
            if self.ch.executeCommand(command):
                if self.ch.getErrorOutput() == []:
                    servicesuccess = False
                    self.logdispatcher.log(LogPriority.DEBUG,
                                   'Blank output (' + service + ', ' + \
                                    servicename + \
                                    ')!')
                elif self.ch.findInOutput(self.findstring[0]) or self.ch.findInOutput(self.findstring[1]):
                    servicesuccess = False
                    self.logdispatcher.log(LogPriority.DEBUG,
                                           'Cannot Find service ' + \
                                           service + ', ' + \
                                           servicename + \
                                           ') Output is ' + \
                                           str(self.ch.getErrorOutput()) + \
                                           "!")
                else:
                    self.logdispatcher.log(LogPriority.DEBUG,
                                   'Found (' + service + ', ' + \
                                    servicename + \
                                    ') Output is ' + \
                                    str(self.ch.getErrorOutput()) + "!")
            self.logdispatcher.log(LogPriority.DEBUG,
                                   '(' + service + ', ' + \
                                    servicename + \
                                    ') = ' + str(servicesuccess))
            return servicesuccess
        except Exception:
            raise

    def reloadservice(self, service, servicename):
        '''
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active.

        @param service string: Name of the service to be reloaded
        @param servicename string: Short Name of the service to be reloaded
        @return: bool indicating success status
        '''

        servicesuccess = False
        startsuccess = True
        stopsuccess = self.stopservice(service, servicename)
        if stopsuccess:
            startsuccess = self.startservice(service, servicename)
        servicesuccess = startsuccess and stopsuccess

        self.logdispatcher.log(LogPriority.DEBUG,
                               '(' + service + ', ' + servicename + \
                               ') = ' + str(servicesuccess))
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
