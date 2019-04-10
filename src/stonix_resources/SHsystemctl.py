###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
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
"""
Created on Sep 19, 2012

@author: David Kennel
@change: 2016/05/09 Eric Ball Changed auditservice to check output for "enabled"
        rather than just checking the return code.
"""

import subprocess
import os

from CommandHelper import CommandHelper
from logdispatcher import LogPriority
from ServiceHelperTemplate import ServiceHelperTemplate


class SHsystemctl(ServiceHelperTemplate):
    """
    SHsystemctl is the Service Helper for systems using the systemctl command to
    configure services. (Fedora and future RHEL and variants)
    """

    def __init__(self, environment, logdispatcher):
        """
        Constructor
        """
        super(SHsystemctl, self).__init__(environment, logdispatcher)
        self.environment = environment
        self.logdispatcher = logdispatcher
        self.ch = CommandHelper(self.logdispatcher)
        if os.path.exists('/bin/systemctl'):
            self.cmd = '/bin/systemctl '
        elif os.path.exists('/usr/bin/systemctl'):
            self.cmd = '/usr/bin/systemctl '
        else:
            raise IOError('Cannot find systemctl command')

    def disableService(self, service, **kwargs):
        """
        Disables the service and terminates it if it is running.

        @param string: Name of the service to be disabled
        @return: Bool indicating success status
        """
        ret2 = 0
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsystemctl.disable ' + service)
        confsuccess = True
        svcoff = True
        ret = subprocess.call(self.cmd + '-q disable ' + service,
                              shell=True, close_fds=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        if ret != 0:
            confsuccess = False
        if self.isRunning(service):
            ret2 = subprocess.call(self.cmd + 'stop ' + service,
                                   shell=True, close_fds=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            if ret2 != 0:
                svcoff = False
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsystemctl.disable ' + service + ' ' + str(confsuccess) + str(svcoff))
        if confsuccess and svcoff:
            return True
        else:
            return False

    def enableService(self, service, **kwargs):
        """
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @param string: Name of the service to be enabled
        @return: Bool indicating success status
        """
        ret2 = 0
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsystemctl.enable ' + service)
        confsuccess = True
        svcon = True
        ret = subprocess.call(self.cmd + '-q enable ' + service,
                              shell=True, close_fds=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        if ret != 0:
            confsuccess = False
        if not self.environment.getinstallmode():
            ret2 = subprocess.call(self.cmd + 'start ' + service,
                                   shell=True, close_fds=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            if ret2 != 0:
                svcon = False
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsystemctl.enable ' + service + ' ' + str(confsuccess) + str(svcon))
        if confsuccess and svcon:
            return True
        else:
            return False

    def auditService(self, service, **kwargs):
        """
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @param string: Name of the service to audit
        @return: Bool, True if the service is configured to run
        """

        self.logdispatcher.log(LogPriority.DEBUG, "Checking if service " + service + " is enabled")

        running = False

        self.ch.executeCommand(self.cmd + " is-enabled " + service)
        if self.ch.findInOutput("enabled"):
            running = True

        if running:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + service + " is ENABLED")
        else:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + service + " is DISABLED")

        return running

    def isRunning(self, service, **kwargs):
        """
        Check to see if a service is currently running. The enable service uses
        this so that we're not trying to start a service that is already
        running.

        @param service: string; name of service to check
        @return: running
        @rtype: bool
        @author: ???
        @change: Breen Malmberg - 04/10/2019 - method refactor; doc string edit;
                debug logging edit
        """

        self.logdispatcher.log(LogPriority.DEBUG, "Checking if " + service + " is running")

        running = True
        inactive_keys = ["inactive", "unknown"]

        self.ch.executeCommand(self.cmd + " is-active " + service)
        for k in inactive_keys:
            if self.ch.findInOutput(k):
                running = False

        if running:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + service + " IS running")
        else:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + service + " is NOT running")

        return running

    def reloadService(self, service, **kwargs):
        """
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active.

        @param service: string; Name of the service to reload
        @return: success
        @rtype: bool
        @author: ???
        @change: Breen Malmberg - 04/10/2019 - method refactor; doc string edit;
                debug logging edit
        """

        success = True

        self.logdispatcher.log(LogPriority.DEBUG, "Reloading service " + service)

        self.ch.executeCommand(self.cmd + " reload-or-restart " + service)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            success = False
            errmsg = self.ch.getErrorString()
        if not self.isRunning(service):
            success = False
            errmsg = "Service not running after reload"

        if success:
            self.logdispatcher.log(LogPriority.DEBUG, "Successfully reloaded service " + service)
        else:
            self.logdispatcher.log(LogPriority.DEBUG, "Failed to reload service " + service + "\n" + str(errmsg))

        return success

    def listServices(self, **kwargs):
        """
        Return a list containing strings that are service names.

        @return: service_list
        @rtype: bool
        @author: ???
        @change: Breen Malmberg - 04/10/2019 - method refactor; debug logging
                edit; doc string edit
        """

        self.logdispatcher.log(LogPriority.DEBUG, "Getting list of services")

        service_list = []

        self.ch.executeCommand(self.cmd + " -a -t service --no-pager list-unit-files")
        output = self.ch.getOutput()

        for line in output:
            try:
                service_list.append(line.split()[0])
            except IndexError:
                pass

        return service_list
