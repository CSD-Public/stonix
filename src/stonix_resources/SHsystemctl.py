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
@change: 2019/04/10 Breen Malmberg refactored every method; fixed command syntax;
        added start and stop service methods; fixed doc strings; added error logging;
        removed unused imports; methods now use commandhelper instead of subprocess;
        fixed typo in license
"""

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

        self.localize()

    def localize(self):
        """

        @return:
        """

        systemctl_paths = ["/usr/bin/systemctl", "/bin/systemctl"]
        self.sysctl = ""

        for sp in systemctl_paths:
            if os.path.exists(sp):
                self.sysctl = sp
                break

        if not self.sysctl:
            raise IOError("Cannot find systemctl utility on this system!")

    def disableService(self, service, **kwargs):
        """
        Disables the service and terminates it if it is running.

        @param service: string; Name of the service to be disabled
        @return: disabled
        @rtype: bool
        @author: ???
        @change: Breen Malmberg - 04/10/2019 - method refactor;
                doc string edit; logging edit
        """

        disabled = True
    
        self.ch.executeCommand(self.sysctl + " disable " + service)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            disabled = False
            errmsg = self.ch.getErrorString()
            self.logdispatcher.log(LogPriority.DEBUG, str(errmsg))

        if not self.stopService(service):
            disabled = False

        return disabled

    def enableService(self, service, **kwargs):
        """
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @param service: string; Name of the service to be disabled
        @return: enabled
        @rtype: bool
        @author: ???
        @change: Breen Malmberg - 04/10/2019 - method refactor;
                doc string edit; logging edit
        """

        enabled = True

        self.ch.executeCommand(self.sysctl + " enable " + service)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            enabled = False
            errmsg = self.ch.getErrorString()
            self.logdispatcher.log(LogPriority.DEBUG, str(errmsg))

        return enabled

    def auditService(self, service, **kwargs):
        """
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @param string: Name of the service to audit
        @return: Bool, True if the service is configured to run
        """

        enabled = False

        self.ch.executeCommand(self.sysctl + " is-enabled " + service)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            enabled = False
            errmsg = self.ch.getErrorString()
            self.logdispatcher.log(LogPriority.DEBUG, str(errmsg))
        if self.ch.findInOutput("enabled"):
            enabled = True
        elif self.ch.findInOutput("not a native service"):
            self.logdispatcher.log(LogPriority.DEBUG, "Attempted to audit a non-systemd service with systemctl commands")

        return enabled

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

        running = True
        inactive_keys = ["inactive", "unknown"]

        self.ch.executeCommand(self.sysctl + " is-active " + service)
        for k in inactive_keys:
            if self.ch.findInOutput(k):
                running = False

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

        self.ch.executeCommand(self.sysctl + " reload-or-restart " + service)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            success = False
            errmsg = self.ch.getErrorString()
            self.logdispatcher.log(LogPriority.DEBUG, str(errmsg))
        if not self.isRunning(service):
            success = False

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

        service_list = []

        self.ch.executeCommand(self.sysctl + " -a -t service --no-pager list-unit-files")
        output = self.ch.getOutput()

        for line in output:
            try:
                service_list.append(line.split()[0])
            except IndexError:
                pass
            except:
                raise

        if not service_list:
            errmsg = self.ch.getErrorString()
            if errmsg:
                self.logdispatcher.log(LogPriority.DEBUG, str(errmsg))

        return service_list

    def startService(self, service, **kwargs):
        """
        start given service

        @param service:
        @param kwargs:
        @return: started
        @rtype: bool
        @author: Breen Malmberg
        """

        started = True

        self.ch.executeCommand(self.sysctl + " start " + service)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            started = False
            errmsg = self.ch.getErrorString()
            self.logdispatcher.log(LogPriority.DEBUG, str(errmsg))

        return started

    def stopService(self, service, **kwargs):
        """
        stop given service

        @param service:
        @param kwargs:
        @return: stopped
        @rtype: bool
        @author: Breen Malmberg
        """

        stopped = True

        if not self.isRunning(service):
            return stopped # nothing to do

        else:
            self.ch.executeCommand(self.sysctl + " stop " + service)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                stopped = False
                errmsg = self.ch.getErrorString()
                self.logdispatcher.log(LogPriority.DEBUG, str(errmsg))

        return stopped
