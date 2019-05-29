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

"""
Created on Sep 19, 2012

@author: Dave Kennel
@change: 2015/10/15 Eric Ball Added chk.wait() and chk.returncode == 0 to isrunning
@change: 2018/02/22 Brandon Gonzales Changed regex in auditService to cut off after the
                    service's name
@change: 2019/05/13 Breen Malmberg - refactored class
"""

import re

from logdispatcher import LogPriority
from CommandHelper import CommandHelper
from ServiceHelperTemplate import ServiceHelperTemplate


class SHupdaterc(ServiceHelperTemplate):
    """SHupdaterc is the Service Helper for systems using the rcupdate command to
    configure services. (Debian, Ubuntu and variants)


    """

    def __init__(self, environment, logdispatcher):
        """
        Constructor
        """
        super(SHupdaterc, self).__init__(environment, logdispatcher)
        self.environment = environment
        self.logdispatcher = logdispatcher
        self.ch = CommandHelper(self.logdispatcher)
        self.updaterc = "/usr/sbin/update-rc.d "
        self.svc = "/usr/sbin/service "

    def disableService(self, service, **kwargs):
        """Disables the service and terminates it if it is running.

        :param service: string; name of service
        :param kwargs: dict; dictionary of key-value arguments
        :param **kwargs: 
        :returns: enabled
        :rtype: bool
@author: ???

        """

        disabled = True

        self.logdispatcher.log(LogPriority.DEBUG, "Disabling service: " + service)

        self.ch.executeCommand(self.updaterc + service + " disable")
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            errmsg = self.ch.getErrorString()
            self.logdispatcher.log(LogPriority.DEBUG, errmsg)
            disabled = False
        else:
            if self.auditService(service):
                disabled = False

        if disabled:
            self.logdispatcher.log(LogPriority.DEBUG, "Successfully disabled service: " + service)

        return disabled

    def enableService(self, service, **kwargs):
        """Enables a service and starts it if it is not running as long as we are
        not in install mode

        :param service: string; name of service
        :param kwargs: dict; dictionary of key-value arguments
        :param **kwargs: 
        :returns: enabled
        :rtype: bool
@author: ???

        """

        enabled = True

        self.logdispatcher.log(LogPriority.DEBUG, "Enabling service: " + service)

        self.ch.executeCommand(self.updaterc + service + " enable")
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            errmsg = self.ch.getErrorString()
            self.logdispatcher.log(LogPriority.DEBUG, errmsg)
            enabled = False
        else:
            if not self.auditService(service):
                enabled = False

        if enabled:
            self.logdispatcher.log(LogPriority.DEBUG, "Successfully enabled service: " + service)

        return enabled

    def auditService(self, service, **kwargs):
        """Checks all /etc/rc*.d/ directories for the "S" (start) service entry
        in updaterc, if an "S" entry with the service name exists in any of the rc*.d/
        directories, it means that the service is scheduled to start at boot

        :param service: string; name of service
        :param kwargs: dict; dictionary of key-value arguments
        :param **kwargs: 
        :returns: enabled
        :rtype: bool
@author: ???

        """

        enabled = False

        self.logdispatcher.log(LogPriority.DEBUG, "Checking if service: " + service + " is enabled")

        self.ch.executeCommand("ls -l /etc/rc*.d/")
        if self.ch.findInOutput("S[0-9]+" + service):
            enabled = True

        if enabled:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + service + " is enabled")
        else:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + service + " is disabled")

        return enabled

    def isRunning(self, service, **kwargs):
        """Check to see if a service is currently running.

        :param service: string; name of service
        :param kwargs: dict; dictionary of key-value arguments
        :param **kwargs: 
        :returns: enabled
        :rtype: bool
@author: ???

        """

        running = False

        self.logdispatcher.log(LogPriority.DEBUG, "Checking if service: " + service + " is running")

        self.ch.executeCommand(self.svc + "--status-all")
        if self.ch.findInOutput("\[\s+\+\s+\]\s+" + service):
            running = True

        if running:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + service + " IS running")
        else:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + service + " is NOT running")

        return running

    def reloadService(self, service, **kwargs):
        """Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active.

        :param service: string; name of service
        :param kwargs: dict; dictionary of key-value arguments
        :param **kwargs: 
        :returns: enabled
        :rtype: bool
@author: ???

        """

        reloaded = True

        self.logdispatcher.log(LogPriority.DEBUG, "Reloading service: " + service)

        self.ch.executeCommand(self.svc + service + " stop")
        self.ch.executeCommand(self.svc + service + " start")
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            reloaded = False
            errmsg = self.ch.getErrorString()
            self.logdispatcher.log(LogPriority.DEBUG, errmsg)
        else:
            if not self.isRunning(service):
                reloaded = False
                self.logdispatcher.log(LogPriority.DEBUG, "Failed to reload service: " + service)

        return reloaded

    def listServices(self, **kwargs):
        """Return a list containing strings that are service names.

        :param kwargs: dict; dictionary of key-value arguments
        :param **kwargs: 
        :returns: enabled
        :rtype: bool
@author: ???

        """

        services = []

        self.logdispatcher.log(LogPriority.DEBUG, "Fetching list of services")

        self.ch.executeCommand(self.svc + "--status-all")
        output = self.ch.getOutput()
        for line in output:
            if re.search("^\[", line):
                try:
                    services.append(line.split("]")[1].strip())
                except (IndexError, AttributeError):
                    continue

        return services

    def getStartCommand(self, service):
        """retrieve the start command.  Mostly used by event recording

        :param service: 
        :returns: string - start command
        @author: Derek Walker

        """
        return self.svc + service + ' start'

    def getStopCommand(self, service):
        """retrieve the stop command.  Mostly used by event recording

        :param service: 
        :returns: string - stop command
        @author: Derek Walker

        """
        return self.svc + service + ' stop'

    def getEnableCommand(self, service):
        """retrieve the enable command.  Mostly used by event recording

        :param service: 
        :returns: string - enable command
        @author: Derek Walker

        """
        return self.updaterc + service + ' enable'

    def getDisableCommand(self, service):
        """retrieve the start command.  Mostly used by event recording

        :param service: 
        :returns: string - disable command
        @author: Derek Walker

        """
        return self.updaterc + service + ' disable'
