"""
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
Created on Aug 9, 2012

@author: David Kennel
@change: ??? - ??? - Added try/except in list services to handle blank lines in output
"""

import os
import re

from logdispatcher import LogPriority
from ServiceHelperTemplate import ServiceHelperTemplate
from CommandHelper import CommandHelper


class SHchkconfig(ServiceHelperTemplate):
    """
    SHchkconfig is the Service Helper for systems using the chkconfig command to
    configure services. (RHEL up to 6, SUSE, Centos up to 6, etc)

    @author: David Kennel
    """

    def __init__(self, environment, logdispatcher):
        """
        Constructor
        """
        super(SHchkconfig, self).__init__(environment, logdispatcher)
        self.environ = environment
        self.logger = logdispatcher
        self.initobjs()
        self.localize()

    def initobjs(self):
        """
        initialize class objects

        @return:
        """

        self.ch = CommandHelper(self.logger)

    def localize(self):
        """
        set base command paths (chkconfig and service) based on OS

        @return:
        """

        self.svc = ""
        self.chk = ""

        chk_paths = ["/sbin/chkconfig", "/usr/sbin/chkconfig"]
        for cp in chk_paths:
            if os.path.exists(cp):
                self.chk = cp
                break
        service_paths = ["/sbin/service", "/usr/sbin/service"]
        for sp in service_paths:
            if os.path.exists(sp):
                self.svc = sp
                break

        if not self.svc:
            raise IOError("Could not locate the service utility on this system")
        if not self.chk:
            raise IOError("Could not locate the chkconfig utility on this system")

    def startService(self, service, **kwargs):
        """
        start a given service

        @param service: string; name of service
        @param kwargs: 
        @return: success
        @rtype: bool
        @author: Breen Malmberg
        """

        success = True

        self.ch.executeCommand(self.svc + " " + service + " start")
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            success = False

        if not self.isRunning(service):
            success = False

        return success

    def stopService(self, service, **kwargs):
        """
        stop a given service

        @param service: 
        @param kwargs: 
        @return: success
        @rtype: bool
        @author: Breen Malmberg
        """

        success = True

        self.ch.executeCommand(self.svc + " " + service + " stop")
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            success = False

        if self.isRunning(service):
            success = False

        return success

    def disableService(self, service, **kwargs):
        """
        Disables the specified service and stops it if
        it is running

        @param service: string; Name of the service to be disabled
        @return: bool
        @author: David Kennel
        @change: Breen Malmberg - 04/10/2019 - method refactor; doc string edit;
                logging edit
        """

        disabled = True

        self.ch.executeCommand(self.chk + " " + service + " off")
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            disabled = False

        if self.auditService(service):
            disabled = False

        if not self.stopService(service):
            disabled = False

        return disabled

    def enableService(self, service, **kwargs):
        """
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @param service: string; Name of the service to be enabled
        @return: enabled
        @rtype: bool
        @author: David Kennel
        @change: Breen Malmberg - 04/10/2019 - 
        """

        enabled = True

        self.ch.executeCommand(self.chk + " " + service + " on")
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            enabled = False

        if self.auditService(service):
            enabled = False

        if not self.startService(service):
            enabled = False

        return enabled

    def auditService(self, service, **kwargs):
        """
        Checks the status of a service and returns a bool indicating whether or
        not the service is enabled

        @param service: string; Name of the service to audit
        @return: enabled
        @rtype: bool
        @author: ???
        @change: Breen Malmberg - 04/10/2019 - method refactor; doc string edit;
                logging edit
        """

        enabled = True

        if not self.audit_chkconfig_service(service):
            enabled = False

        return enabled

    def audit_chkconfig_service(self, service):
        """
        uses the chkconfig command to check if a given
        service is enabled or not

        @return: enabled
        @rtype: bool
        @author: Breen Malmberg
        """

        enabled = True

        self.ch.executeCommand(self.chk + " --list " + service)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            enabled = False
            self.logger.log(LogPriority.DEBUG, "Failed to get status of service: " + service)
            return enabled

        output = self.ch.getOutputString()
        if not re.search(":on", output):
            enabled = False

        return enabled

    def isRunning(self, service, **kwargs):
        """
        Check to see if a service is currently running.

        @param service: string; Name of the service to check
        @return: running
        @rtype: bool
        @author: ???
        @change: Breen Malmberg - 04/10/2019 - method refactor; doc string edit;
                logging edit
        """

        running = True
        # see: http://refspecs.linuxbase.org/LSB_3.1.0/LSB-generic/LSB-generic/iniscrptact.html
        success_codes = [0, 1, 2, 3]

        self.ch.executeCommand(self.svc + " " + service + " status")
        retcode = self.ch.getReturnCode()
        if retcode not in success_codes:
            running = False
            self.logger.log(LogPriority.DEBUG, "Command error while getting run status of service: " + service)
            return running

        outputlines = self.ch.getOutput()
        # need to parse for either sysv or systemd output
        if not self.parse_running(outputlines):
            running = False

        return running

    def parse_running(self, outputlines):
        """
        check whether given service is running, with the
        service command
        this is the older (classic) systemV case

        @param outputlines: list; list of strings to search
        @return: running
        @rtype: bool
        @author: Breen Malmberg
        """

        running = True
        systemctl_locations = ["/usr/bin/systemctl", "/bin/systemctl"]
        if any(os.path.exists(sl) for sl in systemctl_locations):
            searchterms = ["Active:\s+inactive", "Active:\s+unknown"]
        else:
            searchterms = ["is stopped", "hook is not installed"]

        for line in outputlines:
            if any(re.search(st, line) for st in searchterms):
                running = False
                break

        return running

    def reloadService(self, service, **kwargs):
        """
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active.

        @param service: string; Name of service to be reloaded
        @return: reloaded
        @rtype: bool
        @author: ???
        @change: Breen Malmberg - 04/10/2019 - method refactor; doc string edit;
                logging edit
        """

        reloaded = True

        # force-reload: cause the configuration to be reloaded if the service supports this,
        # otherwise restart the service if it is running
        self.ch.executeCommand(self.svc + " " + service + " force-reload")
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            reloaded = False
            self.logger.log(LogPriority.DEBUG, "Failed to reload service: " + service)

        return reloaded

    def listServices(self, **kwargs):
        """
        Return a list containing strings that are service names.

        @return: service_list
        @rtype: list
        @author: ???
        @change: Breen Malmberg - 04/10/2019 - method refactor; doc string edit;
                logging edit
        """

        service_list = []

        self.ch.executeCommand(self.chk + " --list")
        outputlines = self.ch.getOutput()
        for line in outputlines:
            try:
                service_list.append(line.split()[0])
            except IndexError:
                pass

        return service_list
