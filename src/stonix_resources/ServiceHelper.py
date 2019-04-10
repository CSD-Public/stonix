"""
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
Created on Aug 9, 2012

@author: Dave Kennel
@change: 2015/10/15 Eric Ball Added method names to debug output
@change: 2015/10/15 Eric Ball disableservice now checks audit and isrunning
@change: 2016/06/10 Dave Kennel wrapped audit in try catch in case service is not
installed.
@change: 2016/11/03 Roy Nielsen upgrading the interface to allow for more flexibility.
@change: 2017/01/31 Breen Malmberg clarified the difference between auditservice
        and isrunning methods in the documentation; clarified the nature of the
        two parameters in each of those methods in the doc strings as well
@author: 2017-23-2017 Roy Nielsen modified/simplified to second generation 
        service helper with **kwargs concept
@change: 2018/02/27 Brandon Gonzales Fixed Traceback caused by using self.logger
"""

import os
import re

import SHchkconfig
import SHrcupdate
import SHupdaterc
import SHsystemctl
import SHsvcadm
import SHrcconf
import SHlaunchd
import SHlaunchdTwo

from logdispatcher import LogPriority
from get_libc import getLibc


class ServiceHelper(object):
    """
    The ServiceHelper class serves as an abstraction layer between rules that
    need to manipulate services and the actual implementation of changing
    service status on various operating systems.

    @Note: Interface methods abstracted to allow for different parameter
           lists for different helpers.  This moves the requirement for 
           input validation the the concrete helpers.

    @author: Dave Kennel
    """

    def __init__(self, environ, logger):
        """
        The ServiceHelper needs to receive the STONIX environment and
        logdispatcher objects as parameters to init.

        @param environ: environment object reference
        @param logger: logdispatcher object reference
        @author: ???
        @change: Breen Malmberg - 1/24/2017 - doc string edit
        @change: Breen Malmberg - 2/27/2018 - added libc object instantiation and
                call to libc function .sync() to fix an issue with mac os x cacheing
                related to diable and enable service functions
        """

        self.environ = environ
        self.logdispatcher = logger
        self.isHybrid = False
        self.isdualparameterservice = False
        self.svchelper = None
        self.secondary = None
        self.service = ""
        self.servicename = ""

        try:
            self.lc = getLibc()
        except Exception as err:
            self.logdispatcher.log(LogPriority.ERROR, str(err))
            raise

        # Red Hat, CentOS, SUSE
        if os.path.exists('/sbin/chkconfig'):
            ischkconfig = True
        else:
            ischkconfig = False
        # Gentoo
        if os.path.exists('/sbin/rc-update'):
            isrcupdate = True
        else:
            isrcupdate = False
        # Ubuntu, Debian
        if os.path.exists('/usr/sbin/update-rc.d'):
            isupdaterc = True
        else:
            isupdaterc = False
        # Fedora, RHEL 7
        if os.path.exists('/bin/systemctl'):
            issystemctl = True
        else:
            issystemctl = False
        # Solaris
        if os.path.exists('/usr/sbin/svcadm'):
            issvcadm = True
        else:
            issvcadm = False
        # FreeBSD
        if os.path.exists('/etc/rc.conf') and \
        os.path.exists('/etc/rc.d/LOGIN'):
            isrcconf = True
        else:
            isrcconf = False
        # OS X
        if os.path.exists('/sbin/launchd'):
            islaunchd = True
            self.isdualparameterservice = True
        else:
            islaunchd = False

        truecount = 0
        for svctype in [ischkconfig, isrcupdate, isupdaterc,
                        issystemctl, issvcadm, isrcconf, islaunchd]:
            if svctype:
                truecount += 1
        if truecount == 0:
            raise RuntimeError("Could not identify service management programs")
        elif truecount == 1:
            if ischkconfig:
                self.svchelper = SHchkconfig.SHchkconfig(self.environ,
                                                         self.logdispatcher)
            elif isrcupdate:
                self.svchelper = SHrcupdate.SHrcupdate(self.environ,
                                                       self.logdispatcher)
            elif isupdaterc:
                self.svchelper = SHupdaterc.SHupdaterc(self.environ,
                                                       self.logdispatcher)
            elif issystemctl:
                self.svchelper = SHsystemctl.SHsystemctl(self.environ,
                                                         self.logdispatcher)
            elif issvcadm:
                self.svchelper = SHsvcadm.SHsvcadm(self.environ,
                                                   self.logdispatcher)
            elif isrcconf:
                self.svchelper = SHrcconf.SHrcconf(self.environ,
                                                   self.logdispatcher)
            elif islaunchd:
                if re.match("10.11", self.environ.getosver()):
                    self.svchelper = SHlaunchd.SHlaunchd(self.environ,
                                                     self.logdispatcher)
                else:
                    self.svchelper = SHlaunchdTwo.SHlaunchdTwo(self.environ,
                                                     self.logdispatcher)
            else:
                raise RuntimeError("Could not identify service management programs")
        elif truecount > 1:
            self.isHybrid = True
            count = 0
            if issystemctl:
                self.svchelper = SHsystemctl.SHsystemctl(self.environ,
                                                         self.logdispatcher)
                count = 1
            if ischkconfig:
                if count == 0:
                    self.svchelper = SHchkconfig.SHchkconfig(self.environ,
                                                             self.logdispatcher)
                    count = 1
                elif count == 1:
                    self.secondary = SHchkconfig.SHchkconfig(self.environ,
                                                             self.logdispatcher)
            if isrcupdate:
                if count == 0:
                    self.svchelper = SHrcupdate.SHrcupdate(self.environ,
                                                           self.logdispatcher)
                    count = 1
                elif count == 1:
                    self.secondary = SHrcupdate.SHrcupdate(self.environ,
                                                           self.logdispatcher)
            if isupdaterc:
                if count == 0:
                    self.svchelper = SHupdaterc.SHupdaterc(self.environ,
                                                           self.logdispatcher)
                    count = 1
                elif count == 1:
                    self.secondary = SHupdaterc.SHupdaterc(self.environ,
                                                           self.logdispatcher)
            if issvcadm:
                if count == 0:
                    self.svchelper = SHsvcadm.SHsvcadm(self.environ,
                                                       self.logdispatcher)
                    count = 1
                elif count == 1:
                    self.secondary = SHsvcadm.SHsvcadm(self.environ,
                                                       self.logdispatcher)
            if isrcconf:
                if count == 0:
                    self.svchelper = SHrcconf.SHrcconf(self.environ,
                                                       self.logdispatcher)
                    count = 1
                elif count == 1:
                    self.secondary = SHrcconf.SHrcconf(self.environ,
                                                       self.logdispatcher)
            if islaunchd:
                self.svchelper = SHlaunchd.SHlaunchd(self.environ,
                                                     self.logdispatcher)
                count = 1

        self.logdispatcher.log(LogPriority.DEBUG,
                               'ischkconfig: ' + str(ischkconfig))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'isrcupdate: ' + str(isrcupdate))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'isupdaterc: ' + str(isupdaterc))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'issystemctl: ' + str(issystemctl))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'issvcadm: ' + str(issvcadm))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'isrcconf: ' + str(isrcconf))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'ishybrid: ' + str(self.isHybrid))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'isdualparameterservice: ' +
                               str(self.isdualparameterservice))

    def getService(self):
        """

        @return:
        """
        return self.service

    def getServiceName(self):
        """

        @return:
        """
        return self.servicename

    def isServiceVarValid(self, service):
        """
        Input validator for the service variable

        @author: Roy Nielsen
        @return: serviceValid
        @rtype: bool
        """

        serviceValid = False

        try:

            #####
            # Generic factory input validation, only for "service", the
            # rest of the parameters need to be validated by the concrete
            # service helper instance.
            if not isinstance(service, basestring):
                raise TypeError("Service: " + str(service) +
                                " is not a string as expected.")
                serviceValid = False
            elif not service:  # if service is an empty string
                raise ValueError('service specified is blank. ' +
                                'No action will be taken!')
                serviceValid = False
            elif service : # service is a string of one or more characters
                self.logdispatcher.log(LogPriority.DEBUG,
                                   'Service name set to: ' + service)
                serviceValid = True

        except Exception as err:
            self.logdispatcher.log(LogPriority.DEBUG, str(err))
            raise

        return serviceValid

    def setService(self, service, **kwargs):
        """
        Update the name of the service being worked with.

        @param: service - Name of the service being audited or modified
                    Mac - Full path to the service plist
        @param: serviceTarget - should contain an empty string, unless the
                              concrete service helper requires it
        Note: for macOS-
        @param: service: String bearing the full path to the service plist
        @param: serviceTarget: what launchctl would consider a service-target
                or a domain-target.  See below:

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
        """

        self.logdispatcher.log(LogPriority.DEBUG, 'Setting service name')

        setServiceSuccess = False
        servicenames = ["servicename", "serviceName"]
        self.servicename = ""

        if self.isServiceVarValid(service):
            self.service = service
            setServiceSuccess = True

        for sn in servicenames:
            if sn in kwargs:
                self.servicename = kwargs.get(sn)
                break

        return setServiceSuccess

    def disableService(self, service, **kwargs):
        """
        Disables the service and terminates it if it is running.

        @param service string: Name of the service to be disabled
        @param: serviceTarget - should contain an empty string, unless the
                              concrete service helper requires it

        Note: for macOS-
        @param: service: String bearing the full path to the service plist
        @param: serviceTarget: what launchctl would consider a service-target
                or a domain-target.  See below:

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
        """

        disabled = False

        if self.setService(service):
            chkSingle = False
            chkSecond = False

            service = self.getService()

            self.logdispatcher.log(LogPriority.DEBUG, 'Disabling service ' + str(service))

            chkSingle = self.svchelper.disableService(service, **kwargs)
            if self.isHybrid:
                chkSecond = self.secondary.disableService(service, **kwargs)

            if chkSingle or chkSecond:
                disabled = True

        # sync OS cache to filesystem (force write)
        # this was added to eliminate the delay on mac between
        # issuing the service disable command and when the service
        # actually gets disabled
        try:
            self.lc.sync()
        except Exception:
            raise

        if self.auditService(service, **kwargs):
            disabled = False
            self.logdispatcher.log(LogPriority.DEBUG, "Audit after disable and sync indicates service still enabled")

        return disabled

    def enableService(self, service, **kwargs):
        """
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @param service string: Name of the service to be disabled
        @param: serviceTarget - should contain an empty string, unless the
                              concrete service helper requires it

        Note: for macOS-
        @param: service: String bearing the full path to the service plist
        @param: serviceTarget: what launchctl would consider a service-target
                or a domain-target.  See below:

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

        @return: enabledSuccess
        @rtype: bool
        @author: Roy Nielsen
        """

        enabledSuccess = False

        if self.setService(service):
            enabledSingle = False
            enabledSecondary = False

            service = self.getService()

            self.logdispatcher.log(LogPriority.DEBUG, 'Enabling service ' + str(service))

            if not self.auditService(service, **kwargs):
                if self.svchelper.enableService(service, **kwargs):
                    enabledSingle = True

                if self.isHybrid:
                    if self.secondary.enableService(service, **kwargs):
                        enabledSecondary = True
            else:
                enabledSingle = True

            enabledSuccess = bool(enabledSingle or enabledSecondary)

        # sync OS cache to filesystem (force write)
        # this was added to eliminate the delay on mac between
        # issuing the service enable command and when the service
        # actually gets enabled
        try:
            self.lc.sync()
        except Exception:
            raise

        if not self.auditService(service, **kwargs):
            enabledSuccess = False
            self.logdispatcher.log(LogPriority.DEBUG, "Audit after enable and sync indicates service still not running.")

        return enabledSuccess

    def auditService(self, service, **kwargs):
        """
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @param service string: Name of the service to be disabled
        @param: serviceTarget - should contain an empty string, unless the
                              concrete service helper requires it

        Note: for macOS-
        @param: service: String bearing the full path to the service plist
        @param: serviceTarget: what launchctl would consider a service-target
                or a domain-target.  See below:

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

        @return: isloaded
        @rtype: bool
        @author: Roy Nielsen
        """

        isloaded = False

        if self.setService(service):
            singleSuccess = False
            secondarySuccess = False

            service = self.getService()

            self.logdispatcher.log(LogPriority.DEBUG, 'Auditing service ' + str(service))

            try:
                singleSuccess = self.svchelper.auditService(service, **kwargs)
            except OSError:
                singleSuccess = False

            if self.isHybrid:
                try:
                    secondarySuccess = self.secondary.auditService(service, **kwargs)
                except OSError:
                    secondarySuccess = False

            if self.isHybrid:
                if bool(singleSuccess or secondarySuccess):
                    isloaded = True
            else:
                if singleSuccess:
                    isloaded = True

        return isloaded

    def isRunning(self, service, **kwargs):
        """
        Check to see if a service is currently running. The enable service uses
        this so that we're not trying to start a service that is already
        running.

        @param service string: Name of the service to be disabled
        @param: serviceTarget - should contain an empty string, unless the
                              concrete service helper requires it

        Note: for macOS-
        @param: service: String bearing the full path to the service plist
        @param: serviceTarget: what launchctl would consider a service-target
                or a domain-target.  See below:

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

        @return: isRunning
        @rtype: bool
        @author: Roy Nielsen
        """

        isRunning = False

        if self.setService(service):
            singleSuccess = False
            secondarySuccess = False

            service = self.getService()

            self.logdispatcher.log(LogPriority.DEBUG, 'Checking if service ' + str(service) + ' is running')

            try:
                singleSuccess = self.svchelper.isRunning(service, **kwargs)
                if self.isHybrid:
                    secondarySuccess = self.secondary.isRunning(service, **kwargs)
            except Exception as err:
                self.logdispatcher.log(LogPriority.DEBUG, str(err))
                raise

            if bool(singleSuccess or secondarySuccess):
                isRunning = True

        if isRunning:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " is running")
        else:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " is NOT running")

        return isRunning

    def reloadService(self, service, **kwargs):
        """
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active. This method ignores services that do not return true when
        self.isrunning() is called. The assumption being that this method is
        being called due to a change in a conf file, and a service that isn't
        currently running will pick up the change when (if) it is started.

        @param service string: Name of the service to be disabled
        @param: serviceTarget - should contain an empty string, unless the
                              concrete service helper requires it

        Note: for macOS-
        @param: service: String bearing the full path to the service plist
        @param: serviceTarget: what launchctl would consider a service-target
                or a domain-target.  See below:

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

        @return: reloadSuccess
        @rtype: bool
        @author: Roy Nielsen
        """

        servicenames = ["serviceName", "servicename"]
        self.servicename = ""
        reloadSuccess = False

        for sn in servicenames:
            if sn in kwargs:
                self.servicename = kwargs.get(sn)
                break

        if self.setService(service, servicename=self.servicename):
            singleSuccess = False
            secondarySuccess = False

            service = self.getService()

            self.logdispatcher.log(LogPriority.DEBUG, 'Reloading service ' + str(service))

            try:

                singleSuccess = self.svchelper.reloadService(service, **kwargs)
                if self.isHybrid:
                    secondarySuccess = self.secondary.reloadService(service, **kwargs)
                else:
                    secondarySuccess = True
            except Exception as err:
                self.logdispatcher.log(LogPriority.DEBUG, str(err))
                raise

            if self.isHybrid:
                if bool(singleSuccess and secondarySuccess):
                    reloadSuccess = True
            else:
                if singleSuccess:
                    reloadSuccess = True

        else:
            raise ValueError("Problem with setService in the Factory...")

        try:
            self.lc.sync()
        except Exception:
            raise

        return reloadSuccess

    def listServices(self):
        """
        List the services installed on the system.

        @return: serviceList
        @rtype: list
        @author: Roy Nielsen
        """

        self.logdispatcher.log(LogPriority.DEBUG, 'Getting list of services')

        serviceList = []
        secondaryList = []

        try:

            serviceList = self.svchelper.listServices()

            if self.isHybrid:
                secondaryList = self.secondary.listServices()
            if secondaryList:
                serviceList += secondaryList

        except Exception as err:
            self.logdispatcher.log(LogPriority.DEBUG, str(err))
            raise

        return serviceList
