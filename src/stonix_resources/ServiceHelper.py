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
Created on Aug 9, 2012

@author: dkennel
@change: 2015/10/15 eball Added method names to debug output
@change: 2015/10/15 eball disableservice now checks audit and isrunning
@change: 2016/06/10 dkennel wrapped audit in try catch in case service is not
installed.
@change: 2016/11/03 rsn upgrading the interface to allow for more flexibility.
@change: 2017/01/31 Breen Malmberg clarified the difference between auditservice
        and isrunning methods in the documentation; clarified the nature of the
        two parameters in each of those methods in the doc strings as well
@author: 2017-23-2017 rsn modified/simplified to second generation 
        service helper with **kwargs concept
@change: 2018/02/27 bgonz12 Fixed Traceback caused by using self.logger
'''
import os
import re
import inspect

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
    '''
    The ServiceHelper class serves as an abstraction layer between rules that
    need to manipulate services and the actual implementation of changing
    service status on various operating systems.

    @Note: Interface methods abstracted to allow for different parameter
           lists for different helpers.  This moves the requirement for 
           input validation the the concrete helpers.

    @author: dkennel
    '''

    def __init__(self, environ, logger):
        '''
        The ServiceHelper needs to receive the STONIX environment and
        logdispatcher objects as parameters to init.

        @param environ: environment object reference
        @param logger: logdispatcher object reference
        @author: ???
        @change: Breen Malmberg - 1/24/2017 - doc string edit
        @change: Breen Malmberg - 2/27/2018 - added libc object instantiation and
                call to libc function .sync() to fix an issue with mac os x cacheing
                related to diable and enable service functions
        '''
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
            self.logdispatcher.log(LogPriority.ERROR, "Unable to instantiate libc object reference, through getLibc helper\n" + str(err))
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
                truecount = truecount + 1
        if truecount == 0:
            raise RuntimeError("Could not identify service management " + \
                               "programs")
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
                raise RuntimeError("Could not identify service management " +
                                   "programs")
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
                               'ischkconfig:' + str(ischkconfig))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'isrcupdate:' + str(isrcupdate))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'isupdaterc:' + str(isupdaterc))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'issystemctl:' + str(issystemctl))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'issvcadm:' + str(issvcadm))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'isrcconf:' + str(isrcconf))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'ishybrid:' + str(self.isHybrid))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'isdualparameterservice:' +
                               str(self.isdualparameterservice))

    #----------------------------------------------------------------------
    # helper Methods
    #----------------------------------------------------------------------

    def getService(self):
        return self.service

    #----------------------------------------------------------------------

    def getServiceName(self):
        return self.servicename

    #----------------------------------------------------------------------

    def __calledBy(self):
        """
        Log the caller of the method that calls this method

        @author: Roy Nielsen
        """
        try:
            filename = inspect.stack()[2][1]
            functionName = str(inspect.stack()[2][3])
            lineNumber = str(inspect.stack()[2][2])
        except Exception, err:
            raise err
        else:
            self.logdispatcher.log(LogPriority.DEBUG, "called by: " + \
                                      filename + ": " + \
                                      functionName + " (" + \
                                      lineNumber + ")")

    #----------------------------------------------------------------------

    def isServiceVarValid(self, service):
        """
        Input validator for the service variable

        @author: Roy Nielsen
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
                                   '-- self.service set to: ' + service)
                serviceValid = True

        except Exception, err:
            self.__calledBy()
            raise err

        return serviceValid

    #----------------------------------------------------------------------

    def setService(self, service, **kwargs):
        '''
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
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START SET(' + service + ')')

        setServiceSuccess = False

        if self.isServiceVarValid(service):
            self.service = service
            setServiceSuccess = True

        if "serviceName" in kwargs:
            self.servicename = kwargs.get("serviceName")
        elif "servicename" in kwargs:
            self.servicename = kwargs.get("servicename")
        else:
            self.servicename = ""

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END SET(' + service + \
                               ') = ' + str(setServiceSuccess))

        return setServiceSuccess

    #----------------------------------------------------------------------
    # Standard interface to the service helper.
    #----------------------------------------------------------------------

    def disableService(self, service, **kwargs):
        '''
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
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START DISABLE(' + service + ')')

        disabled = False

        if self.setService(service):
            chkSingle = False
            chkSecond = False

            chkSingle = self.svchelper.disableService(self.getService(), **kwargs)
            if self.isHybrid:
                chkSecond = self.secondary.disableService(self.getService(), **kwargs)

            if chkSingle or chkSecond:
                disabled = True
            else:
                disabled=False

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END DISABLE(' + service + \
                               ') = ' + str(disabled))

        # sync OS cache to filesystem (force write)
        # this was added to eliminate the delay on mac between
        # issuing the service disable command and when the service
        # actually gets disabled
        try:
            self.lc.sync()
        except Exception:
            raise

        return disabled

    #----------------------------------------------------------------------

    def enableService(self, service, **kwargs):
        '''
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

        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START ENABLE(' + service + ')')

        enabledSuccess = False

        if self.setService(service):
            enabledSingle = False
            enabledSecondary = False

            if not self.auditService(self.getService(), **kwargs):
                if self.svchelper.enableService(self.getService(), **kwargs):
                    enabledSingle = True

                if self.isHybrid:
                    if self.secondary.enableService(self.getService(), **kwargs):
                        enabledSecondary = True
            else:
                enabledSingle = True

            enabledSuccess = enabledSingle or enabledSecondary

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END ENABLE(' + service + \
                               ') = ' + str(enabledSuccess))

        # sync OS cache to filesystem (force write)
        # this was added to eliminate the delay on mac between
        # issuing the service enable command and when the service
        # actually gets enabled
        try:
            self.lc.sync()
        except Exception:
            raise

        return enabledSuccess

    #----------------------------------------------------------------------

    def auditService(self, service, **kwargs):
        '''
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

        @return: Bool, True if the service is configured to run
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START AUDIT(' + service + ')')

        auditSuccess = False
        if self.setService(service):
            singleSuccess = False
            secondarySuccess = False

            try:
                singleSuccess = self.svchelper.auditService(self.getService(), **kwargs)
            except OSError:
                singleSuccess = False

            if self.isHybrid:
                try:
                    secondarySuccess = self.secondary.auditService(self.getService(), **kwargs)
                except OSError:
                    secondarySuccess = False

            if singleSuccess or secondarySuccess:
                auditSuccess = True

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END AUDIT(' + service + \
                               ') = ' + str(auditSuccess))
        return auditSuccess

    #----------------------------------------------------------------------

    def isRunning(self, service, **kwargs):
        '''
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

        @return: bool, True if the service is already running
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START ISRUNNING(' + service + ')')
        isRunning = False
        if self.setService(service):
            singleSuccess = False
            secondarySuccess = False

            try:
                singleSuccess = self.svchelper.isRunning(self.getService(), **kwargs)
                if self.isHybrid:
                    secondarySuccess = self.secondary.isRunning(self.getService(), **kwargs)
            except:
                self.__calledBy()
                raise

            if singleSuccess or secondarySuccess:
                isRunning = True

        if isRunning:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " is running")
        else:
            self.logdispatcher.log(LogPriority.DEBUG, "Service: " + str(service) + " is NOT running")

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END ISRUNNING(' + service + \
                               ') = ' + str(isRunning))
        return isRunning

    #----------------------------------------------------------------------

    def reloadService(self, service, **kwargs):
        '''
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

        @return: bool indicating success status
        '''

        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START RELOAD(' + service + ')')

        if "serviceName" in kwargs:
            self.servicename = kwargs.get("serviceName")
        elif "servicename" in kwargs:
            self.servicename = kwargs.get("servicename")
        else:
            self.servicename = ""

        reloadSuccess = False
        if self.setService(service, servicename=self.servicename):
            singleSuccess = False
            secondarySuccess = False

            try:
                if self.isRunning(self.getService(), **kwargs):
                    singleSuccess = self.svchelper.reloadService(self.getService(), **kwargs)
                    if self.isHybrid:
                        secondarySuccess = self.secondary.reloadService(self.getService(), **kwargs)
                    else:
                        secondarySuccess = True
            except Exception, err:
                self.__calledBy()
                raise err

            if singleSuccess and secondarySuccess:
                reloadSuccess = True
        else:
            raise ValueError("Problem with setService in the Factory...")

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END RELOAD(' + service + \
                               ') = ' + str(reloadSuccess))
        return reloadSuccess

    #----------------------------------------------------------------------

    def listServices(self):
        '''
        List the services installed on the system.

        @param:

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.DEBUG, '--START')

        serviceList = []
        secondaryList = []
        try:
            serviceList = self.svchelper.listServices()

            if self.isHybrid:
                secondaryList = self.secondary.listServices()
                if secondaryList:
                    serviceList += secondaryList

        except:
            self.logdispatcher.log(LogPriority.DEBUG, str(self.__calledBy()))
            self.logdispatcher.log(LogPriority.DEBUG, "Sorry, exception raised, " +
                                   "we cannot acquire a sercideList.")

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END = ' + str(serviceList))
        return serviceList
