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
'''
import os
import types
import SHchkconfig
import SHrcupdate
import SHupdaterc
import SHsystemctl
import SHsvcadm
import SHrcconf
import SHlaunchd
from logdispatcher import LogPriority


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

    def __init__(self, environment, logdispatcher):
        '''
        The ServiceHelper needs to receive the STONIX environment and
        logdispatcher objects as parameters to init.

        @param environment: STONIX environment object
        '''
        self.environ = environment
        self.logdispatcher = logdispatcher
        self.ishybrid = False
        self.isdualparameterservice = False
        self.svchelper = None
        self.secondary = None
        self.service = ""
        self.servicename = ""
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
                self.svchelper = SHchkconfigTwo.SHchkconfig(self.environ,
                                                         self.logdispatcher)
            elif isrcupdate:
                self.svchelper = SHrcupdateTwo.SHrcupdate(self.environ,
                                                       self.logdispatcher)
            elif isupdaterc:
                self.svchelper = SHupdatercTwo.SHupdaterc(self.environ,
                                                       self.logdispatcher)
            elif issystemctl:
                self.svchelper = SHsystemctlTwo.SHsystemctl(self.environ,
                                                         self.logdispatcher)
            elif issvcadm:
                self.svchelper = SHsvcadmTwo.SHsvcadm(self.environ,
                                                   self.logdispatcher)
            elif isrcconf:
                self.svchelper = SHrcconfTwo.SHrcconf(self.environ,
                                                   self.logdispatcher)
            elif islaunchd:
                self.svchelper = SHlaunchdTwo.SHlaunchd(self.environ,
                                                     self.logdispatcher)
            else:
                raise RuntimeError("Could not identify service management " +
                                   "programs")
        elif truecount > 1:
            self.ishybrid = True
            count = 0
            if issystemctl:
                self.svchelper = SHsystemctlTwo.SHsystemctl(self.environ,
                                                         self.logdispatcher)
                count = 1
            if ischkconfig:
                if count == 0:
                    self.svchelper = SHchkconfigTwo.SHchkconfig(self.environ,
                                                             self.logdispatcher)
                    count = 1
                elif count == 1:
                    self.secondary = SHchkconfigTwo.SHchkconfig(self.environ,
                                                             self.logdispatcher)
            if isrcupdate:
                if count == 0:
                    self.svchelper = SHrcupdateTwo.SHrcupdate(self.environ,
                                                           self.logdispatcher)
                    count = 1
                elif count == 1:
                    self.secondary = SHrcupdateTwo.SHrcupdate(self.environ,
                                                           self.logdispatcher)
            if isupdaterc:
                if count == 0:
                    self.svchelper = SHupdatercTwo.SHupdaterc(self.environ,
                                                           self.logdispatcher)
                    count = 1
                elif count == 1:
                    self.secondary = SHupdatercTwo.SHupdaterc(self.environ,
                                                           self.logdispatcher)
            if issvcadm:
                if count == 0:
                    self.svchelper = SHsvcadmTwo.SHsvcadm(self.environ,
                                                       self.logdispatcher)
                    count = 1
                elif count == 1:
                    self.secondary = SHsvcadmTwo.SHsvcadm(self.environ,
                                                       self.logdispatcher)
            if isrcconf:
                if count == 0:
                    self.svchelper = SHrcconfTwo.SHrcconf(self.environ,
                                                       self.logdispatcher)
                    count = 1
                elif count == 1:
                    self.secondary = SHrcconfTwo.SHrcconf(self.environ,
                                                       self.logdispatcher)
            if islaunchd:
                self.svchelper = SHlaunchdTwo.SHlaunchd(self.environ,
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
                               'ishybrid:' + str(self.ishybrid))
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

    def getSpecificHelper(self):
        """
        Getter to acqure the specific keychain manager
        """
        return self.svchelper.getHelper(), self.secondary.getHelper()

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
            self.logger.log(lp.DEBUG, "called by: " + \
                                      filename + ": " + \
                                      functionName + " (" + \
                                      lineNumber + ")")

    #----------------------------------------------------------------------

    def setService(self, *args, **kwargs):
        '''
        Update the name of the service being worked with.

        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START SET(' + service + ', ' + servicename +
                               ')')

        serviceSuccessAll = False
        serviceSuccessAll = self.svchelper.setService(*args, **kwargs)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END SET(' + service + ', ' + servicename +
                               ') = ' + str(setservicesuccessall))

        return setserviceSuccessAll

    #----------------------------------------------------------------------
    # Standard interface to the service helper.
    #----------------------------------------------------------------------

    def disableService(self, service, *args, **kwargs):
        '''
        Disables the service and terminates it if it is running.

        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START DISABLE(' + service + ', ' + servicename +
                                ')')

        serviceSuccess = False
        serviceSuccess = self.svchelper.disableService(*args, **kwargs)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END DISABLE(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return serviceSuccess

    #----------------------------------------------------------------------

    def enableService(self, service, *args, **kwargs):
        '''
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START ENABLE(' + service + ', ' + servicename +
                               ')')

        serviceSuccess = False
        serviceSuccess = self.svchelper.enableService(*args, **kwargs)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END ENABLE(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return serviceSuccess

    #----------------------------------------------------------------------

    def auditService(self, service, *args, **kwargs):
        '''
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @return: Bool, True if the service is configured to run
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START AUDIT(' + service + ', ' + servicename +
                               ')')

        serviceSuccess = False
        serviceSuccess = self.svchelper.auditService(*args, **kwargs)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END AUDIT(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return serviceSuccess

    #----------------------------------------------------------------------

    def isRunning(self, service, *args, **kwargs):
        '''
        Check to see if a service is currently running. The enable service uses
        this so that we're not trying to start a service that is already
        running.

        @return: bool, True if the service is already running
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START ISRUNNING(' + service + ', ' +
                               servicename + ')')

        serviceSuccess = False
        serviceSuccess = self.svchelper.isRunning(*args, **kwargs)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END ISRUNNING(' + service + ', ' +
                               servicename + ') = ' + str(servicesuccess))
        return serviceSuccess

    #----------------------------------------------------------------------

    def reloadService(self, service, *args, **kwargs):
        '''
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active. This method ignores services that do not return true when
        self.isrunning() is called. The assumption being that this method is
        being called due to a change in a conf file, and a service that isn't
        currently running will pick up the change when (if) it is started.

        @return: bool indicating success status
        '''

        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START RELOAD(' + service + ', ' + servicename +
                                ')')

        serviceSuccess = False
        serviceSuccess = self.svchelper.reloadService(*args, **kwargs)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END RELOAD(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return serviceSuccess

    #----------------------------------------------------------------------

    def listServices(self):
        '''
        List the services installed on the system.

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.DEBUG, '--START')

        serviceList = None
        serviceList = self.svchelper.listServices(*args, **kwargs)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END = ' + str(serviceList))
        return serviceList

    #----------------------------------------------------------------------

    def kill(self, process, *args, **kwargs):
        '''
        Kills a process with a unix signal.

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START KILL(' + service + ', ' + servicename +
                                ')')

        serviceSuccess = False
        serviceSuccess = self.svchelper.kill(*args, **kwargs)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END KILL(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return serviceSuccess

    #----------------------------------------------------------------------

    def start(self, service, *args, **kwargs):
        '''
        Start a service installed on the system.

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START START(' + service + ', ' + servicename +
                                ')')

        serviceSuccess = False
        serviceSuccess = self.svchelper.start(*args, **kwargs)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END START(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return serviceSuccess

    #----------------------------------------------------------------------

    def stop(self, service, *args, **kwargs):
        '''
        Stop a service installed on the system.

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START STOP(' + service + ', ' + servicename +
                                ')')

        serviceSuccess = False
        serviceSuccess = self.svchelper.stop(*args, **kwargs)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END STOP(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return serviceSuccess

    #----------------------------------------------------------------------

    def restart(self, service, *args, **kwargs):
        '''
        Restart a service installed on the system.

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START RESTART(' + service + ', ' + servicename +
                                ')')

        serviceSuccess = False
        serviceSuccess = self.svchelper.restart(*args, **kwargs)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END RESTART(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return serviceSuccess
