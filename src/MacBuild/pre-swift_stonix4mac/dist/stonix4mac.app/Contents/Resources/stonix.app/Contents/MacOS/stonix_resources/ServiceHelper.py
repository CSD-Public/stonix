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
                self.svchelper = SHlaunchd.SHlaunchd(self.environ,
                                                     self.logdispatcher)
            else:
                raise RuntimeError("Could not identify service management " +
                                   "programs")
        elif truecount > 1:
            self.ishybrid = True
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
                               'ishybrid:' + str(self.ishybrid))
        self.logdispatcher.log(LogPriority.DEBUG,
                               'isdualparameterservice:' +
                               str(self.isdualparameterservice))

    def getService(self):
        return self.service

    def getServiceName(self):
        return self.servicename

    def setService(self, service, servicename=""):
        '''
        Update the name of the service being worked with.

        @param service string: Name of the service to be disabled
        @param servicename string: Short Name of the service to be disabled
        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START SET(' + service + ', ' + servicename +
                               ')')
        setservicesuccessall = False
        setservicesuccess = False
        setservicenamesuccess = False

        if not(type(self.getService()) is types.StringType):
            raise TypeError("self.getService() of " + \
                            str(self.getService()) + \
                            " is of type " + \
                            str(type(self.getService())) + \
                            " Not of type " + str(types.StringType) +\
                            "as expected!")
            self.service = ""
            setservicesuccess = False
        elif (service != ""):
            self.service = service
            setservicesuccess = True
        elif (self.service != ""):
            self.service = self.service
            setservicesuccess = True
            self.logdispatcher.log(LogPriority.DEBUG,
                               '-- self.service set to: ' + service)
        else:
            raise ValueError('service specified is blank. ' +\
                            'No action will be taken!')
            self.service = ""
            setservicesuccess = False

        if self.isdualparameterservice:
            if not(type(servicename) is types.StringType):
                raise TypeError("servicename of " + str(servicename) + \
                                " is of type " + str(type(servicename)) + \
                                " Not of type " + str(types.StringType) +\
                                "as expected!")
                self.servicename = ""
                setservicenamesuccess = False
            elif (servicename != ""):
                self.servicename = servicename
                setservicenamesuccess = True
                self.logdispatcher.log(LogPriority.DEBUG,
                               '-- Dual parameter service: self.servicename set to: ' + servicename)
            elif (self.servicename != ""):
                self.servicename = self.servicename
                setservicenamesuccess = True
            else:
                raise ValueError('Servicename specified is blank. ' +\
                                   'No action will be taken!')
                self.servicename = ""
                setservicenamesuccess = False
        else:
            self.servicename = ""
            setservicenamesuccess = True

        if (setservicesuccess and setservicenamesuccess):
            setservicesuccessall = True
        else:
            setservicesuccessall = False

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END SET(' + service + ', ' + servicename +
                               ') = ' + str(setservicesuccessall))

        return setservicesuccessall

    def disableservice(self, service, servicename=""):
        '''
        Disables the service and terminates it if it is running.

        @param service string: Name of the service to be disabled
        @param servicename string: Short Name of the service to be disabled
        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START DISABLE(' + service + ', ' + servicename +
                                ')')
        servicesuccess = False
        chksingle = False
        chksecond = True
        if (self.setService(service, servicename)):
            if self.isdualparameterservice:
                self.logdispatcher.log(LogPriority.DEBUG,
                                       'Starting disable for dual parameter ('
                                       + service + ', ' + servicename + ')')
                chksecond = False
                chksingle = self.svchelper.disableservice(self.getService(),
                                                          self.getServiceName())
                if self.ishybrid:
                    chksecond = self.secondary.disableservice(self.getService(),
                                                              self.getServiceName())
                if chksingle or chksecond:
                    servicesuccess = True
                else:
                    servicesuccess = False
            else:
                if self.auditservice(self.getService()) or \
                   self.isrunning(self.getService()):
                    self.logdispatcher.log(LogPriority.DEBUG,
                                           ['ServiceHelper.disableservice',
                                            'Audit Successful (' + service + ')'])
                    chksecond = False
                    chksingle = self.svchelper.disableservice(self.getService())
                    if self.ishybrid:
                        chksecond = self.secondary.disableservice(self.getService())
                    if chksingle or chksecond:
                        servicesuccess = True
                    else:
                        servicesuccess = False
                else:
                    servicesuccess = True
        else:
            servicesuccess = False

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END DISABLE(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return servicesuccess

    def enableservice(self, service, servicename=""):
        '''
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @param service string: Name of the service to be enabled
        @param servicename string: Short Name of the service to be enabled
        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START ENABLE(' + service + ', ' + servicename +
                               ')')
        servicesuccess = False
        chksingle = False
        chksecond = True
        if (self.setService(service, servicename)):
            if self.isdualparameterservice:
                if not self.auditservice(self.getService(), self.getServiceName()):
                    # print 'Audit returned False'
                    chksecond = False
                    chksingle = self.svchelper.enableservice(self.getService(),
                                                             self.getServiceName())
                if self.ishybrid:
                    chksecond = self.secondary.enableservice(self.getService(),
                                                             self.getServiceName())
                if chksingle or chksecond:
                    servicesuccess = True
                else:
                    servicesuccess = False
            else:
                if not self.auditservice(self.getService()):
                    # print 'Audit returned False'
                    chksecond = False
                    chksingle = self.svchelper.enableservice(self.getService())
                    if self.ishybrid:
                        chksecond = self.secondary.enableservice(self.getService())
                    if chksingle or chksecond:
                        servicesuccess = True
                    else:
                        servicesuccess = False
                else:
                    servicesuccess = True
        else:
            servicesuccess = False

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END ENABLE(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return servicesuccess

    def auditservice(self, service, servicename=""):
        '''
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @param service string: Name of the service to be audited
        @param servicename string: Short Name of the service to be audit
        @return: Bool, True if the service is configured to run
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START AUDIT(' + service + ', ' + servicename +
                               ')')
        servicesuccess = False
        if (self.setService(service, servicename)):
            chksecond = False
            if self.isdualparameterservice:
                self.logdispatcher.log(LogPriority.DEBUG,
                               '--auditing dual parameter service ('
                               + service + ', ' + servicename + ')')
                try:
                    chksingle = self.svchelper.auditservice(self.getService(),
                                                        self.getServiceName())
                except(OSError):
                    # OS Error usually indicates program is not installed
                    chksingle = False
                if self.ishybrid:
                    self.logdispatcher.log(LogPriority.DEBUG,
                               '--Service is a hybrid')
                    try:
                        chksecond = self.secondary.auditservice(self.getService(),
                                                            self.getServiceName())
                    except(OSError):
                        chksecond = False
                if chksingle or chksecond:
                    servicesuccess = True
                else:
                    servicesuccess = False
                self.logdispatcher.log(LogPriority.DEBUG,
                               '--auditing dual parameter service results ('
                               + str(chksingle) + ', ' + str(chksecond) + ')')
            else:
                self.logdispatcher.log(LogPriority.DEBUG,
                               '--auditing single parameter service ('
                               + service + ')')
                try:
                    chksingle = self.svchelper.auditservice(self.getService())
                except(OSError):
                    chksingle = False
                if self.ishybrid:
                    self.logdispatcher.log(LogPriority.DEBUG,
                               '--Service is a hybrid')
                    try:
                        chksecond = self.secondary.auditservice(self.getService())
                    except(OSError):
                        chksecond = False
                if chksingle or chksecond:
                    servicesuccess = True
                else:
                    servicesuccess = False
                self.logdispatcher.log(LogPriority.DEBUG,
                               '--auditing single parameter service results ('
                               + str(chksingle) + ', ' + str(chksecond) + ')')
        else:
            servicesuccess = False

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END AUDIT(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return servicesuccess

    def isrunning(self, service, servicename=""):
        '''
        Check to see if a service is currently running. The enable service uses
        this so that we're not trying to start a service that is already
        running.

        @param service string: Name of the service to be checked
        @param servicename string: Short Name of the service to be checked
        @return: bool, True if the service is already running
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START ISRUNNING(' + service + ', ' +
                               servicename + ')')
        servicesuccess = False
        if (self.setService(service, servicename)):
            runsecond = False
            if self.isdualparameterservice:
                runpri = self.svchelper.isrunning(self.getService(),
                                                  self.getServiceName())
                if self.ishybrid:
                    runsecond = self.secondary.isrunning(self.getService(),
                                                         self.getServiceName())
                if runpri or runsecond:
                    servicesuccess = True
                else:
                    servicesuccess = False
            else:
                runpri = self.svchelper.isrunning(self.getService())
                if self.ishybrid:
                    runsecond = self.secondary.isrunning(self.getService())
                if runpri or runsecond:
                    servicesuccess = True
                else:
                    servicesuccess = False
        else:
            servicesuccess = False

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END ISRUNNING(' + service + ', ' +
                               servicename + ') = ' + str(servicesuccess))
        return servicesuccess

    def reloadservice(self, service, servicename=""):
        '''
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active. This method ignores services that do not return true when
        self.isrunning() is called. The assumption being that this method is
        being called due to a change in a conf file, and a service that isn't
        currently running will pick up the change when (if) it is started.

        @param service string: Name of the service to be reloaded
        @param servicename string: Short Name of the service to be reloaded
        @return: bool indicating success status
        '''

        self.logdispatcher.log(LogPriority.DEBUG,
                               '--START RELOAD(' + service + ', ' + servicename +
                                ')')
        servicesuccess = False
        if (self.setService(service, servicename)):
            chksingle = False
            chksecond = True
            if self.isdualparameterservice:
                if self.isrunning(self.getService(), self.getServiceName()):
                    chksecond = False
                    chksingle = self.svchelper.reloadservice(self.getService(),
                                                             self.getServiceName())
                    if self.ishybrid:
                        chksecond = self.secondary.reloadservice(self.getService(),
                                                                  self.getServiceName())
                    if chksingle or chksecond:
                        servicesuccess = True
                    else:
                        servicesuccess = False
            else:
                if self.isrunning(self.getService()):
                    chksecond = False
                    chksingle = self.svchelper.reloadservice(self.getService())
                    if self.ishybrid:
                        chksecond = self.secondary.reloadservice(self.getService())
                    if chksingle or chksecond:
                        servicesuccess = True
                    else:
                        servicesuccess = False
        else:
            servicesuccess = False

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END RELOAD(' + service + ', ' + servicename +
                               ') = ' + str(servicesuccess))
        return servicesuccess

    def listservices(self):
        '''
        List the services installed on the system.

        @return: list of strings
        '''
        self.logdispatcher.log(LogPriority.DEBUG, '--START')

        servicelist = self.svchelper.listservices()
        if self.ishybrid:
            secondary = self.secondary.listservices()
            for svc in secondary:
                servicelist.append(svc)

        self.logdispatcher.log(LogPriority.DEBUG,
                               '-- END = ' + str(servicelist))
        return servicelist
