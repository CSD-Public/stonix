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
@change: Added try/except in list services to handle blank lines in output
'''

import subprocess
import os
import re
from . logdispatcher import LogPriority
from ServiceHelperTemplate import ServiceHelperTemplate

class SHchkconfig(ServiceHelperTemplate):
    '''
    SHchkconfig is the Service Helper for systems using the chkconfig command to
    configure services. (RHEL up to 6, SUSE, Centos up to 6, etc)

    @author: dkennel
    '''

    def __init__(self, environment, logdispatcher):
        '''
        Constructor
        '''
        super(SHchkconfig, self).__init__(self, environment, logdispatcher)
        self.environment = environment
        self.logdispatcher = logdispatcher
        self.cmd = '/sbin/chkconfig '
        if os.path.exists('/sbin/service'):
            self.svc = '/sbin/service '
        else:
            self.svc = '/etc/init.d/'

    def disableService(self, service, **kwargs):
        '''
        Disables the service and terminates it if it is running.

        @param string: Name of the service to be disabled
        @return: Bool indicating success status
        '''
        ret2 = 0
        confsuccess = True
        svcoff = True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.disableservice: ' + service)
        ret = subprocess.call(self.cmd + service + ' off',
                              shell=True, close_fds=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        if ret != 0:
            confsuccess = False
        if self.isRunning(service):
            ret2 = subprocess.call(self.svc + service + ' stop',
                                   shell=True, close_fds=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            if ret2 != 0:
                svcoff = False
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.disableservice: ' + service + ' results ' + str(ret) + ' ' + str(ret2))
        if confsuccess and svcoff:
            return True
        else:
            return False

    def enableService(self, service, **kwargs):
        '''
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @param string: Name of the service to be enabled
        @return: Bool indicating success status
        '''
        ret2 = 0
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.enableservice: ' + service)
        if not os.path.exists('/etc/init.d/' + service):
            return False
        confsuccess = True
        svcon = True
        ret = subprocess.call(self.cmd + service + ' on',
                              shell=True, close_fds=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        if ret != 0:
            confsuccess = False
        if not self.environment.getinstallmode():
            ret2 = subprocess.call(self.svc + service + ' start',
                                   shell=True, close_fds=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            if ret2 != 0:
                svcon = False
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.enableservice: ' + service + ' results ' + str(ret) + ' ' + str(ret2))
        if confsuccess and svcon:
            return True
        else:
            return False

    def auditService(self, service, **kwargs):
        '''
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @param string: Name of the service to audit
        @return: Bool, True if the service is configured to run
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.auditservice: ' + service)
        chk = subprocess.Popen(self.cmd + '--list ' + service,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=True,
                               close_fds=True)
        proclist = chk.stdout.readlines()
        for line in proclist:
            if re.search(service, line) and re.search(':on', line):
                self.logdispatcher.log(LogPriority.DEBUG,
                                   'SHchkconfig.auditservice: ' + service + ' True')
                return True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.auditservice: ' + service + ' False')
        return False

    def isRunning(self, service, **kwargs):
        '''
        Check to see if a service is currently running.

        @param sting: Name of the service to check
        @return: bool, True if the service is already running
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.isrunning: ' + service)
        running = False
        chk = subprocess.Popen(self.svc + service + ' status',
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=True,
                               close_fds=True)
        message = chk.stdout.readlines()
        if len(message) == 0:
            running = self.auditService(service)
        for line in message:
            if re.search('running', line):
                running = True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.isrunning: ' + service + ' ' + str(running))
        return running

    def reloadService(self, service, **kwargs):
        '''
        Reload (HUP) a service so that it re-reads it's config files. Called
        by rules that are configuring a service to make the new configuration
        active.

        @param string: Name of the service to reload
        @return: bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.reloadservice ' + service)
        if not os.path.exists('/etc/init.d/' + service):
            return False
        if not self.environment.getinstallmode():
            ret = subprocess.call(self.svc + service + ' reload',
                                  shell=True, close_fds=True,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.reloadservice ' + service + str(ret))
            if ret != 0:
                return False
            else:
                return True

    def listServices(self, **kwargs):
        '''
        Return a list containing strings that are service names.

        @return: list
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.listservices')
        svclist = []
        chk = subprocess.Popen(self.cmd + '--list', stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=True,
                               close_fds=True)
        proclist = chk.stdout.readlines()
        for line in proclist:
            line = line.split()
            try:
                svclist.append(line[0])
            except IndexError:
                # caused by blank lines in output
                continue
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHchkconfig.listservices' + str(svclist))
        return svclist
