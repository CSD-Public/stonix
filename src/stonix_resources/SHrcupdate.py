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
Created on Sep 19, 2012

@author: dkennel
'''
import subprocess
import re
import os
from logdispatcher import LogPriority
from ServiceHelperTemplate import ServiceHelperTemplate


class SHrcupdate(ServiceHelperTemplate):
    '''
    SHrcupdate is the Service Helper for systems using the rcupdate command to
    configure services. (Gentoo & variants)

    @author: dkennel
    '''

    def __init__(self, environment, logdispatcher):
        '''
        Constructor
        '''
        super(SHrcupdate, self).__init__(self, environment, logdispatcher)
        self.environment = environment
        self.logdispatcher = logdispatcher
        self.cmd = '/sbin/rc-update '
        self.svc = '/etc/init.d/ '
        self.svclist = self.getsvclist()

    def getsvclist(self):
        '''
        Returns the list of enabled services and the run level in which they are
        scheduled to run. This is the raw output of rc-update show.

        @author: D. Kennel
        '''
        self.logdispatcher.log(LogPriority.DEBUG, 'SHrcupdate.getsvclist')
        try:
            proc = subprocess.Popen(self.cmd + 'show', stdout = subprocess.PIPE,
                                    stderr = subprocess.PIPE, shell = True,
                                    close_fds = True)
            svclist = proc.stdout.readlines()
        except(OSError):
            svclist = []
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcupdate.getsvclist' + str(svclist))
        return svclist

    def findrunlevel(self, service):
        '''
        Returns a string indicating the run level that the named service is
        configured to run at. If the service is not configured to run it will
        return None.

        @param string: service name
        @return: string: runlevel
        @author: D. Kennel
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcupdate.findrunlevel ' + service)
        runlevel = None
        for line in self.svclist:
            if re.search(service, line):
                splitline = line.split()
                try:
                    runlevel = splitline[2]
                except(IndexError):
                    continue
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcupdate.findrunlevel ' + service + ' ' + runlevel)
        return runlevel

    def disableService(self, service, **kwargs):
        '''
        Disables the service and terminates it if it is running.

        @param string: Name of the service to be disabled
        @return: Bool indicating success status
        '''
        ret2 = 0
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcupdate.disableservice ' + service)
        confsuccess = True
        svcoff = True
        runlevel = self.findrunlevel(service)
        ret = subprocess.call(self.cmd + 'delete ' + service + ' ' + runlevel,
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
                               'SHrcupdate.disableservice ' + service + ' ' + str(confsuccess) + str(svcoff))
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
                               'SHrcupdate.enableservice ' + service)
        if not os.path.exists('/etc/init.d/' + service):
            return False
        confsuccess = True
        svcon = True
        ret = subprocess.call(self.cmd + 'add ' + service,
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
                               'SHrcupdate.enableservice ' + service + ' ' + str(confsuccess) + str(svcon))
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
                               'SHrcupdate.auditservice ' + service)
        running = False
        try:
            proc = subprocess.Popen(self.cmd + 'show', stdout = subprocess.PIPE,
                                    stderr = subprocess.PIPE, shell = True,
                                    close_fds = True)
            svclist = proc.stdout.readlines()
        except(OSError):
            svclist = []
        for line in svclist:
            if re.search(service, line):
                running = True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcupdate.auditservice ' + service + ' ' + str(running))
        return running

    def isRunning(self, service, **kwargs):
        '''
        Check to see if a service is currently running. 

        @param sting: Name of the service to check
        @return: bool, True if the service is already running
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcupdate.isrunning ' + service)
        running = False
        chk = subprocess.Popen(self.svc + service + 'status',
                               stdout = subprocess.PIPE,
                               stderr = subprocess.PIPE, shell = True,
                               close_fds = True)
        message = chk.stdout.readlines()
        # some services don't return any output (sysstat) so we call audit
        chk.poll()
        if len(message) == 0:
            running = self.auditService(service)
        for line in message:
            if re.search('started', line):
                running = True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcupdate.isrunning ' + service + ' ' + str(running))
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
                               'SHrcupdate.reload ' + service)
        if not os.path.exists('/etc/init.d/' + service):
            return False
        if not self.environment.getinstallmode():
            ret = subprocess.call(self.svc + service + ' stop',
                                  shell=True, close_fds=True,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            ret = subprocess.call(self.svc + service + ' start',
                                  shell=True, close_fds=True,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            self.logdispatcher.log(LogPriority.DEBUG,
                                   'SHrcupdate.reload ' + service + str(ret))
            return True

    def listServices(self, **kwargs):
        '''
        Return a list containing strings that are service names.

        @return: list
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcupdate.listservices')
        svclist = os.listdir('/etc/init.d/')
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcupdate.listservices' + str(svclist))
        return svclist