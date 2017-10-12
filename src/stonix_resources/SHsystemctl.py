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
@change: 2016/05/09 eball Changed auditservice to check output for "enabled"
    rather than just checking the return code.
'''
import subprocess
import re
import os
from CommandHelper import CommandHelper
from logdispatcher import LogPriority
from ServiceHelperTemplate import ServiceHelperTemplate

class SHsystemctl(ServiceHelperTemplate):
    '''
    SHsystemctl is the Service Helper for systems using the systemctl command to
    configure services. (Fedora and future RHEL and variants)
    '''

    def __init__(self, environment, logdispatcher):
        '''
        Constructor
        '''
        super(SHsystemctl, self).__init__(self, environment, logdispatcher)
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
        '''
        Disables the service and terminates it if it is running.

        @param string: Name of the service to be disabled
        @return: Bool indicating success status
        '''
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
        '''
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @param string: Name of the service to be enabled
        @return: Bool indicating success status
        '''
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
        '''
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @param string: Name of the service to audit
        @return: Bool, True if the service is configured to run
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsystemctl.audit ' + service)
        running = False
        command = [self.cmd, "is-enabled", service]
        self.ch.executeCommand(command)
        output = self.ch.getOutputString()
        if re.search("enabled", output):
            running = True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsystemctl.audit ' + service + ' '
                               + str(running) + ' ' + str(output))
        return running

    def isRunning(self, service, **kwargs):
        '''
        Check to see if a service is currently running. The enable service uses
        this so that we're not trying to start a service that is already
        running.

        @param sting: Name of the service to check
        @return: bool, True if the service is already running
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsystemctl.isrunning ' + service)
        running = False
        chk = subprocess.Popen(self.cmd + '--no-pager show ' + service,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=True,
                               close_fds=True)
        message = chk.stdout.readlines()
        for line in message:
            if re.search('SubState', line):
                line = line.split('=')
                if re.search('running', line[1]):
                    running = True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsystemctl.isrunning ' + service + ' ' + str(running))
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
                               'SHsystemctl.reload ' + service)
        if not self.environment.getinstallmode():
            ret = subprocess.call(self.cmd + 'reload-or-restart ' + service,
                                  shell=True, close_fds=True,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsystemctl.reload ' + service + str(ret))
        return True

    def listServices(self, **kwargs):
        '''
        Return a list containing strings that are service names.

        @return: list
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsystemctl.listservices')
        svclist = []
        chk = subprocess.Popen(self.cmd + '--no-pager --full -t service -a --no-legend',
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=True,
                               close_fds=True)
        proclist = chk.stdout.readlines()
        for line in proclist:
            if re.search('units listed', line):
                continue
            if re.search('^fsck', line):
                continue
            line = line.split()
            try:
                svclist.append(line[0])
            except(IndexError):
                # we hit an empty line, don't worry about it
                pass
        metaentries = ['LOAD', 'ACTIVE', 'SUB', 'JOB', 'UNIT']
        # This list comprehension will filter out entries listed
        # in metaentries which are just chatter from systemctl.
        svclist = [service for service in svclist if service not in metaentries]
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsystemctl.listservices ' + str(svclist))
        return svclist