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
@change: 2017/10/11 - rsn - Switching to service helper two
'''
import subprocess
import re
from logdispatcher import LogPriority
from ServiceHelperTemplate import ServiceHelperTemplate


class SHsvcadm(ServiceHelperTemplate):
    '''
    SHsvcadm is the Service Helper for systems using the svcadm command to
    configure services. (Solaris)
    '''

    def __init__(self, environment, logdispatcher):
        '''
        Constructor
        '''
        super(SHsvcadm, self).__init__(self, environment, logdispatcher)
        self.environment = environment
        self.logdispatcher = logdispatcher
        self.cmd = '/usr/sbin/svcadm '
        self.svc = '/usr/bin/svcs '

    def disableService(self, service, **kwargs):
        '''
        Disables the service and terminates it if it is running.

        @param string: Name of the service to be disabled
        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsvcadm.disable ' + service)
        confsuccess = True
        ret = subprocess.call(self.cmd + 'disable ' + service,
                              shell=True, close_fds=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        if ret != 0:
            confsuccess = False
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsvcadm.disable ' + service + str(confsuccess))
        return confsuccess

    def enableService(self, service, **kwargs):
        '''
        Enables a service and starts it if it is not running as long as we are
        not in install mode

        @param string: Name of the service to be enabled
        @return: Bool indicating success status
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsvcadm.enable ' + service)
        confsuccess = True
        ret = subprocess.call(self.cmd + 'enable ' + service,
                              shell=True, close_fds=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        if ret != 0:
            confsuccess = False
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsvcadm.enable ' + service + str(confsuccess))
        return confsuccess

    def auditService(self, service, **kwargs):
        '''
        Checks the status of a service and returns a bool indicating whether or
        not the service is configured to run or not.

        @param string: Name of the service to audit
        @return: Bool, True if the service is configured to run
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsvcadm.audit ' + service)
        running = False
        chk = subprocess.Popen(self.svc + '-a ',
                               stdout = subprocess.PIPE,
                               stderr = subprocess.PIPE, shell = True,
                               close_fds = True)
        message = chk.stdout.readlines()
        for line in message:
            if re.search(service, line):
                if re.search('^disabled', line):
                    running = True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsvcadm.audit ' + service + str(running))
        return running

    def isRunning(self, service, **kwargs):
        '''
        Check to see if a service is currently running. The enable service uses
        this so that we're not trying to start a service that is already
        running.

        Like BSD this fails the unittest but works IRL.

        @param sting: Name of the service to check
        @return: bool, True if the service is already running
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsvcadm.isrunning ' + service)
        running = False
        chk = subprocess.Popen(self.svc + '-a',
                               stdout = subprocess.PIPE,
                               stderr = subprocess.PIPE, shell = True,
                               close_fds = True)
        message = chk.stdout.readlines()
        for line in message:
            if re.search(service, line):
                if re.search('^legacy_run|^online', line):
                    running = True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsvcadm.isrunning ' + service + str(running))
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
                               'SHsvcadm.reload ' + service)
        if not self.environment.getinstallmode():
            ret = subprocess.call(self.cmd + 'refresh ' + service,
                                  shell=True, close_fds=True,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsvcadm.reload ' + service + str(ret))
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
                               'SHsvcadm.listservices')
        svclist = []
        chk = subprocess.Popen(self.svc + '-a',
                               stdout = subprocess.PIPE,
                               stderr = subprocess.PIPE, shell = True,
                               close_fds = True)
        if chk.poll() != 0:
            raise RuntimeError, self.svc + \
                '-a command failed: ' \
                + chk.stderr.read() + ' ' + chk.stdout.read()
        proclist = chk.stdout.readlines()
        for line in proclist:
            if re.search('STIME', line):
                continue
            line = line.split()
            try:
                svclist.append(line[2])
            except(IndexError):
                # we hit an empty line, don't worry about it
                pass
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHsvcadm.listservices ' + str(svclist))
        return svclist