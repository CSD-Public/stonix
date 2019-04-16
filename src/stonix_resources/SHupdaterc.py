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

'''
Created on Sep 19, 2012

@author: dkennel
@change: 2015/10/15 eball Added chk.wait() and chk.returncode == 0 to isrunning
@change: 2018/02/22 bgonz12 Changed regex in auditService to cut off after the
                    service's name
'''
import subprocess
import re
import os
from logdispatcher import LogPriority
from ServiceHelperTemplate import ServiceHelperTemplate


class SHupdaterc(ServiceHelperTemplate):
    '''
    SHupdaterc is the Service Helper for systems using the rcupdate command to
    configure services. (Debian, Ubuntu and variants)
    '''

    def __init__(self, environment, logdispatcher):
        '''
        Constructor
        '''
        super(SHupdaterc, self).__init__(environment, logdispatcher)
        self.environment = environment
        self.logdispatcher = logdispatcher
        self.cmd = '/usr/sbin/update-rc.d '
        self.svc = '/usr/sbin/service '

    def disableService(self, service, **kwargs):
        '''
        Disables the service and terminates it if it is running.

        @param string: Name of the service to be disabled
        @return: Bool indicating success status
        '''
        ret2 = 0
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHupdaterc.disableservice ' + service)
        confsuccess = True
        svcoff = True
        ret = subprocess.call(self.cmd + '-f ' + service + ' remove',
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
                               'SHupdaterc.disableservice ' + service + ' ' +
                               str(confsuccess) + " " + str(svcoff))
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
                               'SHupdaterc.enableservice ' + service)
        if not os.path.exists('/etc/init.d/' + service):
            return False
        confsuccess = True
        svcon = True
        ret = subprocess.call(self.cmd + service + ' defaults',
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
                               'SHupdaterc.enableservice ' + service + ' ' +
                               str(confsuccess) + str(svcon))
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
                               'SHupdaterc.auditservice ' + service)
        running = False
        sklist = []
        for rcdir in ['/etc/rc2.d', '/etc/rc3.d', '/etc/rc4.d', '/etc/rc5.d']:
            sklist = sklist + os.listdir(rcdir)
        for entry in sklist:
            if re.search('S..' + service + '$', entry):
                running = True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHupdaterc.auditservice ' + service + ' ' +
                               str(running))
        return running

    def isRunning(self, service, **kwargs):
        '''
        Check to see if a service is currently running.

        @param sting: Name of the service to check
        @return: bool, True if the service is already running
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHupdaterc.isrunning ' + service)
        running = False
        chk = subprocess.Popen(self.svc + service + ' status',
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=True,
                               close_fds=True)
        # wait() can be a risky call, but in this case, the service command
        # will almost never output more than a few lines
        chk.wait()
        message = chk.stdout.readlines()
        # some services don't return any output (sysstat) so we call audit
        if len(message) == 0:
            running = self.auditService(service)
        for line in message:
            if re.search('running', line) and chk.returncode == 0:
                running = True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHupdaterc.isrunning ' + service + ' ' +
                               str(running))
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
                               'SHupdaterc.reload ' + service)
        if not os.path.exists('/etc/init.d/' + service):
            return False
        if not self.environment.getinstallmode():
            ret = subprocess.call(self.svc + service + ' reload',
                                  shell=True, close_fds=True,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            self.logdispatcher.log(LogPriority.DEBUG,
                                   'SHupdaterc.reload ' + service + str(ret))
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
                               'SHupdaterc.listservices')
        svclist = os.listdir('/etc/init.d/')
        metafiles = ['README', 'skeleton', 'rc', 'rcS']
        # This list comprehension will filter out filenames listed
        # in metafiles.
        svclist = [service for service in svclist if service not in metafiles]
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHupdaterc.listservices ' + str(svclist))
        return svclist
