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
import os
import re
import subprocess
from logdispatcher import LogPriority
from ServiceHelperTemplate import ServiceHelperTemplate


class SHrcconf(object):
    '''
    SHrcconf is the Service Helper for systems using /etc/rc.conf to
    configure services. (FreeBSD and some variants)
    '''

    def __init__(self, environment, logdispatcher):
        '''
        Constructor
        '''
        super(SHrcconf, self).__init__(environment, logdispatcher)
        self.environment = environment
        self.logdispatcher = logdispatcher
        self.svc = '/etc/rc.d/'

    def disableService(self, service, **kwargs):
        '''
        Disables the service and terminates it if it is running.

        @param string: Name of the service to be disabled
        @return: Bool indicating success status
        '''
        ret2 = 0
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcconf.disable ' + service)
        confsuccess = True
        svcoff = True
        try:
            self.editrcconf(service, False)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            confsuccess = False
        if self.isRunning(service):
            ret2 = subprocess.call(self.svc + service + ' stop',
                                   shell=True, close_fds=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            if ret2 != 0:
                svcoff = False
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcconf.disable ' + service + ' ' + str(confsuccess) + str(svcoff))
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
                               'SHrcconf.enable ' + service)
        confsuccess = True
        svcon = True
        try:
            self.editrcconf(service, True)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            confsuccess = False
        if not self.environment.getinstallmode():
            ret2 = subprocess.call(self.svc + service + ' start',
                                   shell=True, close_fds=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            if ret2 != 0:
                svcon = False
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcconf.enable ' + service + ' ' + str(confsuccess) + str(svcon))
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
                               'SHrcconf.audit ' + service)
        enabled = False
        pattern = service + '_enable="YES"'
        rcfile = open('/etc/rc.conf', 'r')
        rcdata = rcfile.readlines()
        for line in rcdata:
            if re.search('^#', line):
                continue
            elif re.search(pattern, line):
                enabled = True
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcconf.audit ' + service + str(enabled))
        return enabled

    def isRunning(self, service, **kwargs):
        '''
        Check to see if a service is currently running. The enable service uses
        this so that we're not trying to start a service that is already
        running.

        Note that this fails it's unittest due to some odd quirk of BSD.

        @param sting: Name of the service to check
        @return: bool, True if the service is already running
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcconf.isrunning ' + service)
        running = True
        chk = subprocess.Popen(self.svc + service + ' status',
                               stdout = subprocess.PIPE,
                               stderr = subprocess.PIPE, shell = True,
                               close_fds = True)
        message = chk.stdout.readlines()
        # some services don't return any output (sysstat) so we call audit
        if len(message) == 0:
            running = self.auditService(service)
        for line in message:
            if re.search('not running', line):
                running = False
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcconf.isrunning ' + service + str(running))
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
                               'SHrcconf.reload ' + service)
        if not self.environment.getinstallmode():
            ret = subprocess.call(self.svc + service + ' restart',
                                  shell=True, close_fds=True,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcconf.reload ' + service + str(ret))
            if ret != 0:
                return False
            else:
                return True

    def listServices(self, **kwargs):
        '''
        Walk through the FreeBSD service control files in rc.d and gather
        the service names. We have to do this this way because some services
        <cough> sendmail </cough> have multiple names from a single rc.d
        file.

        @return: list of strings which are service names
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcconf.listservices')
        servicelist = []
        rcfiles = os.listdir('/etc/rc.d')
        for rcfile in rcfiles:
            myfile = open('/etc/rc.d/' + rcfile)
            mydata = myfile.readlines()
            for line in mydata:
                line = line.strip()
                if re.search('^name=', line):
                    line = line.split('=')
                    sname = re.sub(r'^"|"$', '', line[1])
                    servicelist.append(sname)
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcconf.listservices ' + str(servicelist))
        return servicelist

    def editrcconf(self, service, enabled):
        '''
        This method assists the enable and disable methods in editing the
        /etc/rc.conf file. It expects to be passed a service name
        (without _enable) and a bool for enabled. True equates to "YES" in the
        rc.conf and False to "NO".

        @param string: service name
        @param bool: enabled status
        '''
        self.logdispatcher.log(LogPriority.DEBUG,
                               'SHrcconf.editrcconf ' + service + str(enabled))

        rcconf = open('/etc/rc.conf', 'r')
        rcdata = rcconf.read()
        rcconf.close()
        if enabled:
            if re.search(service + '_enable', rcdata):
                rcdata = re.sub(service + '_enable="NO"',
                                service + '_enable="YES"', rcdata)
            else:
                rcdata = rcdata + '/n'+service+'_enable="YES"'
        if not enabled:
            if re.search(service + '_enable', rcdata):
                rcdata = re.sub(service + '_enable="YES"',
                                service + '_enable="NO"', rcdata)
            else:
                rcdata = rcdata + '/n'+service+'_enable="NO"'
        rcconfw = open('/etc/rc.conf', 'w')
        rcconfw.write(rcdata)
        rcconfw.close()
