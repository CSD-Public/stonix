#!/usr/bin/env python

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
# ============================================================================#
#               Filename          $RCSfile: stonix/logdispatcher.py,v $
#               Description       Security Configuration Script
#               OS                Linux, Mac OS X, Solaris, BSD
#               Author            Dave Kennel
#               Last updated by   $Author: $
#               Notes             Based on CIS Benchmarks, NSA RHEL
#                                 Guidelines, NIST and DISA STIG/Checklist
#               Release           $Revision: 1.0 $
#               Modified Date     $Date: 2013/10/3 14:00:00 $
# ============================================================================#
'''
Created on September 14, 2015, based on logdispatcher in the stonix_resources
directory.  We need instrumentation for tests.  A mock will no longer suffice.

Primary instruction for this class is to perform all logdispatcher functionality
minus the xml related functionality.

@author: dkennel - of logdispatcher in the stonix_resources directory.
@note: rsn - started logdispatcher lite
'''

import logging
import logging.handlers
import os.path
import os
import socket
import inspect
import traceback
import weakref
import subprocess
from shutil import move
import src.stonix_resources.localize as localize

class LogDispatcher ():
    """
    Responsible for taking any log data and formating both a human readable log
    containing machine info and run errors.
    :version: 1
    :author: scmcleni
    """

    def __init__(self, environment):
        self.environment = environment
        self.debug = self.environment.getdebugmode()
        self.verbose = self.environment.getverbosemode()
        reportfile = 'stonix-report.log'
        self.logpath = self.environment.get_log_path()
        self.reportlog = os.path.join(self.logpath, reportfile)
        self.metadataopen = False
        self.__initializelogs()
        self.last_message_received = ""
        self.last_prio = LogPriority.ERROR

    def log(self, priority, msg_data):
        """
        Handles all writing of logger data to files. `msg_data` should be
        passed as an array of [tag, message_details] where tag is a
        descriptive string for the detailed message and XML log. For example

        ['StonixRunDateTime', '2000-01-11 11:40:01']

        If msg_data is passed as only a string then it will be tagged as "None"

        For STONIX logging purposes all essential notifications should come in
        on the "WARNING" channel. All informational notifications should come
        in on the "INFO" channel. Debug messages should use "DEBUG". Program
        errors should be sent to the "ERROR" facility. "CRITICAL" is reserved
        for events that stop the stonix program.

        @param: enum priority
        @param: string msg_data
        @return: void
        @author scmcleni
        @author: dkennel
        """

        entry = self.format_message_data(msg_data)

        self.last_message_received = entry
        self.last_prio = priority
        if isinstance(msg_data, list):
            msg = str(msg_data[0]).strip() + ':' + str(msg_data[1]).strip()
        else:
            # msg = 'none' + ':' + msg_data.strip()
            msg = msg_data.strip()
        if self.debug:
            #####
            # Set up inspect to use stack variables to log file and
            # method/function that is being called. Message to be in the
            # format:
            # DEBUG:<name_of_module>:<name of function>(<line number>): <message to print>
            stack1 = inspect.stack()[1]
            mod = inspect.getmodule(stack1[0])
            if mod:
                prefix = mod.__name__ + \
                      ":" + stack1[3] + \
                      "(" + str(stack1[2]) + "): "
            else:
                prefix = stack1[3] + \
                      "(" + str(stack1[2]) + "): "
        else:
            stack1 = inspect.stack()[1]
            mod = inspect.getmodule(stack1[0])
            if mod:
                prefix = mod.__name__ + \
                      ":" + stack1[3] + ":"
            else:
                prefix = stack1[3] + ":"

        if priority == LogPriority.INFO:
            logging.info('INFO:' + prefix + msg)

        elif priority == LogPriority.WARNING:
            logging.warning('WARNING:' + msg)
        elif priority == LogPriority.ERROR:
            logging.error('ERROR:' + prefix + msg)
        elif priority == LogPriority.CRITICAL:
            logging.critical('CRITICAL:' + prefix + msg)
        elif priority == LogPriority.DEBUG:
            logging.debug('DEBUG:' + prefix + msg)
        else:
            # Invalid log priority
            pass

    def format_message_data(self, msg_data):
        """
        If the expected 2 item array is passed then attach those items to
        a MessageData object. Index 0 is expected to be a tag, Index 1 is
        expected to be the detail. If an array is not passed then it is assumed
        that there is no tag (defaults to 'None') and the passed data is set
        as the Detail of the MessageData object.
        @return MessageData
        @author: scmcleni
        """
        entry = MessageData()
        if isinstance(msg_data, list):
            entry.Tag = msg_data[0].strip()
            detail = str(msg_data[1])
            entry.Detail = detail.strip()
        else:
            entry.Detail = msg_data.strip()

        return entry

    def getconsolemessage(self):
        """
        Returns the current message if called while in a dirty state.

        @return: MessageData
        @author: scmcleni
        """
        return self.last_message_received

    def getmessageprio(self):
        """
        Returns the message priority of the last message received.

        @return: LogPriority instance
        @author: dkennel
        """
        return self.last_prio

    def displaylastrun(self):
        """
        Read through the entirety of the stonix_last.log file and return it.

        @return: string
        @author: scmcleni
        """
        # Make sure the file exists first
        if os.path.isfile(self.reportlog + '.old'):
            try:
                last_log = open(self.reportlog + '.old').readlines()
                # removed DK because it's a noop
                # last_log = filter(None, last_log)
                return ''.join(last_log)

            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception, err:
                print 'logdispatcher: '
                print traceback.format_exc()
                print err
                return False

    def logRuleCount(self):
        '''
        This method logs the rule count. This is part of the run metadata but
        is processed seperately due to timing issues in the controller's init

        @author: dkennel
        '''
        self.metadataopen = True
        self.log(LogPriority.WARNING,
                 ['RuleCount', self.environment.getnumrules()])
        self.metadataopen = False

    def __initializelogs(self):
        """
        Open a handle to a text file (stonix.log) making it available for
        writing (append) mode. Also need to look for an old log file (prior run)
        and move it to stonix_last.log.

        @return: void
        @author: scmcleni
        @author: D. Kennel
        """

        # Check for old log file and move it to a different file name
        # overwriting any old one if it exists.
        if not os.path.isdir(self.logpath):
            try:
                os.makedirs(self.logpath, 0750)
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception, err:
                print 'logdispatcher: '
                print traceback.format_exc()
                print err
                return False
        if os.path.isfile(self.reportlog):
            try:
                if os.path.exists(self.reportlog + '.old'):
                    os.remove(self.reportlog + '.old')
                move(self.reportlog, self.reportlog + '.old')
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception, err:
                print 'logdispatcher: '
                print traceback.format_exc()
                print err
                return False

        # It's important that this happens after the attempt to move
        # the old log file.
        # Configure the python logging utility. Set the minimum reported log
        # data to warning or higher. (INFO and DEBUG messages will be ignored)

        if self.environment.getdebugmode():
            logging.basicConfig(filename=self.reportlog,
                                level=logging.DEBUG)
        elif self.environment.getverbosemode():
            logging.basicConfig(filename=self.reportlog,
                                level=logging.INFO)
        else:
            logging.basicConfig(filename=self.reportlog,
                                level=logging.WARNING)
        console = logging.StreamHandler()
        if self.environment.getdebugmode():
            console.setLevel(logging.DEBUG)
        elif self.environment.getverbosemode():
            console.setLevel(logging.INFO)
        else:
            console.setLevel(logging.WARNING)
        try:
            syslogs = logging.handlers.SysLogHandler()
            syslogs.setLevel(logging.WARNING)
            logging.getLogger('').addHandler(syslogs)
            logging.getLogger('').addHandler(console)
        except socket.error:
            logging.getLogger('').addHandler(console)
            self.log(LogPriority.ERROR,
                     ['LogDispatcher',
                      'SYSLOG not accepting connections!'])

        self.metadataopen = True
        self.log(LogPriority.WARNING,
                 ["Hostname", self.environment.hostname])
        self.log(LogPriority.WARNING,
                 ["IPAddress", self.environment.ipaddress])
        self.log(LogPriority.WARNING,
                 ["MACAddress", self.environment.macaddress])
        self.log(LogPriority.WARNING,
                 ["OS", str(self.environment.getosreportstring())])
        self.log(LogPriority.WARNING,
                 ["STONIXversion", self.environment.getstonixversion()])
        self.log(LogPriority.WARNING,
                 ['RunTime', self.environment.getruntime()])
        self.log(LogPriority.WARNING,
                 ['PropertyNumber',
                  str(self.environment.get_property_number())])
        self.log(LogPriority.WARNING,
                 ['SystemSerialNo',
                  self.environment.get_system_serial_number()])
        self.log(LogPriority.WARNING,
                 ['ChassisSerialNo',
                  self.environment.get_chassis_serial_number()])
        self.log(LogPriority.WARNING,
                 ['SystemManufacturer',
                  self.environment.get_system_manufacturer()])
        self.log(LogPriority.WARNING,
                 ['ChassisManufacturer',
                  self.environment.get_chassis_manfacturer()])
        self.log(LogPriority.WARNING,
                 ['UUID', self.environment.get_sys_uuid()])
        self.log(LogPriority.WARNING,
                 ['PropertyNumber', self.environment.get_property_number()])
        self.log(LogPriority.DEBUG,
                 ['ScriptPath', self.environment.get_script_path()])
        self.log(LogPriority.DEBUG,
                 ['ResourcePath', self.environment.get_resources_path()])
        self.log(LogPriority.DEBUG,
                 ['RulePath', self.environment.get_rules_path()])
        self.log(LogPriority.DEBUG,
                 ['ConfigurationPath', self.environment.get_config_path()])
        self.log(LogPriority.DEBUG,
                 ['LogPath', self.environment.get_log_path()])
        self.log(LogPriority.DEBUG,
                 ['IconPath', self.environment.get_icon_path()])
        # --- End machine specific information


class MessageData:
    """
    Simple object for handling Message Data in a concrete fashion.
    @author: scmcleni
    """
    Tag = "None"
    Detail = "None"


class LogPriority:
    """
    Enum (python way) of log levels.

    @author: scmcleni
    """

    # I'm not really happy about doing it this way, but it's the shortest
    # way to be able to compare and get a string name back from an 'enum'
    # in python.

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

