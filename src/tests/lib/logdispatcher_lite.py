#!/usr/bin/env python
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

import os
import re
import time
import socket
import logging
import inspect
import os.path
import weakref
import datetime
import traceback
import subprocess
import logging.handlers
from shutil import move
from logging.handlers import RotatingFileHandler

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        #else:
        #    cls._instances[cls].__init__(*args, **kwargs)
        return cls._instances[cls]


def singleton_decorator(class_):
  instances = {}
  def getinstance(*args, **kwargs):
    if class_ not in instances:
        instances[class_] = class_(*args, **kwargs)
    return instances[class_]
  return getinstance

@singleton_decorator
class LogDispatcher ():
    '''Responsible for taking any log data and formating both a human readable
    log containing machine info and run errors.

    :param environment: Environment object from Stonix
    :param debug_mode: Whether or not to turn on debug mode
    :param verbose_mode: Whether or not to turn on verbose mode
    :param version: 
    :param author: scmcleni
    :param note: rsn
    :param log: files
    :param and: xml functionality

    '''

    def __init__(self, environment=None, debug_mode=False, verbose_mode=False):
        if environment:
            self.environment = environment
            self.debug = self.environment.getdebugmode()
            self.verbose = self.environment.getverbosemode()
        else:
            self.debug = debug_mode
            self.verbose = verbose_mode

   ##########################################################################

    def logEnv(self):
        '''Log environment information to the console.  Taken from original
        __initializeLogs method, this needs to be an optional method for
        logdispatcher_lite
        
        @author: Roy Nielsen


        '''
        if self.environment:
            # start machine specific information
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

    ##########################################################################

    def setDebug(self, debug):
        '''Setter for debug mode
        
        @author: Roy Nielsen

        :param debug: 

        '''
        self.debug = debug

    ##########################################################################

    def setVerbose(self, verbose):
        '''Setter for verbose mode
        
        @author: Roy Nielsen

        :param verbose: 

        '''
        self.verbose = verbose

    ##########################################################################

    def log(self, priority, msg_data):
        '''Handles all writing of logger data to files. `msg_data` should be
        passed as an array of [tag, message_details] where tag is a
        descriptive string for the detailed message and XML log. For example
        
        ['StonixRunDateTime', '2000-01-11 11:40:01']
        
        If msg_data is passed as only a string then it will be tagged as "None"
        
        For STONIX logging purposes all essential notifications should come in
        on the "WARNING" channel. All informational notifications should come
        in on the "INFO" channel. Debug messages should use "DEBUG". Program
        errors should be sent to the "ERROR" facility. "CRITICAL" is reserved
        for events that stop the stonix program.

        :param priority: 
        :param msg_data: 
        :returns: void
        @author scmcleni
        @author: dkennel

        '''

        entry = self.formatMessageData(msg_data)

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

    ##########################################################################

    def formatMessageData(self, msg_data):
        '''If the expected 2 item array is passed then attach those items to
        a MessageData object. Index 0 is expected to be a tag, Index 1 is
        expected to be the detail. If an array is not passed then it is assumed
        that there is no tag (defaults to 'None') and the passed data is set
        as the Detail of the MessageData object.

        :param msg_data: 
        :returns: MessageData
        @author: scmcleni

        '''
        entry = MessageData()
        if isinstance(msg_data, list):
            entry.Tag = msg_data[0].strip()
            detail = str(msg_data[1])
            entry.Detail = detail.strip()
        else:
            entry.Detail = msg_data.strip()

        return entry

    ##########################################################################

    def getconsolemessage(self):
        '''Returns the current message if called while in a dirty state.


        :returns: MessageData
        @author: scmcleni

        '''
        return self.last_message_received

    ##########################################################################

    def getmessageprio(self):
        '''Returns the message priority of the last message received.


        :returns: LogPriority instance
        @author: dkennel

        '''
        return self.last_prio
    
    ##########################################################################

    def rotateLog(self):
        '''Rotate the log if the log handler has been set up
        
        @author: Roy Nielsen


        '''
        try:
            if self.rotHandler:
                self.rotHandler.doRollover()
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise

    ##########################################################################

    def markStartLog(self):
        '''Mark the beginning of a log session.  Rely on if/when a programmer wants
        to use this functionality.
        
        @author: Roy Nielsen


        '''
        logging.warning("############### Starting Log... ##################")

    ##########################################################################

    def markEndLog(self):
        '''Mark the end of a log session.  Rely on if/when a programmer wants
        to use this functionality.
        
        @author: Roy Nielsen


        '''
        logging.warning("################## End Log... ####################")

    ##########################################################################

    def markSeparator(self):
        '''Mark a separator in the log.
        
        @author: Roy Nielsen


        '''
        logging.warning("##################################################")
    
    ##########################################################################

    def initializeLogs(self, filename = "", 
                             extension_type="inc", 
                             log_count=10, 
                             size=10000000, 
                             syslog=True,
                             myconsole=True):
        '''Parameters -
          filename: Name of the file you would like to log to. String
        
          extension_type: type of extension to use on the filename. String
                  none: overwrite the file currently with the passed in name
                 epoch: time since epoch
                  time: date/time stamp .ccyymmdd.hhmm.ss in military time
                   inc: will increment log number similar to logrotate.
        
          log_count:  if "inc" is used above, the count of logs to keep
                      Default keep the last 10 logs.  Int
        
          size     :  if "inc", the size to allow logs to get. Default 10Mb. Int
        
          syslog: Whether or not to log to syslog. Bool
        
          console: Whether or not to log to the console. Bool
        
        Open a handle to a text file making it available for writing (append)
        mode. Also need to look for an old log file (prior run) and move it
        to stonix_last.log.

        :param filename:  (Default value = "")
        :param extension_type:  (Default value = "inc")
        :param log_count:  (Default value = 10)
        :param size:  (Default value = 10000000)
        :param syslog:  (Default value = True)
        :param myconsole:  (Default value = True)
        :returns: void
        @author: scmcleni
        @author: D. Kennel
        @note: R. Nielsen - Making console, rotate and syslog optional

        '''
        rotate = False
        
        if not filename:
            filename = "/tmp/" + str(os.geteuid()) + "." + "stonixtest.log"
            
        self.last_prio = LogPriority.ERROR
        self.last_message_received = ""

        rotate = False
        if extension_type in ["none", "epoch", "time", "inc"]:
            if extension_type == "none":
                #####
                # Overwrite self.reportlog
                self.reportlog = filename
                
            elif extension_type == "epoch":
                #####
                # Set filename to <filename>.<seconds-since-epoch>
                self.reportlog = filename + "." + str(time.time())
                
            elif extension_type == "time":
                #####
                # Set filename to <filename>.<YYYYMMDD>.<HHMM>.<SS>
                self.reportlog = filename + "." + str(datetime.datetime.now().strftime("%Y%m%d.%H%M.%s"))
            elif extension_type == "inc":
                #####
                # Rotate logs similar to logrotate
                rotate = True
                self.reportlog = filename
                
        elif re.match("^\s+$", filename) or re.match("^$", filename):
            print " ... no filename given ..."
        else:
            self.reportlog = filename

        if rotate or syslog or myconsole or self.reportlog:
            #####
            # Safe initialization as the variable may be used elsewhere in
            # the class
            self.rotHandler = None
            
            #####
            # Acquire the root logger for initialization
            mylogger = logging.getLogger('')

            #####
            # Setting the log priority
            if self.debug:
                mylogger.setLevel(logging.DEBUG)
            elif self.verbose:
                mylogger.setLevel(logging.INFO)
            else:
                mylogger.setLevel(logging.WARNING)
            
            if myconsole:
                #####
                #set up console logging
                console = logging.StreamHandler()
                
                mylogger.addHandler(console)
                    
            if not rotate:
                # Configure the python logging utility. Set the minimum reported log
                # data to warning or higher. (INFO and DEBUG messages will be ignored)
                if self.debug:
                    logging.basicConfig(filename=self.reportlog,
                                        level=logging.DEBUG)
                elif self.verbose:
                    logging.basicConfig(filename=self.reportlog,
                                        level=logging.INFO)
                else:
                    logging.basicConfig(filename=self.reportlog,
                                        level=logging.WARNING)
            else:
                # create a rotating handler
                self.rotHandler = RotatingFileHandler(self.reportlog, 
                                                      maxBytes=size,
                                                      backupCount=log_count)

                mylogger.addHandler(self.rotHandler)
    
            if syslog:
                #####
                # Set up syslog logging
                try:
                    syslogs = logging.handlers.SysLogHandler()
                    syslogs.setLevel(logging.WARNING)
                    logging.getLogger('').addHandler(syslogs)
                except (KeyboardInterrupt, SystemExit):
                    # User initiated exit
                    raise
                except socket.error:
                    self.log(LogPriority.ERROR,
                             ['LogDispatcher',
                              'SYSLOG not accepting connections!'])

##############################################################################

class MessageData:
    '''Simple object for handling Message Data in a concrete fashion.
    @author: scmcleni


    '''
    Tag = "None"
    Detail = "None"

##############################################################################

class LogPriority:
    '''Enum (python way) of log levels.
    
    @author: scmcleni


    '''

    # I'm not really happy about doing it this way, but it's the shortest
    # way to be able to compare and get a string name back from an 'enum'
    # in python.

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

