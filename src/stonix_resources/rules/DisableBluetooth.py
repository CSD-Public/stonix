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
'''
Created on Jun 24, 2013

The DisableBluetooth rule does all of the following:
Disable all bluetooth services
Blacklist all bluetooth drivers
Remove all bluetooth packages
Check to see if all of the above operations have been done or not - report()

@author: bemalmbe
@change: 01/30/2014 dwalker revised
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 02/14/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel Replaced old style CI with new
@change: 2015/04/14 dkennel updated for new isApplicable
'''

from __future__ import absolute_import
import os
import traceback
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..ServiceHelper import ServiceHelper
from ..pkghelper import Pkghelper
from ..KVEditorStonix import KVEditorStonix
from ..stonixutilityfunctions import iterate, setPerms, checkPerms, resetsecon


class DisableBluetooth(Rule):
    '''
    The DisableBluetooth rule does all of the following:
    Disable all bluetooth services
    Blacklist all bluetooth drivers
    Remove all bluetooth packages
    Check to see if all of the above operations have been done or
    not - report()
    '''

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 99
        self.rulename = 'DisableBluetooth'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "Disable all bluetooth services, Blacklist all " + \
        "bluetooth drivers, Remove all bluetooth packages, Check to see " + \
        "if all of the above operations have been done or not - report() " + \
        "Currently there is no undo for the disabling of bluetooth " + \
        "services.  Will be implemented very soon"

        #configuration item instantiation
        datatype = 'bool'
        key = 'DISABLEBLUETOOTH'
        instructions = "To prevent the disabling of bluetooth services, " + \
        "set the value of DISABLEBLUETOOTH to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.applicable = {'type': 'white',
                           'family': ['linux', 'freebsd']}
        self.servicehelper = ServiceHelper(self.environ, self.logger)
        self.guidance = ["NSA(3.3.14)", "CCE 14948-4", "CCE 4377-8",
                         "CCE 4355-4"]
        self.driverdict = { "blacklist":["bluetooth", "btusb", "bcm203x", 
                            "bfusb", "bluecard_cs", "bpa10x", "bt3c_cs", 
                            "btuart_cs", "dtl1_cs", "hci_uart", "hci_usb", 
                            "hci_vhci", "bnep", "cmtp", "hidp", "rfcomm", 
                            "sco", "sdp", "tcs-bin", "bluez", "hid-control", 
                            "avctp", "upnp", "hid-interrupt", 
                            "tcs-bin-cordless", "bfusb"]}
        self.iditerator = 0
        self.created = False

    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the 
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated 
        if the rule does not succeed.

        @return bool
        @author bemalmbe
        @change: dwalker - implemented kveditor
        @change: dwalker - 9-3-2014 commented out bluetooth package removal
            sections due to issues with redhat7 and fedora20
        '''
        try:
            self.detailedresults = ""
            compliant = True
            kvtype = 'conf'
            kvpath = '/etc/modprobe.d/blacklist.conf'
            kvtmppath = '/etc/modprobe.d/blacklist.conf.stonixtmp'
            kvconftype = 'space'
            kvintent = 'present'

#             self.packagelist = ['bluez-libs', 'bluez-libs-devel',
#             'libbtctl-devel', 'libbtctl', 'gnome-bluetooth-libs',
#             'gnome-bluetooth', 'gnome-bluetooth-devel', 'openobex-apps',
#             'openobex-devel', 'bluez']

            # Solaris doesn't support bluetooth and there is no bsd package
            self.servicelist = ['bluetooth', 'dund', 'pand', 'hidd',
                                'ubthidhci', 'bthidd']
            # check whether bluetooth services are disabled
            for service in self.servicelist:
                enabled = self.servicehelper.auditservice(service)
                if enabled:
                    compliant = False
#             self.pkghelper = Pkghelper(self.logger, self.environ)
#             # check whether bluetooth packages exist
#             for package in self.packagelist:
#                 installed = self.pkghelper.check(package)
#                 if installed:
#                     compliant = False
            # check whether bluetooth drivers are blacklisted
            if os.path.exists(kvpath):
                self.kve = KVEditorStonix(self.statechglogger, self.logger,
                   kvtype, kvpath, kvtmppath, self.driverdict, kvintent, kvconftype)
                if not checkPerms(kvpath, [0, 0, 420], self.logger):
                    compliant = False
                if not self.kve.report():
                    self.detailedresults += "Blacklist file exists but is not \
correct\n"
                    compliant = False
            else:
                if os.path.exists('/etc/modprobe.d'):
                    compliant = False
                    os.system('touch /etc/modprobe.d/blacklist.conf')
                    os.system('chmod 644 /etc/modprobe.d/blacklist.conf')
                    os.system('chown root:root /etc/modprobe.d/blacklist.conf')
                    self.created = True
                    self.detailedresults += "Created blacklist file for \
Bluetooth\n"
                    self.kve = KVEditorStonix(self.statechglogger, self.logger,
                    kvtype, kvpath, kvtmppath, self.driverdict, kvintent, kvconftype)
                    self.kve.fixables = self.driverdict
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                                          self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant
    
###############################################################################

    def fix(self):
        '''
        disable all bluetooth services
        remove all bluetooth packages
        blacklist all bluetooth drivers
        
        @author bemalmbe
        @change: dwalker - implemented kveditor
        @return: bool
        @change: dwalker - 9-3-2014 commented out bluetooth package removal
            sections due to issues with redhat7 and fedora20
        '''
        try:
            if not self.ci.getcurrvalue():
                return
            
            #clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            success = True
            debug = ""
            # disable bluetooth services
            for service in self.servicelist:
                if self.servicehelper.auditservice(service):
                    if not self.servicehelper.disableservice(service):
                        success = False
                        debug += "Unable to disable " + service + "\n"

#             # remove bluetooth packages
#             for package in self.packagelist:
#                 if self.pkghelper.check(package):
#                     if self.pkghelper.remove(package):
#                         self.iditerator += 1
#                         myid = iterate(self.iditerator, self.rulenumber)
#                         cmd = self.pkghelper.getInstall()
#                         cmd += package
#                         event = {"eventtype":"commandstring",
#                                  "command":cmd}
#                         self.statechglogger.recordchgevent(myid, event)
#                     else:
#                         success = False
#                         debug += "Unable to remove " + package + "\n"
            if self.created:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype":"creation",
                         "filepath":self.kve.getPath()}

                self.statechglogger.recordchgevent(myid, event)
            # blacklist bluetooth drivers
            if os.path.exists(self.kve.getPath()):
                if not checkPerms(self.kve.getPath(), [0, 0, 420], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.kve.getPath(), [0, 0, 420], self.logger,
                                                  self.statechglogger, myid):
                        success = False
            if self.kve.fixables:
                self.iditerator += 1
                if not self.created:
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.kve.setEventID(myid)
                if not self.kve.fix():
                    success = False
                elif not self.kve.commit():
                    success = False
                os.chown(self.kve.getPath(), 0, 0)
                os.chmod(self.kve.getPath(), 420)
                resetsecon(self.kve.getPath())
            if debug:
                self.logger.log(LogPriority.DEBUG, debug)
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            success = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                                          self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess