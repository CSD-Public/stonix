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
@change: 2015/10/07 eball Help text cleanup
@change 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/10/23 rsn - change to new service helper interface
'''

from __future__ import absolute_import
import os
import traceback
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..ServiceHelper import ServiceHelper
from ..KVEditorStonix import KVEditorStonix
from ..stonixutilityfunctions import iterate, setPerms, checkPerms, resetsecon


class DisableBluetooth(Rule):
    '''The DisableBluetooth rule does all of the following:
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

        # configuration item instantiation
        datatype = 'bool'
        key = 'DISABLEBLUETOOTH'
        instructions = "To prevent the disabling of Bluetooth services, " + \
            "set the value of DISABLEBLUETOOTH to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.applicable = {'type': 'white',
                           'family': ['linux', 'freebsd']}
        self.servicehelper = ServiceHelper(self.environ, self.logger)
        self.guidance = ["NSA(3.3.14)", "CCE 14948-4", "CCE 4377-8",
                         "CCE 4355-4"]
        self.driverdict = {"blacklist": ["bluetooth", "btusb", "bcm203x",
                                         "bfusb", "bluecard_cs", "bpa10x",
                                         "bt3c_cs", "btuart_cs", "dtl1_cs",
                                         "hci_uart", "hci_usb", "hci_vhci",
                                         "bnep", "cmtp", "hidp", "rfcomm",
                                         "sco", "sdp", "tcs-bin", "bluez",
                                         "hid-control", "avctp", "upnp",
                                         "hid-interrupt", "tcs-bin-cordless",
                                         "bfusb"]}
        self.iditerator = 0
        self.created = False
        self.sethelptext()

    def report(self):
        '''The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.


        :returns: bool
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

            # Solaris doesn't support bluetooth and there is no bsd package
            self.servicelist = ['bluetooth', 'dund', 'pand', 'hidd',
                                'ubthidhci', 'bthidd']
            # check whether bluetooth services are disabled
            for service in self.servicelist:
                enabled = self.servicehelper.auditService(service, _="_")
                if enabled:
                    self.detailedresults += service + " is enabled\n"
                    compliant = False
            # check whether bluetooth drivers are blacklisted
            if os.path.exists(kvpath):
                self.kve = KVEditorStonix(self.statechglogger, self.logger,
                                          kvtype, kvpath, kvtmppath,
                                          self.driverdict, kvintent,
                                          kvconftype)
                if not checkPerms(kvpath, [0, 0, 420], self.logger):
                    self.detailedresults += "Permissions are incorrect on " + \
                        kvpath + "\n"
                    debug = "Permissions are incorrect on " + kvpath + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    compliant = False
                self.kve.report()
                if self.kve.fixables:
                    self.detailedresults += "\nThe following configuration options are missing or incorrect in " + str(kvpath) + ":\n" + "\n".join(self.kve.fixables)
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
                                              kvtype, kvpath, kvtmppath,
                                              self.driverdict, kvintent,
                                              kvconftype)
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
        '''disable all bluetooth services
        remove all bluetooth packages
        blacklist all bluetooth drivers
        
        @author bemalmbe
        @change: dwalker - implemented kveditor


        :returns: bool
        @change: dwalker - 9-3-2014 commented out bluetooth package removal
            sections due to issues with redhat7 and fedora20

        '''
        try:
            if not self.ci.getcurrvalue():
                return

            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            success = True
            debug = ""
            # disable bluetooth services
            for service in self.servicelist:
                if self.servicehelper.auditService(service, _="_"):
                    if self.servicehelper.disableService(service, _="_"):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "servicehelper",
                                 "servicename": service,
                                 "startstate": "enabled",
                                 "endstate": "disabled"}
                        self.statechglogger.recordchgevent(myid, event)
                    else:
                        success = False
                        debug += "Unable to disable " + service + "\n"

            if self.created:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": self.kve.getPath()}
                self.statechglogger.recordchgevent(myid, event)
            # blacklist bluetooth drivers
            if os.path.exists(self.kve.getPath()):
                if not checkPerms(self.kve.getPath(), [0, 0, 420],
                                  self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.kve.getPath(), [0, 0, 420],
                                    self.logger, self.statechglogger, myid):
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
